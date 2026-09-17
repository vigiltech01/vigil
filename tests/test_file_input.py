"""File input (VIGIL_INPUT=file): the host already runs a syslog server on 514 and Vigil reads its file read-only.

Settings are read at import time, so each scenario runs in a fresh interpreter with its own environment.
"""
import gzip
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(code, **env):
    e = dict(os.environ, PYTHONPATH=ROOT, VIGIL_WARM='0', VIGIL_DEMO='0')
    e.update({k: str(v) for k, v in env.items()})
    r = subprocess.run([sys.executable, '-c', textwrap.dedent(code)], env=e, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_settings_modes(tmp_path):
    code = """
        import json
        from vigil import settings as s
        print(json.dumps([s.INPUT, s.LOG_DIR, s.LOG_BASE, s.HOST_LOG_FILE, s.BACKFILL_DAYS]))"""
    data = str(tmp_path / 'data')
    assert _run(code, VIGIL_DATA=data) == ['receiver', f'{data}/logs', f'{data}/logs/fortigate.log', None, 0.0]
    assert _run(code, VIGIL_DATA=data, VIGIL_INPUT='file', VIGIL_HOST_LOG_MOUNT='/host-logs', VIGIL_LOG_NAME='fortigate.log',
                VIGIL_HOST_LOG_FILE='/var/log/remote/fortigate.log') == \
        ['file', '/host-logs', '/host-logs/fortigate.log', '/var/log/remote/fortigate.log', 1.0]
    # demo traffic is sent to the built-in receiver, so demo mode always uses it
    assert _run(code, VIGIL_DATA=data, VIGIL_INPUT='file', VIGIL_DEMO='1')[0] == 'receiver'
    assert _run(code, VIGIL_DATA=data, VIGIL_INPUT='nonsense')[0] == 'receiver'


def _host_lines(start_ms, count, host='fw-edge'):
    """What rsyslog writes for a FortiGate: '<ISO time> <hostname> <message>', mixed with the host's own logs."""
    from vigil import demo
    demo.R.seed(3)
    out, t, i = [], start_ms, 0
    while len(out) < count:
        for rec in demo.batch(t):
            iso = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(t / 1000))
            msg = demo.render(t, rec, 'cef' if i % 2 else 'default').decode().split('>', 1)[1]
            out.append(f'{iso} {host} {msg}\n')
            if i % 7 == 0:
                out.append(f'{iso} vigil-host systemd[1]: Started Daily apt download activities.\n')
                out.append(f'{iso} vigil-host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP DPT=22\n')
            i += 1
        t += 400
    return out


def test_ingest_host_syslog_file_read_only(tmp_path):
    host_dir = tmp_path / 'var-log'
    host_dir.mkdir()
    now = int(time.time() * 1000)
    live = _host_lines(now - 3_600_000, 1500)
    rotated = _host_lines(now - 20 * 3_600_000, 800, host='fw-edge')
    old = _host_lines(now - 5 * 86_400_000, 600, host='fw-edge')
    (host_dir / 'syslog').write_text(''.join(live))
    (host_dir / 'syslog.1').write_text(''.join(rotated))
    with gzip.open(host_dir / 'syslog.2.gz', 'wt') as f:
        f.write(''.join(old))
    week_ago = time.time() - 5 * 86400
    os.utime(host_dir / 'syslog.2.gz', (week_ago, week_ago))
    for p in host_dir.iterdir():                                   # the mount is read-only: nothing may be written
        p.chmod(stat.S_IRUSR | stat.S_IRGRP)
    host_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        res = _run("""
            import json, sqlite3
            from vigil import ingest, settings
            settings.ensure_dirs()
            ingest.run(follow=False)
            c = sqlite3.connect(settings.DB_PATH)
            files = {p.rsplit('/', 1)[1]: [done, off] for p, done, off in c.execute('SELECT path, done, off FROM files')}
            lines = c.execute('SELECT sum(n) FROM r_1m').fetchone()[0]
            print(json.dumps({'files': files, 'lines': lines, 'input': settings.INPUT}))""",
                   VIGIL_DATA=tmp_path / 'data', VIGIL_INPUT='file', VIGIL_HOST_LOG_MOUNT=host_dir, VIGIL_LOG_NAME='syslog')
    finally:
        host_dir.chmod(stat.S_IRWXU)
    assert res['input'] == 'file'
    fortigate_lines = sum(1 for l in live + rotated if ' vigil-host ' not in l)
    assert res['lines'] == fortigate_lines                        # host lines ignored, the old rotation skipped
    assert res['files']['syslog.2.gz'][0] == 1 and res['files']['syslog.2.gz'][1] == 0
    assert res['files']['syslog.1'][0] == 1 and res['files']['syslog.1'][1] > 0
    assert sorted(os.listdir(host_dir)) == ['syslog', 'syslog.1', 'syslog.2.gz']


def test_health_reports_file_input(tmp_path):
    host_dir = tmp_path / 'var-log'
    host_dir.mkdir()
    (host_dir / 'fortigate.log').write_text(''.join(_host_lines(int(time.time() * 1000) - 600_000, 50)))
    res = _run("""
        import json
        from fastapi.testclient import TestClient
        from vigil import db, settings
        settings.ensure_dirs()
        db.connect().close()
        from vigil.web import app
        with TestClient(app) as c:
            h = c.get('/api/health').json()
            s = c.get('/api/settings').json()
        print(json.dumps({'health': h['input'], 'settings': s['input'], 'receiver': h['receiver']}))""",
               VIGIL_DATA=tmp_path / 'data', VIGIL_INPUT='file', VIGIL_HOST_LOG_MOUNT=host_dir, VIGIL_LOG_NAME='fortigate.log',
               VIGIL_HOST_LOG_FILE='/var/log/fortigate.log', VIGIL_AUTH='off')
    for d in (res['health'], res['settings']):
        assert d['mode'] == 'file' and d['file'] == '/var/log/fortigate.log'
        assert d['exists'] and d['readable'] and d['bytes'] > 0 and d['age_s'] < 60 and d['host_port'] == 514
    assert res['receiver'] is None
