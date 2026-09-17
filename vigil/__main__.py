"""Vigil launcher.

    python -m vigil                run everything (syslog receiver, ingest, web UI; plus demo traffic if VIGIL_DEMO=1)
    python -m vigil receiver       only the syslog receiver
    python -m vigil ingest         only the ingest (follows /data/logs/fortigate.log)
    python -m vigil web            only the web UI
    python -m vigil demo           only the demo traffic generator
    python -m vigil import-config FILE [--backup-time ISO] [--vdom root]
    python -m vigil reset-password USER     (prompts for the new password)

The supervisor restarts a crashed component with back-off and writes /data/status/supervisor.json.
"""
import json
import logging
import os
import signal
import subprocess
import sys
import time

from . import __version__, settings

log = logging.getLogger('vigil')
COMPONENTS = ['receiver', 'ingest', 'web']


def _web():
    import uvicorn
    uvicorn.run('vigil.web:app', host=os.environ.get('VIGIL_HOST', '0.0.0.0'), port=int(os.environ.get('VIGIL_PORT', '8080')),
                workers=1, access_log=False, log_level='info', proxy_headers=True,
                forwarded_allow_ips=os.environ.get('VIGIL_TRUSTED_PROXIES', '127.0.0.1'),
                limit_concurrency=int(os.environ.get('VIGIL_MAX_CONN', '200')), timeout_keep_alive=5)


def _component(name):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    settings.ensure_dirs()
    if name == 'receiver':
        from . import syslogd
        syslogd.run()
    elif name == 'ingest':
        sys.argv = ['vigil-ingest', '--tail']
        from . import ingest
        ingest.main()
    elif name == 'web':
        _web()
    elif name == 'demo':
        from . import demo
        demo.run()
    elif name == 'community':
        from . import community
        community.run()
    else:
        raise SystemExit(f'unknown component {name}')


def _write_status(procs):
    path = os.path.join(settings.DATA, 'status', 'supervisor.json')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {'version': __version__, 'updated': int(time.time() * 1000), 'demo': settings.DEMO,
            'components': {n: {'pid': p['proc'].pid if p['proc'] else None, 'running': bool(p['proc'] and p['proc'].poll() is None),
                               'restarts': p['restarts'], 'started': p['started']} for n, p in procs.items()}}
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.replace(tmp, path)


def supervise():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    settings.ensure_dirs()
    from . import auth, db
    auth.bootstrap_from_env()
    db.connect().close()                                  # create / migrate the schema once, before the readers start
    from . import community
    names = COMPONENTS + (['demo'] if settings.DEMO else []) + (['community'] if community.COMMUNITY_URL and not community.ENV_OFF else [])
    procs = {n: {'proc': None, 'restarts': 0, 'started': None, 'next': 0.0, 'backoff': 1.0} for n in names}
    stopping = []

    def stop(*_):
        stopping.append(True)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info('Vigil %s starting: %s%s', __version__, ', '.join(names),
             ' (DEMO MODE - fictional data)' if settings.DEMO else '')
    last_status = 0
    while not stopping:
        now = time.time()
        for n, p in procs.items():
            proc = p['proc']
            if proc is not None and proc.poll() is not None:
                log.warning('%s exited with code %s - restarting in %.0fs', n, proc.returncode, p['backoff'])
                p['proc'], p['next'] = None, now + p['backoff']
                p['backoff'] = min(60.0, p['backoff'] * 2)
                p['restarts'] += 1
            if p['proc'] is None and now >= p['next']:
                p['proc'] = subprocess.Popen([sys.executable, '-m', 'vigil', n])
                p['started'] = int(now * 1000)
                if n == 'receiver':
                    time.sleep(0.5)                       # demo and FortiGate traffic need the port open first
            if p['proc'] is not None and p['started'] and now * 1000 - p['started'] > 300_000:
                p['backoff'] = 1.0                        # stable for 5 minutes: reset back-off
        if now - last_status > 5:
            _write_status(procs)
            last_status = now
        time.sleep(1)
    log.info('stopping components')
    for n in reversed(names):
        proc = procs[n]['proc']
        if proc and proc.poll() is None:
            proc.terminate()
    deadline = time.time() + 60
    for n in reversed(names):
        proc = procs[n]['proc']
        if proc:
            try:
                proc.wait(max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                proc.kill()
    _write_status(procs)


def import_config(args):
    import argparse
    from datetime import datetime
    from . import fgconf
    ap = argparse.ArgumentParser(prog='vigil import-config')
    ap.add_argument('file')
    ap.add_argument('--backup-time', help='when the backup was taken, ISO 8601 (default: now)')
    ap.add_argument('--vdom', default='root')
    a = ap.parse_args(args)
    backup_ms = int(datetime.fromisoformat(a.backup_time).timestamp() * 1000) if a.backup_time else None
    with open(a.file, 'rb') as f:
        clean, info = fgconf.import_backup(f.read(), os.path.basename(a.file), backup_ms, a.vdom)
    settings.ensure_dirs()
    with open(settings.CONFIG_PATH, 'w') as f:
        f.write(fgconf.dump(clean))
    print(json.dumps(info, indent=2))


def reset_password(args):
    import getpass
    from . import auth
    if len(args) != 1:
        raise SystemExit('usage: python -m vigil reset-password USER')
    pw = getpass.getpass('New password: ')
    err = auth.validate_new(args[0], pw, getpass.getpass('Repeat: '))
    if err:
        raise SystemExit(err)
    auth.set_account(args[0], pw)
    print('Password set. All sessions are signed out.')


def main():
    args = sys.argv[1:]
    if not args:
        supervise()
    elif args[0] in ('receiver', 'ingest', 'web', 'demo', 'community'):
        _component(args[0])
    elif args[0] == 'import-config':
        import_config(args[1:])
    elif args[0] == 'reset-password':
        reset_password(args[1:])
    elif args[0] in ('-V', '--version', 'version'):
        print(__version__)
    else:
        print(__doc__)
        raise SystemExit(2)


if __name__ == '__main__':
    main()
