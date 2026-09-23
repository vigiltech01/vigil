"""A firewall that publishes nothing to the internet (branch / SD-WAN office box).

Its whole exposed surface is traffic aimed at the firewall itself - SSL-VPN portal, admin ports, scanners - which
FortiOS logs as traffic:local from a WAN interface. That must count as inbound, otherwise every inbound view shows
zero while the attack tables are full.
"""
import json
import os
import subprocess
import sys
import textwrap
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CODE = """
    import json, os, time
    from vigil import db, ingest, queries, graph3d, settings

    now = int(time.time() * 1000) - 60_000
    def line(ts, cat, role, src, dst, dpt, act, pid, country='Germany'):
        return (f'<188>date=2026-01-01 time=00:00:00 devname="FW" devid="FG100FTK00000001" '
                f'eventtime={ts * 1000000} tz="+0000" logid="0000000013" type="traffic" subtype="{cat}" level="notice" '
                f'vd="root" srcip={src} srcport=40000 srcintf="port1" srcintfrole="{role}" dstip={dst} dstport={dpt} '
                f'dstintf="root" srccountry="{country}" sessionid=1 proto=6 action="{act}" policyid={pid} '
                f'policytype="policy" service="tcp/{dpt}"' + chr(10))

    path = settings.LOG_BASE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        for i in range(20):                       # internet -> the firewall itself (SSL-VPN portal), accepted
            f.write(line(now + i, 'local', 'wan', '198.51.100.7', '203.0.113.1', 10443, 'accept', 0))
        for i in range(5):                        # LAN -> the firewall (management), must NOT count as inbound
            f.write(line(now + 100 + i, 'local', 'lan', '10.1.1.5', '10.1.1.1', 443, 'accept', 0, country='Reserved'))
        for i in range(7):                        # LAN -> internet, outbound
            f.write(line(now + 200 + i, 'forward', 'lan', '10.1.1.5', '9.9.9.9', 443, 'close', 6, country='Reserved'))
    ingest.run(follow=False)

    frm, to = now - 3_600_000, now + 3_600_000
    inb = queries.inbound(frm, to)
    tl = graph3d.timeline(frm, to)
    print(json.dumps({
        'inbound_hits': sum(p['hits'] for p in inb['policies']),
        'inbound_sources': sum(p['srcs'] for p in inb['policies']),
        'countries': [c['country'] for c in inb['countries_acc']],
        'timeline_allowed': sum(b[1] for b in tl['buckets']),
        'outbound_hits': sum(r['n'] for r in queries.outbound(frm, to)['policies']) if queries.outbound(frm, to).get('policies') else 0,
    }))
"""


def test_local_in_from_internet_counts_as_inbound(tmp_path):
    env = dict(os.environ, PYTHONPATH=ROOT, VIGIL_WARM='0', VIGIL_DEMO='0', VIGIL_DATA=str(tmp_path / 'data'))
    r = subprocess.run([sys.executable, '-c', textwrap.dedent(CODE)], env=env, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr[-3000:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out['inbound_hits'] == 20, out          # the 20 internet -> firewall sessions
    assert out['inbound_sources'] == 1, out
    assert out['countries'] == ['Germany'], out    # LAN traffic to the firewall ("Reserved") stays out of it
    assert out['timeline_allowed'] == 20, out
