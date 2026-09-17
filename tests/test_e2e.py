"""End to end: demo syslog lines -> ingest -> every API endpoint, through first-run setup and login."""
import os
import random
import re
import time

import pytest

from vigil import demo, settings

PASSWORD = 'correct-horse-battery'
LINES = []


@pytest.fixture(scope='module')
def client():
    settings.ensure_dirs()
    now = int(time.time() * 1000)
    start = now - 6 * 3_600_000
    demo.R.seed(7)
    lines, t, i = [], start, 0
    while t < now - 60_000:
        for rec in demo.batch(t):
            fmt = 'cef' if i % 2 else 'default'
            msg = demo.render(t, rec, fmt).decode()[5:]
            lines.append(f"{time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(t / 1000))} 127.0.0.1 {msg}\n")
            i += 1
        if i % 400 == 0:
            for rec in demo.ips_attack(t) + demo.brute_force(t) + demo.config_change(t, i // 400):
                lines.append(f"{time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(t / 1000))} 127.0.0.1 "
                             f"{demo.render(t, rec, 'cef').decode()[5:]}\n")
        t += random.Random(i).uniform(200, 900)
    with open(settings.LOG_BASE, 'w') as f:
        f.writelines(lines)
    LINES[:] = lines
    demo.install_demo_config(start + 60_000)
    from vigil import ingest
    ingest.run(follow=False)
    from fastapi.testclient import TestClient
    from vigil.web import app
    with TestClient(app) as c:
        yield c


def test_setup_login_and_session(client):
    r = client.get('/api/overview', follow_redirects=False)
    assert r.status_code == 401 and r.json().get('setup')
    assert client.get('/', follow_redirects=False).headers['location'] == '/setup'
    r = client.post('/setup', data={'username': 'admin', 'password': 'short', 'confirm': 'short'})
    assert r.status_code == 400
    r = client.post('/setup', data={'username': 'admin', 'password': PASSWORD, 'confirm': PASSWORD}, follow_redirects=False)
    assert r.status_code == 303
    assert client.post('/setup', data={'username': 'x', 'password': PASSWORD, 'confirm': PASSWORD},
                       follow_redirects=False).headers['location'] == '/login'          # setup closes after the first account
    assert client.get('/api/session').json()['user'] == 'admin'
    client.cookies.clear()
    assert client.get('/api/overview').status_code == 401
    r = client.post('/login', data={'username': 'admin', 'password': 'wrong-password'})
    assert r.status_code == 401
    r = client.post('/login', data={'username': 'admin', 'password': PASSWORD, 'next': '/'}, follow_redirects=False)
    assert r.status_code == 303 and 'vigil_session' in r.headers.get('set-cookie', '')


@pytest.mark.parametrize('path', ['/api/meta', '/api/overview?preset=24h', '/api/insights?preset=24h', '/api/inbound?preset=24h',
                                  '/api/outbound?preset=24h', '/api/utm?preset=24h', '/api/security?preset=24h',
                                  '/api/graph3d/meta', '/api/graph3d/live', '/api/graph3d/timeline?preset=24h', '/api/health',
                                  '/api/settings', '/api/config/live', '/api/logs?table=traffic&limit=50',
                                  '/api/inv/search?q=port+3389', '/api/inv/trace?type=ip&value=198.51.100.66', '/api/policy/5'])
def test_endpoints(client, path):
    r = client.get(path)
    assert r.status_code == 200, (path, r.text[:300])
    assert 'error' not in r.json(), r.text[:300]


def test_data_makes_sense(client):
    sec = client.get('/api/security?preset=24h').json()
    # the replayed demo changes can leave policy 5 disabled, depending on where the generated hours end
    assert sec['config']['loaded'] and sec['posture']['accept_rules'] >= 4
    assert {r['id'] for r in sec['rules']} >= {1, 2, 3, 4}
    assert sec['config']['live']['changes_since_backup'] > 0
    assert sec['detections']['scanners']['count'] > 0
    meta = client.get('/api/meta').json()
    assert meta['firewall']['name'] == 'FGT-DEMO'
    inb = client.get('/api/inbound?preset=24h').json()
    assert inb['policies'] and inb['deny_port']
    out = client.get('/api/outbound?preset=24h').json()
    assert out['roots']
    s = client.get('/api/inv/search?q=198.51.100.66').json()
    assert s['items'], s
    ev = client.get('/api/inv/event', params={'ref': s['items'][0]['ref']}).json()
    assert ev['summary']['firewall'] == 'FGT-DEMO' and ev['path']
    live = client.get('/api/graph3d/live').json()
    assert live['agg']['totals']['denied'] > 0
    # scanner denies are not stored as rows: they must be found in the raw log in both formats
    for is_cef in (False, True):
        line = next(x for x in LINES if (('|traffic:forward deny|' in x) if is_cef
                                         else ('subtype="forward"' in x and 'action="deny"' in x)))
        ip = re.search(r' (?:src|srcip)=([0-9.]+) ', line).group(1)
        r = client.get('/api/inv/search', params={'q': f'why was {ip} blocked', 'preset': '24h'}).json()
        assert any(it['table'] == 'raw-deny' for it in r['items']), (is_cef, ip, r['counts'])


def test_settings_upload_and_password(client):
    r = client.put('/api/settings', json={'firewall_name': 'EDGE-1', 'retention_days': 14, 'domain_allowlist': ['*.Example.com']})
    assert r.status_code == 200 and r.json()['settings']['domain_allowlist'] == ['example.com']
    assert client.put('/api/settings', json={'retention_days': 'x'}).status_code == 400
    assert client.put('/api/settings', json={'nope': 1}).status_code == 400
    assert client.put('/api/settings', json={'retention_days': True}).status_code == 400
    assert client.put('/api/settings', json={'telemetry': 'yes'}).status_code == 400
    r = client.put('/api/settings', json={'telemetry': False})
    assert r.status_code == 200 and r.json()['settings']['telemetry'] is False
    st = client.get('/api/settings').json()
    assert st['community']['telemetry']['enabled'] is False and 'instance_id' in st['community']['telemetry']['preview']
    client.put('/api/settings', json={'telemetry': True})
    with open(demo.DEMO_CONFIG, 'rb') as f:
        r = client.post('/api/config/upload', files={'file': ('edge.conf', f.read())}, data={'backup_time': str(int(time.time() * 1000))})
    assert r.status_code == 200 and r.json()['imported']['policies'] == 7
    assert client.post('/api/config/upload', files={'file': ('x.txt', b'not a config at all, sorry')}).status_code == 400
    r = client.post('/api/account/password', json={'current': 'wrong', 'password': 'another-long-pass', 'confirm': 'another-long-pass'})
    assert r.status_code == 403
    r = client.post('/api/account/password', json={'current': PASSWORD, 'password': 'another-long-pass', 'confirm': 'another-long-pass'})
    assert r.status_code == 200
    assert client.get('/api/session').json()['user'] == 'admin'          # this session was re-issued


def test_static_ui_is_served(client):
    r = client.get('/')
    assert r.status_code == 200 and 'Vigil' in r.text
    for name in ('app.js', 'style.css', 'security.js', 'graph3d.js', 'inv.js', 'favicon.svg'):
        assert client.get('/static/' + name).status_code == 200, name
