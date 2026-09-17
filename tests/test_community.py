"""Usage ping: only the documented fields, off switches respected, delivered as a plain POST."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from vigil import community, settings

ALLOWED = {'type', 'instance_id', 'version', 'arch', 'demo', 'days_installed', 'firewalls', 'eps_bucket', 'config_loaded',
           'login_enabled'}


def test_payload_is_anonymous_and_stable():
    settings.ensure_dirs()
    a, b = community.ping_payload(), community.ping_payload()
    assert set(a) == ALLOWED
    assert a['instance_id'] == b['instance_id'] and len(a['instance_id']) == 36
    text = json.dumps(a)
    for secret_ish in ('127.0.0.1', settings.DATA, 'FGT'):
        assert secret_ish not in text


def test_eps_buckets():
    assert [community._eps_bucket(x) for x in (None, 0, 0.5, 5, 50, 500, 5000)] == \
        ['unknown', '0', '<1', '1-10', '10-100', '100-1000', '1000+']


def test_switches(monkeypatch):
    monkeypatch.setattr(community, 'COMMUNITY_URL', 'http://127.0.0.1:9/')
    monkeypatch.setattr(community, 'ENV_OFF', True)
    assert not community.telemetry_enabled()                 # VIGIL_TELEMETRY=off wins
    monkeypatch.setattr(community, 'ENV_OFF', False)
    settings.save({'telemetry': False})
    assert not community.telemetry_enabled()                 # Settings switch
    settings.save({'telemetry': True})
    assert community.telemetry_enabled()
    monkeypatch.setattr(community, 'COMMUNITY_URL', '')
    assert not community.telemetry_enabled()                 # no endpoint configured


def test_send_ping_posts_json(monkeypatch):
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append((self.headers.get('Content-Type'), json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *a):
            pass
    srv = HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    monkeypatch.setattr(community, 'COMMUNITY_URL', f'http://127.0.0.1:{srv.server_port}/exec')
    assert community.send_ping()
    assert got and got[0][0].startswith('text/plain') and set(got[0][1]) == ALLOWED
    assert community.status()['last_ok'] is True
    srv.server_close()


def test_send_ping_offline_is_quiet(monkeypatch):
    monkeypatch.setattr(community, 'COMMUNITY_URL', 'http://127.0.0.1:9/')
    assert community.send_ping() is False
