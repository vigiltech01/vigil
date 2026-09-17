"""Admin account, first-run setup, login page and signed session cookie.

* No account yet -> every page redirects to /setup, where the first visitor creates the admin account (do this right after
  installing, or pre-create it with VIGIL_ADMIN_USER / VIGIL_ADMIN_PASSWORD).
* The password is stored as PBKDF2-SHA256 (600k iterations) in /data/auth.json together with a random session key;
  changing the password rotates the key and signs everyone out.
* Session cookie: base64(user|expiry).hmac, HttpOnly, SameSite=Lax (Secure when served over HTTPS).
* Five failed logins from one IP lock that IP out for 60 s. VIGIL_AUTH=off disables authentication (local demos only).
"""
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import threading
import time

from . import settings

COOKIE = 'vigil_session'
SESSION_S = 12 * 3600
REMEMBER_S = 7 * 86400
MAX_FAILS, LOCK_S = 5, 60
ITER = 600_000
MIN_PASSWORD = 10
DISABLED = os.environ.get('VIGIL_AUTH', 'on').lower() in ('off', '0', 'false', 'no')
_fails = {}
_lock = threading.Lock()
_acct = {'mtime': None, 'v': None}


# ---------------------------------------------------------------- account storage
def account():
    try:
        mt = os.path.getmtime(settings.AUTH_PATH)
    except OSError:
        return None
    if mt != _acct['mtime']:
        try:
            with open(settings.AUTH_PATH) as f:
                _acct.update(v=json.load(f), mtime=mt)
        except (OSError, ValueError):
            return None
    return _acct['v']


def configured():
    return DISABLED or account() is not None


def _hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ITER).hex()


def set_account(user, password):
    salt = secrets.token_hex(16)
    acct = {'user': user, 'salt': salt, 'hash': _hash(password, salt), 'iterations': ITER,
            'secret': secrets.token_hex(32), 'changed': int(time.time() * 1000)}
    os.makedirs(os.path.dirname(settings.AUTH_PATH), exist_ok=True)
    tmp = settings.AUTH_PATH + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(acct, f)
    os.replace(tmp, settings.AUTH_PATH)
    _acct['mtime'] = None
    return acct


def validate_new(user, password, confirm):
    if not user or len(user) > 64 or not all(c.isalnum() or c in '._-@' for c in user):
        return 'Username: 1-64 characters, letters, digits and . _ - @ only.'
    if len(password) < MIN_PASSWORD:
        return f'Password must be at least {MIN_PASSWORD} characters.'
    if password != confirm:
        return 'The two passwords do not match.'
    if password.lower() in (user.lower(), 'password12', 'administrator', 'fortigate123'):
        return 'Choose a less guessable password.'
    return None


def bootstrap_from_env():
    """Pre-create the admin account from VIGIL_ADMIN_USER / VIGIL_ADMIN_PASSWORD (only if none exists)."""
    pw = os.environ.get('VIGIL_ADMIN_PASSWORD', '')
    if pw and account() is None and not DISABLED:
        user = os.environ.get('VIGIL_ADMIN_USER', 'admin')
        err = validate_new(user, pw, pw)
        if err:
            raise SystemExit(f'VIGIL_ADMIN_PASSWORD rejected: {err}')
        set_account(user, pw)


# ---------------------------------------------------------------- sessions
def _key():
    a = account()
    return bytes.fromhex(a['secret']) if a else b''


def _sig(payload):
    return hmac.new(_key(), payload.encode(), hashlib.sha256).hexdigest()


def make_token(user, ttl):
    payload = base64.urlsafe_b64encode(f'{user}|{int(time.time()) + ttl}'.encode()).decode()
    return f'{payload}.{_sig(payload)}'


def check_token(token):
    a = account()
    if not a or not token:
        return None
    try:
        payload, sig = token.rsplit('.', 1)
        if not hmac.compare_digest(sig, _sig(payload)):
            return None
        user, exp = base64.urlsafe_b64decode(payload.encode()).decode().rsplit('|', 1)
        return user if int(exp) > time.time() and user == a['user'] else None
    except (ValueError, UnicodeDecodeError):
        return None


def check_basic(header):
    """Scripts may send HTTP basic credentials."""
    a = account()
    if not a or not header.startswith('Basic '):
        return None
    try:
        u, _, p = base64.b64decode(header[6:]).decode().partition(':')
    except (ValueError, UnicodeDecodeError):
        return None
    return u if hmac.compare_digest(u, a['user']) and hmac.compare_digest(_hash(p, a['salt']), a['hash']) else None


def locked_for(ip):
    with _lock:
        n, first = _fails.get(ip, (0, 0))
        left = LOCK_S - (time.time() - first)
        if left <= 0:
            _fails.pop(ip, None)
            return 0
        return int(left) + 1 if n >= MAX_FAILS else 0


def verify(ip, user, password):
    a = account()
    ok = bool(a) and hmac.compare_digest(user or '', a['user']) & hmac.compare_digest(_hash(password or '', a['salt']), a['hash'])
    with _lock:
        if ok:
            _fails.pop(ip, None)
        else:
            n, first = _fails.get(ip, (0, time.time()))
            _fails[ip] = [n + 1, first]
    return ok


def safe_next(nxt):
    return nxt if nxt and nxt.startswith('/') and not nxt.startswith('//') and '\\' not in nxt else '/'


# ---------------------------------------------------------------- pages
_CSS = """
*{box-sizing:border-box}html,body{margin:0;height:100%;background:#000;color:#f4f4f4;
font:15px/1.5 "Inter","Segoe UI",system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased}
body{display:grid;place-items:center;padding:24px;background:radial-gradient(1200px 600px at 50% 0%,#1b1d22 0%,#000 70%)}
.box{width:100%;max-width:380px}
.mark{font-weight:300;letter-spacing:.42em;font-size:22px;text-align:center;margin-bottom:6px}
.tag{color:#8e8e93;text-align:center;font-size:13px;margin-bottom:34px}
h1{font-weight:400;font-size:17px;margin:0 0 18px;text-align:center;color:#d1d1d6}
label{display:block;color:#8e8e93;font-size:12px;margin:14px 0 6px}
input[type=text],input[type=password]{width:100%;font:inherit;color:#f4f4f4;background:#141416;border:1px solid #2a2a2e;
border-radius:10px;padding:13px 14px;outline:none;transition:border-color .15s}
input:focus{border-color:#8e8e93}
.row{display:flex;align-items:center;gap:8px;margin:16px 0 22px;color:#8e8e93;font-size:13px}.row input{accent-color:#f4f4f4}
button{width:100%;font:inherit;font-weight:500;color:#000;background:#f4f4f4;border:0;border-radius:10px;padding:13px;
cursor:pointer;transition:opacity .15s}button:hover{opacity:.88}button:disabled{opacity:.5}
.err{background:rgba(232,33,39,.12);border:1px solid rgba(232,33,39,.4);color:#ff8a8d;border-radius:10px;padding:10px 12px;
font-size:13px;margin-bottom:6px}
.note{color:#636366;font-size:12px;text-align:center;margin-top:22px;line-height:1.6}
"""


def _page(title, body):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · Vigil</title><link rel="icon" href="/static/favicon.svg"><style>{_CSS}</style></head>
<body><div class="box"><div class="mark">VIGIL</div><div class="tag">FortiGate log intelligence</div>{body}</div>
<script>
var h=document.getElementById('h');if(h)h.value=location.hash;
var f=document.querySelector('form');if(f)f.onsubmit=function(){{var b=f.querySelector('button');b.disabled=true;b.textContent='Please wait…';}};
</script></body></html>'''


def login_page(error='', user='', nxt='/'):
    e = html.escape
    return _page('Sign in', f'''<form method="post" action="/login" autocomplete="on">
  {f'<div class="err">{e(error)}</div>' if error else ''}
  <label for="u">Username</label><input type="text" id="u" name="username" value="{e(user)}" autocomplete="username" required {'' if user else 'autofocus'}>
  <label for="p">Password</label><input type="password" id="p" name="password" autocomplete="current-password" required {'autofocus' if user else ''}>
  <div class="row"><input type="checkbox" id="r" name="remember" value="1"><label for="r" style="margin:0;font-size:13px">Keep me signed in for 7 days</label></div>
  <input type="hidden" name="next" value="{e(nxt)}"><input type="hidden" name="hash" id="h">
  <button type="submit">Sign in</button></form>''')


def setup_page(error='', user='admin'):
    e = html.escape
    return _page('Setup', f'''<form method="post" action="/setup" autocomplete="off">
  <h1>Create the administrator account</h1>
  {f'<div class="err">{e(error)}</div>' if error else ''}
  <label for="u">Username</label><input type="text" id="u" name="username" value="{e(user)}" required>
  <label for="p">Password <span style="color:#636366">(at least {MIN_PASSWORD} characters)</span></label>
  <input type="password" id="p" name="password" autocomplete="new-password" required autofocus>
  <label for="c">Repeat password</label><input type="password" id="c" name="confirm" autocomplete="new-password" required>
  <div style="height:22px"></div><button type="submit">Create account</button>
  <div class="note">This page is only available until an account exists.<br>Stored as a salted PBKDF2 hash in the data volume.</div>
  {_telemetry_note()}</form>''')


def _telemetry_note():
    from . import community
    if not community.COMMUNITY_URL or community.ENV_OFF:
        return ''
    return ('<div class="note" style="margin-top:14px">Vigil sends an anonymous daily usage ping (random install ID, version, rough log '
            'volume - never logs, IP addresses or names). Turn it off in Settings &rarr; Community or with VIGIL_TELEMETRY=off.</div>')
