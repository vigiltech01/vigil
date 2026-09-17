"""Vigil web app: JSON API + static single-page UI (web/static), login / first-run setup, settings and config upload."""
import asyncio
import ctypes
import functools
import gc
import json
import logging
import os
import re
import shutil
import threading
import time
from urllib.parse import parse_qs, quote

import anyio
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, auth, cache, community, db, explorer, fgconf, graph3d, insights, investigate, queries, rules, security, settings

STATIC = os.path.join(settings.APP_DIR, 'web', 'static')
log = logging.getLogger('vigil.web')

# ---- resource guards -------------------------------------------------------------------------------------------
THREADS = int(os.environ.get('VIGIL_THREADS', '12'))                 # worker threads (anyio default: 40)
HEAVY = threading.BoundedSemaphore(int(os.environ.get('VIGIL_HEAVY', '3')))    # concurrent heavy queries
MAX_RSS_MB = int(os.environ.get('VIGIL_MAX_RSS_MB', '2000'))
MAX_UPLOAD = 50 * 2**20


def heavy(fn):
    """Run at most VIGIL_HEAVY expensive requests at once; the rest wait up to 30 s, then get a clear 503."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not HEAVY.acquire(timeout=30):
            raise HTTPException(503, 'Vigil is busy with other large queries - please retry in a few seconds')
        try:
            return fn(*a, **kw)
        finally:
            HEAVY.release()
    return wrapper


def _rss_mb():
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) // 1024
    return 0


def _trim():
    gc.collect()
    try:
        ctypes.CDLL('libc.so.6').malloc_trim(0)
    except (OSError, AttributeError):
        pass


def _memory_watchdog():
    """Shed caches when memory is high; exit (the supervisor restarts the web process) if that is not enough."""
    last_log = 0
    while True:
        time.sleep(10)
        try:
            rss = _rss_mb()
            if rss < MAX_RSS_MB * 0.7:
                continue
            cache.cache.prune()
            _trim()
            rss2 = _rss_mb()
            if time.time() - last_log > 300:
                log.warning('memory high: %d MB -> %d MB after pruning caches (limit %d MB)', rss, rss2, MAX_RSS_MB)
                last_log = time.time()
            if rss2 > MAX_RSS_MB:
                cache.cache.data.clear()
                _trim()
                if _rss_mb() > MAX_RSS_MB:
                    log.error('memory still above %d MB after clearing caches - restarting', MAX_RSS_MB)
                    os._exit(70)
        except Exception as e:                                       # the watchdog must never die
            log.warning('watchdog: %s', e)


app = FastAPI(title='Vigil', docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(GZipMiddleware, minimum_size=2048)
PUBLIC = ('/login', '/logout', '/setup', '/healthz', '/static/favicon.svg')
SECURITY_HEADERS = {'X-Frame-Options': 'SAMEORIGIN', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin'}


def session_user(request: Request):
    if auth.DISABLED:
        return 'local'
    return auth.check_token(request.cookies.get(auth.COOKIE)) or auth.check_basic(request.headers.get('authorization', ''))


@app.middleware('http')
async def require_login(request: Request, call_next):
    path = request.url.path
    if not auth.DISABLED and path not in PUBLIC:
        if not auth.configured():
            if path.startswith('/api/'):
                return JSONResponse({'error': 'setup required', 'setup': True}, status_code=401)
            if not path.startswith('/static/'):
                return RedirectResponse('/setup', status_code=303)
        elif not session_user(request):
            if path.startswith('/api/'):
                return JSONResponse({'error': 'login required'}, status_code=401)
            if not path.startswith('/static/'):
                return RedirectResponse('/login' + (f'?next={quote(path)}' if path != '/' else ''), status_code=303)
    resp = await call_next(request)
    if path.startswith('/static/') and '/vendor/' not in path:
        resp.headers['Cache-Control'] = 'no-cache'
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


def _html(body, status=200):
    return HTMLResponse(body, status_code=status, headers={'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY'})


async def _form(request):
    body = await request.body()
    return {k: v[0] for k, v in parse_qs(body.decode('utf-8', 'replace')[:8192]).items()}


def _client_ip(request):
    return request.client.host if request.client else '?'


def _session_cookie(resp, request, user, ttl):
    resp.set_cookie(auth.COOKIE, auth.make_token(user, ttl), max_age=ttl, httponly=True, samesite='lax', path='/',
                    secure=request.url.scheme == 'https' or request.headers.get('x-forwarded-proto') == 'https')


@app.get('/healthz')
def healthz():
    return {'ok': True, 'version': __version__}


@app.get('/setup')
def setup_form():
    if auth.configured():
        return RedirectResponse('/login', status_code=303)
    return _html(auth.setup_page())


@app.post('/setup')
async def setup_submit(request: Request):
    if auth.configured():
        return RedirectResponse('/login', status_code=303)
    f = await _form(request)
    user = f.get('username', '').strip()
    err = auth.validate_new(user, f.get('password', ''), f.get('confirm', ''))
    if err:
        return _html(auth.setup_page(err, user), 400)
    auth.set_account(user, f['password'])
    log.info('administrator account %r created from %s', user, _client_ip(request))
    resp = RedirectResponse('/#welcome', status_code=303)
    _session_cookie(resp, request, user, auth.SESSION_S)
    return resp


@app.get('/login')
def login_form(request: Request, next: str = '/'):
    if not auth.configured():
        return RedirectResponse('/setup', status_code=303)
    if auth.DISABLED or session_user(request):
        return RedirectResponse(auth.safe_next(next), status_code=303)
    return _html(auth.login_page(nxt=auth.safe_next(next)))


@app.post('/login')
async def login_submit(request: Request):
    f = await _form(request)
    user, nxt = f.get('username', '').strip(), auth.safe_next(f.get('next'))
    ip = _client_ip(request)
    wait = auth.locked_for(ip)
    if wait:
        return _html(auth.login_page(f'Too many failed attempts. Try again in {wait} seconds.', user, nxt), 429)
    if not auth.verify(ip, user, f.get('password', '')):
        await asyncio.sleep(0.6)
        return _html(auth.login_page('Wrong username or password.', user, nxt), 401)
    ttl = auth.REMEMBER_S if f.get('remember') else auth.SESSION_S
    frag = re.sub(r'[^\w#?&=%.:/+,@~-]', '', f.get('hash', ''))[:512]
    resp = RedirectResponse(nxt + (frag if frag.startswith('#') else ''), status_code=303)
    _session_cookie(resp, request, user, ttl)
    return resp


@app.api_route('/logout', methods=['GET', 'POST'])
def logout():
    resp = RedirectResponse('/login', status_code=303)
    resp.delete_cookie(auth.COOKIE, path='/')
    return resp


@app.get('/api/session')
def session(request: Request):
    return {'user': session_user(request), 'auth': not auth.DISABLED, 'version': __version__, 'demo': settings.DEMO}


def rng(frm, to):
    now = int(time.time() * 1000)
    to = int(to) if to else now
    frm = int(frm) if frm else to - 86_400_000
    if frm >= to or to - frm > 400 * 86_400_000:
        raise HTTPException(400, 'bad time range')
    return frm, to


@app.get('/')
def index():
    return FileResponse(os.path.join(STATIC, 'index.html'), headers={'Cache-Control': 'no-cache'})


app.mount('/static', StaticFiles(directory=STATIC), name='static')


@app.on_event('startup')
async def _start():
    anyio.to_thread.current_default_thread_limiter().total_tokens = THREADS
    threading.Thread(target=_memory_watchdog, name='memory-watchdog', daemon=True).start()
    if os.environ.get('VIGIL_WARM', '1') == '1':
        cache.start_warmer()
    log.info('Vigil %s web: %d worker threads, %s heavy queries at once, RSS limit %d MB', __version__, THREADS,
             os.environ.get('VIGIL_HEAVY', '3'), MAX_RSS_MB)


@app.get('/api/meta')
def meta():
    return queries.meta()


def _insights(frm, to):
    return {'insights': insights.insights(frm, to), 'alerts': insights.alerts()}


ENDPOINTS = {'overview': queries.overview, 'insights': _insights, 'inbound': queries.inbound, 'outbound': queries.outbound,
             'utm': queries.utm, 'security': security.bundle}
for _name, _fn in ENDPOINTS.items():
    cache.register(_name, _fn)


def serve(name, preset, frm, to):
    frm, to = rng(frm, to)
    generated, val = cache.cached(name, heavy(ENDPOINTS[name]), preset, frm, to)   # cache entries are (epoch_s, value)
    return JSONResponse(dict(val, _generated=int(generated * 1000)) if isinstance(val, dict) else val)

@app.get('/api/overview')
def overview(frm: int = None, to: int = None, preset: str = None):
    return serve('overview', preset, frm, to)


@app.get('/api/insights')
def insights_api(frm: int = None, to: int = None, preset: str = None):
    return serve('insights', preset, frm, to)


@app.get('/api/inbound')
def inbound(frm: int = None, to: int = None, preset: str = None):
    return serve('inbound', preset, frm, to)


@app.get('/api/outbound')
def outbound(frm: int = None, to: int = None, preset: str = None):
    return serve('outbound', preset, frm, to)


@app.get('/api/utm')
def utm(frm: int = None, to: int = None, preset: str = None):
    return serve('utm', preset, frm, to)


@app.get('/api/security')
def security_api(frm: int = None, to: int = None, preset: str = None):
    """Log evidence comes from the cache; rules are scored against the live configuration on every request."""
    frm, to = rng(frm, to)
    generated, b = cache.cached('security', heavy(security.bundle), preset, frm, to)
    val = security.assemble(b, rules.load())
    return JSONResponse(dict(val, _generated=int(generated * 1000)))


@app.get('/api/config/live')
def config_live(since: str = ''):
    """Configuration change feed for polling: version + changes newer than `since` (epoch ms)."""
    m = rules.load()
    live = getattr(m, 'live', None) or {}
    ms = int(since) if since.isdigit() else 0
    return {'version': live.get('version'), 'loaded': getattr(m, 'loaded', None),
            'last_change': live.get('last_change'), 'changes_since_backup': live.get('changes_since_backup', 0),
            'new': [r for r in live.get('recent', []) if r['ts'] > ms][:50] if ms else []}


@app.get('/api/graph3d/meta')
def graph_meta():
    return graph3d.meta()


@app.get('/api/graph3d/live')
def graph_live(since: int = 0):
    return graph3d.live(since)


@app.get('/api/graph3d/events')
@heavy
def graph_events(frm: int, to: int):
    frm, to = rng(frm, to)
    return graph3d.events(frm, to)


@app.get('/api/graph3d/timeline')
def graph_timeline(frm: int = None, to: int = None, preset: str = None):
    frm, to = rng(frm, to)
    generated, val = cache.cached('graph_timeline', graph3d.timeline, preset, frm, to)
    return JSONResponse(val)


@app.get('/api/security/rule/{pid}')
def security_rule(pid: int):
    m = rules.load()
    if not m or pid not in m.by_id:
        raise HTTPException(404, 'rule not in the loaded configuration')
    return dict(rules.analyze_rule(m, m.by_id[pid]), raw=m.by_id[pid])


@app.get('/api/policy/{pid}')
@heavy
def policy(pid: int, frm: int = None, to: int = None, preset: str = None):
    frm, to = rng(frm, to)
    generated, val = cache.cached(f'policy:{pid}', lambda a, b: explorer.policy_report(pid, a, b), preset, frm, to)
    return JSONResponse(dict(val, _generated=int(generated * 1000)))


@app.get('/api/logs')
@heavy
def logs(request: Request, table: str = 'traffic', frm: int = None, to: int = None, limit: int = 500, offset: int = 0):
    if table not in explorer.TABLES and table != 'noise':
        raise HTTPException(400, 'unknown table')
    f = {k: v for k, v in request.query_params.items() if k not in ('table', 'frm', 'to', 'limit', 'offset')}
    return explorer.logs(table, *rng(frm, to), f, max(1, min(limit, 20000)), max(0, offset))


@app.get('/api/raw')
def raw(fid: int, off: int):
    return explorer.raw_line(fid, off)


@app.get('/api/inv/search')
@heavy
def inv_search(request: Request, q: str = '', frm: int = None, to: int = None):
    extra = {k: v for k, v in request.query_params.items() if k not in ('q', 'frm', 'to')}
    return investigate.search(q, *rng(frm, to), extra)


@app.get('/api/inv/event')
@heavy
def inv_event(ref: str):
    try:
        return investigate.investigate(ref)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.get('/api/inv/raw')
def inv_raw(ref: str):
    return investigate.raw_event(ref)


@app.get('/api/inv/trace')
@heavy
def inv_trace(type: str, value: str, frm: int = None, to: int = None):
    try:
        return investigate.trace(type, value, *rng(frm, to))
    except ValueError as e:
        raise HTTPException(400, str(e))



# ---------------------------------------------------------------- settings, configuration upload, account
def _config_info():
    m = rules.load()
    if not m:
        return {'loaded': False}
    d = rules._cache.get('d') or {}
    live = getattr(m, 'live', {}) or {}
    return {'loaded': True, 'file': d.get('_source'), 'backup_ms': d.get('_backup_ms'), 'uploaded_ms': d.get('_uploaded_ms'),
            'model': d.get('_model'), 'version': d.get('_version'), 'hostname': m.hostname,
            'policies': len(m.policies), 'inbound_rules': len(rules.inbound_rules(m)), 'local_in': len(m.local_in),
            'addresses': len(m.addresses), 'vips': len(m.vips), 'changes_since_backup': live.get('changes_since_backup', 0)}


def _read_status(name):
    try:
        with open(os.path.join(settings.DATA, 'status', name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


@app.get('/api/settings')
def get_settings():
    a = auth.account() or {}
    return {'settings': settings.load(), 'config': _config_info(), 'receiver': _read_status('receiver.json'),
            'account': {'user': a.get('user'), 'changed': a.get('changed')}, 'demo': settings.DEMO, 'version': __version__,
            'syslog_port': int(os.environ.get('VIGIL_SYSLOG_PUBLISHED_PORT', '514')),
            'community': {'url': community.COMMUNITY_URL, 'telemetry': community.status()}}


@app.put('/api/settings')
async def put_settings(request: Request):
    try:
        patch = await request.json()
    except ValueError:
        raise HTTPException(400, 'expected JSON')
    if not isinstance(patch, dict):
        raise HTTPException(400, 'expected a JSON object')
    types = {'firewall_name': str, 'interfaces': dict, 'vpn_pools': list, 'expected_apps': dict, 'domain_allowlist': list,
             'retention_days': int, 'device_tz_hours': (int, float), 'telemetry': bool}
    for k, v in patch.items():
        if k not in types:
            raise HTTPException(400, f'unknown setting {k}')
        if not isinstance(v, types[k]) or (isinstance(v, bool) and types[k] is not bool):
            raise HTTPException(400, f'{k}: wrong type')
    if 'retention_days' in patch and not 1 <= patch['retention_days'] <= 365:
        raise HTTPException(400, 'retention_days must be 1-365')
    if 'firewall_name' in patch and len(patch['firewall_name']) > 64:
        raise HTTPException(400, 'firewall_name too long')
    if 'domain_allowlist' in patch:
        patch['domain_allowlist'] = sorted({str(x).strip().lower().lstrip('*.') for x in patch['domain_allowlist'] if str(x).strip()})[:5000]
    return {'settings': settings.save(patch)}


@app.post('/api/config/upload')
def upload_config(file: UploadFile = File(...), backup_time: str = Form(''), vdom: str = Form('root')):
    data = file.file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, 'file larger than 50 MB')
    backup_ms = None
    if backup_time:
        try:
            backup_ms = int(float(backup_time))
        except ValueError:
            raise HTTPException(400, 'backup_time must be epoch milliseconds')
    try:
        clean, info = fgconf.import_backup(data, os.path.basename(file.filename or 'backup.conf')[:120], backup_ms, vdom or 'root')
    except fgconf.ConfigError as e:
        raise HTTPException(400, str(e))
    os.makedirs(os.path.dirname(settings.CONFIG_PATH), exist_ok=True)
    tmp = settings.CONFIG_PATH + '.tmp'
    with open(tmp, 'w') as f:
        f.write(fgconf.dump(clean))
    os.replace(tmp, settings.CONFIG_PATH)
    cache.cache.data.clear()
    log.info('configuration backup imported: %s', {k: v for k, v in info.items() if k != 'filename'})
    return {'imported': info, 'config': _config_info()}


@app.delete('/api/config')
def delete_config():
    if os.path.exists(settings.CONFIG_PATH):
        os.remove(settings.CONFIG_PATH)
    cache.cache.data.clear()
    return {'config': {'loaded': False}}


@app.post('/api/account/password')
async def change_password(request: Request):
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, 'expected JSON')
    a = auth.account()
    if not a:
        raise HTTPException(400, 'authentication is disabled')
    if not auth.verify(_client_ip(request), a['user'], body.get('current', '')):
        await asyncio.sleep(0.6)
        raise HTTPException(403, 'current password is wrong')
    err = auth.validate_new(a['user'], body.get('password', ''), body.get('confirm', ''))
    if err:
        raise HTTPException(400, err)
    auth.set_account(a['user'], body['password'])
    resp = JSONResponse({'ok': True, 'message': 'Password changed. Other sessions are signed out.'})
    _session_cookie(resp, request, a['user'], auth.SESSION_S)
    return resp


# ---------------------------------------------------------------- health
@app.get('/api/health')
def health():
    d = queries.health()
    d['disk'] = shutil.disk_usage(settings.DATA)._asdict()
    d['db_bytes'] = sum(os.path.getsize(db.DB_PATH + s) for s in ('', '-wal') if os.path.exists(db.DB_PATH + s))
    base = settings.LOG_BASE
    d['log_mtime_age_s'] = round(time.time() - os.path.getmtime(base), 1) if os.path.exists(base) else None
    files = []
    if os.path.isdir(settings.LOG_DIR):
        names = {base} | {os.path.join(settings.LOG_DIR, f) for f in os.listdir(settings.LOG_DIR)
                          if f.startswith(os.path.basename(base) + '.')}
        files = [{'path': os.path.basename(p), 'bytes': os.path.getsize(p), 'mtime': int(os.path.getmtime(p) * 1000)}
                 for p in sorted(names) if os.path.exists(p)]
    d['log_files'] = files
    d['receiver'] = _read_status('receiver.json')
    d['supervisor'] = _read_status('supervisor.json')
    mem = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':', 1)
                if k in ('MemTotal', 'MemAvailable'):
                    mem[k] = int(v.split()[0]) * 1024
    except OSError:
        pass
    for p in ('/sys/fs/cgroup/memory.current', '/sys/fs/cgroup/memory.max'):
        try:
            with open(p) as f:
                v = f.read().strip()
            mem['cgroup_' + os.path.basename(p).split('.')[1]] = int(v) if v.isdigit() else None
        except OSError:
            pass
    d['mem'] = mem
    d['version'] = __version__
    d['demo'] = settings.DEMO
    return d


@app.exception_handler(Exception)
def on_error(request: Request, exc: Exception):
    log.exception('unhandled error on %s', request.url.path)
    return JSONResponse({'error': f'{type(exc).__name__}: {exc}'}, status_code=500)
