"""Data for the 3D Inbound Graph: live inbound events (syslog tail), exact event windows for replay (raw syslog via the
sparse offset index), reconstructed windows from rollups when the raw file is archived, the timeline, and the
service map (exposed ports from the firewall configuration).

Every raw event carries its log file id + byte offset, so a single particle can be opened as the original log line.

verdict: 0 allowed, 1 denied, 2 blocked by a security profile, 3 IPS threat
why (denied only): 1 closed port (no rule opens it) · 2 open port but source not allowed · 3 matched a deny rule ·
                   4 aimed at the firewall itself (local-in)
"""
import random
import threading
import time
from collections import Counter, defaultdict

from . import queries, rules as R
from .cef import parse, to_int, has_any
from .ingest import LOG_BASE
from .investigate import files_for, _window_offsets, pkey
from .explorer import fid_path
from .queries import q, floor, M5, H1, DAY
from .threatkb import KB, PORT_CLASS, WELL_KNOWN

ALLOW, DENY, UTM, THREAT = 0, 1, 2, 3
CLOSED, NOT_ALLOWED, DENY_RULE, FIREWALL = 1, 2, 3, 4
MAX_EVENTS = 4000
RAW_WINDOW_MS = 120_000
WHY_TEXT = {CLOSED: 'Closed port - no rule opens it', NOT_ALLOWED: 'Open port, source not allowed',
            DENY_RULE: 'Matched a deny rule', FIREWALL: 'Aimed at the firewall itself'}
# event list layout (internal)
T, SRC, CTRY, DPT, PROTO, APP, V, PID, SRV, BYT, ATTACK, SPT, WHY, FID, OFF = range(15)

_svc = {'t': 0, 'titles': {}, 'exposed': {}}
WAN_ROLE = (b'srcintfrole=wan', b'srcintfrole="wan"')      # CEF / default format


def _ensure_meta():
    if time.time() - _svc['t'] > 300:
        meta()


def _event(d, fid=None, off=None):
    """Parsed CEF dict -> event list, or None if it is not inbound (source interface role != wan)."""
    if d.get('FTNTFGTsrcintfrole') != 'wan':
        return None
    cat = d.get('cat', '')
    act = d.get('act', '')
    if cat.startswith('traffic'):
        v = UTM if d.get('FTNTFGTutmaction') == 'block' or act in ('block', 'blocked', 'dropped') else \
            DENY if act == 'deny' else ALLOW
    elif cat == 'utm:ips':
        v = THREAT
    else:
        return None                      # app-ctrl / webfilter lines duplicate a traffic session; counted separately
    et = d.get('FTNTFGTeventtime', '')
    if not (len(et) >= 13 and et.isdigit()):
        return None
    dpt = to_int(d.get('dpt')) or 0
    pid = pkey(d)
    why = 0
    if v == DENY:
        why = FIREWALL if cat == 'traffic:local' or (pid or 0) >= 100_000 else \
            DENY_RULE if pid not in (0, None) else NOT_ALLOWED if dpt in _svc['exposed'] else CLOSED
    return [int(et[:13]), d.get('src') or '', d.get('FTNTFGTsrccountry') or '', dpt, to_int(d.get('proto')) or 0,
            d.get('FTNTFGTapp') or d.get('app') or '', v, pid, d.get('destinationTranslatedAddress') or d.get('dst') or '',
            (to_int(d.get('out')) or 0) + (to_int(d.get('in')) or 0), d.get('FTNTFGTattack'), to_int(d.get('spt')) or 0,
            why, fid, off]


def _parse_block(data, base_off, fid, t0=None, t1=None):
    """Parse a byte block of complete syslog lines starting at file offset base_off."""
    _ensure_meta()
    out, appblk = [], Counter()
    pos, n = 0, len(data)
    while pos < n:
        nl = data.find(b'\n', pos)
        if nl < 0:
            break
        raw = data[pos:nl]
        off = base_off + pos
        pos = nl + 1
        if not has_any(raw, WAN_ROLE):
            continue
        d = parse(raw.decode('utf-8', 'replace'))
        if not d:
            continue
        if d.get('cat') == 'utm:app-ctrl' and d.get('act') == 'block':
            appblk[d.get('FTNTFGTapp') or d.get('app') or '?'] += 1
            continue
        e = _event(d, fid, off)
        if e and (t0 is None or t0 <= e[T] < t1):
            out.append(e)
    return out, appblk


def _sample(evs, cap=MAX_EVENTS):
    """Keep every non-denied event; thin the (very numerous) scanner denies uniformly."""
    if len(evs) <= cap:
        return evs, 1.0
    keep = [e for e in evs if e[V] != DENY]
    deny = [e for e in evs if e[V] == DENY]
    room = max(cap - len(keep), cap // 4)
    step = max(1, -(-len(deny) // room))
    out = sorted(keep[:cap] + deny[::step], key=lambda e: e[T])
    return out, round(len(deny) / max(1, len(deny[::step])), 2)


def _pack(evs):
    """Wire format: string tables + rows [t, country_i, dpt, verdict, app_i, src, attack, server_i, policy, why, fid, off, spt]."""
    ci, ai, si = {}, {}, {}
    rows = [[e[T], ci.setdefault(e[CTRY], len(ci)), e[DPT], e[V], ai.setdefault(e[APP], len(ai)), e[SRC], e[ATTACK] or '',
             si.setdefault(e[SRV], len(si)), e[PID], e[WHY], e[FID], e[OFF], e[SPT]] for e in evs]
    return {'countries': list(ci), 'apps': list(ai), 'servers': list(si), 'rows': rows}


def _port_title(p):
    _ensure_meta()
    return _svc['titles'].get(p) or WELL_KNOWN.get(p) or (KB[PORT_CLASS[p]]['title'] if p in PORT_CLASS else f'port {p}')


def _agg(evs, appblk=None):
    ports = defaultdict(lambda: [0, 0, 0, 0])
    apps = defaultdict(lambda: [0, 0])
    countries = defaultdict(lambda: [0, 0])
    attackers = defaultdict(lambda: {'n': 0, 'country': '', 'ports': set(), 'why': Counter()})
    threats = Counter()
    whys = defaultdict(lambda: {'n': 0, 'ports': Counter(), 'rules': Counter()})
    rate = defaultdict(lambda: [0, 0, 0, 0])
    tot = [0, 0, 0, 0]
    for e in evs:
        v = e[V]
        tot[v] += 1
        ports[e[DPT]][v] += 1
        app = e[APP]
        apps[app if app and not app.startswith(('tcp/', 'udp/', 'TCP-', 'UDP-')) else _port_title(e[DPT])][0 if v == ALLOW else 1] += 1
        countries[e[CTRY] or '?'][0 if v == ALLOW else 1] += 1
        rate[e[T] // 1000][v] += 1
        if v != ALLOW:
            a = attackers[e[SRC]]
            a['n'] += 1; a['country'] = e[CTRY]
            if len(a['ports']) < 60:
                a['ports'].add(e[DPT])
            if e[WHY]:
                a['why'][e[WHY]] += 1
        if v == DENY:
            w = whys[e[WHY]]
            w['n'] += 1; w['ports'][e[DPT]] += 1; w['rules'][e[PID]] += 1
        if v == THREAT:
            threats[(e[ATTACK] or '?', e[SRC], e[DPT])] += 1
    for app, n in (appblk or {}).items():
        apps[app][1] += n
    top = lambda d, k=12: sorted(d.items(), key=lambda x: -sum(x[1]))[:k]
    secs = sorted(rate)
    return {
        'totals': {'allowed': tot[ALLOW], 'denied': tot[DENY], 'blocked': tot[UTM], 'threats': tot[THREAT]},
        'ports': [{'port': p, 'title': _port_title(p), 'exposed': p in _svc['exposed'], 'allowed': v[0], 'denied': v[1],
                   'blocked': v[2], 'threats': v[3]} for p, v in top(ports, 16)],
        'svc_ports': [{'port': p, 'allowed': v[0], 'denied': v[1], 'blocked': v[2], 'threats': v[3]}
                      for p, v in ports.items() if p in _svc['titles']],
        'closed_ports': [{'port': p, 'title': _port_title(p), 'n': v[1]} for p, v in
                         sorted(((p, v) for p, v in ports.items() if p not in _svc['exposed'] and v[1]), key=lambda x: -x[1][1])[:16]],
        'apps': [{'app': a, 'allowed': v[0], 'blocked': v[1]} for a, v in top(apps, 14)],
        'countries': [{'country': c, 'allowed': v[0], 'blocked': v[1]} for c, v in top(countries, 12)],
        'attackers': sorted(({'src': s, 'n': a['n'], 'country': a['country'], 'ports': len(a['ports']),
                              'why': a['why'].most_common(1)[0][0] if a['why'] else 0}
                             for s, a in attackers.items()), key=lambda x: -x['n'])[:12],
        'threats': [{'attack': k[0], 'src': k[1], 'port': k[2], 'n': n} for k, n in threats.most_common(10)],
        'why': [{'why': k, 'label': WHY_TEXT[k], 'n': w['n'], 'ports': [{'port': p, 'title': _port_title(p), 'n': n} for p, n in w['ports'].most_common(4)],
                 'rules': [r for r, _ in w['rules'].most_common(3)]} for k, w in sorted(whys.items()) if k],
        'rate': [[s * 1000, *rate[s]] for s in secs[-120:]],
    }


# ---------------------------------------------------------------- API
def meta():
    """Exposed services (from config) -> orbs in the sphere."""
    m = R.load()
    svcs, exposed = {}, {}
    if m:
        for p in R.inbound_rules(m):
            if p['action'] != 'accept' or p['status'] != 'enable':
                continue
            a = R.analyze_rule(m, p)
            for port in a['ports'][:12]:
                exposed.setdefault(port, []).append({'id': p['id'], 'name': p.get('name'), 'source': a['source']['label']})
                s = svcs.setdefault(port, {'port': port, 'rules': [], 'level': 'low', 'score': 0, 'scope': a['source']['scope']})
                s['rules'].append({'id': p['id'], 'name': p.get('name'), 'source': a['source']['label']})
                if a['score'] > s['score']:
                    cls = PORT_CLASS.get(port)
                    s.update(score=a['score'], level=a['level'], scope=a['source']['scope'],
                             title=KB[cls]['title'] if cls and (cls in a['classes'] or not a['classes']) else
                             (a['service_titles'][0] if a['service_titles'] else f'port {port}'))
        admin = m.admin_port
        svcs.setdefault(admin, {'port': admin, 'rules': [], 'level': 'low', 'score': 0, 'scope': 'restricted',
                                'title': 'FortiGate admin (local-in)'})
        vpn = int(m.sslvpn.get('port') or 0)
        if vpn:
            svcs.setdefault(vpn, {'port': vpn, 'rules': [], 'level': 'low', 'score': 0, 'scope': 'restricted',
                                  'title': 'SSL-VPN (disabled)' if m.sslvpn.get('status') == 'disable' else 'SSL-VPN'})
    for port, s in svcs.items():
        s.setdefault('title', KB[PORT_CLASS[port]]['title'] if port in PORT_CLASS else f'port {port}')
        _svc['titles'][port] = s['title']
    _svc.update(t=time.time(), exposed=exposed)
    return {'firewall': (m.hostname if m else None) or queries.conf()['firewall']['name'], 'services': sorted(svcs.values(), key=lambda s: -s['score'])[:24],
            'config': getattr(m, 'loaded', None), 'why': WHY_TEXT}


_tail = {'t': 0, 'v': None}
_tail_lock = threading.Lock()


def _parse_tail():
    """Parse the last 10 MB of the live syslog once per 1.5 s, shared by every viewer."""
    with _tail_lock:
        if _tail['v'] is not None and time.time() - _tail['t'] < 1.5:
            return _tail['v']
        with open(LOG_BASE, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            start = max(0, size - 10 * 2**20)
            f.seek(start)
            data = f.read()
        skip = data.find(b'\n') + 1 if start else 0
        fid = q('SELECT fid FROM files WHERE path = ? AND done = 0 ORDER BY fid DESC LIMIT 1', (LOG_BASE,), one=True).get('fid')
        evs, appblk = _parse_block(data[skip:], start + skip, fid)
        del data
        evs.sort(key=lambda e: e[T])
        _tail.update(t=time.time(), v=(evs, appblk))
        return evs, appblk


def live(since=0, window_ms=60_000):
    """Newest inbound events from the tail of the live syslog (~last 40-60 s)."""
    t_start = time.time()
    try:
        evs, appblk = _parse_tail()
    except OSError as e:
        return {'error': str(e)}
    newest = evs[-1][T] if evs else int(time.time() * 1000)
    recent = [e for e in evs if e[T] >= newest - window_ms]
    fresh = [e for e in evs if e[T] > since] if since else recent[-800:]
    new_counts = Counter(e[V] for e in fresh)
    fresh, rate = _sample(fresh, 2500)
    span = max(1, (evs[-1][T] - evs[0][T]) / 1000) if len(evs) > 1 else 1
    return {'mode': 'live', 'newest': newest, 'events': _pack(fresh), 'deny_sample': rate, 'eps': round(len(evs) / span, 1),
            'new': [new_counts[i] for i in range(4)], 'agg': _agg(recent, appblk), 'window_ms': window_ms,
            'took_ms': int((time.time() - t_start) * 1000)}


def events(frm, to):
    """Exact inbound events for [frm, to) (max 2 min) from the raw syslog; reconstructed from rollups if archived."""
    t_start = time.time()
    to = min(to, frm + RAW_WINDOW_MS)
    evs, appblk, raw = [], Counter(), False
    for fid in files_for(frm, to):
        path = fid_path(fid)
        if not path or path.endswith('.gz'):
            continue
        a, b = _window_offsets(fid, frm, to)
        with open(path, 'rb') as fh:
            if b is None:
                fh.seek(0, 2)
                b = fh.tell()
            fh.seek(a)
            data = fh.read(min(b - a, 60 * 2**20))
        raw = True
        e, ab = _parse_block(data, a, fid, frm, to)
        evs += e
        appblk.update(ab)
    if not raw:
        return reconstructed(frm, to)
    evs.sort(key=lambda e: e[T])
    agg = _agg(evs, appblk)
    new_counts = Counter(e[V] for e in evs)
    evs, rate = _sample(evs)
    return {'mode': 'raw', 'frm': frm, 'to': to, 'events': _pack(evs), 'deny_sample': rate, 'agg': agg,
            'new': [new_counts[i] for i in range(4)], 'took_ms': int((time.time() - t_start) * 1000)}


def reconstructed(frm, to):
    """Archived period: spread the 5-minute / hourly rollup counts over the window as representative events."""
    _ensure_meta()
    b5, h = floor(frm, M5), floor(frm, H1)
    rng = random.Random(frm)
    scale = (to - frm) / M5
    evs = []

    def ev(t, country, dpt, proto, app, v, pid, why=0, src='', attack=None):
        return [t, src, country or '', dpt or 0, proto or 0, app or '', v, pid, '', 0, attack, 0, why, None, None]
    for r in q("""SELECT policyid, act, app, dpt, proto, country, sum(n) AS n FROM r_pol_5m WHERE dir = 'in' AND b = ?
                  GROUP BY 1, 2, 3, 4, 5, 6""", (b5,)):
        v = UTM if r['act'] == 'utm-block' else DENY if r['act'] == 'deny' else ALLOW
        why = (DENY_RULE if r['policyid'] else CLOSED) if v == DENY else 0
        for _ in range(min(200, max(1, round(r['n'] * scale)))):
            evs.append(ev(frm + rng.randrange(max(1, to - frm)), r['country'], r['dpt'], r['proto'], r['app'], v, r['policyid'], why))
    ports = q("""SELECT dpt, proto, policyid, sum(n) AS n FROM r_deny_port_1h WHERE b = ? GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 60""", (h,))
    ctry = [(r['country'], r['n']) for r in q("""SELECT country, sum(n) AS n FROM r_deny_src_1h WHERE b = ? GROUP BY 1
                                                 ORDER BY n DESC LIMIT 30""", (h,))]
    part = (to - frm) / H1
    if not ports:                                   # hourly deny tables keep 3 days; fall back to the daily ones
        d0 = floor(frm, DAY)
        ports = q("""SELECT dpt, proto, policyid, sum(n) AS n FROM r_deny_port_1d WHERE b = ? GROUP BY 1, 2, 3
                     ORDER BY n DESC LIMIT 60""", (d0,))
        ctry = [(r['country'], r['n']) for r in q("""SELECT country, sum(n) AS n FROM r_deny_src_1d WHERE b = ? GROUP BY 1
                                                     ORDER BY n DESC LIMIT 30""", (d0,))]
        part = (to - frm) / DAY
    cw = [c for c, n in ctry for _ in range(max(1, n // max(1, ctry[0][1] // 20)))] if ctry else ['']
    for r in ports:
        pid = r['policyid']
        why = FIREWALL if (pid or 0) >= 100_000 else DENY_RULE if pid else NOT_ALLOWED if r['dpt'] in _svc['exposed'] else CLOSED
        for _ in range(min(120, max(1, round(r['n'] * part)))):
            evs.append(ev(frm + rng.randrange(max(1, to - frm)), rng.choice(cw), r['dpt'], r['proto'], f"tcp/{r['dpt']}", DENY, pid, why))
    for r in q("SELECT ts, src, scountry, dpt, proto, attack, policyid, fid, off FROM utm_ips WHERE ts >= ? AND ts < ?", (frm, to)):
        e = ev(r['ts'], r['scountry'], r['dpt'], r['proto'], '', THREAT, r['policyid'], 0, r['src'], r['attack'])
        e[FID], e[OFF] = r['fid'], r['off']
        evs.append(e)
    evs.sort(key=lambda e: e[T])
    agg = _agg(evs)
    evs, rate = _sample(evs)
    return {'mode': 'reconstructed', 'frm': frm, 'to': to, 'events': _pack(evs), 'deny_sample': rate, 'agg': agg,
            'new': [agg['totals'][k] for k in ('allowed', 'denied', 'blocked', 'threats')]}


def timeline(frm, to):
    step = M5 if to - frm <= 3 * DAY else H1
    lo = floor(frm, step)
    b = {}

    def slot(t):
        k = (t // step) * step
        return b.setdefault(k, [k, 0, 0, 0, 0])      # t, allowed, denied, blocked, threats
    for r in q(f"""SELECT (b / {step}) * {step} AS t, act, sum(n) AS n FROM r_pol_5m WHERE dir = 'in' AND b >= ? AND b < ?
                  GROUP BY 1, 2""", (floor(frm, M5), to)):
        s = slot(r['t'])
        if r['act'] == 'utm-block':
            s[3] += r['n']
        elif r['act'] in ('deny', 'block', 'blocked', 'dropped', 'reset'):
            s[2] += r['n']
        else:
            s[1] += r['n']
    for r in q(f"""SELECT (b / {step}) * {step} AS t, sum(n) AS n FROM r_deny_5m WHERE b >= ? AND b < ? AND
                  cat != 'traffic:local' GROUP BY 1""", (floor(frm, M5), to)):
        slot(r['t'])[2] += r['n']
    markers = [{'t': r['ts'], 'type': 'threat', 'label': f"IPS: {r['attack']} ({r['severity']}) from {r['src']}"}
               for r in q("SELECT ts, attack, severity, src FROM utm_ips WHERE ts >= ? AND ts < ? ORDER BY ts LIMIT 300", (frm, to))]
    for r in q("""SELECT b, src, dpt, sum(short) AS short FROM r_in_1h WHERE b >= ? AND b < ? GROUP BY 1, 2, 3 HAVING short >= 30
                  ORDER BY short DESC LIMIT 100""", (floor(frm, H1), to)):
        markers.append({'t': r['b'] + H1 // 2, 'type': 'brute', 'label': f"Password guessing: {r['src']} → port {r['dpt']} ({r['short']} attempts)"})
    for r in q("SELECT ts FROM utm_ips WHERE ts >= ? AND ts < ?", (frm, to)):
        slot(r['ts'])[4] += 1
    buckets = [b.get(t, [t, 0, 0, 0, 0]) for t in range(lo, to, step)]
    return {'step': step, 'frm': frm, 'to': to, 'buckets': buckets, 'markers': sorted(markers, key=lambda m: m['t'])}
