"""Read-only queries behind the dashboard. Every function takes (frm, to) in epoch ms and returns plain dicts."""
import ipaddress
import json
import os
import threading
import time

from . import db, settings

APP_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
M1, M5, H1, DAY = 60_000, 300_000, 3_600_000, 86_400_000
DROPS = ('deny', 'block', 'blocked', 'dropped', 'reset', 'utm-block')
# "Inbound from the internet" has two shapes, and a firewall usually has one of them:
#   * forward traffic from a WAN interface to a published server  (dir 'in' / 'wan'), and
#   * traffic aimed at the firewall itself from the internet      (dir 'local' with a real source country) -
#     on a branch or SD-WAN firewall that is the entire attack surface: SSL-VPN portal, admin ports, scanners.
# Rollups that carry a country column can tell the second case from LAN traffic to the firewall (country 'Reserved').
IN_DIR = "(dir IN ('in', 'wan') OR (dir = 'local' AND country NOT IN ('', 'Reserved')))"
IN_DIR_NOGEO = "dir IN ('in', 'wan', 'local')"
DROP_IN = "('deny','block','blocked','dropped','reset','utm-block')"
ENDS = ('close', 'client-rst', 'server-rst', 'timeout')
UNCLASSIFIED_PREFIX = ('tcp/', 'udp/', 'TCP-', 'UDP-')

_local = threading.local()
_conf = {'t': 0, 'v': None, 's': None}


def device():
    """What the logs say about the firewall: name, serial, FortiOS version (written by the ingest)."""
    try:
        v = q("SELECT v FROM meta WHERE k = 'device'", one=True).get('v')
        return json.loads(v) if v else {}
    except Exception:
        return {}


def _config_interfaces(m):
    out = {}
    for name, v in (m.interfaces if m else {}).items():
        ip = v.get('ip')
        parts = ip if isinstance(ip, list) else str(ip or '').split()
        entry = {'alias': v.get('alias'), 'role': v.get('role')}
        if len(parts) >= 2 and parts[0] not in ('0.0.0.0',):
            try:
                entry['ip'] = str(ipaddress.ip_interface(f'{parts[0]}/{parts[1]}'))
            except ValueError:
                pass
        out[name] = {k: x for k, x in entry.items() if x}
    return out


def conf():
    """Effective configuration for the analysis code: UI settings, then the uploaded backup, then what the logs show."""
    s = settings.load()
    if _conf['v'] is not None and time.time() - _conf['t'] < 30 and _conf['s'] is s:
        return _conf['v']
    from . import rules
    try:
        m = rules.load()
    except Exception:
        m = None
    dev = device()
    ifaces = _config_interfaces(m)
    for name, v in (s.get('interfaces') or {}).items():
        ifaces.setdefault(name, {}).update({k: x for k, x in v.items() if x})
    src_all = []
    if m:
        src_all = [p['id'] for p in rules.inbound_rules(m) if p['action'] == 'accept' and p['status'] == 'enable'
                   and 'all' in rules._list(p.get('srcaddr')) and not p.get('internet-service-src-name')]
    c = {
        '_expected': {int(p): {str(a) for a in v} for p, v in (s.get('expected_apps') or {}).items()
                      if str(p).isdigit() and isinstance(v, list)},
        '_og': set(s.get('domain_allowlist') or []) or None,
        'interfaces': ifaces,
        'vpn_pools': s.get('vpn_pools') or [],
        'firewall': {'name': s.get('firewall_name') or (m.hostname if m else None) or dev.get('devname') or 'FortiGate',
                     'model': (rules._cache.get('d') or {}).get('_model') if m else None,
                     'serial': dev.get('devid'), 'version': dev.get('version')},
        'monitor_sensors': [],
        'src_all_policies': src_all,
        'tighten_max_sources': 25,
        'mail_ports': [25, 465, 587, 993, 995, 143, 110],
        'expected_countries': [],
        'long_session_seconds': 3600,
        'big_session_bytes': 50_000_000,
        'deny_policies': [],
    }
    _conf.update(t=time.time(), v=c, s=s)
    return c


MAX_ROWS = 250_000                                  # no single query may materialise more rows than this


class Budget:
    """Per-thread deadline: queries stop (sqlite 'interrupted') once the request's time budget is spent."""
    @staticmethod
    def set(seconds):
        _local.deadline = time.time() + seconds

    @staticmethod
    def clear():
        _local.deadline = None

    @staticmethod
    def left():
        d = getattr(_local, 'deadline', None)
        return None if d is None else d - time.time()


def q(sql, args=(), one=False):
    c = getattr(_local, 'c', None)
    if c is None:
        c = _local.c = db.connect(readonly=True)
    start, limit = time.time(), (180 if threading.current_thread().name == 'cache-warmer' else 25)
    deadline = start + limit
    left = Budget.left()
    if left is not None:
        deadline = min(deadline, time.time() + max(0.2, left))
    c.set_progress_handler(lambda: 1 if time.time() > deadline else 0, 100_000)
    cur = c.execute(sql, args)
    cols = [d[0] for d in cur.description]
    rows = []
    while True:
        chunk = cur.fetchmany(5000)
        if not chunk:
            break
        rows += [dict(zip(cols, r)) for r in chunk]
        if len(rows) > MAX_ROWS:
            cur.close()
            raise MemoryError(f'query returned more than {MAX_ROWS:,} rows - narrow the time range or filters')
        if one:
            break
    return (rows[0] if rows else {}) if one else rows


def step_for(frm, to, minimum=M1):
    for s in (M1, M5, 15 * M1, H1, 3 * H1, 6 * H1, DAY):
        if s >= minimum and (to - frm) / s <= 400:
            return s
    return DAY


def is_drop(act):
    return act in DROPS


def unclassified(app):
    return (app or '').startswith(UNCLASSIFIED_PREFIX) or app in ('', None)


def app_base(app):
    return (app or '').split('_', 1)[0]


def unexpected(pid, app):
    exp = conf()['_expected'].get(pid)
    return exp is not None and not unclassified(app) and app_base(app) not in exp


def deny_tables(frm, to):
    return ('r_deny_src_1h', 'r_deny_port_1h') if to - frm <= 6 * H1 else ('r_deny_src_1d', 'r_deny_port_1d')


def floor(ts, step):
    return ts - ts % step


# ---------------------------------------------------------------- meta
def backfill(m):
    """How much of the log history on disk ingest has read, and how long the rest takes at the current speed.
    active = history is still being read; the dashboard keeps filling in while it is."""
    from . import ingest
    try:
        p = json.loads(m.get('ingest_progress') or '{}')
        fresh = p.get('at', 0) > (time.time() - 120) * 1000        # ingest reported within the last two minutes
        rows = [(r['path'], r['off'], r['done']) for r in q('SELECT path, off, done FROM files')]
        st = ingest.backfill_status(rows, p.get('rate') if fresh else None)
    except Exception:                                              # progress must never break the meta call
        return None
    st['active'] = st['left_bytes'] > 4 << 20
    st['rate'] = p.get('rate') if fresh else None
    st['eta_text'] = ingest.human_duration(st['eta_s']) if st['active'] and st['eta_s'] else None
    st['reading'] = os.path.basename(p.get('path') or '') if fresh else None
    return st


def meta():
    m = {r['k']: r['v'] for r in q('SELECT k, v FROM meta')}
    pols = q('SELECT policyid, name, ptype, dir, applists, first_ts, last_ts FROM policy ORDER BY policyid')
    c = conf()
    return {'now': int(time.time() * 1000), 'last_event_ts': int(m.get('last_event_ts', 0) or 0),
            'last_commit': int(m.get('last_commit', 0) or 0), 'policies': pols, 'backfill': backfill(m),
            'expected': {str(k): sorted(v) for k, v in c['_expected'].items()},
            'deny_policies': c.get('deny_policies', []), 'og_list_loaded': c['_og'] is not None,
            'firewall': c['firewall'], 'demo': settings.DEMO}


# ---------------------------------------------------------------- overview
def overview(frm, to):
    step = step_for(frm, to)
    rows = q('SELECT (b / ?) * ? AS t, cat, act, sum(n) AS n FROM r_1m WHERE b >= ? AND b < ? GROUP BY 1, 2, 3',
             (step, step, floor(frm, M1), to))
    series, cls, cats = {}, {'accept': 0, 'drop': 0, 'end': 0, 'other': 0}, {}
    for r in rows:
        c = r['cat'] if r['cat'].startswith(('traffic', 'utm:app', 'utm:web', 'utm:ips', 'utm:virus')) else \
            ('event' if r['cat'].startswith('event') else 'utm:other')
        series.setdefault(c, {}).setdefault(r['t'], 0)
        series[c][r['t']] += r['n']
        cats[c] = cats.get(c, 0) + r['n']
        k = 'drop' if is_drop(r['act']) else 'end' if r['act'] in ENDS else \
            'accept' if r['act'] in ('accept', 'pass', 'passthrough', 'allow', 'dns', 'ip-conn') else 'other'
        cls[k] += r['n']
    drops = q('SELECT (b / ?) * ? AS t, sum(n) AS n FROM r_1m WHERE b >= ? AND b < ? AND act IN ' + DROP_IN +
              " AND NOT (cat LIKE 'traffic:%' AND act = 'deny') GROUP BY 1", (step, step, floor(frm, M1), to))
    hfrm = floor(frm, H1)
    top_in = q(f"""SELECT src, max(country) AS country, sum(n) AS n, sum(drops) AS drops, sum(sent + rcvd) AS bytes,
                  group_concat(DISTINCT policyid) AS policies FROM r_src_1h WHERE {IN_DIR} AND b >= ? AND b < ?
                  GROUP BY src ORDER BY n DESC LIMIT 10""", (hfrm, to))
    top_out = q("""SELECT r.src, h.name AS host, sum(n) AS n, sum(drops) AS drops, sum(sent) AS sent, sum(rcvd) AS rcvd
                   FROM r_src_1h r LEFT JOIN host h ON h.ip = r.src WHERE dir = 'out' AND b >= ? AND b < ?
                   GROUP BY r.src ORDER BY sum(sent + rcvd) DESC LIMIT 10""", (hfrm, to))
    return {'step': step, 'series': {c: sorted(v.items()) for c, v in series.items()}, 'cats': cats,
            'classes': cls, 'real_drops': [(r['t'], r['n']) for r in drops], 'top_in': top_in, 'top_out': top_out}


# ---------------------------------------------------------------- inbound
def inbound(frm, to):
    c = conf()
    b5, hfrm = floor(frm, M5), floor(frm, H1)
    pol = {}
    for r in q(f"""SELECT policyid, act, app, dpt, proto, country, sum(n) AS n, sum(sent + rcvd) AS bytes, max(b) AS last
                  FROM r_pol_5m WHERE {IN_DIR} AND b >= ? AND b < ? GROUP BY 1, 2, 3, 4, 5, 6""", (b5, to)):
        p = pol.setdefault(r['policyid'], {'policyid': r['policyid'], 'hits': 0, 'drops': 0, 'bytes': 0, 'last': 0,
                                           'countries': set(), 'apps': {}, 'ports': {}, 'unexpected': 0})
        p['hits'] += r['n']; p['bytes'] += r['bytes'] or 0; p['last'] = max(p['last'], r['last'])
        if is_drop(r['act']):
            p['drops'] += r['n']
        p['countries'].add(r['country'])
        p['apps'][r['app']] = p['apps'].get(r['app'], 0) + r['n']
        port = f"{r['dpt']}/{ {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(r['proto'], r['proto'])}"
        p['ports'][port] = p['ports'].get(port, 0) + r['n']
    for r in q(f"""SELECT policyid, app, act, applist, sum(n) AS n, max(b) AS last FROM r_app_5m
                  WHERE {IN_DIR_NOGEO} AND b >= ? AND b < ? GROUP BY 1, 2, 3, 4""", (b5, to)):
        p = pol.setdefault(r['policyid'], {'policyid': r['policyid'], 'hits': 0, 'drops': 0, 'bytes': 0, 'last': 0,
                                           'countries': set(), 'apps': {}, 'ports': {}, 'unexpected': 0})
        p.setdefault('ctl', {}).setdefault(r['app'], [0, 0])
        p['ctl'][r['app']][0] += r['n']
        if r['act'] == 'block':
            p['ctl'][r['app']][1] += r['n']
            p['blocked'] = p.get('blocked', 0) + r['n']
        p.setdefault('sensors', set()).add(r['applist'])
        p['last'] = max(p['last'], r['last'])
    srcs = {r['policyid']: r['n'] for r in q(f"""SELECT policyid, count(DISTINCT src) AS n FROM r_src_1h
                  WHERE {IN_DIR} AND b >= ? AND b < ? GROUP BY 1""", (hfrm, to))}
    out = []
    for pid, p in pol.items():
        apps = dict(p['apps'])
        for app, (n, _) in p.get('ctl', {}).items():
            apps[app] = max(apps.get(app, 0), n)
        une = {a: n for a, n in apps.items() if unexpected(pid, a)}
        out.append({'policyid': pid, 'hits': p['hits'], 'drops': p['drops'], 'blocked': p.get('blocked', 0),
                    'bytes': p['bytes'], 'last': p['last'], 'srcs': srcs.get(pid, 0), 'countries': len(p['countries']),
                    'apps': sorted(apps.items(), key=lambda x: -x[1])[:8], 'ports': sorted(p['ports'].items(), key=lambda x: -x[1])[:8],
                    'unexpected': sum(une.values()), 'unexpected_apps': sorted(une.items(), key=lambda x: -x[1]),
                    'sensors': sorted(p.get('sensors', ())), 'has_expected': pid in c['_expected']})
    out.sort(key=lambda x: -x['hits'])
    src_t, port_t = deny_tables(frm, to)
    tb = floor(frm, H1 if src_t.endswith('1h') else DAY)
    deny_pol = q("""SELECT policyid, cat, inif, sum(n) AS n FROM r_deny_5m WHERE b >= ? AND b < ?
                    GROUP BY 1, 2, 3 ORDER BY n DESC""", (b5, to))
    flows = q(f"""SELECT country, policyid, dpt, proto, app, sum(n) AS n FROM r_pol_5m
                 WHERE {IN_DIR} AND b >= ? AND b < ? AND act NOT IN {DROP_IN}
                 GROUP BY 1, 2, 3, 4, 5 ORDER BY n DESC LIMIT 60""", (b5, to))
    countries_acc = q(f"""SELECT country, sum(n) AS n FROM r_pol_5m WHERE {IN_DIR} AND b >= ? AND b < ?
                         AND act NOT IN {DROP_IN} GROUP BY 1 ORDER BY n DESC LIMIT 25""", (b5, to))
    countries_deny = q(f"""SELECT country, sum(n) AS n, count(DISTINCT src) AS srcs FROM {src_t}
                          WHERE b >= ? AND b < ? GROUP BY 1 ORDER BY n DESC LIMIT 25""", (tb, to))
    deny_src = q(f"""SELECT src, max(country) AS country, group_concat(DISTINCT inif) AS inif,
                    group_concat(DISTINCT policyid) AS policies, sum(n) AS n, max(ports) AS ports, max(psample) AS psample
                    FROM {src_t} WHERE b >= ? AND b < ? GROUP BY src ORDER BY n DESC LIMIT 50""", (tb, to))
    deny_port = q(f"""SELECT dpt, proto, group_concat(DISTINCT inif) AS inif, sum(n) AS n, max(srcs) AS srcs
                     FROM {port_t} WHERE b >= ? AND b < ? GROUP BY dpt, proto ORDER BY n DESC LIMIT 50""", (tb, to))
    new_src = q("""SELECT src, country, first_ts, first_acc_ts, last_ts, n_acc, n_deny FROM seen_src
                   WHERE first_acc_ts >= ? AND first_acc_ts < ? ORDER BY first_acc_ts DESC LIMIT 200""", (frm, to))
    if new_src:
        pmap = {}
        marks = ','.join('?' * len(new_src))
        for r in q(f"""SELECT src, group_concat(DISTINCT policyid) AS p FROM r_src_1h WHERE {IN_DIR} AND b >= ?
                       AND src IN ({marks}) GROUP BY src""", (hfrm, *[r['src'] for r in new_src])):
            pmap[r['src']] = r['p']
        for r in new_src:
            r['policies'] = pmap.get(r['src'], '')
    step = step_for(frm, to, M5)
    deny_tl = q('SELECT (b / ?) * ? AS t, policyid, sum(n) AS n FROM r_deny_5m WHERE b >= ? AND b < ? GROUP BY 1, 2',
                (step, step, b5, to))
    return {'policies': out, 'deny_policies': deny_pol, 'flows': flows, 'countries_acc': countries_acc,
            'countries_deny': countries_deny, 'deny_src': deny_src, 'deny_port': deny_port, 'new_src': new_src,
            'deny_timeline': deny_tl, 'step': step, 'deny_table': src_t}


# ---------------------------------------------------------------- outbound
def outbound(frm, to):
    hfrm = floor(frm, H1)
    og = conf()['_og']
    roots = q("""SELECT root, sum(n) AS n, sum(blocked) AS blocked, sum(sent + rcvd) AS bytes,
                 count(DISTINCT src) AS srcs, count(DISTINCT dhost) AS hosts FROM r_dom_1h
                 WHERE b >= ? AND b < ? GROUP BY root ORDER BY n DESC LIMIT 60""", (hfrm, to))
    top_src = [r['src'] for r in q("""SELECT src FROM r_dom_1h WHERE b >= ? AND b < ? GROUP BY src
                                      ORDER BY sum(n) DESC LIMIT 15""", (hfrm, to))]
    top_root = [r['root'] for r in roots[:20]]
    heat = []
    if top_src and top_root:
        heat = q(f"""SELECT src, root, sum(n) AS n FROM r_dom_1h WHERE b >= ? AND b < ?
                     AND src IN ({','.join('?' * len(top_src))}) AND root IN ({','.join('?' * len(top_root))})
                     GROUP BY 1, 2""", (hfrm, to, *top_src, *top_root))
    new_dom = q("""SELECT root, first_ts, last_ts, n, first_src FROM seen_dom WHERE first_ts >= ? AND first_ts < ?
                   ORDER BY first_ts DESC LIMIT 300""", (frm, to))
    for r in new_dom + roots:
        r['in_og'] = None if og is None else (r['root'] in og)
    pol_split = q("""SELECT policyid, sum(n) AS n, sum(sent + rcvd) AS bytes,
                     sum(CASE WHEN act IN """ + DROP_IN + """ THEN n ELSE 0 END) AS drops
                     FROM r_pol_5m WHERE dir = 'out' AND b >= ? AND b < ? GROUP BY 1 ORDER BY n DESC""",
                  (floor(frm, M5), to))
    machines = q("""SELECT r.src, h.name AS host, h.os, sum(n) AS n, sum(drops) AS drops, sum(sent) AS sent,
                    sum(rcvd) AS rcvd, count(DISTINCT policyid) AS policies FROM r_src_1h r LEFT JOIN host h ON h.ip = r.src
                    WHERE dir = 'out' AND b >= ? AND b < ? GROUP BY r.src ORDER BY sum(sent + rcvd) DESC LIMIT 50""",
                 (hfrm, to))
    uniq = q("""SELECT src, count(DISTINCT root) AS roots, sum(n) AS n FROM r_dom_1h WHERE b >= ? AND b < ?
                GROUP BY src ORDER BY roots DESC LIMIT 30""", (hfrm, to))
    tunnels = q("""SELECT r.src, h.name AS host, p.name AS policy, sum(r.n) AS n, sum(r.sent + r.rcvd) AS bytes
                   FROM r_src_1h r JOIN policy p ON p.policyid = r.policyid LEFT JOIN host h ON h.ip = r.src
                   WHERE r.dir = 'out' AND r.b >= ? AND r.b < ? AND (p.name LIKE '%cloudflared%' OR p.name LIKE '%warp%')
                   GROUP BY 1, 2, 3 ORDER BY n DESC""", (hfrm, to))
    denied = q("""SELECT policyid, dpt, proto, country, sum(n) AS n FROM r_pol_5m WHERE dir = 'out' AND b >= ? AND b < ?
                  AND act IN """ + DROP_IN + " GROUP BY 1, 2, 3, 4 ORDER BY n DESC LIMIT 40", (floor(frm, M5), to))
    return {'roots': roots, 'heat': heat, 'heat_src': top_src, 'heat_root': top_root, 'new_dom': new_dom,
            'pol_split': pol_split, 'machines': machines, 'uniq': uniq, 'tunnels': tunnels, 'denied': denied,
            'og_loaded': og is not None}


# ---------------------------------------------------------------- utm
def utm(frm, to):
    b5 = floor(frm, M5)
    step = step_for(frm, to, M5)
    return {
        'step': step,
        'app_block_tl': q("""SELECT (b / ?) * ? AS t, policyid, sum(n) AS n FROM r_app_5m WHERE act = 'block'
                             AND b >= ? AND b < ? GROUP BY 1, 2""", (step, step, b5, to)),
        'app_block_by': q("""SELECT policyid, applist, app, evtype, sum(n) AS n, min(b) AS first, max(b) AS last
                             FROM r_app_5m WHERE act = 'block' AND b >= ? AND b < ? GROUP BY 1, 2, 3, 4
                             ORDER BY n DESC LIMIT 100""", (b5, to)),
        'app_sensor': q("""SELECT applist, act, sum(n) AS n FROM r_app_5m WHERE b >= ? AND b < ? GROUP BY 1, 2
                           ORDER BY 1, 2""", (b5, to)),
        'ips_by': q("""SELECT severity, attack, act, count(*) AS n, count(DISTINCT src) AS srcs, max(ts) AS last
                       FROM utm_ips WHERE ts >= ? AND ts < ? GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 100""", (frm, to)),
        'ips_recent': q("""SELECT ts, policyid, severity, attack, act, src, scountry, dst, dpt, dhost, fid, off
                           FROM utm_ips WHERE ts >= ? AND ts < ? ORDER BY ts DESC LIMIT 200""", (frm, to)),
        'av_recent': q("""SELECT ts, policyid, virus, act, src, dst, dhost, url, filename, fid, off FROM utm_av
                          WHERE ts >= ? AND ts < ? ORDER BY ts DESC LIMIT 200""", (frm, to)),
        'web_by': q("""SELECT evtype, act, profile, sum(n) AS n FROM r_web_1h WHERE b >= ? AND b < ?
                       GROUP BY 1, 2, 3 ORDER BY n DESC""", (floor(frm, H1), to)),
        'web_blocked': q("""SELECT ts, policyid, src, dhost, url, act, evtype, fid, off FROM utm_web
                            WHERE ts >= ? AND ts < ? AND act NOT IN ('passthrough', 'pass', 'allow')
                            ORDER BY ts DESC LIMIT 200""", (frm, to)),
        'other_by': q("""SELECT cat, evtype, act, count(*) AS n, max(ts) AS last FROM utm_other WHERE ts >= ? AND ts < ?
                         GROUP BY 1, 2, 3 ORDER BY n DESC""", (frm, to)),
        'events_by': q("""SELECT cat, logdesc, act, count(*) AS n, max(ts) AS last FROM event WHERE ts >= ? AND ts < ?
                          GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 60""", (frm, to)),
        'admin_events': q("""SELECT ts, logdesc, usr, act, src, msg, substr(ext, 1, 600) AS ext, fid, off FROM event
                             WHERE ts >= ? AND ts < ? AND (logdesc LIKE 'Admin%' OR logdesc LIKE '%configured%'
                             OR logdesc LIKE 'Configuration%' OR logdesc LIKE 'Object%')
                             ORDER BY ts DESC LIMIT 200""", (frm, to)),
    }


# ---------------------------------------------------------------- health
def health():
    now = int(time.time() * 1000)
    m = {r['k']: r['v'] for r in q('SELECT k, v FROM meta')}
    eps = q('SELECT sum(n) AS n FROM r_1m WHERE b >= ?', (floor(now - 6 * M1, M1),), one=True).get('n') or 0
    per_day = q("""SELECT (b / 86400000) * 86400000 AS day, sum(n) AS n,
                   sum(CASE WHEN cat LIKE 'traffic%' AND act = 'deny' THEN n ELSE 0 END) AS noise
                   FROM r_1m WHERE b >= ? GROUP BY 1 ORDER BY 1""", (now - 35 * DAY,))
    # one aggregate per statement so SQLite can answer min()/max() from the index instead of scanning
    one = lambda sql: q(sql, one=True).get('v')
    tables = {}
    for t in ('traffic', 'utm_app', 'utm_web', 'utm_ips', 'utm_av', 'utm_other', 'event'):
        hi, lo = one(f'SELECT max(rowid) AS v FROM {t}'), one(f'SELECT min(rowid) AS v FROM {t}')
        tables[t] = {'rows': (hi - lo + 1) if hi else 0, 'oldest': one(f'SELECT min(ts) AS v FROM {t}')}
    rollups = {t: {'last': one(f'SELECT max(b) AS v FROM {t}'), 'oldest': one(f'SELECT min(b) AS v FROM {t}')}
               for t in ('r_1m', 'r_pol_5m', 'r_app_5m', 'r_src_1h', 'r_dom_1h', 'r_deny_5m', 'r_deny_src_1d')}
    files = q('SELECT fid, path, off, lines, first_ts, last_ts, done FROM files ORDER BY fid DESC LIMIT 20')
    return {'now': now, 'eps_5m': round(eps / 360, 1), 'last_event_ts': int(m.get('last_event_ts', 0) or 0),
            'last_commit': int(m.get('last_commit', 0) or 0), 'last_prune': int(m.get('last_prune', 0) or 0),
            'per_day': per_day, 'tables': tables, 'rollups': rollups, 'files': files}
