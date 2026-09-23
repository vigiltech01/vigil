"""Inbound security: rule risk (config) + what actually happened (logs) + attack detections, in plain English.

Detection thresholds (sources in threatkb.py): port scan >= 15 distinct ports from one source (Zeek default);
brute force >= 30 short sessions per hour from one source to one login service (Zeek SSH default);
recon-then-access: denied before the first accepted session.
"""
import time
from collections import defaultdict

from . import rules as R
from .queries import q, conf, floor, H1, DAY, M5, DROP_IN, IN_DIR_NOGEO
from .threatkb import KB, AUTH_PORTS, SCAN_PORTS, BRUTE_SHORT_PER_HOUR, PORT_CLASS, WELL_KNOWN

LEVELS = ['critical', 'high', 'medium', 'low', 'good']


def _pname():
    return {r['policyid']: r['name'] for r in q('SELECT policyid, name FROM policy')}


def rule_evidence(frm, to):
    """Per policy: sessions, sources, countries, drops, short sessions, top sources (from r_in_1h)."""
    hfrm = floor(frm, H1)
    ev = defaultdict(lambda: {'n': 0, 'srcs': 0, 'countries': {}, 'drops': 0, 'short': 0, 'bytes': 0, 'top': [], 'servers': {}})
    for r in q("""SELECT policyid, count(DISTINCT src) AS srcs, sum(n) AS n, sum(drops) AS drops, sum(short) AS short,
                  sum(bytes) AS bytes, max(b) AS last FROM r_in_1h WHERE b >= ? AND b < ? GROUP BY policyid""", (hfrm, to)):
        e = ev[r['policyid']]
        e.update(n=r['n'], srcs=r['srcs'], drops=r['drops'], short=r['short'], bytes=r['bytes'], last=r['last'])
    for r in q("""SELECT policyid, country, sum(n) AS n FROM r_in_1h WHERE b >= ? AND b < ? GROUP BY 1, 2""", (hfrm, to)):
        ev[r['policyid']]['countries'][r['country'] or '?'] = r['n']
    for r in q("""SELECT policyid, dst, dpt, sum(n) AS n FROM r_in_1h WHERE b >= ? AND b < ? GROUP BY 1, 2, 3""", (hfrm, to)):
        ev[r['policyid']]['servers'][f"{r['dst']}:{r['dpt']}"] = r['n']
    for r in q(f"""SELECT policyid, act, sum(n) AS n FROM r_app_5m WHERE {IN_DIR_NOGEO} AND b >= ? AND b < ? GROUP BY 1, 2""",
               (floor(frm, M5), to)):
        ev[r['policyid']]['app_' + (r['act'] or '')] = r['n']
    for r in q("""SELECT policyid, count(*) AS n, count(DISTINCT attack) AS sigs FROM utm_ips WHERE ts >= ? AND ts < ?
                  GROUP BY 1""", (frm, to)):
        ev[r['policyid']]['ips'] = r['n']
        ev[r['policyid']]['ips_sigs'] = r['sigs']
    return ev


def _exposure(model):
    """port -> enabled allow rules exposing it, and rule id -> service classes (config only, fast)."""
    exposed, rule_classes = defaultdict(list), {}
    if model:
        for p in R.inbound_rules(model):
            if p['action'] == 'accept' and p['status'] == 'enable':
                a = R.analyze_rule(model, p)
                rule_classes[p['id']] = a['classes']
                for port in a['ports']:
                    exposed[port].append({'id': p['id'], 'name': p.get('name'), 'source': a['source']['label']})
    return exposed, rule_classes


def _svc_title(rule_classes, pid, dpt):
    cls = rule_classes.get(pid) or []
    pc = PORT_CLASS.get(dpt)
    return KB[pc if pc in cls or not cls else cls[0]]['title'] if (pc or cls) else KB['other']['title']


def detections(frm, to, model):
    """Log-based detections. Parts that depend on the (live) configuration - which probed ports are really open and the
    service name of brute-forced ports - are filled in by assemble()."""
    hfrm = floor(frm, H1)
    long_range = to - frm > 6 * H1
    src_t = 'r_deny_src_1d' if long_range else 'r_deny_src_1h'
    tb = floor(frm, DAY if long_range else H1)
    pn = _pname()
    out = {}
    # 1. port scanners
    scan = q(f"""SELECT src, max(country) AS country, sum(n) AS n, max(ports) AS ports, max(psample) AS psample
                FROM {src_t} WHERE b >= ? AND b < ? AND ports >= ? GROUP BY src ORDER BY n DESC LIMIT 25""", (tb, to, SCAN_PORTS))
    cnt = q(f"SELECT count(DISTINCT src) AS n, sum(n) AS hits FROM {src_t} WHERE b >= ? AND b < ? AND ports >= ?",
            (tb, to, SCAN_PORTS), one=True)
    out['scanners'] = {'count': cnt.get('n') or 0, 'hits': cnt.get('hits') or 0, 'top': scan}
    # 2. probing of ports you really expose
    probes = q("""SELECT dpt, proto, sum(n) AS n, max(srcs) AS srcs FROM r_deny_port_1d WHERE b >= ? AND b < ? AND dpt > 0
                  GROUP BY 1, 2 ORDER BY n DESC LIMIT 400""", (floor(frm, DAY), to))
    out['_probes'] = probes
    # 3. brute force / password guessing on login services
    brute = q(f"""SELECT src, dst, dpt, policyid, max(country) AS country, sum(short) AS short, max(short) AS peak,
                 sum(n) AS n, count(*) AS hours, max(maxdur) AS maxdur, max(maxbytes) AS maxbytes
                 FROM r_in_1h WHERE b >= ? AND b < ? AND dpt IN ({','.join('?' * len(AUTH_PORTS))})
                 GROUP BY 1, 2, 3, 4 HAVING peak >= ? ORDER BY short DESC LIMIT 30""",
              (hfrm, to, *sorted(AUTH_PORTS), BRUTE_SHORT_PER_HOUR))
    for r in brute:
        r['policy'] = pn.get(r['policyid'])
        r['possible_success'] = bool((r['maxdur'] or 0) > 60 or (r['maxbytes'] or 0) > 50_000)
    out['bruteforce'] = brute
    # 4. denied first, then allowed in
    recon = q("""SELECT src, country, n_deny, n_acc, first_ts, first_acc_ts, last_acc_ts FROM seen_src
                 WHERE src != '' AND last_acc_ts >= ? AND first_acc_ts < ? AND n_deny >= 5 AND first_ts < first_acc_ts
                 ORDER BY n_deny DESC LIMIT 25""", (frm, to))
    if recon:
        marks = ','.join('?' * len(recon))
        pols = defaultdict(set)
        for r in q(f"""SELECT src, policyid FROM r_in_1h WHERE b >= ? AND src IN ({marks}) GROUP BY 1, 2""",
                   (hfrm, *[r['src'] for r in recon])):
            pols[r['src']].add(r['policyid'])
        for r in recon:
            r['policies'] = [{'id': p, 'name': pn.get(p)} for p in sorted(pols[r['src']])]
    out['recon_then_access'] = recon
    # 5. exploit attempts (IPS)
    out['ips'] = q("""SELECT attack, severity, act, policyid, count(*) AS n, count(DISTINCT src) AS srcs, max(ts) AS last
                      FROM utm_ips WHERE ts >= ? AND ts < ? GROUP BY 1, 2, 3, 4 ORDER BY n DESC LIMIT 25""", (frm, to))
    for r in out['ips']:
        r['policy'] = pn.get(r['policyid'])
    # 6. wrong protocol on an allowed port (tunnelling / abuse)
    out['protocol_abuse'] = q(f"""SELECT policyid, app, evtype, act, sum(n) AS n FROM r_app_5m WHERE {IN_DIR_NOGEO} AND b >= ? AND b < ?
                                AND (evtype = 'port-violation' OR act = 'block') GROUP BY 1, 2, 3, 4 ORDER BY n DESC LIMIT 25""",
                              (floor(frm, M5), to))
    for r in out['protocol_abuse']:
        r['policy'] = pn.get(r['policyid'])
    # 7. traffic spikes on published services (hour > 5x median and > 2000 sessions)
    hours = defaultdict(list)
    for r in q("""SELECT dst, dpt, b, sum(n) AS n FROM r_in_1h WHERE b >= ? AND b < ? GROUP BY 1, 2, 3""", (hfrm, to)):
        hours[(r['dst'], r['dpt'])].append((r['b'], r['n']))
    spikes = []
    for (dst, dpt), vals in hours.items():
        if len(vals) < 6:
            continue
        ns = sorted(v for _, v in vals)
        med = ns[len(ns) // 2] or 1
        b, peak = max(vals, key=lambda x: x[1])
        if peak >= 2000 and peak > 5 * med:
            spikes.append({'dst': dst, 'dpt': dpt, 'peak': peak, 'median': med, 'at': b})
    out['spikes'] = sorted(spikes, key=lambda x: -x['peak'] / x['median'])[:10]
    # 8. accepted from countries a rule did not see in the previous 7 days
    oldest = q('SELECT min(b) AS v FROM r_in_1h', one=True).get('v') or hfrm
    new_c = []
    if oldest <= hfrm - 2 * DAY:
        new_c = q("""SELECT policyid, country, sum(n) AS n, count(DISTINCT src) AS srcs FROM r_in_1h WHERE b >= ? AND b < ?
                     AND country NOT IN ('', 'Reserved') AND drops < n AND (policyid, country) NOT IN
                     (SELECT DISTINCT policyid, country FROM r_in_1h WHERE b >= ? AND b < ?)
                     GROUP BY 1, 2 ORDER BY n DESC LIMIT 20""", (hfrm, to, hfrm - 7 * DAY, hfrm))
        for r in new_c:
            r['policy'] = pn.get(r['policyid'])
    out['new_countries'] = new_c
    # 9. admin plane: accepted local-in sessions to management ports from the internet
    admin_ports = [model.admin_port, model.admin_ssh_port, int(model.sslvpn.get('port') or 0)] if model else [443, 10443]
    out['admin_access'] = q(f"""SELECT dpt, country, act, sum(n) AS n FROM r_pol_5m WHERE dir = 'local' AND b >= ? AND b < ?
                               AND dpt IN ({','.join('?' * len(admin_ports))}) GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 20""",
                            (floor(frm, M5), to, *admin_ports))
    return out


def _polname(pid):
    if pid in (None, -1):
        return None
    return {0: 'implicit deny', 100_000: 'local-in implicit deny'}.get(pid) or f'policy {pid}'


def entry_points(frm, to, limit=20):
    """What the internet actually reached on this firewall, straight from the logs: destination, port, how many
    sessions and sources, where from, how much was denied. Needs no configuration backup, and works on a firewall
    that publishes nothing - there the destination is the firewall itself (SSL-VPN portal, admin, probed ports)."""
    hfrm = floor(frm, H1)
    rows = q("""SELECT dst, dpt, proto, sum(n) AS sessions, sum(drops) AS denied, sum(short) AS short,
                       count(DISTINCT src) AS sources, sum(bytes) AS bytes, max(b) AS last, max(policyid) AS policyid
                FROM r_in_1h WHERE b >= ? AND b < ? AND dst != '' GROUP BY 1, 2, 3
                ORDER BY sessions DESC LIMIT ?""", (hfrm, to, limit))
    if not rows:
        return []
    geo = defaultdict(lambda: defaultdict(int))
    for r in q("""SELECT dst, dpt, country, sum(n) AS n FROM r_in_1h
                  WHERE b >= ? AND b < ? AND country NOT IN ('', 'Reserved') GROUP BY 1, 2, 3""", (hfrm, to)):
        geo[(r['dst'], r['dpt'])][r['country']] += r['n']
    for r in rows:
        cs = sorted(geo[(r['dst'], r['dpt'])].items(), key=lambda x: -x[1])
        kb = KB.get(PORT_CLASS.get(r['dpt']) or '')
        r['countries'] = [c for c, _ in cs[:4]]
        r['country_count'] = len(cs)
        r['service'] = (kb or {}).get('title') or WELL_KNOWN.get(r['dpt']) or f"port {r['dpt']}"
        r['allowed'] = max(0, (r['sessions'] or 0) - (r['denied'] or 0))
        r['policy'] = _polname(r['policyid'])
    return rows


def bundle(frm, to):
    """The slow, log-derived part of the page (cached and warmed)."""
    t0 = time.time()
    model = R.load()
    return {'frm': frm, 'to': to, 'ev': rule_evidence(frm, to), 'det': detections(frm, to, model),
            'entry_points': entry_points(frm, to), 'took_ms': int((time.time() - t0) * 1000)}


def overview(frm, to):
    return assemble(bundle(frm, to), R.load())


def assemble(b, model):
    """Combine cached log evidence with the current (live) configuration: rule scores follow config changes at once."""
    t0 = time.time()
    ev = b['ev']
    exposed, rule_classes = _exposure(model)
    det = {k: v for k, v in b['det'].items() if not k.startswith('_')}
    probes = b['det'].get('_probes') or []
    det['bruteforce'] = [dict(r, service=_svc_title(rule_classes, r['policyid'], r['dpt'])) for r in b['det']['bruteforce']]
    det['probed_exposed'] = [dict(r, rules=exposed[r['dpt']], service=KB[PORT_CLASS.get(r['dpt'], 'other')]['title'])
                             for r in probes if r['dpt'] in exposed][:15]
    det['probed_top'] = [dict(r, exposed=r['dpt'] in exposed, service=KB[PORT_CLASS[r['dpt']]]['title'] if r['dpt'] in PORT_CLASS else None)
                         for r in probes[:15]]
    live = getattr(model, 'live', None) or {}
    rules_out, services = [], defaultdict(list)
    if model:
        for p in R.inbound_rules(model):
            a = R.analyze_rule(model, p)
            e = ev.get(p['id'], {})
            a['evidence'] = {k: e.get(k) for k in ('n', 'srcs', 'drops', 'short', 'bytes', 'last', 'ips', 'ips_sigs',
                                                   'app_block', 'app_pass')}
            a['evidence']['countries'] = sorted((e.get('countries') or {}).items(), key=lambda x: -x[1])[:8]
            a['evidence']['servers'] = sorted((e.get('servers') or {}).items(), key=lambda x: -x[1])[:6]
            bf = [b for b in det['bruteforce'] if b['policyid'] == p['id']]
            a['evidence']['bruteforce_sources'] = len(bf)
            active = []
            if bf:
                active.append(f"{len(bf)} source(s) look like password guessing")
            if e.get('ips'):
                active.append(f"{e['ips']:,} exploit attempts caught by IPS")
            if e.get('app_block'):
                active.append(f"{e['app_block']:,} sessions with the wrong protocol were blocked")
            if bf and not any('guessing' in f['text'] for f in a['factors']):
                a['factors'].append({'points': 10, 'text': 'Password-guessing activity seen in the logs'})
                a['score'] = min(100, a['score'] + 10)
            a['level'] = 'critical' if a['score'] >= 70 else 'high' if a['score'] >= 50 else 'medium' if a['score'] >= 30 else 'low'
            a['active'] = active
            if p['action'] == 'accept' and p['status'] == 'enable' and not e.get('n') and not e.get('app_pass'):
                a['unused'] = True
            a['summary'] = _rule_sentence(a)
            a['changes'] = (live.get('by_rule') or {}).get(p['id'], [])
            a['position_unknown'] = (live.get('position_unknown') or {}).get(p['id'])
            rules_out.append(a)
            if p['action'] == 'accept' and p['status'] == 'enable':
                for d in a['destinations']:
                    services[(d.get('server') or d['name'])].append(a['id'])
    accepts = [r for r in rules_out if r['action'] == 'accept' and r['enabled']]
    counts = {lv: sum(1 for r in accepts if r['level'] == lv) for lv in LEVELS[:4]}
    admin = R.admin_plane(model) if model else None
    priorities = _priorities(accepts, det, admin)
    return {'generated': int(time.time() * 1000), 'took_ms': int((time.time() - t0) * 1000), 'logs_took_ms': b.get('took_ms'),
            'config': {'loaded': bool(model), 'file': getattr(model, 'loaded', None), 'backup': getattr(model, 'backup', None),
                       'hostname': getattr(model, 'hostname', None),
                       'live': {k: v for k, v in live.items() if k not in ('by_rule', 'recent')} if live else None,
                       'recent_changes': live.get('recent', [])[:150]},
            'posture': {'rules_total': len(rules_out), 'accept_rules': len(accepts), 'levels': counts,
                        'open_to_anyone': sum(1 for r in accepts if r['source']['scope'] == 'any'),
                        'no_ips': sum(1 for r in accepts if not r['ips']),
                        'unused': sum(1 for r in accepts if r.get('unused')),
                        'servers': len(services), 'grade': _grade(accepts)},
            'priorities': priorities, 'rules': sorted(rules_out, key=lambda r: (r['action'] != 'accept', not r['enabled'], -r['score'])),
            'detections': det, 'admin': admin, 'entry_points': b.get('entry_points') or []}


def _rule_sentence(a):
    svc = ' and '.join(a['service_titles'][:2]) or 'a service'
    dst = ', '.join(sorted({d.get('server') or d['name'] for d in a['destinations']}))[:80]
    if a['action'] != 'accept':
        return f"Blocks {a['source']['label'].lower()} from reaching {dst or 'the destination'}."
    s = f"{a['source']['label']} can reach {svc} on {dst or 'the destination'}"
    ev = a['evidence']
    if ev.get('n'):
        s += f" - {ev['n']:,} sessions from {ev.get('srcs') or 0:,} IPs in this period"
    return s + '.'


def _grade(accepts):
    if not accepts:
        return 'n/a'
    crit = sum(1 for r in accepts if r['level'] == 'critical')
    high = sum(1 for r in accepts if r['level'] == 'high')
    return 'D' if crit >= 3 else 'C' if crit or high >= 5 else 'B' if high else 'A'


def _priorities(accepts, det, admin):
    items = []
    for r in sorted(accepts, key=lambda x: -x['score'])[:4]:
        if r['level'] in ('critical', 'high'):
            items.append({'level': r['level'], 'rule': r['id'],
                          'title': f"Rule {r['id']} “{r['name']}”: {r['service_titles'][0] if r['service_titles'] else 'service'} "
                                   f"reachable by {r['source']['label'].lower()}",
                          'why': (r['attacks'][0]['text'] if r['attacks'] else ''),
                          'fix': r['prevent'][0] if r['prevent'] else ''})
    if det['bruteforce']:
        b = det['bruteforce'][0]
        items.append({'level': 'high', 'title': f"Password guessing: {len(det['bruteforce'])} source(s) hammering login services",
                      'why': f"Top: {b['src']} ({b['country']}) made {b['short']:,} short connections to {b['service']} on {b['dst']}:{b['dpt']}.",
                      'fix': 'Block the source, restrict the rule source, and enable IPS brute-force signatures.'})
    if det['recon_then_access']:
        r = det['recon_then_access'][0]
        items.append({'level': 'high', 'title': f"{len(det['recon_then_access'])} IP(s) were denied first and later let in",
                      'why': f"e.g. {r['src']} ({r['country']}) was blocked {r['n_deny']:,} times, then allowed {r['n_acc']:,} times.",
                      'fix': 'Check what those IPs did after getting in (Investigation Tracker), and narrow the rules they used.'})
    if det['ips']:
        items.append({'level': 'medium', 'title': f"{sum(r['n'] for r in det['ips']):,} exploit attempts caught by IPS",
                      'why': f"Most common: {det['ips'][0]['attack']} ({det['ips'][0]['severity']}).",
                      'fix': 'Rules without an IPS sensor would not have caught these - add IPS to all inbound rules.'})
    if admin:
        for f in admin['findings']:
            if f['level'] in ('critical', 'high'):
                items.append({'level': f['level'], 'title': f['text'], 'why': 'Firewall management exposure', 'fix': 'Restrict with a local-in policy.'})
    return items[:7]
