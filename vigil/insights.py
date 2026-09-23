"""Automatic insights + alert strip. Each item: severity, title, detail, link (explorer filter)."""
import os
import time

from .queries import q, conf, floor, unexpected, DROP_IN, IN_DIR, IN_DIR_NOGEO, M5, H1, DAY
from .ingest import LOG_BASE

SEV = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def _i(sev, title, detail, link=None, kind=''):
    return {'severity': sev, 'title': title, 'detail': detail, 'link': link or {}, 'kind': kind}


def insights(frm, to):
    c = conf()
    out = []
    now = int(time.time() * 1000)
    b5, hfrm = floor(frm, M5), floor(frm, H1)
    pname = {r['policyid']: r['name'] for r in q('SELECT policyid, name FROM policy')}

    def pn(pid):
        return f"{pid} {pname.get(pid) or ''}".strip()

    # 1. monitor-only sensors must never block
    for r in q("""SELECT applist, policyid, sum(n) AS n, min(b) AS first, max(b) AS last FROM r_app_5m
                  WHERE act = 'block' AND b >= ? AND b < ? AND applist IN (%s) GROUP BY 1, 2 ORDER BY n DESC"""
               % ','.join('?' * len(c['monitor_sensors'])), (b5, to, *c['monitor_sensors'])):
        out.append(_i('critical', f"Monitor sensor {r['applist']} is BLOCKING on policy {pn(r['policyid'])}",
                      f"{r['n']:,} app-ctrl blocks; a visibility sensor should block nothing. Check the sensor's "
                      f"entries / other-application-action.", {'table': 'utm_app', 'policyid': r['policyid'], 'act': 'block'},
                      'sensor'))
    # 2. real drops on accept rules (app-ctrl / UTM)
    for r in q("""SELECT policyid, applist, sum(n) AS n FROM r_app_5m WHERE act = 'block' AND b >= ? AND b < ?
                  AND applist NOT IN (%s) GROUP BY 1, 2 ORDER BY n DESC LIMIT 10"""
               % ','.join('?' * len(c['monitor_sensors'])), (b5, to, *c['monitor_sensors'])):
        out.append(_i('high' if r['n'] > 100 else 'medium', f"App-ctrl dropped {r['n']:,} on policy {pn(r['policyid'])}",
                      f"sensor {r['applist']} - verify these are unwanted protocols before tightening further",
                      {'table': 'utm_app', 'policyid': r['policyid'], 'act': 'block'}, 'drops'))
    # 3. IPS
    for r in q("""SELECT severity, count(*) AS n, count(DISTINCT attack) AS attacks FROM utm_ips WHERE ts >= ? AND ts < ?
                  GROUP BY 1""", (frm, to)):
        sev = {'critical': 'critical', 'high': 'high'}.get(r['severity'], 'low')
        out.append(_i(sev, f"IPS: {r['n']:,} {r['severity']} events ({r['attacks']} signatures)", '',
                      {'table': 'utm_ips', 'q': r['severity']}, 'ips'))
    # 4. apps outside EXPECTED (Layer 1)
    rows = q(f"""SELECT policyid, app, sum(n) AS n FROM r_app_5m WHERE {IN_DIR_NOGEO} AND b >= ? AND b < ? GROUP BY 1, 2
                UNION ALL SELECT policyid, app, sum(n) FROM r_pol_5m WHERE {IN_DIR} AND b >= ? AND b < ?
                AND act NOT IN """ + DROP_IN + ' GROUP BY 1, 2', (b5, to, b5, to))
    une = {}
    for r in rows:
        if unexpected(r['policyid'], r['app']):
            une.setdefault(r['policyid'], {}).setdefault(r['app'], 0)
            une[r['policyid']][r['app']] += r['n']
    for pid, apps in sorted(une.items(), key=lambda x: -sum(x[1].values())):
        top = ', '.join(f'{a} ({n:,})' for a, n in sorted(apps.items(), key=lambda x: -x[1])[:5])
        out.append(_i('medium', f"Unexpected apps on policy {pn(pid)}", top,
                      {'table': 'utm_app', 'policyid': pid}, 'layer1'))
    # 5. src=all policies that in practice see few sources (Layer 2)
    for pid in c.get('src_all_policies', []):
        r = q(f"""SELECT count(DISTINCT src) AS n, sum(n) AS hits FROM r_src_1h WHERE {IN_DIR} AND policyid = ?
                 AND b >= ? AND b < ?""", (pid, hfrm, to), one=True)
        if r.get('hits'):
            few = r['n'] <= c.get('tighten_max_sources', 25)
            out.append(_i('medium' if few else 'low', f"Policy {pn(pid)} allows src=all, saw {r['n']:,} distinct sources",
                          'tightening candidate: see Rule assistant for the source list' if few else
                          'many sources - consider ISDB/geo objects instead of explicit IPs',
                          {'page': 'rule', 'policyid': pid}, 'layer2'))
    # 6. recon then access: sources with denies BEFORE their first accepted session
    rows = q("""SELECT src, country, n_deny, n_acc, first_ts, first_acc_ts FROM seen_src
                WHERE first_acc_ts >= ? AND first_acc_ts < ? AND n_deny > 0 AND first_ts < first_acc_ts
                ORDER BY n_deny DESC LIMIT 20""", (frm, to))
    if rows:
        top = ', '.join(f"{r['src']} ({r['country']}, {r['n_deny']} denies)" for r in rows[:6])
        out.append(_i('high', f"{len(rows)} sources were denied, then got through an accept rule", top,
                      {'table': 'traffic', 'src': rows[0]['src']}, 'recon'))
    # 7. new inbound source countries per accept policy (vs the 7 days before the range; needs >= 2 days of history)
    oldest = q('SELECT min(b) AS v FROM r_in_1h', one=True).get('v') or hfrm
    rows = [] if oldest > hfrm - 2 * DAY or to - frm >= 7 * DAY else q(
        """SELECT policyid, country, sum(n) AS n FROM r_in_1h WHERE b >= ? AND b < ? AND drops < n
           AND country NOT IN ('', 'Reserved') AND (policyid, country) NOT IN
           (SELECT DISTINCT policyid, country FROM r_in_1h WHERE b >= ? AND b < ?)
           GROUP BY 1, 2 ORDER BY n DESC LIMIT 15""", (hfrm, to, hfrm - 7 * DAY, hfrm))
    if rows:
        for r in rows[:8]:
            out.append(_i('medium', f"New source country {r['country']} on policy {pn(r['policyid'])}",
                          f"{r['n']:,} accepted hits, not seen in the previous 7 days",
                          {'table': 'traffic', 'policyid': r['policyid'], 'country': r['country']}, 'country'))
    # 8. mail ports: long or large sessions from unexpected countries
    ports = c.get('mail_ports', [])
    rows = q(f"""SELECT src, country AS scountry, policyid, dpt, sum(n) AS n, max(maxdur) AS dur, max(maxbytes) AS bytes
                 FROM r_in_1h WHERE b >= ? AND b < ? AND dpt IN ({','.join('?' * len(ports))})
                 AND (maxdur > ? OR maxbytes > ?) AND country NOT IN ({','.join('?' * len(c['expected_countries']))})
                 GROUP BY 1, 2, 3, 4 ORDER BY bytes DESC LIMIT 10""",
             (hfrm, to, *ports, c['long_session_seconds'], c['big_session_bytes'], *c['expected_countries']))
    for r in rows:
        out.append(_i('medium', f"Large/long mail session from {r['scountry']}: {r['src']} -> :{r['dpt']}",
                      f"policy {pn(r['policyid'])}, {r['n']} sessions, max {r['bytes'] or 0:,} bytes, {r['dur'] or 0}s",
                      {'table': 'traffic', 'src': r['src'], 'dpt': r['dpt']}, 'mail'))
    # 9. outbound: domains first seen in range, machines with unusual unique-domain counts
    r = q('SELECT count(*) AS n FROM seen_dom WHERE first_ts >= ? AND first_ts < ?', (frm, to), one=True)
    if r.get('n'):
        out.append(_i('info', f"{r['n']} root domains contacted for the first time", 'see Outbound -> new domains',
                      {'page': 'outbound'}, 'domains'))
    rows = q('SELECT src, count(DISTINCT root) AS roots FROM r_dom_1h WHERE b >= ? AND b < ? GROUP BY 1', (hfrm, to))
    if len(rows) >= 5:
        vals = sorted(r['roots'] for r in rows)
        med = vals[len(vals) // 2] or 1
        for r in sorted(rows, key=lambda x: -x['roots']):
            if r['roots'] > max(5 * med, med + 50):
                out.append(_i('low', f"{r['src']} contacted {r['roots']} distinct domains (median {med})", '',
                              {'table': 'utm_web', 'src': r['src']}, 'domains'))
    # 10. idle rules (seen before, silent for 7+ days) - removal / cleanup candidates
    for r in q("""SELECT policyid, name, last_ts FROM policy WHERE last_ts < ? AND policyid < 100000
                  ORDER BY last_ts""", (now - 7 * DAY,)):
        out.append(_i('low', f"Policy {pn(r['policyid'])} has had no hits for {(now - r['last_ts']) // DAY} days",
                      'removal / service-cleanup candidate (rules never seen at all need the config export)', {}, 'idle'))
    return sorted(out, key=lambda x: SEV[x['severity']])


def alerts():
    """Always evaluated on the last hour, independent of the selected range."""
    now = int(time.time() * 1000)
    out = []
    m = {r['k']: r['v'] for r in q('SELECT k, v FROM meta')}
    lag = (now - int(m.get('last_event_ts', 0) or 0)) / 1000
    if lag > 60:
        out.append(_i('critical' if lag > 600 else 'high', f"Ingest lag {lag:,.0f}s",
                      'no new FortiGate events in the database - check that the firewall still sends syslog and the Vigil container is healthy', {'page': 'health'}))
    try:
        silence = time.time() - os.path.getmtime(LOG_BASE)
        if silence > 60:
            out.append(_i('critical', f"Syslog silent for {silence:,.0f}s", f"{LOG_BASE} is not growing",
                          {'page': 'health'}))
    except OSError:
        pass
    for it in insights(now - H1, now):
        if it['severity'] in ('critical', 'high') and it['kind'] in ('sensor', 'drops', 'ips', 'recon'):
            out.append(it)
    oldest = q('SELECT min(b) AS v FROM r_in_1h', one=True).get('v') or now
    hb = floor(now, H1) - H1
    r = {} if oldest > now - 2 * DAY else q(
        """SELECT count(*) AS n FROM (SELECT DISTINCT policyid, country FROM r_in_1h WHERE b >= ? AND drops < n
           AND country NOT IN ('', 'Reserved') EXCEPT SELECT DISTINCT policyid, country
           FROM r_in_1h WHERE b >= ? AND b < ?)""", (hb, hb - 8 * DAY, hb), one=True)
    if r.get('n'):
        out.append(_i('medium', f"{r['n']} new inbound source countries in the last hour", '', {'page': 'inbound'}))
    return out
