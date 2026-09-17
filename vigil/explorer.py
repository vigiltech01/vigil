"""Log explorer (DB tables + raw-file scan for scanner noise), raw line lookup, rule-change assistant."""
import collections
import time

from .cef import parse, event_ms, to_int, needles as kv_needles, has_any, DENY_PATS
from .ingest import file_head, log_files
from .queries import q, conf, floor, unclassified, app_base, unexpected, DROP_IN, M5, H1

PROTO = {6: 'tcp', 17: 'udp', 1: 'icmp'}

# table -> (columns shown, free-text columns)
TABLES = {
    'traffic': ('ts,dir,policyid,src,spt,dst,dpt,tdst,proto,app,act,utmact,scountry,dcountry,isdb,shost,sent,rcvd,dur,fid,off',
                'src,dst,app,shost,isdb,scountry,dcountry'),
    'utm_app': ('ts,dir,policyid,applist,app,svc,appid,appcat,act,evtype,src,spt,dst,dpt,scountry,dhost,url,fid,off',
                'src,dst,app,svc,applist,dhost,url'),
    'utm_web': ('ts,policyid,profile,evtype,act,src,dst,dpt,dhost,root,url,method,reqapp,sent,rcvd,fid,off',
                'src,dst,dhost,url,reqapp'),
    'utm_ips': ('ts,policyid,severity,attack,attackid,act,src,scountry,dst,dpt,dhost,url,profile,fid,off',
                'src,dst,attack,dhost,severity'),
    'utm_av': ('ts,policyid,virus,act,src,dst,dhost,url,filename,fid,off', 'src,dst,virus,dhost,url,filename'),
    'utm_other': ('ts,cat,evtype,act,level,policyid,src,dst,dpt,dhost,msg,fid,off', 'cat,src,dst,dhost,msg,ext'),
    'event': ('ts,cat,level,logdesc,act,usr,src,dst,msg,fid,off', 'cat,logdesc,usr,src,msg,ext'),
}
FILTERS = {'policyid': 'policyid', 'src': 'src', 'dst': 'dst', 'dpt': 'dpt', 'app': 'app', 'act': 'act',
           'country': 'scountry', 'dir': 'dir', 'dhost': 'dhost', 'root': 'root'}


def logs(table, frm, to, f, limit=500, offset=0):
    if table == 'noise':
        return scan_noise(frm, to, f, limit)
    cols, text = TABLES[table]
    have = set(cols.split(','))
    where, args = ['ts >= ?', 'ts < ?'], [frm, to]
    for k, col in FILTERS.items():
        v = f.get(k)
        if v in (None, ''):
            continue
        if col not in have:
            if k == 'country' and 'scountry' in have:
                col = 'scountry'
            else:
                continue
        if k in ('policyid', 'dpt'):
            where.append(f'{col} = ?'); args.append(int(v))
        elif k == 'app':                      # SSL also matches SSL_TLSv1.3 etc.
            where.append("(app = ? OR app LIKE ? ESCAPE '\\')"); args += [v, v.replace('_', '\\_') + '\\_%']
        elif k == 'act' and v == 'drops':
            where.append(f"(act IN {DROP_IN}" + (" OR utmact = 'block')" if 'utmact' in have else ')'))
        else:
            where.append(f'{col} = ?'); args.append(v)
    if f.get('q'):
        where.append('(' + ' OR '.join(f'{c} LIKE ?' for c in text.split(',')) + ')')
        args += [f"%{f['q']}%"] * len(text.split(','))
    sql = f"SELECT {cols} FROM {table} WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT ? OFFSET ?"
    t = time.time()
    rows = q(sql, (*args, limit, offset))
    return {'rows': rows, 'columns': cols.split(','), 'took_ms': int((time.time() - t) * 1000), 'truncated': len(rows) == limit}


# ---------------------------------------------------------------- raw files
_heads = {'t': 0, 'map': {}}


def fid_path(fid):
    """Current path of a log file by its identity (it moves syslog -> syslog.1 -> syslog.2.gz)."""
    row = q('SELECT head, path FROM files WHERE fid = ?', (fid,), one=True)
    if not row:
        return None
    if time.time() - _heads['t'] > 60 or row['head'] not in _heads['map']:
        m = {}
        for p in log_files():
            try:
                h = file_head(p)
            except OSError:
                continue
            if h:
                m[h] = p
        _heads.update(t=time.time(), map=m)
    return _heads['map'].get(row['head'])


def raw_line(fid, off):
    path = fid_path(fid)
    if path is None:
        return {'error': 'log file rotated away (older than retention)'}
    if path.endswith('.gz'):
        return {'path': path, 'archived': True,
                'hint': f"zcat {path} | tail -c +{off + 1} | head -1"}
    with open(path, 'rb') as fh:
        fh.seek(off)
        return {'path': path, 'line': fh.readline().decode('utf-8', 'replace').rstrip('\n')}


def scan_noise(frm, to, f, limit, max_bytes=400 * 2**20):
    """Grep the raw syslog for denied/scanner lines (not stored in the DB) within [frm, to)."""
    needles = []
    if f.get('src'):
        needles.append(kv_needles('src', f['src']))
    if f.get('dpt'):
        needles.append(kv_needles('dpt', f['dpt']))
    if f.get('policyid') not in (None, ''):
        needles.append(kv_needles('FTNTFGTpolicyid', int(f['policyid']) % 100000))
    files = q("""SELECT fid, first_ts, last_ts FROM files WHERE last_ts >= ? AND (first_ts < ? OR first_ts IS NULL)
                 ORDER BY fid""", (frm, to))
    out = collections.deque(maxlen=limit)
    scanned, truncated = 0, False
    for fr in files:
        path = fid_path(fr['fid'])
        if not path or path.endswith('.gz'):
            continue
        start = q('SELECT max(off) AS o FROM file_index WHERE fid = ? AND ts <= ?', (fr['fid'], frm), one=True).get('o') or 0
        end = q('SELECT min(off) AS o FROM file_index WHERE fid = ? AND ts >= ?', (fr['fid'], to), one=True).get('o')
        with open(path, 'rb') as fh:
            fh.seek(start)
            off = start
            for raw in fh:
                if end is not None and off > end:
                    break
                o, off = off, off + len(raw)
                scanned += len(raw)
                if scanned > max_bytes:
                    truncated = True
                    break
                if not has_any(raw, DENY_PATS) or not all(has_any(raw, n) for n in needles):
                    continue
                line = raw.decode('utf-8', 'replace')
                d = parse(line)
                if not d:
                    continue
                ts = event_ms(d, line)
                if ts is None or ts < frm or ts >= to:
                    continue
                cat = d.get('cat', '')
                if not (cat == 'traffic:local' or d.get('FTNTFGTsrcintfrole') == 'wan'):
                    continue
                if f.get('country') and d.get('FTNTFGTsrccountry') != f['country']:
                    continue
                out.append({'ts': ts, 'cat': cat, 'policyid': to_int(d.get('FTNTFGTpolicyid')), 'src': d.get('src'),
                            'scountry': d.get('FTNTFGTsrccountry'), 'inif': d.get('deviceInboundInterface'),
                            'dst': d.get('dst'), 'dpt': to_int(d.get('dpt')), 'tdst': d.get('destinationTranslatedAddress'),
                            'proto': to_int(d.get('proto')), 'app': d.get('app'), 'act': d.get('act'),
                            'crlevel': d.get('FTNTFGTcrlevel'), 'fid': fr['fid'], 'off': o})
        if truncated:
            break
    rows = sorted(out, key=lambda r: -r['ts'])
    return {'rows': rows, 'columns': list(rows[0].keys()) if rows else ['ts', 'src', 'dst', 'dpt', 'act'],
            'scanned_mb': round(scanned / 2**20, 1), 'truncated': truncated}


# ---------------------------------------------------------------- rule assistant
def policy_report(pid, frm, to):
    c = conf()
    b5, hfrm = floor(frm, M5), floor(frm, H1)
    p = q('SELECT * FROM policy WHERE policyid = ?', (pid,), one=True)
    apps = q("""SELECT app, sum(n) AS n, sum(CASE WHEN act = 'block' THEN n ELSE 0 END) AS blocked, applist
                FROM r_app_5m WHERE policyid = ? AND b >= ? AND b < ? GROUP BY app ORDER BY n DESC""", (pid, b5, to))
    tapps = q("""SELECT app, sum(n) AS n FROM r_pol_5m WHERE policyid = ? AND b >= ? AND b < ?
                 GROUP BY app ORDER BY n DESC""", (pid, b5, to))
    ports = q("""SELECT dpt, proto, sum(n) AS n, sum(sent + rcvd) AS bytes,
                 sum(CASE WHEN act IN """ + DROP_IN + """ THEN n ELSE 0 END) AS drops
                 FROM r_pol_5m WHERE policyid = ? AND b >= ? AND b < ? GROUP BY 1, 2 ORDER BY n DESC""", (pid, b5, to))
    countries = q("""SELECT country, sum(n) AS n FROM r_pol_5m WHERE policyid = ? AND b >= ? AND b < ?
                     GROUP BY 1 ORDER BY n DESC""", (pid, b5, to))
    srcs = q("""SELECT src, max(country) AS country, sum(n) AS n, sum(drops) AS drops, sum(sent + rcvd) AS bytes,
                min(b) AS first, max(b) AS last FROM r_src_1h WHERE policyid = ? AND b >= ? AND b < ?
                GROUP BY src ORDER BY n DESC""", (pid, hfrm, to))
    isdb = q("""SELECT isdb, count(*) AS n FROM traffic WHERE policyid = ? AND ts >= ? AND ts < ? AND isdb IS NOT NULL
                GROUP BY 1 ORDER BY n DESC LIMIT 10""", (pid, max(frm, to - 3 * 3_600_000), to))   # sample: last 3 h
    appids = {r['app']: r['appid'] for r in q("""SELECT app, max(appid) AS appid FROM utm_app WHERE policyid = ?
                AND appid IS NOT NULL AND ts >= ? GROUP BY app""", (pid, max(frm, to - 7 * 86_400_000)))}
    total = sum(r['n'] for r in srcs) or 0
    exp = c['_expected'].get(pid)
    seen = {}
    for r in apps + tapps:
        seen[r['app']] = max(seen.get(r['app'], 0), r['n'])
    keep = {a: n for a, n in seen.items() if not unclassified(a) and (exp is None or app_base(a) in exp)}
    flagged = {a: n for a, n in seen.items() if unexpected(pid, a)}
    return {'policy': p, 'apps': apps, 'traffic_apps': tapps, 'ports': ports, 'countries': countries,
            'sources': srcs[:500], 'n_sources': len(srcs), 'hits': total, 'isdb': isdb,
            'expected': sorted(exp) if exp is not None else None, 'unexpected': flagged,
            'cli': _cli(pid, p, keep, flagged, appids, srcs, ports, frm, to, c)}


def _cli(pid, p, keep, flagged, appids, srcs, ports, frm, to, c):
    name = (p or {}).get('name') or ''
    fmt = lambda ts: time.strftime('%Y-%m-%d %H:%M', time.gmtime(ts / 1000))
    by_n = lambda d: ', '.join('%s(%s)' % (a, format(n, ',')) for a, n in sorted(d.items(), key=lambda x: -x[1])) or '-'
    port_s = ', '.join('%s/%s(%s)' % (r['dpt'], PROTO.get(r['proto'], r['proto']), format(r['n'], ',')) for r in ports[:12])
    L = [f'# Vigil proposal for policy {pid} "{name}" - evidence {fmt(frm)} .. {fmt(to)} UTC',
         '# REVIEW BEFORE APPLYING. Nothing here is pushed to the FortiGate automatically.',
         f'# observed apps : {by_n(keep)}',
         f'# unexpected    : {by_n(flagged)}',
         f'# ports seen    : {port_s or "-"}',
         f'# sources       : {len(srcs):,} distinct', '']
    if pid >= 100000:
        return '\n'.join(L + ['# local-in / sniffer policy: no proposal generated'])
    ids = sorted({appids[a] for a in keep if appids.get(a)})
    missing = [a for a in keep if not appids.get(a)]
    if ids:
        L += ['# Layer 1 - protocol allow-list (app IDs taken from the app-ctrl logs of this policy)',
              'config application list',
              f'    edit "vigil-p{pid}-allowlist"',
              f'        set comment "Vigil: allow observed apps on policy {pid}, block everything else"',
              '        set other-application-action block',
              '        set unknown-application-action block',
              '        set enforce-default-app-port enable      # check apps used on non-default ports first',
              '        set other-application-log enable',
              '        set unknown-application-log enable',
              '        config entries',
              '            edit 1',
              f'                set application {" ".join(map(str, ids))}',
              '                set action pass',
              '                set log enable',
              '            next',
              '        end',
              '    next',
              'end', '']
        if missing:
            L.append(f"# no app ID seen in app-ctrl logs for: {', '.join(missing)} (traffic-log labels) - look them up")
    else:
        L.append('# no app-ctrl IDs observed for this policy yet (attach a monitor-only application sensor first to collect evidence)')
    n_max = c.get('tighten_max_sources', 25)
    if 0 < len(srcs) <= n_max:
        L += ['', f'# Layer 2 - source tightening: {len(srcs)} sources carried all traffic in this window',
              'config firewall address']
        for i, r in enumerate(srcs, 1):
            L += [f'    edit "IN-p{pid}-src-{i}"', f'        set subnet {r["src"]} 255.255.255.255',
                  f'        set comment "{r["country"]} {r["n"]:,} hits"', '    next']
        L += ['end', 'config firewall addrgrp', f'    edit "IN-p{pid}-sources"',
              '        set member ' + ' '.join(f'"IN-p{pid}-src-{i}"' for i in range(1, len(srcs) + 1)), '    next', 'end']
    elif srcs:
        L += ['', f'# Layer 2 - {len(srcs):,} distinct sources: too many for explicit objects;',
              '#   use ISDB (see the ISDB table) or geography objects for the countries listed above.']
    L += ['', 'config firewall policy', f'    edit {pid}']
    if ids:
        L.append(f'        set application-list "vigil-p{pid}-allowlist"')
    if 0 < len(srcs) <= n_max:
        L.append(f'        set srcaddr "IN-p{pid}-sources"')
    L += ['        set logtraffic all', '    next', 'end']
    return '\n'.join(L)
