"""Firewall Investigation Tracker back end: query parsing, multi-source search, correlation engine,
path / decision reconstruction and entity trace.

Rule: everything returned is read from FortiGate log fields, the learned policy table, the FortiGate device
table (host), the uploaded configuration backup or the interface settings. Missing information is returned as None and
rendered as "Data unavailable" / "Unknown hop" - nothing is inferred beyond that.
"""
import hashlib
import ipaddress
import re
import sqlite3
import threading
import time
from collections import Counter, defaultdict

from .cef import parse, to_int, needles as kv_needles, DENY_PATS
from .explorer import fid_path
from .queries import q, conf, floor, Budget, H1, DAY

SEARCH_BUDGET_S = 15            # a search walks back through the range until it has enough results or this is spent
PER_TABLE = 500

RAW_DROPS = {'deny', 'block', 'blocked', 'dropped', 'reset'}
SEV_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
VERDICT_RANK = {'threat': 0, 'blocked': 1, 'warning': 2, 'allowed': 3, 'info': 4}
TABLE_CAT = {'utm_app': 'utm:app-ctrl', 'utm_web': 'utm:webfilter', 'utm_ips': 'utm:ips', 'utm_av': 'utm:virus'}
PROTO = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMPv6'}
# DB column -> CEF field name (used when the original line is only available in a compressed file)
COL2CEF = {'src': 'src', 'spt': 'spt', 'dst': 'dst', 'dpt': 'dpt', 'proto': 'proto', 'act': 'act',
           'utmact': 'FTNTFGTutmaction', 'app': 'FTNTFGTapp', 'svc': 'app', 'appcat': 'FTNTFGTappcat',
           'scountry': 'FTNTFGTsrccountry', 'dcountry': 'FTNTFGTdstcountry', 'inif': 'deviceInboundInterface',
           'outif': 'deviceOutboundInterface', 'tdst': 'destinationTranslatedAddress', 'tdpt': 'destinationTranslatedPort',
           'isdb': 'FTNTFGTsrcinetsvc', 'shost': 'shost', 'sent': 'out', 'rcvd': 'in', 'dur': 'FTNTFGTduration',
           'sess': 'externalId', 'applist': 'FTNTFGTapplist', 'appid': 'FTNTFGTappid', 'apprisk': 'FTNTFGTapprisk',
           'evtype': 'FTNTFGTeventtype', 'dhost': 'dhost', 'url': 'request', 'profile': 'FTNTFGTprofile',
           'method': 'FTNTFGThttpmethod', 'reqapp': 'requestClientApplication', 'attack': 'FTNTFGTattack',
           'attackid': 'FTNTFGTattackid', 'severity': 'FTNTFGTseverity', 'level': 'FTNTFGTlevel', 'ref': 'FTNTFGTref',
           'virus': 'FTNTFGTvirus', 'filename': 'fname', 'msg': 'msg', 'logdesc': 'FTNTFGTlogdesc', 'usr': 'duser'}
TABLE_COLS = {
    'traffic': 'ts,kind,dir,inif,outif,src,spt,dst,dpt,tdst,tdpt,proto,policyid,act,utmact,app,appcat,scountry,dcountry,isdb,shost,sent,rcvd,dur,sess,fid,off',
    'utm_app': 'ts,dir,policyid,applist,appid,app,svc,appcat,apprisk,act,evtype,src,spt,dst,dpt,proto,scountry,dhost,url,sess,fid,off',
    'utm_web': 'ts,dir,policyid,profile,evtype,act,src,spt,dst,dpt,dhost,root,url,method,reqapp,sent,rcvd,sess,fid,off',
    'utm_ips': 'ts,dir,policyid,attack,attackid,severity,level,act,src,spt,dst,dpt,proto,scountry,dhost,url,profile,ref,sess,fid,off',
    'utm_av': 'ts,dir,policyid,virus,act,level,src,dst,dpt,dhost,url,filename,profile,sess,fid,off',
    'utm_other': 'ts,cat,evtype,act,level,policyid,src,dst,dpt,dhost,msg,ext,fid,off',
    'event': 'ts,cat,level,logdesc,act,usr,src,dst,msg,ext,fid,off',
}
USER_FIELDS = ('duser', 'suser', 'FTNTFGTuser', 'FTNTFGTunauthuser', 'FTNTFGTxauthuser')
KEY_SPLIT = re.compile(r'(?:^|\s)(\w+)=')


def now_ms():
    return int(time.time() * 1000)


def mkref(fid, off, ts):
    return f'{fid}:{off}:{ts}'


def split_ref(ref):
    m = re.fullmatch(r'(\d+):(\d+):(\d+)', ref or '')
    if not m:
        raise ValueError('bad event reference')
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def pkey(d):
    pid = to_int(d.get('FTNTFGTpolicyid'))
    if pid is None:
        return None
    return {'local-in-policy': 100_000, 'local-in-policy6': 100_000, 'sniffer': 300_000}.get(
        d.get('FTNTFGTpolicytype', 'policy'), 0 if d.get('FTNTFGTpolicytype', 'policy') == 'policy' else 900_000) + pid


def ts_ns(d, fallback_ms):
    et = d.get('FTNTFGTeventtime', '')
    if et.isdigit() and len(et) >= 10:
        return int(et.ljust(19, '0')[:19])
    return fallback_ms * 1_000_000


def _ext_dict(ext):
    kv = KEY_SPLIT.split(ext or '')
    return {k: v.strip() for k, v in zip(kv[1::2], kv[2::2])}


# ---------------------------------------------------------------- classification
def classify(d):
    """(kind, verdict) of one FortiGate log record."""
    cat = d.get('cat') or (d.get('_sig') or '').split(' ', 1)[0]
    act = (d.get('act') or '').lower()
    utm = d.get('FTNTFGTutmaction')
    kind = {'traffic': 'traffic', 'utm:app-ctrl': 'app-ctrl', 'utm:webfilter': 'webfilter', 'utm:ips': 'ips',
            'utm:virus': 'av', 'utm:ssl': 'ssl', 'utm:dns': 'dns', 'event:vpn': 'vpn', 'event:user': 'auth'}.get(
        cat if not cat.startswith('traffic') else 'traffic', 'utm' if cat.startswith('utm') else 'system')
    if kind in ('ips', 'av'):
        return kind, 'threat'
    if act in RAW_DROPS or utm == 'block':
        return kind, 'blocked'
    if kind == 'webfilter' and (d.get('FTNTFGTeventtype') == 'ftgd_err' or act == 'warning'):
        return kind, 'warning'
    if kind in ('ssl', 'utm') or (kind in ('vpn', 'system', 'auth') and act in ('failure', 'negotiate_error', 'esp_error', 'failed')):
        return kind, 'warning'
    if kind in ('vpn', 'system', 'auth'):
        return kind, 'info'
    return kind, 'allowed'


def label(d, kind, verdict):
    act = d.get('act', '')
    pid = pkey(d)
    pol = f"policy {polname(pid)}" if pid is not None else ''
    if kind == 'traffic':
        if verdict == 'blocked':
            if d.get('FTNTFGTutmaction') == 'block' and act not in RAW_DROPS:
                return f"Session killed by a security profile ({act}) · {pol}"
            return f"Session denied · {pol}"
        return f"Session {'log' if act == 'accept' else 'ended (' + act + ')'} · {pol}"
    if kind == 'app-ctrl':
        return f"App control: {d.get('FTNTFGTapp') or d.get('app')} → {act}"
    if kind == 'webfilter':
        return f"Web filter: {d.get('dhost') or d.get('request') or '?'} → {act}"
    if kind == 'ips':
        return f"IPS: {d.get('FTNTFGTattack')} ({d.get('FTNTFGTseverity')}) → {act}"
    if kind == 'av':
        return f"Antivirus: {d.get('FTNTFGTvirus') or '?'} → {act}"
    if kind == 'ssl':
        return f"SSL inspection: {d.get('msg') or d.get('FTNTFGTeventtype')}"
    return d.get('FTNTFGTlogdesc') or d.get('msg') or (d.get('_sig') or kind)


_pol_cache = {'t': 0, 'v': {}}


def policies():
    if time.time() - _pol_cache['t'] > 60:
        _pol_cache.update(t=time.time(), v={r['policyid']: r for r in q('SELECT * FROM policy')})
    return _pol_cache['v']


def polname(pid):
    if pid is None:
        return None
    p = policies().get(pid)
    lab = f'LI-{pid - 100000}' if 100000 <= pid < 300000 else f'SN-{pid - 300000}' if 300000 <= pid < 900000 else str(pid)
    return f"{lab} {p['name']}" if p and p.get('name') else lab


# ---------------------------------------------------------------- raw records
def _read_line(fid, off):
    path = fid_path(fid)
    if not path or path.endswith('.gz'):
        return path, None
    with open(path, 'rb') as fh:
        fh.seek(off)
        return path, fh.readline().decode('utf-8', 'replace').rstrip('\n')


def _db_row(fid, off, ts):
    for t, cols in TABLE_COLS.items():
        r = q(f'SELECT {cols} FROM {t} WHERE ts = ? AND fid = ? AND off = ?', (ts, fid, off), one=True)
        if r:
            return t, r
    return None, None


def _row_fields(table, r):
    d = {'cat': TABLE_CAT.get(table) or (f"traffic:{r['kind']}" if table == 'traffic' else r.get('cat'))}
    if r.get('ext'):
        d.update(_ext_dict(r['ext']))
    for c, v in r.items():
        if v is not None and c in COL2CEF and COL2CEF[c] not in d:
            d[COL2CEF[c]] = str(v)
    pid = r.get('policyid')
    if pid is not None:
        d['FTNTFGTpolicyid'] = str(pid % 100000)
        d['FTNTFGTpolicytype'] = 'local-in-policy' if 100000 <= pid < 300000 else 'policy'
    return d


def record(fid, off, ts, d=None, line=None, path=None, conf_=100, method='seed event'):
    """Normalised record: identity, kind/verdict/label and every original field."""
    if d is None:
        path, line = _read_line(fid, off)
        if line:
            d = parse(line) or {}
        else:
            table, row = _db_row(fid, off, ts)
            d = _row_fields(table, row) if row else {}
    kind, verdict = classify(d)
    fields = {k: v for k, v in d.items() if not k.startswith('_')}
    return {'ref': mkref(fid, off, ts), 'fid': fid, 'off': off, 'ts': ts, 'ts_ns': str(ts_ns(d, ts)), 'kind': kind,
            'verdict': verdict, 'label': label(d, kind, verdict), 'cef_name': d.get('_sig'), 'fields': fields,
            'raw': line, 'raw_available': line is not None, 'path': path, 'confidence': conf_, 'method': method}


def raw_event(ref):
    fid, off, ts = split_ref(ref)
    return record(fid, off, ts)


def _window_offsets(fid, t0, t1):
    a = q('SELECT max(off) AS o FROM file_index WHERE fid = ? AND ts <= ?', (fid, t0), one=True).get('o') or 0
    b = q('SELECT min(off) AS o FROM file_index WHERE fid = ? AND ts >= ?', (fid, t1), one=True).get('o')
    return a, b


def raw_find(fid, t0, t1, needle, limit=400, max_bytes=1500 * 2**20):
    """Yield (off, line) for raw lines containing `needle` between t0 and t1 (ms) in file fid - chunked bytes.find.
    `needle` is bytes or a tuple of alternatives (see cef.needles)."""
    if isinstance(needle, bytes):
        def find(buf, pos):
            return buf.find(needle, pos)
    else:
        pat = re.compile(b'|'.join(re.escape(n) for n in needle))

        def find(buf, pos):
            m = pat.search(buf, pos)
            return m.start() if m else -1
    path = fid_path(fid)
    if not path or path.endswith('.gz'):
        return
    start, end = _window_offsets(fid, t0, t1)
    with open(path, 'rb') as fh:
        if end is None:
            fh.seek(0, 2)
            end = fh.tell()
        end = min(end, start + max_bytes)
        fh.seek(start)
        pos, carry, found = start, b'', 0
        while pos < end and found < limit:
            chunk = fh.read(min(32 << 20, end - pos))
            if not chunk:
                break
            buf, base = carry + chunk, pos - len(carry)
            cut = buf.rfind(b'\n') + 1
            work, carry = buf[:cut], buf[cut:]
            i = find(work, 0)
            while i >= 0 and found < limit:
                ls = work.rfind(b'\n', 0, i) + 1
                le = work.find(b'\n', i)
                yield base + ls, work[ls:le].decode('utf-8', 'replace')
                found += 1
                i = find(work, le)
            pos += len(chunk)


def files_for(t0, t1):
    return [r['fid'] for r in q("""SELECT fid FROM files WHERE (last_ts IS NULL OR last_ts >= ?) AND
                                   (first_ts IS NULL OR first_ts <= ?) ORDER BY fid""", (t0, t1))]


# ---------------------------------------------------------------- query parsing
IP_RE = r'(?:\d{1,3}\.){3}\d{1,3}'
MAC_RE = re.compile(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b')
KEYS = {'src': 'src', 'source': 'src', 'sip': 'src', 'srcip': 'src', 'dst': 'dst', 'dest': 'dst', 'destination': 'dst',
        'dip': 'dst', 'dstip': 'dst', 'ip': 'ip', 'spt': 'spt', 'sport': 'spt', 'srcport': 'spt', 'dpt': 'dpt',
        'dport': 'dpt', 'port': 'dpt', 'dstport': 'dpt', 'proto': 'proto', 'protocol': 'proto', 'domain': 'domain',
        'url': 'domain', 'host': 'domain', 'fqdn': 'domain', 'user': 'user', 'username': 'user', 'device': 'device',
        'hostname': 'device', 'mac': 'mac', 'session': 'sess', 'sess': 'sess', 'sessionid': 'sess', 'request': 'reqid',
        'reqid': 'reqid', 'requestid': 'reqid', 'policy': 'policy', 'rule': 'policy', 'policyid': 'policy',
        'policyname': 'policyname', 'action': 'action', 'app': 'app', 'application': 'app', 'category': 'category',
        'cat': 'category', 'country': 'country', 'iface': 'iface', 'interface': 'iface', 'intf': 'iface', 'vpn': 'vpn',
        'threat': 'threat', 'ips': 'threat', 'severity': 'severity', 'keyword': 'keyword'}
ACTION_WORDS = {'blocked': 'blocked', 'block': 'blocked', 'denied': 'blocked', 'deny': 'blocked', 'dropped': 'blocked',
                'drop': 'blocked', 'rejected': 'blocked', 'allowed': 'allowed', 'allow': 'allowed', 'accepted': 'allowed',
                'accept': 'allowed', 'permitted': 'allowed', 'passed': 'allowed'}
STOP = {'why', 'was', 'is', 'were', 'the', 'a', 'an', 'what', 'did', 'does', 'do', 'happened', 'happen', 'to', 'from',
        'and', 'for', 'of', 'on', 'with', 'traffic', 'request', 'requests', 'show', 'me', 'find', 'all', 'get', 'it', 'this',
        'that', 'by', 'in', 'at', 'being', 'been', 'getting', 'events', 'event', 'logs', 'log', 'any', 'who', 'how', 'my'}
COUNTRY_ALIAS = {'russia': 'Russian Federation', 'usa': 'United States',
                 'uk': 'United Kingdom', 'britain': 'United Kingdom', 'korea': 'Korea, Republic of', 'iran': 'Iran, Islamic Republic of',
                 'uae': 'United Arab Emirates', 'holland': 'Netherlands', 'taiwan': 'Taiwan'}
_vocab = {'t': 0}


_vocab_lock = threading.Lock()


def vocab():
    """Country / application names for query parsing. Only recent rollup buckets are read (primary-key range scans),
    and a failed refresh keeps the previous vocabulary - it must never turn every search into a full-table scan."""
    if time.time() - _vocab['t'] < 1800 and 'countries' in _vocab:
        return _vocab
    with _vocab_lock:
        if time.time() - _vocab['t'] < 1800 and 'countries' in _vocab:
            return _vocab
        since = now_ms() - 3 * DAY
        countries, apps = dict(_vocab.get('countries') or {}), dict(_vocab.get('apps') or {})
        try:
            countries.update({r['c'].lower(): r['c'] for r in q(
                "SELECT DISTINCT country AS c FROM r_deny_src_1d WHERE b >= ? AND country NOT IN ('', 'Reserved') UNION "
                "SELECT DISTINCT country FROM r_pol_5m WHERE b >= ? AND country NOT IN ('', 'Reserved')",
                (floor(since, DAY), now_ms() - 6 * H1)) if r['c']})
            apps.update({r['a'].lower(): r['a'] for r in q('SELECT DISTINCT app AS a FROM r_app_5m WHERE b >= ?', (since,))
                         if r['a']})
            # applications seen on firewall sessions (e.g. Microsoft.Teams) so an app name can use the summaries
            apps.update({r['a'].lower(): r['a'] for r in q("SELECT DISTINCT app AS a FROM r_pol_5m WHERE b >= ? AND app != ''",
                                                            (now_ms() - DAY,))
                         if r['a'] and len(r['a']) >= 4 and '/' not in r['a'] and r['a'].lower() not in STOP
                         and r['a'].lower() not in apps})
        except Exception:                                   # keep what we had; retry in 2 minutes
            _vocab['t'] = time.time() - 1800 + 120
        else:
            _vocab['t'] = time.time()
        _vocab['countries'], _vocab['apps'] = countries, apps
    return _vocab


def parse_query(text, extra=None):
    """Free text ('Why was 10.0.0.25 blocked?', '1.2.3.4 -> 8.8.8.8:53', 'src=… policy 5') -> filters."""
    f = {}
    s = (text or '').strip()
    for m in list(re.finditer(r'(\w+)\s*[=:]\s*("[^"]*"|\S+)', s)):
        k = KEYS.get(m.group(1).lower())
        if k and not re.fullmatch(r'\d+', m.group(1)):
            f[k] = m.group(2).strip('"')
            s = s.replace(m.group(0), ' ')
    for m in MAC_RE.finditer(s):
        f.setdefault('mac', m.group(0).lower().replace('-', ':'))
        s = s.replace(m.group(0), ' ')
    ips = [(m.group(1), m.group(2), m.start()) for m in re.finditer(rf'({IP_RE})(?::(\d{{1,5}}))?', s)]
    arrow = re.search(r'→|->|=>|\bto\b', s)
    frm_kw = re.search(r'\bfrom\b', s)
    if ips:
        if len(ips) >= 2:
            (a, ap, _), (b, bp, _) = ips[0], ips[1]
            f.setdefault('src', a); f.setdefault('dst', b)
            if ap: f.setdefault('spt', ap)
            if bp: f.setdefault('dpt', bp)
        else:
            ip, port, pos = ips[0]
            side = 'dst' if arrow and arrow.start() < pos else 'src' if (arrow and arrow.start() > pos) or \
                (frm_kw and frm_kw.start() < pos) else 'ip'
            f.setdefault(side, ip)
            if port:
                f.setdefault('dpt' if side != 'src' else 'spt', port)
        s = re.sub(rf'{IP_RE}(?::\d{{1,5}})?', ' ', s)
    for pat, key in ((r'\b(?:port|dport|dpt)\s+(\d{1,5})\b', 'dpt'), (r'\b(?:sport|spt)\s+(\d{1,5})\b', 'spt'),
                     (r'\b(?:policy|rule)\s+#?(\d+)\b', 'policy'), (r'\b(?:session|sess)\s+#?(\d+)\b', 'sess'),
                     (r'\b(?:request|req)\s+#?(\d+)\b', 'reqid'), (r'\buser\s+(\S+)', 'user'),
                     (r'\b(?:device|hostname)\s+(\S+)', 'device'), (r'\b(?:interface|iface)\s+(\S+)', 'iface')):
        m = re.search(pat, s, re.I)
        if m:
            f.setdefault(key, m.group(1))
            s = s.replace(m.group(0), ' ')
    words = re.findall(r'[\w.\-]+', s.replace('?', ' '))
    v = vocab()
    rest = []
    i = 0
    while i < len(words):
        w, lw = words[i], words[i].lower()
        hit = None
        for n in (3, 2, 1):
            phrase = ' '.join(words[i:i + n]).lower()
            if n > 1 and phrase in v['countries']:
                hit = ('country', v['countries'][phrase], n)
                break
        if hit:
            f.setdefault(hit[0], hit[1]); i += hit[2]; continue
        if lw in ACTION_WORDS:
            f.setdefault('action', ACTION_WORDS[lw])
        elif lw in ('tcp', 'udp', 'icmp'):
            f.setdefault('proto', lw)
        elif lw in ('ips', 'threat', 'threats', 'attack', 'malware', 'virus'):
            f.setdefault('threat', '1')
        elif lw == 'vpn':
            f.setdefault('vpn', '1')
        elif lw in v['apps']:
            f.setdefault('app', v['apps'][lw])
        elif lw in v['countries']:
            f.setdefault('country', v['countries'][lw])
        elif lw in COUNTRY_ALIAS or (len(lw) >= 5 and lw not in STOP and
                                     len([c for c in v['countries'] if c.startswith(lw)]) == 1):
            name = COUNTRY_ALIAS.get(lw) or next(c for c in v['countries'] if c.startswith(lw))
            f.setdefault('country', v['countries'].get(name.lower(), name))
        elif re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z]{2,}', lw):
            f.setdefault('domain', lw)
        elif re.fullmatch(r'\d{5,}', lw) and 'sess' not in f:
            f['sess'] = lw
        elif lw.upper() in ('HTTPS', 'HTTP', 'SSH', 'SMTP', 'SMTPS', 'IMAPS', 'DNS', 'RDP', 'SSL', 'POP3', 'FTP', 'SIP', 'TELNET'):
            f.setdefault('app', lw.upper())
        elif lw not in STOP and len(lw) > 1:
            rest.append(w)
        i += 1
    if rest and 'keyword' not in f:
        f['keyword'] = ' '.join(rest)
    for k, val in (extra or {}).items():
        if val not in (None, '') and k in set(KEYS.values()):
            f[k] = val
    return f


# ---------------------------------------------------------------- search
def _ips_for(f):
    """Resolve user / device / mac filters to IPs using FortiGate data only."""
    ips, how = set(), []
    if f.get('user'):
        u = f['user']
        for r in q("""SELECT ext FROM event WHERE cat = 'event:vpn' AND (ext LIKE ? OR ext LIKE ?) ORDER BY ts DESC LIMIT 500""",
                   (f'%duser={u}%', f'%xauthuser={u}%')):
            m = re.search(r'FTNTFGTassignip=(\S+)', r['ext'] or '')
            if m and m.group(1) not in ('N/A', '0.0.0.0'):
                ips.add(m.group(1))
        how.append(f"user '{u}' → VPN assigned IPs from event:vpn logs")
    if f.get('device'):
        for r in q('SELECT ip FROM host WHERE name LIKE ? LIMIT 50', (f"%{f['device']}%",)):
            ips.add(r['ip'])
        how.append(f"device '{f['device']}' → IPs from FortiGate device identification")
    if f.get('mac'):
        for r in q('SELECT ip FROM host WHERE lower(mac) = ? LIMIT 50', (f['mac'].lower(),)):
            ips.add(r['ip'])
        how.append(f"MAC {f['mac']} → IPs from FortiGate device identification")
    return ips, how


def _where(table, f, frm, to, ids):
    cols = set(TABLE_COLS[table].split(','))
    w, a = ['ts >= ?', 'ts < ?'], [frm, to]

    def need(col):
        return col in cols

    def add(cond, *args):
        w.append(cond); a.extend(args)
    if f.get('src'):
        if not need('src'): return None
        add('src = ?', f['src'])
    if f.get('dst'):
        if not need('dst'): return None
        add('(dst = ?' + (' OR tdst = ?)' if need('tdst') else ')'), *([f['dst']] * (2 if need('tdst') else 1)))
    if f.get('ip'):
        if not need('src'): return None
        add('(src = ? OR dst = ?' + (' OR tdst = ?)' if need('tdst') else ')'), *([f['ip']] * (3 if need('tdst') else 2)))
    if ids is not None:
        if not need('src') or not ids: return None
        add(f"src IN ({','.join('?' * len(ids))})", *ids)
    for k, col in (('spt', 'spt'), ('dpt', 'dpt')):
        if f.get(k):
            if not need(col): return None
            add(f'{col} = ?', int(f[k]))
    if f.get('proto'):
        if not need('proto'): return None
        add('proto = ?', {'tcp': 6, 'udp': 17, 'icmp': 1}.get(f['proto'].lower(), to_int(f['proto'])))
    if f.get('sess'):
        if not need('sess'): return None
        add('sess = ?', int(f['sess']))
    if f.get('policy_ids') is not None:
        if not need('policyid') or not f['policy_ids']: return None
        add(f"policyid IN ({','.join('?' * len(f['policy_ids']))})", *f['policy_ids'])
    if f.get('domain'):
        dom = f['domain'].lower()
        if need('dhost'):
            add('(dhost = ? OR dhost LIKE ?' + (' OR root = ?)' if need('root') else ')'),
                dom, '%.' + dom, *([dom] if need('root') else []))
        elif table == 'traffic':
            dsts = [r['dst'] for r in q("""SELECT DISTINCT dst FROM utm_web WHERE ts >= ? AND ts < ?
                    AND (dhost = ? OR dhost LIKE ? OR root = ?) LIMIT 50""", (frm, to, dom, '%.' + dom, dom))]
            if not dsts: return None
            add(f"dst IN ({','.join('?' * len(dsts))})", *dsts)
        else:
            return None
    if f.get('app'):
        if not need('app'): return None
        add("(app = ? OR app LIKE ? ESCAPE '\\')", f['app'], f['app'].replace('_', '\\_') + '\\_%')
    if f.get('category'):
        if not need('appcat'): return None
        add('appcat LIKE ?', f"%{f['category']}%")
    if f.get('country'):
        if need('scountry') and need('dcountry'):
            add('(scountry = ? OR dcountry = ?)', f['country'], f['country'])
        elif need('scountry'):
            add('scountry = ?', f['country'])
        else:
            return None
    if f.get('iface'):
        if not need('inif'): return None
        add('(inif = ? OR outif = ?)', f['iface'], f['iface'])
    if f.get('threat') and table not in ('utm_ips', 'utm_av'):
        return None
    if f.get('severity'):
        if not need('severity'): return None
        add('severity = ?', f['severity'])
    if f.get('vpn'):
        if table == 'event':
            add("cat = 'event:vpn'")
        elif need('inif'):
            add("(inif LIKE 'ssl.%' OR outif LIKE 'ssl.%' OR inif LIKE '%vpn%')")
        else:
            return None
    act = f.get('action')
    if act == 'blocked':
        if table == 'traffic':
            add("(act IN ('deny','block','blocked','dropped','reset') OR utmact = 'block')")
        elif table in ('utm_app', 'utm_web'):
            add("act IN ('block','blocked','deny')")
        elif table in ('utm_ips', 'utm_av'):
            add("act IN ('dropped','blocked','block','reset')")
        else:
            return None
    elif act == 'allowed':
        if table == 'traffic':
            add("act NOT IN ('deny','block','blocked','dropped','reset') AND coalesce(utmact, '') != 'block'")
        elif table in ('utm_app', 'utm_web'):
            add("act NOT IN ('block','blocked','deny')")
        else:
            return None
    if f.get('keyword'):
        text = {'traffic': 'src,dst,app,shost,isdb,scountry,dcountry,appcat', 'utm_app': 'src,dst,app,applist,dhost,url,appcat',
                'utm_web': 'src,dst,dhost,url,reqapp,profile', 'utm_ips': 'src,dst,attack,dhost,severity,profile',
                'utm_av': 'src,dst,virus,dhost,url,filename', 'utm_other': 'cat,src,dst,dhost,msg,ext',
                'event': 'cat,logdesc,usr,src,msg,ext'}[table].split(',')
        add('(' + ' OR '.join(f'{c} LIKE ?' for c in text) + ')', *[f"%{f['keyword']}%"] * len(text))
    return w, a


def _item_from_row(table, r):
    act = r.get('act') or ''
    if table == 'traffic':
        kind = 'traffic'
        verdict = 'blocked' if act in RAW_DROPS or r.get('utmact') == 'block' else 'allowed'
    elif table == 'utm_app':
        kind, verdict = 'app-ctrl', 'blocked' if act == 'block' else 'allowed'
    elif table == 'utm_web':
        kind = 'webfilter'
        verdict = 'blocked' if act in ('blocked', 'block', 'deny') else 'warning' if r.get('evtype') == 'ftgd_err' else 'allowed'
    elif table in ('utm_ips', 'utm_av'):
        kind, verdict = ('ips' if table == 'utm_ips' else 'av'), 'threat'
    elif table == 'utm_other':
        kind, verdict = (r.get('cat') or 'utm').replace('utm:', ''), 'warning'
    else:
        kind = (r.get('cat') or 'event').replace('event:', '')
        verdict = 'warning' if act in ('failure', 'negotiate_error', 'esp_error', 'failed') else 'info'
    pid = r.get('policyid')
    app = r.get('app') or r.get('attack') or r.get('virus') or r.get('logdesc') or r.get('evtype')
    return {'ref': mkref(r['fid'], r['off'], r['ts']), 'ts': r['ts'], 'table': table, 'kind': kind, 'verdict': verdict,
            'src': r.get('src'), 'spt': r.get('spt'), 'dst': r.get('dst'), 'dpt': r.get('dpt'), 'tdst': r.get('tdst'),
            'proto': r.get('proto'), 'app': app, 'domain': r.get('dhost'), 'policyid': pid, 'policy': polname(pid),
            'act': act or r.get('utmact'), 'utmact': r.get('utmact'), 'sess': r.get('sess'),
            'country': r.get('scountry') or r.get('dcountry'), 'dir': r.get('dir'), 'inif': r.get('inif'),
            'outif': r.get('outif'), 'bytes': (r.get('sent') or 0) + (r.get('rcvd') or 0) if 'sent' in r else None,
            'severity': r.get('severity'), 'user': r.get('usr'), 'sources': [table]}


def _noise_items(f, frm, to, limit=300):
    """Scanner denies are not stored as rows: find them in the raw syslog, guided by the hourly aggregates."""
    needle, windows, scanned = None, [], 0
    if f.get('src') or f.get('ip'):
        ip = f.get('src') or f.get('ip')
        needle = kv_needles('src', ip)
        hours = q("""SELECT b, sum(n) AS n FROM r_deny_src_1h WHERE src = ? AND b >= ? AND b < ? GROUP BY b
                     ORDER BY b DESC LIMIT 3""", (ip, floor(frm, H1), to))
        windows = [(max(frm, h['b']), min(to, h['b'] + H1)) for h in hours]
    elif f.get('dst'):
        needle = kv_needles('dst', f['dst'])
        windows = [(max(frm, to - 20 * 60_000), to)]
    elif f.get('dpt'):
        needle = kv_needles('dpt', int(f['dpt']))
        windows = [(max(frm, to - 10 * 60_000), to)]
    if not needle:
        return [], 0
    out = []
    for t0, t1 in windows:
        if Budget.left() is not None and Budget.left() <= 0.5:
            break
        for fid in files_for(t0, t1):
            for off, line in raw_find(fid, t0, t1, needle, limit=limit * 4, max_bytes=300 * 2**20):
                if not any(p.decode() in line for p in DENY_PATS):
                    continue
                d = parse(line)
                if not d:
                    continue
                cat = d.get('cat', '')
                if not (cat == 'traffic:local' or d.get('FTNTFGTsrcintfrole') == 'wan') or 'FTNTFGTutmaction' in d:
                    continue                        # rows the DB already has
                tsn = ts_ns(d, 0)
                ts = tsn // 1_000_000
                if ts < t0 or ts >= t1 or not _raw_match(d, f):
                    continue
                pid = pkey(d)
                out.append({'ref': mkref(fid, off, ts), 'ts': ts, 'table': 'raw-deny', 'kind': 'traffic', 'verdict': 'blocked',
                            'src': d.get('src'), 'spt': to_int(d.get('spt')), 'dst': d.get('dst'), 'dpt': to_int(d.get('dpt')),
                            'tdst': d.get('destinationTranslatedAddress'), 'proto': to_int(d.get('proto')),
                            'app': d.get('FTNTFGTapp') or d.get('app'), 'domain': None, 'policyid': pid, 'policy': polname(pid),
                            'act': 'deny', 'sess': to_int(d.get('externalId')), 'country': d.get('FTNTFGTsrccountry'),
                            'dir': 'local' if cat == 'traffic:local' else 'in', 'inif': d.get('deviceInboundInterface'),
                            'outif': d.get('deviceOutboundInterface'), 'bytes': 0, 'sources': ['raw syslog']})
                if len(out) >= limit:
                    return out, scanned
    return out, scanned


def _raw_match(d, f):
    for k, fld in (('src', 'src'), ('dst', 'dst'), ('spt', 'spt'), ('dpt', 'dpt')):
        if f.get(k) and d.get(fld) != str(f[k]):
            return False
    if f.get('ip') and f['ip'] not in (d.get('src'), d.get('dst'), d.get('destinationTranslatedAddress')):
        return False
    if f.get('country') and d.get('FTNTFGTsrccountry') != f['country']:
        return False
    if f.get('iface') and f['iface'] not in (d.get('deviceInboundInterface'), d.get('deviceOutboundInterface')):
        return False
    if f.get('proto') and d.get('proto') != str({'tcp': 6, 'udp': 17, 'icmp': 1}.get(f['proto'].lower(), f['proto'])):
        return False
    if f.get('policy_ids') is not None and pkey(d) not in f['policy_ids']:
        return False
    return True


def _windows(frm, to):
    """Newest-first slices of [frm, to): 1 h, 5 h, 18 h, then one day at a time."""
    edges = [to]
    for step in (H1, 5 * H1, 18 * H1):
        edges.append(edges[-1] - step)
    while edges[-1] > frm:
        edges.append(edges[-1] - DAY)
    edges = [max(frm, e) for e in edges]
    return [(edges[i + 1], edges[i]) for i in range(len(edges) - 1) if edges[i + 1] < edges[i]]


GUIDE_KEYS = {'dpt', 'proto', 'country', 'policy', 'policyname', 'policy_ids', 'action', 'app'}
DROP_IN = "('deny','block','blocked','dropped','reset','utm-block')"
M5 = 300_000


def _guide(f, frm, to):
    """For filters the 5-minute summary table can answer (port, protocol, country, policy, action, application),
    return the 5-minute buckets that contain matching traffic sessions, newest first: [(bucket_ms, n)].
    The traffic table (~120k rows/hour) is then read only inside those buckets. None = not applicable."""
    keys = {k for k, v in f.items() if v not in (None, '')}
    if not keys or not keys <= GUIDE_KEYS or not keys & {'dpt', 'proto', 'country', 'policy_ids', 'app'}:
        return None
    w, a = ['b >= ?', 'b < ?'], [floor(frm, M5), to]
    if f.get('dpt'):
        w.append('dpt = ?'); a.append(int(f['dpt']))
    if f.get('proto'):
        w.append('proto = ?'); a.append({'tcp': 6, 'udp': 17, 'icmp': 1}.get(str(f['proto']).lower(), to_int(f['proto'])))
    if f.get('country'):
        w.append('country = ?'); a.append(f['country'])
    if f.get('policy_ids') is not None:
        if not f['policy_ids']:
            return []
        w.append(f"policyid IN ({','.join('?' * len(f['policy_ids']))})"); a += f['policy_ids']
    if f.get('app'):
        w.append("(app = ? OR app LIKE ? ESCAPE '\\')"); a += [f['app'], f['app'].replace('_', '\\_') + '\\_%']
    if f.get('action') == 'blocked':
        w.append(f'act IN {DROP_IN}')
    elif f.get('action') == 'allowed':
        w.append(f'act NOT IN {DROP_IN}')
    try:
        return [(r['b'], r['n']) for r in q(f"SELECT b, sum(n) AS n FROM r_pol_5m WHERE {' AND '.join(w)} GROUP BY b ORDER BY b DESC", a)]
    except sqlite3.OperationalError:
        return None


def _guided_windows(buckets, frm, to, max_span=6 * H1):
    """Merge adjacent 5-minute buckets (newest first) into query windows."""
    out = []
    for b, _ in buckets:
        lo, hi = max(frm, b), min(to, b + M5)
        if out and out[-1][0] == hi and out[-1][1] - lo <= max_span:
            out[-1] = (lo, out[-1][1])
        else:
            out.append((lo, hi))
    return out


def search(text, frm, to, extra=None, limit=1500):
    Budget.set(SEARCH_BUDGET_S)
    try:
        return _search(text, frm, to, extra, limit)
    finally:
        Budget.clear()


def _search(text, frm, to, extra=None, limit=1500):
    t_start = time.time()
    f = parse_query(text, extra)
    notes = []
    range_frm = frm
    if f.get('policy'):
        p = f['policy']
        f['policy_ids'] = [int(p)] if str(p).isdigit() else \
            [r['policyid'] for r in q('SELECT policyid FROM policy WHERE name LIKE ?', (f'%{p}%',))]
    elif f.get('policyname'):
        f['policy_ids'] = [r['policyid'] for r in q('SELECT policyid FROM policy WHERE name LIKE ?', (f"%{f['policyname']}%",))]
    ids = None
    if f.get('user') or f.get('device') or f.get('mac'):
        found, how = _ips_for(f)
        notes += how
        ids = sorted(found)
        if not ids:
            notes.append('no IPs found for that identity in FortiGate data (user identity is only logged for VPN sessions)')
    if f.get('reqid'):
        notes.append('request IDs (UTM incident serial numbers) are matched in the raw syslog of the last hour only')
    # How each table is read, so that any range up to 30 days stays bounded in CPU and memory:
    #  - IP / session / policy lookups use their indexes over the whole range at once;
    #  - traffic filtered by port / protocol / country / policy / action / app is read only inside the 5-minute slices
    #    that the summary table says contain matches;
    #  - anything else walks back from the newest data in growing slices until PER_TABLE matches or the time budget.
    # Small tables go first and get at most 3 s each, so the big traffic table cannot starve them.
    only_raw = bool(f.get('reqid'))
    single = any(f.get(k) for k in ('src', 'dst', 'ip', 'sess')) or bool(f.get('policy_ids'))
    guide = None if only_raw or any(f.get(k) for k in ('src', 'dst', 'ip', 'sess')) else _guide(f, frm, to)
    progressive = _windows(frm, to)
    items, counts, cov, stops = [], {}, {}, set()
    overall_end = time.time() + (Budget.left() or SEARCH_BUDGET_S)
    order = () if only_raw else ('utm_ips', 'utm_av', 'utm_other', 'event', 'utm_web', 'utm_app', 'traffic')
    for i, table in enumerate(order):
        share = max(3.0, (overall_end - time.time()) / (len(order) - i))      # unused time flows to later tables
        table_end = overall_end if table == 'traffic' else min(overall_end, time.time() + share)
        wins = _guided_windows(guide, frm, to) if table == 'traffic' and guide is not None else \
            [(frm, to)] if single else progressive
        got, cov_t, applicable = 0, to, True
        for w0, w1 in wins:
            if time.time() >= table_end:
                stops.add('time')
                break
            wa = _where(table, f, w0, w1, ids)
            if wa is None:
                applicable = False
                break
            w, a = wa
            Budget.set(table_end - time.time())
            try:
                rows = q(f"SELECT {TABLE_COLS[table]} FROM {table} WHERE {' AND '.join(w)} ORDER BY ts DESC LIMIT ?",
                         (*a, PER_TABLE - got))
            except sqlite3.OperationalError as e:
                if 'interrupt' not in str(e):
                    raise
                stops.add('time')
                break
            got += len(rows)
            items += [_item_from_row(table, r) for r in rows]
            cov_t = w0
            if got >= PER_TABLE:
                stops.add('enough')
                break
        else:
            cov_t = frm
        if not applicable:
            continue
        cov[table] = cov_t
        counts[table] = got
    Budget.set(max(0.0, overall_end - time.time()))
    searched_from = max(cov.values()) if cov else frm
    if guide is not None:
        total = sum(n for _, n in guide)
        notes.append(f"5-minute summaries: {total:,} matching traffic sessions in {len(guide):,} time slices of the range"
                     + (' - traffic rows were read only inside those slices' if guide else ''))
    if searched_from > range_frm:
        span_h = (to - searched_from) / H1
        why = 'Time limit reached' if 'time' in stops else 'Enough matches found'
        notes.append(f"{why} after searching the newest {span_h:,.0f} h of the range - showing the most recent results. "
                     "Use 'Search older' to continue.")
    noise_ok = f.get('action') != 'allowed' and not any(f.get(k) for k in ('domain', 'app', 'threat', 'sess', 'user', 'device',
                                                                            'mac', 'category', 'vpn', 'keyword', 'reqid'))
    if noise_ok and (Budget.left() or 0) > 1:
        raw_items, _ = _noise_items(f, max(frm, searched_from), to)
        counts['raw syslog (scanner denies)'] = len(raw_items)
        items += raw_items
    if f.get('dpt') and noise_ok and not any(f.get(k) for k in ('src', 'dst', 'ip')) and (Budget.left() or 0) > 0.5:
        long_range = to - frm > 3 * DAY
        try:
            r = q(f"SELECT sum(n) AS n, max(srcs) AS srcs FROM {'r_deny_port_1d' if long_range else 'r_deny_port_1h'} "
                  "WHERE b >= ? AND b < ? AND dpt = ?", (floor(frm, DAY if long_range else H1), to, int(f['dpt'])), one=True)
            if r.get('n'):
                notes.append(f"Scanner denies to port {int(f['dpt'])} in the range: {r['n']:,} (kept as totals, not per request"
                             f"{'; all countries' if f.get('country') else ''}) - up to {r['srcs']:,} different sources "
                             f"per {'day' if long_range else 'hour'}")
        except sqlite3.OperationalError:
            pass
    if f.get('reqid'):
        needle = kv_needles('FTNTFGTincidentserialno', int(f['reqid']))
        for fid in files_for(to - H1, to):
            for off, line in raw_find(fid, max(frm, to - H1), to, needle, limit=20):
                d = parse(line) or {}
                r = record(fid, off, ts_ns(d, 0) // 1_000_000, d=d, line=line)
                items.append({'ref': r['ref'], 'ts': r['ts'], 'table': 'raw', 'kind': r['kind'], 'verdict': r['verdict'],
                              'src': d.get('src'), 'dst': d.get('dst'), 'dpt': to_int(d.get('dpt')), 'spt': to_int(d.get('spt')),
                              'proto': to_int(d.get('proto')), 'app': d.get('FTNTFGTapp') or d.get('app'), 'domain': d.get('dhost'),
                              'policyid': pkey(d), 'policy': polname(pkey(d)), 'act': d.get('act'), 'sess': to_int(d.get('externalId')),
                              'country': d.get('FTNTFGTsrccountry'), 'sources': ['raw syslog']})
        counts['raw syslog (request id)'] = len(items)
    merged = _merge_sessions(items)[:limit]
    agg = []
    ip = f.get('src') or f.get('ip')
    if ip:
        agg = q("""SELECT policyid, inif, country, sum(n) AS n, max(ports) AS ports, max(psample) AS psample, min(b) AS first,
                   max(b) AS last FROM r_deny_src_1h WHERE src = ? AND b >= ? AND b < ? GROUP BY 1, 2, 3""",
                (ip, floor(frm, H1), to)) or \
            q("""SELECT policyid, inif, country, sum(n) AS n, max(ports) AS ports, max(psample) AS psample, min(b) AS first,
                 max(b) AS last FROM r_deny_src_1d WHERE src = ? AND b >= ? AND b < ? GROUP BY 1, 2, 3""",
              (ip, floor(frm, DAY), to))
        for r in agg:
            r['policy'] = polname(r['policyid'])
    return {'filters': {k: v for k, v in f.items() if k != 'policy_ids'}, 'notes': notes, 'counts': counts,
            'items': merged, 'total': len(merged), 'truncated': len(merged) >= limit, 'deny_aggregates': agg,
            'searched': {'frm': searched_from, 'to': to, 'range_frm': range_frm, 'complete': searched_from <= range_frm},
            'took_ms': int((time.time() - t_start) * 1000)}


def _merge_sessions(items):
    """One result per session: records sharing session id + src + dst are merged (worst verdict wins)."""
    groups, out = {}, []
    for it in sorted(items, key=lambda x: -x['ts']):
        k = (it['sess'], it['src'], it['dst']) if it.get('sess') else None
        if k and k in groups:
            g = groups[k]
            g['records'] += 1
            g['sources'] = sorted(set(g['sources']) | set(it['sources']))
            if VERDICT_RANK[it['verdict']] < VERDICT_RANK[g['verdict']]:
                keep = {x: g[x] for x in ('records', 'sources')}
                g.update(it); g.update(keep)
            for fld in ('domain', 'app', 'tdst', 'inif', 'outif', 'bytes', 'country'):
                if not g.get(fld) and it.get(fld):
                    g[fld] = it[fld]
            continue
        g = dict(it, records=1)
        if k:
            groups[k] = g
        out.append(g)
    return out


# ---------------------------------------------------------------- correlation
MATCH_LEVELS = [
    (100, 'Exact match', 'session ID + source IP + destination IP'),
    (95, 'Strong correlation', '5-tuple (source:port → destination:port, protocol) within ±2 min'),
    (78, 'Probable correlation', 'source IP + destination IP + destination port within ±60 s'),
    (52, 'Weak correlation', 'source IP + destination IP within ±2 min'),
]


def _match(seed, d, dt_ms):
    s, x = seed['fields'], d
    same = lambda k: s.get(k) is not None and s.get(k) == x.get(k)
    dst_same = same('dst') or (s.get('destinationTranslatedAddress') and
                                s.get('destinationTranslatedAddress') in (x.get('dst'), x.get('destinationTranslatedAddress')))
    if same('externalId') and same('src') and dst_same:
        return MATCH_LEVELS[0]
    if same('src') and same('spt') and dst_same and same('dpt') and abs(dt_ms) <= 120_000:
        return MATCH_LEVELS[1]
    if same('src') and dst_same and same('dpt') and abs(dt_ms) <= 60_000:
        return MATCH_LEVELS[2]
    if same('src') and dst_same and abs(dt_ms) <= 120_000:
        return MATCH_LEVELS[3]
    return None


def correlate(seed):
    s = seed['fields']
    src, sess, ts = s.get('src'), to_int(s.get('externalId')), seed['ts']
    got = {seed['ref']: seed}
    context = []
    # 1. exact: same session id in the DB tables (sessions can be logged hours apart, e.g. long IMAPS sessions)
    if sess is not None and src:
        for t in ('traffic', 'utm_app', 'utm_web', 'utm_ips', 'utm_av'):
            for r in q(f'SELECT ts, fid, off FROM {t} WHERE sess = ? AND src = ? AND ts BETWEEN ? AND ? LIMIT 40',
                       (sess, src, ts - DAY, ts + DAY)):
                ref = mkref(r['fid'], r['off'], r['ts'])
                if ref not in got:
                    rec = record(r['fid'], r['off'], r['ts'])
                    m = _match(seed, rec['fields'], rec['ts'] - ts)
                    if m:
                        rec.update(confidence=m[0], method=f'{m[1]}: {m[2]}')
                        got[ref] = rec
    # 2. raw syslog window around the event: finds every record incl. those not stored in the DB
    raw_scanned = False
    if src:
        needle = kv_needles('src', src)
        for fid in files_for(ts - 120_000, ts + 120_000):
            raw_scanned = True
            for off, line in raw_find(fid, ts - 120_000, ts + 120_000, needle, limit=3000, max_bytes=300 * 2**20):
                d = parse(line)
                if not d:
                    continue
                tsn = ts_ns(d, 0)
                t = tsn // 1_000_000
                ref = mkref(fid, off, t)
                if ref in got:
                    continue
                m = _match(seed, d, t - ts)
                if m:
                    rec = record(fid, off, t, d=d, line=line, conf_=m[0], method=f'{m[1]}: {m[2]}')
                    got[ref] = rec
                elif abs(t - ts) <= 120_000 and len(context) < 400:
                    context.append((abs(t - ts), fid, off, t, d, line))
    recs = sorted(got.values(), key=lambda r: int(r['ts_ns']))
    context.sort(key=lambda x: x[0])
    ctx = [record(fid, off, t, d=d, line=line, conf_=0, method='context: same source, different destination/session')
           for _, fid, off, t, d, line in context[:40]]
    return recs[:80], sorted(ctx, key=lambda r: int(r['ts_ns'])), raw_scanned


# ---------------------------------------------------------------- investigation
def _iface(name):
    c = conf().get('interfaces', {})
    return c.get(name) or {}


def _gateway(src, inif):
    """The FortiGate interface is the gateway only if src is inside a documented connected subnet of it."""
    i = _iface(inif)
    try:
        ip = ipaddress.ip_address(src)
    except (ValueError, TypeError):
        return None
    nets = ([i['ip']] if i.get('ip') else []) + i.get('secondary_subnets', [])
    for n in nets:
        net = ipaddress.ip_interface(n).network
        if ip in net:
            return {'subnet': str(net), 'gateway_ip': i['ip'].split('/')[0] if n == i.get('ip') else None}
    return None


def _vpn_user(ip, ts):
    r = q("""SELECT ts, usr, ext FROM event WHERE cat = 'event:vpn' AND ext LIKE ? AND ts BETWEEN ? AND ?
             ORDER BY ts DESC LIMIT 1""", (f'%FTNTFGTassignip={ip} %', ts - 7 * DAY, ts + DAY), one=True)
    if not r:
        return None
    e = _ext_dict(r['ext'])
    return {'user': r['usr'] or e.get('duser'), 'group': e.get('FTNTFGTgroup'), 'tunnel': e.get('FTNTFGTvpntunnel'),
            'remote_ip': e.get('src') or e.get('FTNTFGTremip'), 'ts': r['ts']}


def _first(recs, kind=None, key=None, verdict=None):
    for r in recs:
        if (kind is None or r['kind'] == kind) and (verdict is None or r['verdict'] == verdict) and \
                (key is None or r['fields'].get(key)):
            return r
    return None


def _val(*vals):
    for v in vals:
        if v not in (None, '', 'N/A'):
            return v
    return None


def investigate(ref):
    seed = raw_event(ref)
    if not seed['fields']:
        raise ValueError('event not found (log file rotated away?)')
    recs, ctx, raw_scanned = correlate(seed)
    s = seed['fields']
    corr = [r for r in recs if r['confidence'] >= 52]
    by = defaultdict(list)
    for r in corr:
        by[r['kind']].append(r)
    T = _first(corr, 'traffic')
    A = _first(by['app-ctrl'], verdict='blocked') or _first(by['app-ctrl'])
    W = _first(by['webfilter'], verdict='blocked') or _first(by['webfilter'])
    I = _first(by['ips'])
    V = _first(by['av'])
    SS = _first(by['ssl'])
    F = lambda k: _val(*(r['fields'].get(k) for r in [seed] + corr))   # first non-empty value across correlated records
    src, dst = s.get('src'), s.get('dst')
    tdst = F('destinationTranslatedAddress')
    pid = pkey(s) if pkey(s) is not None else (pkey(T['fields']) if T else None)
    pol = policies().get(pid) or {}
    cat = s.get('cat', '')
    local_in = cat == 'traffic:local' or s.get('deviceOutboundInterface') == 'root'
    inif, outif = F('deviceInboundInterface'), F('deviceOutboundInterface')
    wan_src = F('FTNTFGTsrcintfrole') == 'wan'
    host = q('SELECT * FROM host WHERE ip = ?', (src,), one=True) if src else {}
    dhost_host = q('SELECT * FROM host WHERE ip = ?', (tdst or dst,), one=True) if (tdst or dst) else {}
    vpn = _vpn_user(src, seed['ts']) if src and not wan_src else None
    user = _val(*(F(k) for k in USER_FIELDS)) or (vpn or {}).get('user')
    domain = _val(F('dhost'), F('FTNTFGTsni'), F('FTNTFGTscertcname'))
    status = min((r['verdict'] for r in corr), key=lambda v: VERDICT_RANK[v]) if corr else seed['verdict']
    blocked = status in ('blocked', 'threat') and any(r['verdict'] == 'blocked' or
                                                     r['fields'].get('act') in RAW_DROPS for r in corr)
    fw = conf().get('firewall', {})
    decision, reason, explain = _decision(seed, corr, T, A, W, I, V, SS, pid, pol, local_in, wan_src, inif, outif, tdst, domain)
    path = _path(seed, corr, T, A, W, I, V, SS, pid, pol, local_in, wan_src, inif, outif, tdst, domain, host, dhost_host,
                 user, vpn, decision, fw)
    t_ns = sorted(int(r['ts_ns']) for r in corr) or [int(seed['ts_ns'])]
    dur_s = to_int(F('FTNTFGTduration'))
    timeline = _timeline(corr, ctx, T)
    graph = _graph(seed, corr, user, host, src, dst, tdst, domain, pid, inif, outif, A, W, I, status, fw)
    related = q("""SELECT count(DISTINCT policyid) AS policies, sum(n) AS n FROM r_src_1h WHERE src = ? AND b >= ? AND b < ?""",
                (src, floor(seed['ts'], H1) - H1, floor(seed['ts'], H1) + 2 * H1), one=True) if src else {}
    sev = _severity(status, corr, wan_src, blocked, A, W, I)
    confs = [r['confidence'] for r in corr if r['ref'] != seed['ref']]
    header = {
        'id': 'INV-%06d' % (int(hashlib.sha1(ref.encode()).hexdigest()[:8], 16) % 1_000_000),
        'status': 'BLOCKED' if blocked else 'THREAT' if status == 'threat' else 'WARNING' if status == 'warning' else
        'INFO' if status == 'info' else 'ALLOWED',
        'severity': sev, 'start_ns': str(t_ns[0]), 'duration_ms': round((t_ns[-1] - t_ns[0]) / 1e6, 3),
        'session_duration_s': dur_s, 'events': len(corr) + len(ctx), 'correlated': len(corr) - 1,
        'entities': len(graph['nodes']), 'confidence': round(sum(confs) / len(confs)) if confs else 100,
        'raw_window_scanned': raw_scanned,
    }
    summary = {
        'status': header['status'], 'source': src, 'source_port': to_int(s.get('spt')), 'user': user,
        'device': _val(host.get('name') if host else None, F('FTNTFGTsrcname'), F('shost')),
        'destination': domain or dst, 'destination_ip': dst, 'translated_ip': tdst,
        'port': to_int(s.get('dpt')), 'protocol': PROTO.get(to_int(s.get('proto')), s.get('proto')),
        'application': _val(A and A['fields'].get('FTNTFGTapp'), F('FTNTFGTapp'), F('app')),
        'action': (s.get('act') or '').upper(), 'firewall': fw.get('name') or 'FortiGate',
        'policy': polname(pid), 'policy_id': pid, 'reason': reason, 'ts_ns': seed['ts_ns'],
        'src_country': F('FTNTFGTsrccountry'), 'dst_country': F('FTNTFGTdstcountry'), 'direction':
            'local-in (to the FortiGate)' if local_in else 'inbound (WAN → LAN)' if wan_src else
            'outbound (LAN → WAN)' if F('FTNTFGTdstintfrole') == 'wan' else 'internal',
    }
    return {'ref': ref, 'header': header, 'summary': summary, 'path': path, 'decision': decision, 'explanation': explain,
            'request': _request(seed, corr, F, host, user, vpn, domain, tdst), 'timeline': timeline, 'records': corr,
            'context': ctx, 'graph': graph, 'related': related, 'correlation': _corr_summary(corr, raw_scanned),
            'compare': _compare_candidates(seed, status)}


def _severity(status, corr, wan_src, blocked, A, W, I):
    if I:
        s = (I['fields'].get('FTNTFGTseverity') or '').lower()
        return 'critical' if s == 'critical' else 'high' if s == 'high' else 'medium'
    if blocked and (A or W or any(r['fields'].get('FTNTFGTutmaction') == 'block' for r in corr)):
        return 'high'
    if blocked:
        return 'low' if wan_src else 'medium'
    return 'medium' if status == 'warning' else 'info'


def _decision(seed, corr, T, A, W, I, V, SS, pid, pol, local_in, wan_src, inif, outif, tdst, domain):
    s = seed['fields']
    nodes = []

    def node(lbl, detail, status, rec=None, fields=None):
        nodes.append({'id': len(nodes), 'label': lbl, 'detail': detail, 'status': status,
                      'ref': rec['ref'] if rec else seed['ref'], 'fields': fields or {}})
    src, dst, dpt = s.get('src'), s.get('dst'), s.get('dpt')
    proto = PROTO.get(to_int(s.get('proto')), s.get('proto'))
    i_in, i_out = _iface(inif), _iface(outif)
    node('Traffic received', f"{src}:{s.get('spt') or '?'} → {dst}:{dpt or '?'}/{proto} on {inif or '?'}"
         f"{' (' + i_in['alias'] + ')' if i_in.get('alias') else ''}", 'info', seed,
         {'Source IP': src, 'Source port': s.get('spt'), 'Destination IP': dst, 'Destination port': dpt, 'Protocol': proto,
          'Ingress interface': inif, 'Interface role': s.get('FTNTFGTsrcintfrole'), 'Source country': s.get('FTNTFGTsrccountry'),
          'Client reputation': _val(s.get('FTNTFGTcrlevel') and f"{s.get('FTNTFGTcrlevel')} (score {s.get('FTNTFGTcrscore')})")})
    if tdst and s.get('FTNTFGTtrandisp') in ('dnat', 'snat+dnat'):
        node('Destination NAT (VIP)', f"{dst}:{dpt} → {tdst}:{s.get('destinationTranslatedPort') or dpt}", 'info', seed,
             {'Public destination': dst, 'Translated destination': tdst, 'Translated port': s.get('destinationTranslatedPort'),
              'NAT disposition': s.get('FTNTFGTtrandisp')})
    raw_pid = pid % 100000 if pid is not None else None
    final_rec, final, reason = seed, 'ALLOWED', None
    act = s.get('act')
    if local_in:
        node('Destination is the FortiGate itself', f"local-in traffic to {dst}:{dpt}/{proto}", 'info', seed,
             {'Destination': dst, 'Service': f'{dpt}/{proto}', 'Policy type': s.get('FTNTFGTpolicytype')})
        if act == 'deny':
            if raw_pid == 0:
                node('No local-in policy allows this service', 'implicit local-in deny (policy 0)', 'blocked', seed,
                     {'Policy ID': '0 (implicit)', 'Policy type': s.get('FTNTFGTpolicytype'), 'Action': 'deny'})
                reason = f'No local-in policy allows {dpt}/{proto} to the FortiGate (implicit local-in deny)'
            else:
                node(f'Local-in policy {raw_pid} matched', 'action: deny', 'blocked', seed, {'Policy ID': raw_pid, 'Action': 'deny'})
                reason = f'Local-in policy {raw_pid} denies {dpt}/{proto}'
            final = 'BLOCKED'
        else:
            node(f'Local-in policy {raw_pid} permits it', f'action: {act}', 'allowed', seed, {'Policy ID': raw_pid, 'Action': act})
    elif pid == 0 or (raw_pid == 0 and act == 'deny'):
        node('Firewall policy lookup', f"{inif} → {outif}: no policy matches this source / destination / service", 'blocked', seed,
             {'Ingress interface': inif, 'Egress interface': outif, 'Source': src, 'Destination': tdst or dst,
              'Service': f'{dpt}/{proto}', 'Rule/order': None, 'Matching policy': 'none'})
        node('Implicit deny (policy 0)', 'FortiGate drops traffic that no policy accepts', 'blocked', seed,
             {'Policy ID': 0, 'Policy name': 'implicit deny', 'Action': 'deny'})
        reason, final = f'No firewall policy matched {inif} → {outif} for {dpt}/{proto} (implicit deny, policy 0)', 'BLOCKED'
    else:
        pr = T or seed
        pact = pr['fields'].get('act')
        explicit_deny = pact == 'deny' and pr['fields'].get('FTNTFGTutmaction') != 'block'
        node(f"Policy {polname(pid)} matched", f"{inif} → {outif} · type {s.get('FTNTFGTpolicytype') or 'policy'}"
             f" · action {'DENY' if explicit_deny else 'ACCEPT'}", 'blocked' if explicit_deny else 'allowed', pr,
             {'Policy ID': raw_pid, 'Policy name': pol.get('name'), 'Policy UUID': s.get('FTNTFGTpoluuid') or pol.get('uuid'),
              'Rule/order': None, 'Matching criteria': f"srcintf {inif}, dstintf {outif}, source {s.get('src')}, "
                                                        f"destination {tdst or dst}, service {dpt}/{proto}",
              'Sensors seen on this policy': pol.get('applists'), 'Policy action': 'deny' if explicit_deny else 'accept'})
        if explicit_deny:
            reason, final = f"Firewall policy {polname(pid)} action is DENY", 'BLOCKED'
        for rec, name in ((SS, 'SSL inspection'), (A, 'Application Control'), (W, 'Web Filter'), (I, 'IPS'), (V, 'Antivirus')):
            if not rec:
                continue
            d, st = rec['fields'], rec['verdict']
            if name == 'Application Control':
                detail = (f"sensor {d.get('FTNTFGTapplist')} → {d.get('FTNTFGTapp') or d.get('app')} (id {d.get('FTNTFGTappid')}, "
                          f"{d.get('FTNTFGTappcat')}, risk {d.get('FTNTFGTapprisk')}) → {d.get('act')}")
                flds = {'Security profile': d.get('FTNTFGTapplist'), 'Application': d.get('FTNTFGTapp'), 'App ID': d.get('FTNTFGTappid'),
                        'Service label': d.get('app'), 'Category': d.get('FTNTFGTappcat'), 'Risk': d.get('FTNTFGTapprisk'),
                        'Match type': d.get('FTNTFGTeventtype'), 'Profile action': d.get('act'), 'Message': d.get('msg'),
                        'Incident serial (request ID)': d.get('FTNTFGTincidentserialno')}
                if st == 'blocked':
                    reason = (f"Application Control sensor '{d.get('FTNTFGTapplist')}' blocked {d.get('FTNTFGTapp') or d.get('app')}"
                              f" ({d.get('FTNTFGTeventtype')}) on policy {polname(pid)}")
            elif name == 'Web Filter':
                detail = f"profile {d.get('FTNTFGTprofile')} → {d.get('dhost')} ({d.get('FTNTFGTeventtype')}) → {d.get('act')}"
                flds = {'Security profile': d.get('FTNTFGTprofile'), 'Host': d.get('dhost'), 'URL': d.get('request'),
                        'Category': _val(d.get('FTNTFGTcatdesc'), d.get('FTNTFGTcat')), 'URL filter list': d.get('FTNTFGTurlfilterlist'),
                        'Event type': d.get('FTNTFGTeventtype'), 'Profile action': d.get('act'), 'Message': d.get('msg'),
                        'HTTP method': d.get('FTNTFGThttpmethod'), 'Client application': d.get('requestClientApplication')}
                if st == 'blocked':
                    reason = f"Web Filter profile '{d.get('FTNTFGTprofile')}' blocked {d.get('dhost')}: {d.get('msg')}"
            elif name == 'IPS':
                detail = f"profile {d.get('FTNTFGTprofile')} → {d.get('FTNTFGTattack')} ({d.get('FTNTFGTseverity')}) → {d.get('act')}"
                flds = {'Security profile': d.get('FTNTFGTprofile'), 'Signature': d.get('FTNTFGTattack'),
                        'Signature ID': d.get('FTNTFGTattackid'), 'Severity': d.get('FTNTFGTseverity'),
                        'Reference': d.get('FTNTFGTref'), 'Profile action': d.get('act')}
                if d.get('act') in RAW_DROPS:
                    reason = f"IPS profile '{d.get('FTNTFGTprofile')}' {d.get('act')} {d.get('FTNTFGTattack')} ({d.get('FTNTFGTseverity')})"
            elif name == 'Antivirus':
                detail = f"{d.get('FTNTFGTvirus')} → {d.get('act')}"
                flds = {'Virus': d.get('FTNTFGTvirus'), 'File': d.get('fname'), 'Profile action': d.get('act')}
                if d.get('act') in RAW_DROPS:
                    reason = f"Antivirus blocked {d.get('FTNTFGTvirus')}"
            else:
                detail = f"{d.get('FTNTFGTeventtype')}: {d.get('msg')} → {d.get('act')}"
                flds = {'Profile': d.get('FTNTFGTprofile'), 'Event': d.get('FTNTFGTeventtype'), 'SNI': d.get('FTNTFGTsni'),
                        'TLS version': d.get('FTNTFGTtlsver'), 'Message': d.get('msg'), 'Action': d.get('act')}
            node(name, detail, 'blocked' if (st == 'blocked' or d.get('act') in RAW_DROPS) else
                 'threat' if st == 'threat' else 'warning' if st == 'warning' else 'allowed', rec, flds)
            if st == 'blocked' or d.get('act') in RAW_DROPS:
                final, final_rec = 'BLOCKED', rec
        if T and T['fields'].get('FTNTFGTutmaction') == 'block' and final != 'BLOCKED':
            node('Security profile verdict', 'traffic log reports utmaction=block, but the UTM log for this session was not '
                 'found in the correlated window', 'blocked', T, {'utmaction': 'block', 'Session end': T['fields'].get('act')})
            reason, final, final_rec = 'A security profile blocked the session (utmaction=block; profile log not found)', 'BLOCKED', T
        if final != 'BLOCKED' and T:
            ta = T['fields'].get('act')
            node('Session end', f"{ta} after {T['fields'].get('FTNTFGTduration') or 0}s · "
                 f"{T['fields'].get('out') or 0} B sent / {T['fields'].get('in') or 0} B received"
                 + (' (normal session end - not a drop)' if ta in ('close', 'client-rst', 'server-rst', 'timeout') else ''),
                 'allowed', T, {'Session end state': ta, 'Duration (s)': T['fields'].get('FTNTFGTduration'),
                                'Bytes sent': T['fields'].get('out'), 'Bytes received': T['fields'].get('in')})
    node('FINAL ACTION', '✕ BLOCKED' if final == 'BLOCKED' else '✓ ALLOWED', 'blocked' if final == 'BLOCKED' else 'allowed',
         final_rec, {'Final action': final, 'Reason': reason})
    return nodes, reason, _explain(seed, final, reason, pid, domain, tdst, T, A, W, I, local_in, wan_src)


def _explain(seed, final, reason, pid, domain, tdst, T, A, W, I, local_in, wan_src):
    s = seed['fields']
    who = f"{s.get('src')}" + (f" ({s.get('FTNTFGTsrccountry')})" if wan_src and s.get('FTNTFGTsrccountry') else '')
    where = (domain + f' ({s.get("dst")})') if domain else s.get('dst')
    proto = PROTO.get(to_int(s.get('proto')), s.get('proto'))
    base = f"Request from {who} to {where} on {s.get('dpt')}/{proto}"
    if tdst and tdst != s.get('dst'):
        base += f" (translated to {tdst})"
    if final == 'BLOCKED':
        txt = f"{base} was blocked by FortiGate {conf().get('firewall', {}).get('name') or 'FortiGate'}: {reason}."
    else:
        txt = f"{base} was allowed by policy {polname(pid)}."
        if T:
            txt += f" The session ended with '{T['fields'].get('act')}' after {T['fields'].get('FTNTFGTduration') or 0}s."
    if I:
        txt += f" IPS also recorded {I['fields'].get('FTNTFGTattack')} ({I['fields'].get('FTNTFGTseverity')})."
    return txt


PROFILE_FIELDS = {
    'app': [('Security profile (sensor)', 'FTNTFGTapplist'), ('Application', 'FTNTFGTapp'), ('Application ID', 'FTNTFGTappid'),
            ('Service label', 'app'), ('Category', 'FTNTFGTappcat'), ('Risk', 'FTNTFGTapprisk'), ('Match type', 'FTNTFGTeventtype'),
            ('Profile action', 'act'), ('Message', 'msg'), ('Host (SNI)', 'dhost'), ('Request ID (incident serial)', 'FTNTFGTincidentserialno')],
    'web': [('Security profile', 'FTNTFGTprofile'), ('Host', 'dhost'), ('URL', 'request'), ('Category', 'FTNTFGTcatdesc'),
            ('URL filter list', 'FTNTFGTurlfilterlist'), ('Event type', 'FTNTFGTeventtype'), ('Profile action', 'act'),
            ('Message', 'msg'), ('HTTP method', 'FTNTFGThttpmethod'), ('Client application', 'requestClientApplication')],
    'ips': [('Security profile', 'FTNTFGTprofile'), ('Signature', 'FTNTFGTattack'), ('Signature ID', 'FTNTFGTattackid'),
            ('Severity', 'FTNTFGTseverity'), ('Reference', 'FTNTFGTref'), ('Profile action', 'act'), ('Host', 'dhost'),
            ('Request ID (incident serial)', 'FTNTFGTincidentserialno')],
    'av': [('Security profile', 'FTNTFGTprofile'), ('Virus', 'FTNTFGTvirus'), ('File', 'fname'), ('Profile action', 'act')],
    'ssl': [('Security profile', 'FTNTFGTprofile'), ('Event', 'FTNTFGTeventtype'), ('SNI', 'FTNTFGTsni'), ('TLS version', 'FTNTFGTtlsver'),
            ('Message', 'msg'), ('Action', 'act')],
}


def _hop(hid, typ, title, status, lines, details, refs=(), trace=None, note=None):
    return {'id': hid, 'type': typ, 'title': title, 'status': status, 'lines': [l for l in lines if l],
            'details': details, 'refs': list(refs), 'trace': trace, 'note': note}


def _path(seed, corr, T, A, W, I, V, SS, pid, pol, local_in, wan_src, inif, outif, tdst, domain, host, dhost_host, user,
          vpn, decision, fw):
    s = seed['fields']
    F = lambda k: _val(*(r['fields'].get(k) for r in [seed] + corr))
    src, dst = s.get('src'), s.get('dst')
    hops = []
    unknown_note = 'Network path information unavailable from available FortiGate telemetry.'
    if wan_src:
        hops.append(_hop('source', 'SOURCE', 'Internet source', 'info', [src, F('FTNTFGTsrccountry'), F('FTNTFGTsrcinetsvc')],
                         [['Source IP', src], ['Source port', s.get('spt')], ['Country', F('FTNTFGTsrccountry')],
                          ['Internet service (ISDB)', F('FTNTFGTsrcinetsvc')], ['Client reputation level', F('FTNTFGTcrlevel')],
                          ['Client reputation score', F('FTNTFGTcrscore')], ['Username', user]],
                         [seed['ref']], {'type': 'ip', 'value': src}))
        hops.append(_hop('upstream', 'UNKNOWN HOP', 'Internet / upstream ISP', 'unknown', ['Unknown hop'], [], note=unknown_note))
    else:
        hops.append(_hop('user', 'USER', user or 'User unknown', 'info' if user else 'unavailable',
                         [user or 'Data unavailable', vpn and f"VPN {vpn.get('tunnel') or ''} group {vpn.get('group') or '?'}"],
                         [['Username', user], ['Source of identity', 'event:vpn assigned IP' if vpn else
                           ('log user field' if user else None)], ['VPN group', (vpn or {}).get('group')],
                          ['VPN tunnel', (vpn or {}).get('tunnel')], ['VPN remote IP', (vpn or {}).get('remote_ip')]],
                         [], {'type': 'user', 'value': user} if user else None,
                         None if user else 'FortiGate logged no user identity for this traffic (no FSSO/auth user on the policy).'))
        dev_name = _val(host.get('name') if host else None, F('FTNTFGTsrcname'), F('shost'))
        dev_avail = dev_name or F('FTNTFGTsrcmac') or (host or {}).get('mac')
        hops.append(_hop('device', 'DEVICE', dev_name or src, 'info' if dev_avail else 'unavailable',
                         [dev_name, src, _val(F('FTNTFGTosname'), (host or {}).get('os')), _val(F('FTNTFGTsrcmac'), (host or {}).get('mac'))],
                         [['Device name', dev_name], ['IP address', src], ['MAC address', _val(F('FTNTFGTsrcmac'), (host or {}).get('mac'))],
                          ['OS', _val(F('FTNTFGTosname'), (host or {}).get('os'))], ['Vendor', _val(F('FTNTFGTsrchwvendor'), (host or {}).get('vendor'))],
                          ['Device type', _val(F('FTNTFGTdevtype'), (host or {}).get('devtype'))], ['Source port', s.get('spt')]],
                         [seed['ref']], {'type': 'ip', 'value': src}))
        hops.append(_hop('switch', 'UNKNOWN HOP', 'Access switch', 'unknown', ['Unknown hop'], [], note=unknown_note))
        gw = _gateway(src, inif)
        if gw:
            hops.append(_hop('gateway', 'GATEWAY', f"{inif} {gw['gateway_ip'] or ''}".strip(), 'info',
                             [f"directly connected {gw['subnet']}", 'FortiGate is the L3 gateway'],
                             [['Connected subnet', gw['subnet']], ['Gateway IP', gw['gateway_ip']], ['Interface', inif],
                              ['Basis', 'interface subnet from the uploaded configuration or Settings + address match']], []))
        else:
            hops.append(_hop('gateway', 'UNKNOWN HOP', 'Router / gateway', 'unknown', ['Unknown hop'], [],
                             note=unknown_note + ' Source is not in a documented connected subnet of ' + str(inif) + '.'))
    i_in, i_out = _iface(inif), _iface(outif)
    hops.append(_hop('fortigate', 'FORTIGATE', fw.get('name') or 'FortiGate', 'info',
                     [f"in {inif} ({i_in.get('alias', '?')})", f"out {outif} ({i_out.get('alias', 'FortiGate' if local_in else '?')})",
                      f"VDOM {F('FTNTFGTvd')}"],
                     [['Firewall name', fw.get('name')], ['Model', fw.get('model')], ['Serial', F('deviceExternalId') or fw.get('serial')],
                      ['Firewall IP (ingress)', i_in.get('ip')], ['Ingress interface', inif], ['Ingress role', F('FTNTFGTsrcintfrole')],
                      ['Ingress alias', i_in.get('alias')], ['Egress interface', outif], ['Egress role', F('FTNTFGTdstintfrole')],
                      ['Egress alias', i_out.get('alias')], ['VDOM', F('FTNTFGTvd')], ['Session ID', F('externalId')],
                      ['NAT', F('FTNTFGTtrandisp')], ['Source NAT', _val(F('sourceTranslatedAddress') and
                       f"{F('sourceTranslatedAddress')}:{F('sourceTranslatedPort') or ''}")],
                      ['Destination NAT', _val(tdst and f"{tdst}:{F('destinationTranslatedPort') or ''}")],
                      ['Timestamp', seed['ts_ns']]], [seed['ref']]))
    pact = (T or seed)['fields'].get('act')
    blocked_at_policy = pid in (0, 100000) or (pact == 'deny' and (T or seed)['fields'].get('FTNTFGTutmaction') != 'block')
    hops.append(_hop('policy', 'POLICY', polname(pid) or 'no policy', 'blocked' if blocked_at_policy else 'allowed',
                     [pol.get('name') or ('implicit deny' if pid in (0, 100000) else None),
                      f"type {F('FTNTFGTpolicytype') or 'policy'}", 'action DENY' if blocked_at_policy else 'action ACCEPT'],
                     [['Policy ID', pid % 100000 if pid is not None else None], ['Policy name', pol.get('name')],
                      ['Policy type', F('FTNTFGTpolicytype')], ['Policy UUID', F('FTNTFGTpoluuid') or pol.get('uuid')],
                      ['Policy action', 'deny' if blocked_at_policy else 'accept'], ['Rule/order', None],
                      ['Address / service objects', None], ['Sensors seen on this policy', pol.get('applists')],
                      ['First seen', pol.get('first_ts')], ['Last seen', pol.get('last_ts')]],
                     [(T or seed)['ref']], {'type': 'policy', 'value': pid} if pid is not None else None,
                     'Rule order, address and service objects need the config export.' if pid not in (0, 100000) else None))
    for rec, name, key in ((SS, 'SSL INSPECTION', 'ssl'), (A, 'APPLICATION CONTROL', 'app'), (W, 'WEB FILTER', 'web'),
                           (I, 'IPS', 'ips'), (V, 'ANTIVIRUS', 'av')):
        if not rec:
            continue
        d = rec['fields']
        st = 'blocked' if (rec['verdict'] == 'blocked' or d.get('act') in RAW_DROPS) else rec['verdict']
        prof = d.get('FTNTFGTapplist') or d.get('FTNTFGTprofile')
        what = d.get('FTNTFGTapp') or d.get('dhost') or d.get('FTNTFGTattack') or d.get('FTNTFGTvirus') or d.get('msg')
        hops.append(_hop(key, 'SECURITY PROFILE', name.title(), st, [prof, what, f"→ {d.get('act')}"],
                         [[lbl, d.get(k)] for lbl, k in PROFILE_FIELDS[key]], [rec['ref']]))
    if T and T['fields'].get('FTNTFGTutmaction') == 'block' and not any(h['status'] == 'blocked' for h in hops[-5:]):
        hops.append(_hop('utm', 'SECURITY PROFILE', 'Security profile (unidentified)', 'blocked',
                         ['utmaction=block', 'profile log not in correlated window'], [['utmaction', 'block']], [T['ref']]))
    if F('sourceTranslatedAddress') or (tdst and tdst != dst):
        hops.append(_hop('nat', 'NAT', 'Address translation', 'info',
                         [F('sourceTranslatedAddress') and f"SNAT → {F('sourceTranslatedAddress')}",
                          tdst and f"DNAT {dst} → {tdst}"],
                         [['NAT disposition', F('FTNTFGTtrandisp')], ['Source NAT IP', F('sourceTranslatedAddress')],
                          ['Source NAT port', F('sourceTranslatedPort')], ['Destination NAT IP', tdst],
                          ['Destination NAT port', F('destinationTranslatedPort')], ['Central NAT ID', F('FTNTFGTcentralnatid')]],
                         [seed['ref']]))
    if not local_in:
        hops.append(_hop('egress', 'EGRESS', f"{outif} ({i_out.get('alias', '?')})", 'info', [f"role {F('FTNTFGTdstintfrole')}"],
                         [['Egress interface', outif], ['Alias', i_out.get('alias')], ['Role', F('FTNTFGTdstintfrole')],
                          ['Interface IP', i_out.get('ip')]], [seed['ref']]))
    dest_ip = tdst or dst
    dname = _val(domain, (dhost_host or {}).get('name'))
    hops.append(_hop('destination', 'DESTINATION', dname or dest_ip, 'info',
                     [dname and dest_ip, (dst if tdst and tdst != dst else None) and f'public {dst}',
                      f"{s.get('dpt')}/{PROTO.get(to_int(s.get('proto')), s.get('proto'))}", F('FTNTFGTdstcountry')],
                     [['Destination IP', dst], ['Translated IP', tdst], ['Domain / host', domain], ['Destination port', s.get('dpt')],
                      ['Protocol', PROTO.get(to_int(s.get('proto')), s.get('proto'))], ['Country', F('FTNTFGTdstcountry')],
                      ['Internet service (ISDB)', F('FTNTFGTdstinetsvc')], ['Device name', (dhost_host or {}).get('name')],
                      ['Resolved from', 'web filter / app-ctrl hostname (SNI) of the same session' if domain else None]],
                     [seed['ref']], {'type': 'domain', 'value': domain} if domain else {'type': 'ip', 'value': dest_ip}))
    # everything after the decision point is "not reached"
    stop = next((i for i, h in enumerate(hops) if h['status'] == 'blocked'), None)
    if stop is not None:
        for h in hops[stop + 1:]:
            if h['status'] in ('info', 'allowed'):
                h['status'] = 'notreached'
    return hops


def _timeline(corr, ctx, T):
    ev = []
    for r in corr:
        ev.append({'ts_ns': r['ts_ns'], 'label': r['label'], 'kind': r['kind'], 'verdict': r['verdict'], 'ref': r['ref'],
                   'confidence': r['confidence'], 'method': r['method'], 'derived': False, 'context': False})
    if T and T['fields'].get('act') not in RAW_DROPS and to_int(T['fields'].get('FTNTFGTduration')):
        start = int(T['ts_ns']) - to_int(T['fields'].get('FTNTFGTduration')) * 1_000_000_000
        ev.append({'ts_ns': str(start), 'label': 'Session started (derived: traffic-log time − duration, 1 s precision)',
                   'kind': 'traffic', 'verdict': 'info', 'ref': T['ref'], 'confidence': None, 'method': 'derived',
                   'derived': True, 'context': False})
    for r in ctx:
        ev.append({'ts_ns': r['ts_ns'], 'label': f"{r['label']} → {r['fields'].get('dst')}:{r['fields'].get('dpt')}",
                   'kind': r['kind'], 'verdict': r['verdict'], 'ref': r['ref'], 'confidence': 0, 'method': r['method'],
                   'derived': False, 'context': True})
    return sorted(ev, key=lambda e: int(e['ts_ns']))


def _graph(seed, corr, user, host, src, dst, tdst, domain, pid, inif, outif, A, W, I, status, fw):
    nodes, edges = {}, []

    def n(nid, typ, lbl, **kw):
        nodes.setdefault(nid, dict({'id': nid, 'type': typ, 'label': str(lbl)}, **kw))

    def e(a, b, lbl):
        if a in nodes and b in nodes:
            edges.append({'source': a, 'target': b, 'label': lbl})
    if user:
        n('user', 'user', user, trace={'type': 'user', 'value': user})
    if host and host.get('name'):
        n('device', 'device', host['name'], trace={'type': 'device', 'value': host['name']})
    if host and host.get('mac'):
        n('mac', 'mac', host['mac'], trace={'type': 'mac', 'value': host['mac']})
    n('src', 'ip', src, trace={'type': 'ip', 'value': src})
    sess = seed['fields'].get('externalId')
    if sess:
        n('sess', 'session', f'session {sess}', trace={'type': 'session', 'value': sess})
    n('fw', 'firewall', fw.get('name') or 'FortiGate')
    if inif:
        n('inif', 'interface', f'in {inif}')
    if outif:
        n('outif', 'interface', f'out {outif}')
    if pid is not None:
        n('policy', 'policy', polname(pid), trace={'type': 'policy', 'value': pid})
    for rec, key in ((A, 'app'), (W, 'web'), (I, 'ips')):
        if rec:
            d = rec['fields']
            n('prof_' + key, 'profile', d.get('FTNTFGTapplist') or d.get('FTNTFGTprofile') or key)
            if key == 'app':
                n('application', 'application', d.get('FTNTFGTapp') or d.get('app'), trace={'type': 'app', 'value': d.get('FTNTFGTapp')})
            if key == 'ips':
                n('threat', 'threat', d.get('FTNTFGTattack'))
    n('verdict', 'verdict', {'blocked': 'BLOCKED', 'threat': 'THREAT'}.get(status, status.upper()), status=status)
    if domain:
        n('domain', 'domain', domain, trace={'type': 'domain', 'value': domain})
    n('dst', 'ip', dst, trace={'type': 'ip', 'value': dst})
    if tdst and tdst != dst:
        n('tdst', 'ip', tdst, trace={'type': 'ip', 'value': tdst})
    e('user', 'device', 'uses'); e('device', 'src', 'source IP'); e('mac', 'src', 'MAC')
    if not host or not host.get('name'):
        e('user', 'src', 'VPN IP')
    e('src', 'sess', 'session'); e('sess' if sess else 'src', 'inif', 'enters'); e('inif', 'fw', 'ingress')
    e('fw', 'policy', 'evaluated by')
    for key in ('app', 'web', 'ips'):
        e('policy', 'prof_' + key, 'inspected by')
    e('prof_app', 'application', 'detected'); e('prof_ips', 'threat', 'detected')
    last = next((k for k in ('prof_ips', 'prof_web', 'prof_app') if k in nodes), 'policy')
    e(last, 'verdict', 'decision'); e('verdict', 'outif', 'egress'); e('outif', 'domain', 'destination')
    e('domain' if domain else 'outif', 'dst', 'resolves to' if domain else 'destination'); e('dst', 'tdst', 'NAT to')
    return {'nodes': list(nodes.values()), 'edges': edges}


def _request(seed, corr, F, host, user, vpn, domain, tdst):
    s = seed['fields']
    dur = to_int(F('FTNTFGTduration'))
    return [
        {'title': 'Request', 'open': True, 'rows': [
            ['Timestamp', seed['ts_ns'], 'ts'], ['Source IP', s.get('src')], ['Source port', s.get('spt')],
            ['Destination IP', s.get('dst')], ['Destination port', s.get('dpt')],
            ['Protocol', PROTO.get(to_int(s.get('proto')), s.get('proto'))], ['URL', F('request')], ['Domain', domain],
            ['HTTP method', F('FTNTFGThttpmethod')], ['HTTP status', F('FTNTFGTstatus')],
            ['Application', _val(F('FTNTFGTapp'), F('app'))], ['User agent / client app', _val(F('requestClientApplication'), F('FTNTFGTagent'))]]},
        {'title': 'Identity', 'open': True, 'rows': [
            ['Username', user], ['Device name', _val(host.get('name') if host else None, F('FTNTFGTsrcname'), F('shost'))],
            ['Source MAC', _val(F('FTNTFGTsrcmac'), (host or {}).get('mac'))], ['OS', _val(F('FTNTFGTosname'), (host or {}).get('os'))],
            ['VPN', vpn and f"{vpn.get('tunnel') or ''} (group {vpn.get('group') or '?'}, from {vpn.get('remote_ip') or '?'})"]]},
        {'title': 'Session', 'open': False, 'rows': [
            ['Session ID', F('externalId')], ['Request ID (UTM incident serial)', F('FTNTFGTincidentserialno')],
            ['Log ID', s.get('FTNTFGTlogid')], ['Bytes sent', F('out')], ['Bytes received', F('in')],
            ['Packets sent', F('FTNTFGTsentpkt')], ['Packets received', F('FTNTFGTrcvdpkt')],
            ['Session duration (s)', dur], ['Session end state', _val(*(r['fields'].get('act') for r in corr if r['kind'] == 'traffic'))]]},
        {'title': 'NAT & interfaces', 'open': False, 'rows': [
            ['Ingress interface', F('deviceInboundInterface')], ['Egress interface', F('deviceOutboundInterface')],
            ['NAT disposition', F('FTNTFGTtrandisp')], ['NAT source', _val(F('sourceTranslatedAddress'))],
            ['NAT source port', F('sourceTranslatedPort')], ['NAT destination', tdst], ['NAT destination port', F('destinationTranslatedPort')],
            ['VDOM', F('FTNTFGTvd')]]},
        {'title': 'Geo & reputation', 'open': False, 'rows': [
            ['Source country', F('FTNTFGTsrccountry')], ['Destination country', F('FTNTFGTdstcountry')],
            ['Source ISDB', F('FTNTFGTsrcinetsvc')], ['Destination ISDB', F('FTNTFGTdstinetsvc')],
            ['Client reputation', _val(F('FTNTFGTcrlevel') and f"{F('FTNTFGTcrlevel')} (score {F('FTNTFGTcrscore')})")]]},
    ]


def _corr_summary(corr, raw_scanned):
    src = Counter(r['kind'] for r in corr)
    lv = Counter(r['confidence'] for r in corr)
    return {'by_kind': dict(src), 'by_confidence': {str(k): v for k, v in lv.items()}, 'raw_window_scanned': raw_scanned,
            'levels': [{'confidence': c, 'name': n, 'keys': k} for c, n, k in MATCH_LEVELS],
            'sources_checked': ['traffic (forward / local)', 'application control', 'web filter', 'IPS', 'antivirus', 'SSL inspection',
                                'raw syslog window ±2 min', 'VPN events (identity)', 'FortiGate device table', 'learned policy table',
                                'documented interface config'],
            'not_available': ['DNS query logs (no DNS filter logging)', 'authentication / FSSO user logs',
                              'address & service objects (config export not imported)', 'switch / L2 path']}


def _compare_candidates(seed, status):
    s = seed['fields']
    src, ts = s.get('src'), seed['ts']
    if not src:
        return []
    want_blocked = status not in ('blocked', 'threat')
    out = []
    for t, cond in (('traffic', "(act IN ('deny','block','blocked','dropped','reset') OR utmact = 'block')" if want_blocked else
                     "act NOT IN ('deny','block','blocked','dropped','reset') AND coalesce(utmact, '') != 'block'"),
                    ('utm_app', "act = 'block'" if want_blocked else "act = 'pass'")):
        for r in q(f"""SELECT ts, fid, off, dst, dpt, policyid, act FROM {t} WHERE src = ? AND {cond}
                       AND ts BETWEEN ? AND ? ORDER BY abs(ts - ?) LIMIT 5""", (src, ts - DAY, ts + DAY, ts)):
            out.append({'ref': mkref(r['fid'], r['off'], r['ts']), 'ts': r['ts'], 'dst': r['dst'], 'dpt': r['dpt'],
                        'policy': polname(r['policyid']), 'act': r['act'], 'verdict': 'blocked' if want_blocked else 'allowed',
                        'same_port': str(r['dpt']) == s.get('dpt')})
    out.sort(key=lambda x: (not x['same_port'], abs(x['ts'] - ts)))
    return out[:8]


# ---------------------------------------------------------------- trace
def trace(typ, value, frm, to):
    hfrm = floor(frm, H1)
    v = str(value)
    if typ in ('user', 'device', 'mac'):
        ips, how = _ips_for({typ: v})
        res = {'entity': {'type': typ, 'value': v}, 'resolved_ips': sorted(ips), 'how': how}
        res['ip_traces'] = [trace('ip', ip, frm, to) for ip in sorted(ips)[:3]]
        res['chain'] = [{'label': f'{typ} {v}', 'value': None}] + [{'label': 'uses IP', 'value': ip, 'trace': {'type': 'ip', 'value': ip}}
                                                                 for ip in sorted(ips)]
        return res
    if typ == 'ip':
        host = q('SELECT * FROM host WHERE ip = ?', (v,), one=True)
        seen = q('SELECT * FROM seen_src WHERE src = ?', (v,), one=True)
        as_src = q("""SELECT dir, policyid, sum(n) AS n, sum(drops) AS drops, sum(sent) AS sent, sum(rcvd) AS rcvd, max(country) AS country
                      FROM r_src_1h WHERE src = ? AND b >= ? AND b < ? GROUP BY 1, 2 ORDER BY n DESC""", (v, hfrm, to))
        for r in as_src:
            r['policy'] = polname(r['policyid'])
        deny = q("""SELECT policyid, inif, sum(n) AS n, max(ports) AS ports, max(psample) AS psample FROM r_deny_src_1h
                    WHERE src = ? AND b >= ? AND b < ? GROUP BY 1, 2""", (v, hfrm, to)) or \
            q("""SELECT policyid, inif, sum(n) AS n, max(ports) AS ports, max(psample) AS psample FROM r_deny_src_1d
                 WHERE src = ? AND b >= ? AND b < ? GROUP BY 1, 2""", (v, floor(frm, DAY), to))
        for r in deny:
            r['policy'] = polname(r['policyid'])
        t24 = max(frm, to - DAY)
        dests = q("""SELECT dst, dpt, proto, count(*) AS n, sum(CASE WHEN act IN ('deny','block','blocked','dropped','reset')
                     OR utmact = 'block' THEN 1 ELSE 0 END) AS blocked, sum(coalesce(sent,0) + coalesce(rcvd,0)) AS bytes,
                     max(dcountry) AS country FROM traffic WHERE src = ? AND ts >= ? AND ts < ? GROUP BY 1, 2, 3
                     ORDER BY n DESC LIMIT 40""", (v, t24, to))
        as_dst = q("""SELECT src, dpt, count(*) AS n, max(scountry) AS country, max(policyid) AS policyid FROM traffic
                      WHERE (dst = ? OR tdst = ?) AND ts >= ? AND ts < ? GROUP BY 1, 2 ORDER BY n DESC LIMIT 30""", (v, v, t24, to))
        for r in as_dst:
            r['policy'] = polname(r['policyid'])
        dns = q("""SELECT dst, count(*) AS n FROM traffic WHERE src = ? AND dpt = 53 AND ts >= ? AND ts < ? GROUP BY 1
                   ORDER BY n DESC LIMIT 10""", (v, t24, to))
        doms = q("""SELECT root, sum(n) AS n, sum(blocked) AS blocked FROM r_dom_1h WHERE src = ? AND b >= ? AND b < ?
                    GROUP BY 1 ORDER BY n DESC LIMIT 30""", (v, hfrm, to))
        apps = q("""SELECT app, act, count(*) AS n FROM utm_app WHERE src = ? AND ts >= ? AND ts < ? GROUP BY 1, 2
                    ORDER BY n DESC LIMIT 20""", (v, t24, to))
        threats = q("""SELECT attack, severity, act, count(*) AS n, max(ts) AS last FROM utm_ips WHERE (src = ? OR dst = ?)
                       AND ts >= ? AND ts < ? GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 20""", (v, v, frm, to))
        vpn = _vpn_user(v, to)
        hist = q("""SELECT b, sum(n) AS n, sum(drops) AS drops FROM r_src_1h WHERE src = ? AND b >= ? AND b < ? GROUP BY b ORDER BY b""",
                 (v, hfrm, to))
        dhist = {r['b']: r['n'] for r in q("""SELECT b, sum(n) AS n FROM r_deny_src_1h WHERE src = ? AND b >= ? AND b < ?
                                              GROUP BY b""", (v, hfrm, to))}
        tot = sum(r['n'] for r in as_src)
        drops = sum(r['drops'] for r in as_src) + sum(r['n'] for r in deny)
        chain = [
            {'label': 'IP', 'value': v, 'sub': (seen or {}).get('country') or (host or {}).get('name')},
            {'label': 'User activity', 'value': (vpn or {}).get('user') or 'no user identity logged',
             'trace': {'type': 'user', 'value': vpn['user']} if vpn and vpn.get('user') else None},
            {'label': 'Device', 'value': (host or {}).get('name') or
             ('identified by FortiGate (no hostname logged)' if host else 'not identified by FortiGate'),
             'sub': ' · '.join(filter(None, [host.get('os'), host.get('mac')])) if host else None},
            {'label': 'DNS sessions', 'value': f"{sum(r['n'] for r in dns):,} to {len(dns)} resolvers (last 24 h)" if dns else
             'none seen (DNS query names are not logged)'},
            {'label': 'Firewall sessions', 'value': f"{tot:,} accepted/logged lines on {len(as_src)} policy/direction pairs"},
            {'label': 'Blocked requests', 'value': f"{drops:,}", 'status': 'blocked' if drops else None},
            {'label': 'Allowed requests', 'value': f"{max(0, tot - sum(r['drops'] for r in as_src)):,}", 'status': 'allowed'},
            {'label': 'Threat events', 'value': f"{sum(r['n'] for r in threats):,}", 'status': 'threat' if threats else None},
            {'label': 'Destinations', 'value': f"{len(dests)} dst:port (24 h) · {len(doms)} domains"},
        ]
        nodes = [{'id': 'ip:' + v, 'type': 'ip', 'label': v, 'center': True}]
        edges = []

        def add(nid, typ_, lbl, e_lbl, n=0, rev=False, **kw):
            if not any(x['id'] == nid for x in nodes):
                nodes.append(dict({'id': nid, 'type': typ_, 'label': lbl, 'n': n}, **kw))
            edges.append({'source': nid if rev else 'ip:' + v, 'target': 'ip:' + v if rev else nid, 'label': e_lbl, 'n': n})
        if vpn and vpn.get('user'):
            add('user:' + vpn['user'], 'user', vpn['user'], 'VPN user', rev=True, trace={'type': 'user', 'value': vpn['user']})
        if host and host.get('name'):
            add('dev:' + host['name'], 'device', host['name'], 'device', rev=True)
        for r in as_src[:8]:
            add(f"pol:{r['policyid']}", 'policy', r['policy'], f"{r['n']:,} sessions", r['n'], trace={'type': 'policy', 'value': r['policyid']})
        for r in deny[:6]:
            add(f"pol:{r['policyid']}", 'policy', r['policy'], f"{r['n']:,} denied", r['n'], status='blocked',
                trace={'type': 'policy', 'value': r['policyid']})
        for r in dests[:12]:
            add(f"dst:{r['dst']}", 'ip', r['dst'], f":{r['dpt']} ×{r['n']}", r['n'], status='blocked' if r['blocked'] else None,
                trace={'type': 'ip', 'value': r['dst']})
        if len(dests) > 12:
            add('more-dst', 'cluster', f"{len(dests) - 12} more destinations", 'more', sum(r['n'] for r in dests[12:]))
        for r in doms[:10]:
            add(f"dom:{r['root']}", 'domain', r['root'], f"{r['n']:,} req", r['n'], trace={'type': 'domain', 'value': r['root']})
        for r in as_dst[:8]:
            add(f"src:{r['src']}", 'ip', r['src'], f"→ :{r['dpt']} ×{r['n']}", r['n'], rev=True, trace={'type': 'ip', 'value': r['src']})
        if len(as_dst) > 8:
            add('more-src', 'cluster', f"{len(as_dst) - 8} more sources", 'more', sum(r['n'] for r in as_dst[8:]), rev=True)
        for r in threats[:5]:
            add('thr:' + (r['attack'] or '?'), 'threat', r['attack'], f"{r['n']} ({r['severity']})", r['n'], status='threat')
        return {'entity': {'type': 'ip', 'value': v}, 'identity': {'host': host, 'vpn': vpn, 'seen': seen},
                'chain': chain, 'as_src': as_src, 'deny': deny, 'destinations': dests, 'as_dst': as_dst, 'dns': dns,
                'domains': doms, 'apps': apps, 'threats': threats,
                'hist': [{'b': r['b'], 'n': r['n'], 'drops': r['drops'] + dhist.get(r['b'], 0)} for r in hist] +
                        [{'b': b, 'n': 0, 'drops': n} for b, n in dhist.items() if b not in {r['b'] for r in hist}],
                'graph': {'nodes': nodes, 'edges': edges}}
    if typ == 'domain':
        d = v.lower()
        rows = q("""SELECT src, root, dhost, sum(n) AS n, sum(blocked) AS blocked FROM r_dom_1h WHERE (root = ? OR dhost = ?
                    OR dhost LIKE ?) AND b >= ? AND b < ? GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 60""", (d, d, '%.' + d, hfrm, to))
        dsts = q("""SELECT dst, count(*) AS n, max(act) AS act FROM utm_web WHERE (dhost = ? OR root = ? OR dhost LIKE ?)
                    AND ts >= ? AND ts < ? GROUP BY 1 ORDER BY n DESC LIMIT 20""", (d, d, '%.' + d, max(frm, to - DAY), to))
        seen = q('SELECT * FROM seen_dom WHERE root = ?', (d,), one=True)
        nodes = [{'id': 'dom:' + d, 'type': 'domain', 'label': d, 'center': True}]
        edges = []
        for r in rows[:15]:
            nid = 'src:' + r['src']
            if not any(x['id'] == nid for x in nodes):
                nodes.append({'id': nid, 'type': 'ip', 'label': r['src'], 'n': r['n'], 'trace': {'type': 'ip', 'value': r['src']}})
            edges.append({'source': nid, 'target': 'dom:' + d, 'label': f"{r['n']:,} req", 'n': r['n']})
        for r in dsts[:10]:
            nodes.append({'id': 'dst:' + r['dst'], 'type': 'ip', 'label': r['dst'], 'n': r['n'], 'trace': {'type': 'ip', 'value': r['dst']}})
            edges.append({'source': 'dom:' + d, 'target': 'dst:' + r['dst'], 'label': 'resolves to (seen)', 'n': r['n']})
        return {'entity': {'type': 'domain', 'value': d}, 'seen': seen, 'sources': rows, 'dst_ips': dsts,
                'chain': [{'label': 'Domain', 'value': d, 'sub': seen and f"first seen {seen.get('first_ts')}"},
                          {'label': 'Requests', 'value': f"{sum(r['n'] for r in rows):,} from {len({r['src'] for r in rows})} machines"},
                          {'label': 'Blocked', 'value': f"{sum(r['blocked'] or 0 for r in rows):,}"},
                          {'label': 'Destination IPs (web filter)', 'value': ', '.join(r['dst'] for r in dsts[:6]) or '—'}],
                'graph': {'nodes': nodes, 'edges': edges}}
    if typ == 'policy':
        pid = int(v)
        p = policies().get(pid) or {}
        srcs = q("""SELECT src, sum(n) AS n, sum(drops) AS drops, max(country) AS country FROM r_src_1h WHERE policyid = ?
                    AND b >= ? AND b < ? GROUP BY 1 ORDER BY n DESC LIMIT 30""", (pid, hfrm, to))
        apps = q("""SELECT app, act, sum(n) AS n FROM r_app_5m WHERE policyid = ? AND b >= ? AND b < ? GROUP BY 1, 2
                    ORDER BY n DESC LIMIT 20""", (pid, floor(frm, 300_000), to))
        ports = q("""SELECT dpt, proto, act, sum(n) AS n FROM r_pol_5m WHERE policyid = ? AND b >= ? AND b < ? GROUP BY 1, 2, 3
                     ORDER BY n DESC LIMIT 20""", (pid, floor(frm, 300_000), to))
        denies = q("""SELECT sum(n) AS n FROM r_deny_5m WHERE policyid = ? AND b >= ? AND b < ?""", (pid, floor(frm, 300_000), to), one=True)
        nodes = [{'id': f'pol:{pid}', 'type': 'policy', 'label': polname(pid), 'center': True}]
        edges = []
        for r in srcs[:15]:
            nodes.append({'id': 'src:' + r['src'], 'type': 'ip', 'label': r['src'], 'n': r['n'],
                          'status': 'blocked' if r['drops'] else None, 'trace': {'type': 'ip', 'value': r['src']}})
            edges.append({'source': 'src:' + r['src'], 'target': f'pol:{pid}', 'label': f"{r['n']:,}", 'n': r['n']})
        if len(srcs) > 15:
            nodes.append({'id': 'more', 'type': 'cluster', 'label': f'{len(srcs) - 15}+ more sources'})
            edges.append({'source': 'more', 'target': f'pol:{pid}', 'label': 'more'})
        for r in apps[:10]:
            nid = 'app:' + (r['app'] or '?')
            if not any(x['id'] == nid for x in nodes):
                nodes.append({'id': nid, 'type': 'application', 'label': r['app'], 'n': r['n'],
                              'status': 'blocked' if r['act'] == 'block' else None})
            edges.append({'source': f'pol:{pid}', 'target': nid, 'label': f"{r['act']} {r['n']:,}", 'n': r['n']})
        return {'entity': {'type': 'policy', 'value': pid}, 'policy': p, 'sources': srcs, 'apps': apps, 'ports': ports,
                'denied': (denies or {}).get('n'),
                'chain': [{'label': 'Policy', 'value': polname(pid), 'sub': f"{p.get('dir') or ''} · {p.get('ptype') or ''}"},
                          {'label': 'Sensors', 'value': p.get('applists') or '—'},
                          {'label': 'Sources', 'value': f"{len(srcs)}{'+' if len(srcs) >= 30 else ''} distinct"},
                          {'label': 'Blocked by app control', 'value': f"{sum(r['n'] for r in apps if r['act'] == 'block'):,}",
                           'status': 'blocked'},
                          {'label': 'Denied (noise aggregates)', 'value': f"{(denies or {}).get('n') or 0:,}"}],
                'graph': {'nodes': nodes, 'edges': edges}}
    if typ == 'session':
        sess = int(v)
        items = []
        for t in ('traffic', 'utm_app', 'utm_web', 'utm_ips'):
            items += [_item_from_row(t, r) for r in q(f"SELECT {TABLE_COLS[t]} FROM {t} WHERE sess = ? AND ts >= ? AND ts < ? LIMIT 50",
                                                       (sess, frm - DAY, to + DAY))]
        return {'entity': {'type': 'session', 'value': sess}, 'items': sorted(items, key=lambda x: x['ts']),
                'chain': [{'label': 'Session', 'value': str(sess)},
                          {'label': 'Records', 'value': f"{len(items)} across {len({i['table'] for i in items})} log types"}],
                'graph': {'nodes': [], 'edges': []}}
    if typ == 'app':
        rows = q("""SELECT policyid, act, src, dst, dpt, count(*) AS n FROM utm_app WHERE app = ? AND ts >= ? AND ts < ?
                    GROUP BY 1, 2, 3, 4, 5 ORDER BY n DESC LIMIT 60""", (v, max(frm, to - DAY), to))
        for r in rows:
            r['policy'] = polname(r['policyid'])
        return {'entity': {'type': 'app', 'value': v}, 'rows': rows,
                'chain': [{'label': 'Application', 'value': v},
                          {'label': 'Detections (24 h)', 'value': f"{sum(r['n'] for r in rows):,}"},
                          {'label': 'Blocked', 'value': f"{sum(r['n'] for r in rows if r['act'] == 'block'):,}", 'status': 'blocked'}],
                'graph': {'nodes': [], 'edges': []}}
    raise ValueError('unknown trace type')
