"""forti-ingest: FortiGate CEF syslog -> SQLite.

  forti-ingest.py --backfill   ingest every rotated file + the live file up to EOF, then exit
  forti-ingest.py --tail       same catch-up, then follow /var/log/syslog across rotations (systemd)

Exactly-once: rows, rollup deltas and the file offset are committed in one transaction, so a crash or
restart resumes from the last commit. Files are identified by a hash of their first lines, so syslog ->
syslog.1 -> syslog.2.gz is recognised as the same file and never counted twice. A lock file stops
--backfill and --tail from running at the same time.
"""
import argparse
import fcntl
import glob
import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import time
from collections import defaultdict

from . import cfglive, db, settings
from .cef import parse, event_ms, to_int

LOG_BASE = settings.LOG_BASE
LOCK_PATH = os.path.join(settings.DATA, 'ingest.lock')
M1, M5, H1, DAY = 60_000, 300_000, 3_600_000, 86_400_000
INDEX_EVERY = 20_000            # sparse (ts -> byte offset) index for time-window greps of raw lines
DROP_ACTS = {'deny', 'block', 'blocked', 'dropped', 'reset', 'utm-block'}
DISK_MIN_FREE = int(os.environ.get('VIGIL_DISK_MIN_FREE_GB', '5')) * 2**30      # below this, raw traffic retention is shortened (never below 7 days)

log = logging.getLogger('vigil.ingest')
_stop = False


def _on_term(*_):
    global _stop
    _stop = True


# local-in / sniffer policies have their own id space; keep them apart from firewall policy ids
PTYPE_BASE = {'policy': 0, 'local-in-policy': 100_000, 'local-in-policy6': 100_000, 'sniffer': 300_000}


def policy_key(d):
    pid = to_int(d.get('FTNTFGTpolicyid'))
    if pid is None:
        return None
    return PTYPE_BASE.get(d.get('FTNTFGTpolicytype', 'policy'), 900_000) + pid


def direction(d, cat):
    if cat == 'traffic:local' or d.get('deviceOutboundInterface') == 'root':
        return 'local'
    s, t = d.get('FTNTFGTsrcintfrole'), d.get('FTNTFGTdstintfrole')
    if s == 'wan':
        return 'wan' if t == 'wan' else 'in'
    return 'out' if t == 'wan' else 'int'


_tld = None
_root_cache = {}
_IP_RE = re.compile(r'^[\d.]+$|:')


def root_of(host):
    """example.co.uk for a.b.example.co.uk, offline (bundled public-suffix snapshot)."""
    if not host:
        return ''
    host = host.lower().lstrip('*.').rstrip('.')
    if _IP_RE.search(host):
        return host
    r = _root_cache.get(host)
    if r is None:
        global _tld
        if _tld is None:
            import tldextract
            _tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
        x = _tld(host)
        r = getattr(x, 'top_domain_under_public_suffix', None) or x.registered_domain or host
        if len(_root_cache) > 100_000:
            _root_cache.clear()
        _root_cache[host] = r
    return r


def file_head(path):
    """Identity of a log file = hash of its first 3 lines (survives rename and gzip)."""
    opener = gzip.open if path.endswith('.gz') else open
    with opener(path, 'rb') as f:
        lines = [f.readline() for _ in range(3)]
    if not all(l.endswith(b'\n') for l in lines):
        return None                      # freshly rotated, not enough content yet
    return hashlib.sha1(b''.join(lines)).hexdigest()


def log_files():
    """Rotated files oldest first, live file last."""
    rot = []
    for p in glob.glob(LOG_BASE + '.*'):
        m = re.fullmatch(re.escape(LOG_BASE) + r'\.(\d+)(\.gz)?', p)
        if m:
            rot.append((int(m.group(1)), p))
    return [p for _, p in sorted(rot, reverse=True)] + [LOG_BASE]


# ---- backfill progress: how much of the history is read, and how long the rest will take -------------------------
GZ_RATIO = 8                      # rough uncompressed:compressed ratio of syslog text, for size estimates only


def _skip_old(path):
    """Rotated files older than VIGIL_BACKFILL_DAYS are never read, so they must not count towards the total."""
    if path == LOG_BASE or settings.BACKFILL_DAYS <= 0:
        return False
    try:
        return os.path.getmtime(path) < time.time() - settings.BACKFILL_DAYS * 86400
    except OSError:
        return True


def backfill_status(rows, rate=None):
    """rows: (path, off, done) from the files table -> bytes read / to read, percent and seconds left."""
    sizes = {}
    for p in log_files():
        if _skip_old(p):
            continue
        try:
            sizes[p] = os.path.getsize(p) * (GZ_RATIO if p.endswith('.gz') else 1)
        except OSError:
            continue
    seen = {r[0]: r for r in rows}
    done = 0
    for p, size in sizes.items():
        r = seen.get(p)
        if not r:
            continue
        done += size if r[2] else min(size, r[1] or 0)      # r[1] is the byte offset, uncompressed for .gz too
    total = sum(sizes.values())
    left = max(0, total - done)
    return {'done': done, 'total': total, 'left_bytes': left, 'files': len(sizes),
            'percent': round(100 * done / total, 1) if total else 100.0,
            'eta_s': int(left / rate) if rate and rate > 0 and left else (0 if not left else None)}


def human_duration(seconds):
    if seconds is None:
        return 'unknown'
    if seconds < 90:
        return f'{max(1, int(seconds))} s'
    if seconds < 5400:
        return f'{round(seconds / 60)} min'
    return f'{seconds / 3600:.1f} h'


def backfill_left(con, rate):
    """Short note for the ingest log line; empty once everything on disk has been read."""
    try:
        st = backfill_status(con.execute('SELECT path, off, done FROM files').fetchall(), rate)
    except Exception:                                        # progress reporting must never break ingest
        return ''
    if st['left_bytes'] < 4 << 20 or not st['eta_s']:
        return ''
    return f"{st['percent']:.0f}% read, about {human_duration(st['eta_s'])} left"


class Ingest:
    def __init__(self, con):
        self.con = con
        self.rows = defaultdict(list)
        # rollup deltas since the last commit: key -> [n, ...measures, (non-key attribute)]
        self.r = {t: defaultdict(lambda: [0, 0, 0, 0, '']) for t in
                  ('r_1m', 'r_pol_5m', 'r_app_5m', 'r_src_1h', 'r_dom_1h', 'r_deny_5m', 'r_deny_src_1h', 'r_deny_port_1h')}
        self.inb = defaultdict(lambda: [0, 0, 0, 0, 0, 0, ''])   # r_in_1h: n, short, drops, bytes, maxdur, maxbytes, country
        self.web = defaultdict(int)                              # r_web_1h
        self.deny_ports = {}              # hourly key -> set of dst ports (capped), survives commits
        self.deny_srcs = {}               # hourly key -> set of hashed src (capped)
        self.seen_src = {}
        self.seen_dom = {}
        self.hosts = {}
        self.pol = {r[0]: {'name': r[1], 'uuid': r[2], 'ptype': r[3], 'dir': r[4],
                           'applists': set(filter(None, (r[5] or '').split(','))), 'first': r[6], 'last': r[7], 'n': 0}
                    for r in con.execute('SELECT policyid,name,uuid,ptype,dir,applists,first_ts,last_ts FROM policy')}
        self.pol_dirty = set()
        self.max_ts = 0
        self.lines = 0
        row = con.execute("SELECT v FROM meta WHERE k = 'device'").fetchone()
        self.device = json.loads(row[0]) if row else {}
        self.device_dirty = False

    # ------------------------------------------------------------ per line
    def handle(self, raw, fid, off):
        line = raw.decode('utf-8', 'replace')
        d = parse(line)
        if d is None:
            return None
        ts = event_ms(d, line)
        if ts is None:
            return None
        if ts > self.max_ts:
            self.max_ts = ts
        for k, src in (('devname', '_devname'), ('devid', '_devid'), ('version', '_version')):
            v = d.get(src)
            if v and self.device.get(k) != v:
                self.device[k] = v
                self.device_dirty = True
        cat = d.get('cat') or d['_sig'].split(' ', 1)[0]
        act = d.get('act', '')
        # sessions killed by a UTM profile end as client-rst/close/timeout + utmaction=block: count them as drops
        ract = 'utm-block' if d.get('FTNTFGTutmaction') == 'block' and act not in DROP_ACTS else act
        self.r['r_1m'][(ts - ts % M1, cat, ract)][0] += 1
        pid = policy_key(d)
        dr = direction(d, cat)
        if pid is not None:
            self._policy(pid, d, dr, ts)
        typ = cat.split(':', 1)[0]
        if typ == 'traffic':
            self._traffic(d, cat, act, dr, pid, ts, fid, off)
        elif cat == 'utm:app-ctrl':
            self._app(d, act, dr, pid, ts, fid, off)
        elif cat == 'utm:webfilter':
            self._web(d, act, dr, pid, ts, fid, off)
        elif cat == 'utm:ips':
            self.rows['utm_ips'].append((
                ts, dr, pid, d.get('FTNTFGTattack'), to_int(d.get('FTNTFGTattackid')), d.get('FTNTFGTseverity'),
                d.get('FTNTFGTlevel'), act, d.get('src'), to_int(d.get('spt')), d.get('dst'), to_int(d.get('dpt')),
                to_int(d.get('proto')), d.get('FTNTFGTsrccountry'), d.get('dhost'), d.get('request'),
                d.get('FTNTFGTprofile'), d.get('FTNTFGTref'), to_int(d.get('externalId')), fid, off))
        elif cat == 'utm:virus':
            self.rows['utm_av'].append((
                ts, dr, pid, d.get('FTNTFGTvirus') or d.get('cs1'), act, d.get('FTNTFGTlevel'), d.get('src'),
                d.get('dst'), to_int(d.get('dpt')), d.get('dhost'), d.get('request'), d.get('fname') or d.get('FTNTFGTfilename'),
                d.get('FTNTFGTprofile'), to_int(d.get('externalId')), fid, off))
        elif typ == 'utm':
            self.rows['utm_other'].append((
                ts, cat, d.get('FTNTFGTeventtype'), act, d.get('FTNTFGTlevel'), pid, d.get('src'), d.get('dst'),
                to_int(d.get('dpt')), d.get('dhost') or d.get('FTNTFGTsni'), d.get('msg'), _ext(line), fid, off))
        else:
            self.rows['event'].append((
                ts, cat, d.get('FTNTFGTlevel'), d.get('FTNTFGTlogdesc'), act, d.get('duser') or d.get('suser'),
                d.get('src'), d.get('dst'), d.get('msg'), _ext(line), fid, off))
            if 'FTNTFGTcfgpath' in d:
                self.rows['cfg_change'].append(cfglive.row(d, ts, fid, off))
        return ts

    def _policy(self, pid, d, dr, ts):
        p = self.pol.get(pid)
        if p is None:
            implicit = {0: 'implicit-deny', 100_000: 'local-in implicit deny'}.get(pid)
            p = self.pol[pid] = {'name': implicit, 'uuid': None, 'ptype': None,
                                 'dir': dr, 'applists': set(), 'first': ts, 'last': ts, 'n': 0}
            self.pol_dirty.add(pid)
        name = d.get('FTNTFGTpolicyname')
        if name and name != p['name']:
            p['name'] = name
            self.pol_dirty.add(pid)
        if not p['uuid'] and d.get('FTNTFGTpoluuid'):
            p['uuid'] = d['FTNTFGTpoluuid']
            self.pol_dirty.add(pid)
        if not p['ptype'] and d.get('FTNTFGTpolicytype'):
            p['ptype'] = d['FTNTFGTpolicytype']
            self.pol_dirty.add(pid)
        al = d.get('FTNTFGTapplist')
        if al and al not in p['applists']:
            p['applists'].add(al)
            self.pol_dirty.add(pid)
        if p['dir'] in (None, 'local', 'int') and dr in ('in', 'out'):
            p['dir'] = dr
            self.pol_dirty.add(pid)
        p['first'] = min(p['first'] or ts, ts)
        p['last'] = max(p['last'] or ts, ts)
        p['n'] += 1
        self.pol_dirty.add(pid)

    def _traffic(self, d, cat, act, dr, pid, ts, fid, off):
        src = d.get('src') or ''
        inif = d.get('deviceInboundInterface') or ''
        wan_src = d.get('FTNTFGTsrcintfrole') == 'wan'
        # scanner noise: implicit/explicit deny from the internet, and all local-in denies -> aggregates only.
        # (UTM-blocked sessions on accept rules carry FTNTFGTutmaction and are kept as raw rows.)
        if act == 'deny' and (cat == 'traffic:local' or wan_src) and 'FTNTFGTutmaction' not in d:
            self._noise(d, cat, src, inif, pid, ts, wan_src)
            return
        sent = to_int(d.get('FTNTFGTsentdelta')) if 'FTNTFGTsentdelta' in d else to_int(d.get('out'))
        rcvd = to_int(d.get('FTNTFGTrcvddelta')) if 'FTNTFGTrcvddelta' in d else to_int(d.get('in'))
        sent, rcvd = sent or 0, rcvd or 0
        dpt, proto = to_int(d.get('dpt')), to_int(d.get('proto'))
        country = d.get('FTNTFGTsrccountry') if dr in ('in', 'wan', 'local') else d.get('FTNTFGTdstcountry')
        app = d.get('FTNTFGTapp') or d.get('app') or ''
        self.rows['traffic'].append((
            ts, cat.split(':', 1)[1], dr, inif, d.get('deviceOutboundInterface'), src, to_int(d.get('spt')),
            d.get('dst'), dpt, d.get('destinationTranslatedAddress'), to_int(d.get('destinationTranslatedPort')), proto,
            pid, act, d.get('FTNTFGTutmaction'), app, d.get('FTNTFGTappcat'), d.get('FTNTFGTsrccountry'),
            d.get('FTNTFGTdstcountry'), d.get('FTNTFGTsrcinetsvc') or d.get('FTNTFGTdstinetsvc'),
            d.get('shost') or d.get('FTNTFGTsrcname'), to_int(d.get('out')), to_int(d.get('in')),
            to_int(d.get('FTNTFGTduration')), to_int(d.get('externalId')), fid, off))
        ract = 'utm-block' if d.get('FTNTFGTutmaction') == 'block' and act not in DROP_ACTS else act
        k = (ts - ts % M5, dr, _i(pid), ract, app, _i(dpt), _i(proto), country or '')
        a = self.r['r_pol_5m'][k]
        a[0] += 1; a[1] += sent; a[2] += rcvd
        a = self.r['r_src_1h'][(ts - ts % H1, dr, _i(pid), src)]
        a[0] += 1; a[2] += sent; a[3] += rcvd; a[4] = country or ''
        if act in DROP_ACTS or d.get('FTNTFGTutmaction') == 'block':
            a[1] += 1
        if wan_src:
            self._seen(src, d.get('FTNTFGTsrccountry'), ts, act not in DROP_ACTS)
            dur = to_int(d.get('FTNTFGTduration')) or 0
            total = (to_int(d.get('out')) or 0) + (to_int(d.get('in')) or 0)
            srv = d.get('destinationTranslatedAddress') or d.get('dst') or ''
            port = to_int(d.get('destinationTranslatedPort')) or dpt
            a = self.inb[(ts - ts % H1, src, srv, _i(port), _i(proto), _i(pid))]
            a[0] += 1
            a[1] += 1 if (dur <= 2 and total < 4000 and act not in ('accept',)) else 0     # probe / failed-login shaped
            a[2] += 1 if ract in DROP_ACTS else 0
            a[3] += sent + rcvd
            a[4] = max(a[4], dur)
            a[5] = max(a[5], total)
            a[6] = d.get('FTNTFGTsrccountry') or a[6]
        elif src and ('shost' in d or 'FTNTFGTosname' in d or 'FTNTFGTsrcmac' in d):
            self.hosts[src] = (d.get('shost') or d.get('FTNTFGTsrcname'), d.get('FTNTFGTosname'),
                               d.get('FTNTFGTsrcmac'), d.get('FTNTFGTsrchwvendor'), d.get('FTNTFGTdevtype'), ts)

    def _noise(self, d, cat, src, inif, pid, ts, wan_src):
        country = d.get('FTNTFGTsrccountry') or ''
        dpt, proto = _i(to_int(d.get('dpt'))), _i(to_int(d.get('proto')))
        self.r['r_deny_5m'][(ts - ts % M5, cat, inif, _i(pid))][0] += 1
        h = ts - ts % H1
        ks = (h, src, inif, _i(pid))
        a = self.r['r_deny_src_1h'][ks]
        a[0] += 1; a[4] = country
        ports = self.deny_ports.setdefault(ks, set())
        if len(ports) < 32:
            ports.add(dpt)
        kp = (h, inif, dpt, proto, _i(pid))
        self.r['r_deny_port_1h'][kp][0] += 1
        srcs = self.deny_srcs.setdefault(kp, set())
        if len(srcs) < 2000:
            srcs.add(hash(src))
        if wan_src:
            self._seen(src, country, ts, False)

    def _seen(self, src, country, ts, accepted):
        s = self.seen_src.get(src)
        if s is None:
            s = self.seen_src[src] = [country, ts, ts, 0, 0, None, None]
        s[1] = min(s[1], ts); s[2] = max(s[2], ts)
        if accepted:
            s[3] += 1
            s[5] = ts if s[5] is None else min(s[5], ts)
            s[6] = ts if s[6] is None else max(s[6], ts)
        else:
            s[4] += 1

    def _app(self, d, act, dr, pid, ts, fid, off):
        # CEF app= is the service label (SSL, SMTPS); FTNTFGTapp is the detected application the verdict and
        # FTNTFGTappid refer to (IMAPS, MPTCP, HTTP.BROWSER_Chrome)
        applist, evtype = d.get('FTNTFGTapplist') or '', d.get('FTNTFGTeventtype') or ''
        app = d.get('FTNTFGTapp') or d.get('app') or ''
        self.rows['utm_app'].append((
            ts, dr, pid, applist, to_int(d.get('FTNTFGTappid')), app, d.get('app'), d.get('FTNTFGTappcat'),
            d.get('FTNTFGTapprisk'),
            act, evtype, d.get('src'), to_int(d.get('spt')), d.get('dst'), to_int(d.get('dpt')), to_int(d.get('proto')),
            d.get('FTNTFGTsrccountry'), d.get('dhost'), d.get('request'), to_int(d.get('externalId')), fid, off))
        self.r['r_app_5m'][(ts - ts % M5, dr, _i(pid), applist, app, act, evtype)][0] += 1

    def _web(self, d, act, dr, pid, ts, fid, off):
        dhost = (d.get('dhost') or '').lower()
        root = root_of(dhost)
        src = d.get('src') or ''
        sent, rcvd = to_int(d.get('out')) or 0, to_int(d.get('in')) or 0
        self.rows['utm_web'].append((
            ts, dr, pid, d.get('FTNTFGTprofile'), d.get('FTNTFGTeventtype'), act, src, to_int(d.get('spt')),
            d.get('dst'), to_int(d.get('dpt')), dhost, root, d.get('request'), d.get('FTNTFGThttpmethod'),
            d.get('requestClientApplication'), sent, rcvd, to_int(d.get('externalId')), fid, off))
        self.web[(ts - ts % H1, d.get('FTNTFGTprofile') or '', d.get('FTNTFGTeventtype') or '', act)] += 1
        if not root:
            return
        a = self.r['r_dom_1h'][(ts - ts % H1, src, root, dhost)]
        a[0] += 1; a[2] += sent; a[3] += rcvd
        if act in DROP_ACTS:
            a[1] += 1
        s = self.seen_dom.get(root)
        if s is None:
            s = self.seen_dom[root] = [ts, ts, 0, src]
        if ts < s[0]:
            s[0], s[3] = ts, src
        s[1] = max(s[1], ts); s[2] += 1

    # ------------------------------------------------------------ commit
    def flush(self, fid, off, lines, index_points, first_ts):
        c = self.con
        c.execute('BEGIN IMMEDIATE')
        try:
            for table, rows in self.rows.items():
                if rows:
                    verb = 'INSERT OR IGNORE' if table == 'cfg_change' else 'INSERT'
                    c.executemany(f'{verb} INTO {table} VALUES ({",".join("?" * len(rows[0]))})', rows)
            for t in ('r_1m', 'r_app_5m', 'r_deny_5m'):
                self._upsert(t, 'n=n+excluded.n', [(*k, v[0]) for k, v in self.r[t].items()])
            self._upsert('r_pol_5m', 'n=n+excluded.n, sent=sent+excluded.sent, rcvd=rcvd+excluded.rcvd',
                         [(*k, v[0], v[2], v[3]) for k, v in self.r['r_pol_5m'].items()])
            self._upsert('r_src_1h', 'country=excluded.country, n=n+excluded.n, drops=drops+excluded.drops, '
                         'sent=sent+excluded.sent, rcvd=rcvd+excluded.rcvd',
                         [(*k, v[4], v[0], v[1], v[2], v[3]) for k, v in self.r['r_src_1h'].items()])
            self._upsert('r_dom_1h', 'n=n+excluded.n, blocked=blocked+excluded.blocked, '
                         'sent=sent+excluded.sent, rcvd=rcvd+excluded.rcvd',
                         [(*k, *v[:4]) for k, v in self.r['r_dom_1h'].items()])
            self._flush_noise()
            self._upsert('r_in_1h', 'country=excluded.country, n=n+excluded.n, short=short+excluded.short, '
                         'drops=drops+excluded.drops, bytes=bytes+excluded.bytes, maxdur=max(maxdur, excluded.maxdur), '
                         'maxbytes=max(maxbytes, excluded.maxbytes)',
                         [(*k[:6], v[6], *v[:6]) for k, v in self.inb.items()])
            self._upsert('r_web_1h', 'n=n+excluded.n', [(*k, n) for k, n in self.web.items()])
            if self.seen_src:
                c.executemany("""INSERT INTO seen_src VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(src) DO UPDATE SET
                    country=coalesce(excluded.country, country), first_ts=min(first_ts, excluded.first_ts),
                    last_ts=max(last_ts, excluded.last_ts), n_acc=n_acc+excluded.n_acc, n_deny=n_deny+excluded.n_deny,
                    first_acc_ts=coalesce(min(first_acc_ts, excluded.first_acc_ts), first_acc_ts, excluded.first_acc_ts),
                    last_acc_ts=coalesce(max(last_acc_ts, excluded.last_acc_ts), last_acc_ts, excluded.last_acc_ts)""",
                              [(k, *v) for k, v in self.seen_src.items()])
            if self.seen_dom:
                c.executemany("""INSERT INTO seen_dom VALUES (?,?,?,?,?) ON CONFLICT(root) DO UPDATE SET
                    first_src=CASE WHEN excluded.first_ts < first_ts THEN excluded.first_src ELSE first_src END,
                    first_ts=min(first_ts, excluded.first_ts), last_ts=max(last_ts, excluded.last_ts), n=n+excluded.n""",
                              [(k, *v) for k, v in self.seen_dom.items()])
            if self.hosts:
                c.executemany("""INSERT INTO host VALUES (?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
                    name=coalesce(excluded.name, name), os=coalesce(excluded.os, os), mac=coalesce(excluded.mac, mac),
                    vendor=coalesce(excluded.vendor, vendor), devtype=coalesce(excluded.devtype, devtype),
                    last_ts=max(last_ts, excluded.last_ts)""", [(k, *v) for k, v in self.hosts.items()])
            for pid in self.pol_dirty:
                p = self.pol[pid]
                c.execute("""INSERT INTO policy VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(policyid) DO UPDATE SET
                    name=coalesce(excluded.name, name), uuid=coalesce(excluded.uuid, uuid), ptype=coalesce(excluded.ptype, ptype),
                    dir=excluded.dir, applists=excluded.applists, first_ts=min(first_ts, excluded.first_ts),
                    last_ts=max(last_ts, excluded.last_ts), n=n+excluded.n""",
                          (pid, p['name'], p['uuid'], p['ptype'], p['dir'], ','.join(sorted(p['applists'])),
                           p['first'], p['last'], p['n']))
                p['n'] = 0
            if index_points:
                c.executemany('INSERT OR IGNORE INTO file_index VALUES (?,?,?)', index_points)
            c.execute('UPDATE files SET off=?, lines=lines+?, first_ts=coalesce(first_ts, ?), last_ts=? WHERE fid=?',
                      (off, lines, first_ts, self.max_ts or None, fid))
            c.execute("INSERT OR REPLACE INTO meta VALUES ('last_commit', ?), ('last_event_ts', ?)",
                      (str(int(time.time() * 1000)), str(self.max_ts)))
            if self.device_dirty:
                c.execute("INSERT OR REPLACE INTO meta VALUES ('device', ?)", (json.dumps(self.device),))
                self.device_dirty = False
            c.execute('COMMIT')
        except BaseException:
            c.execute('ROLLBACK')
            raise
        self.rows.clear()
        for acc in self.r.values():
            acc.clear()
        self.seen_src.clear(); self.seen_dom.clear(); self.hosts.clear(); self.pol_dirty.clear()

    def note_progress(self, path, off, rate):
        """Publish where ingest is and how fast, so the UI can show backfill progress and a time estimate."""
        self.con.execute("INSERT OR REPLACE INTO meta VALUES ('ingest_progress', ?)",
                         (json.dumps({'path': path, 'off': off, 'rate': round(rate), 'lines': self.lines,
                                      'at': int(time.time() * 1000)}),))
        self.inb.clear(); self.web.clear()
        # hourly distinct sets: keep only the current and previous hour
        cut = self.max_ts - self.max_ts % H1 - H1
        for dct in (self.deny_ports, self.deny_srcs):
            for k in [k for k in dct if k[0] < cut]:
                del dct[k]

    def _flush_noise(self):
        """Hourly deny rows plus their daily roll-up (distinct counts: daily keeps the max hourly value)."""
        src_h, src_d = [], {}
        for k, v in self.r['r_deny_src_1h'].items():
            ports = self.deny_ports.get(k, ())
            row = (*k, v[4], v[0], len(ports), ','.join(map(str, sorted(ports)[:12])))
            src_h.append(row)
            dk = (k[0] - k[0] % DAY, *k[1:])
            prev = src_d.get(dk)
            src_d[dk] = row[4:] if prev is None else (row[4], prev[1] + v[0], max(prev[2], len(ports)), row[7])
        upd = 'country=excluded.country, n=n+excluded.n, ports=max(ports, excluded.ports), psample=excluded.psample'
        self._upsert('r_deny_src_1h', upd, src_h)
        self._upsert('r_deny_src_1d', upd, [(*k, *v) for k, v in src_d.items()])
        port_h, port_d = [], {}
        for k, v in self.r['r_deny_port_1h'].items():
            srcs = len(self.deny_srcs.get(k, ()))
            port_h.append((*k, v[0], srcs))
            dk = (k[0] - k[0] % DAY, *k[1:])
            n, s = port_d.get(dk, (0, 0))
            port_d[dk] = (n + v[0], max(s, srcs))
        upd = 'n=n+excluded.n, srcs=max(srcs, excluded.srcs)'
        self._upsert('r_deny_port_1h', upd, port_h)
        self._upsert('r_deny_port_1d', upd, [(*k, *v) for k, v in port_d.items()])

    _pk = {}

    def _upsert(self, table, update, rows):
        if not rows:
            return
        pk = self._pk.get(table)
        if pk is None:
            pk = self._pk[table] = self.con.execute(
                f"SELECT group_concat(name) FROM pragma_table_info('{table}') WHERE pk > 0").fetchone()[0]
        self.con.executemany(f'INSERT INTO {table} VALUES ({",".join("?" * len(rows[0]))}) '
                             f'ON CONFLICT({pk}) DO UPDATE SET {update}', rows)


def _i(v):
    return -1 if v is None else v


def _ext(line):
    return line[line.find('CEF:'):].split('|', 7)[-1].rstrip('\n')[:4000]


# ---------------------------------------------------------------- files
def register(con, path):
    """Return (fid, off, done) for a file, creating its row if new; None if not yet identifiable."""
    head = file_head(path)
    if head is None:
        return None
    ino = os.stat(path).st_ino
    row = con.execute('SELECT fid, off, done FROM files WHERE head=?', (head,)).fetchone()
    if row:
        con.execute('UPDATE files SET path=?, ino=? WHERE fid=?', (path, ino, row[0]))
        return row
    cur = con.execute('INSERT INTO files(path, ino, head) VALUES (?,?,?)', (path, ino, head))
    return cur.lastrowid, 0, 0


def ingest_file(con, ing, path, fid, off, follow, batch, on_idle=lambda: None):
    """Read path from byte offset `off`; with follow=True keep reading until the path is rotated away."""
    gz = path.endswith('.gz')
    fh = gzip.open(path, 'rb') if gz else open(path, 'rb')
    ino = None if gz else os.fstat(fh.fileno()).st_ino
    if off:
        if gz:
            while off - fh.tell() > 0:
                fh.read(min(1 << 24, off - fh.tell()))
        else:
            fh.seek(off)
    pending, lines, idx, first_ts = b'', 0, [], None
    last_commit, last_note, rotated_at, last_off = time.time(), time.time(), None, off
    try:
        while not _stop:
            raw = fh.readline()
            if raw.endswith(b'\n'):
                raw, pending = pending + raw, b''
                ts = ing.handle(raw, fid, off)
                if ts is not None and first_ts is None:
                    first_ts = ts
                if ts is not None and (ing.lines % INDEX_EVERY == 0):
                    idx.append((fid, ts, off))
                off += len(raw)
                lines += 1
                ing.lines += 1
                if lines >= batch or (follow and time.time() - last_commit > 2):
                    ing.flush(fid, off, lines, idx, first_ts)
                    lines, idx, last_commit = 0, [], time.time()
                if time.time() - last_note > 30:
                    now_t = time.time()
                    rate = (off - last_off) / max(0.001, now_t - last_note)      # bytes/s over the last half minute
                    ing.note_progress(path, off, rate)
                    left = backfill_left(ing.con, rate)
                    log.info('%s: %d lines total, at %s (%.1f MB/s)%s', path, ing.lines,
                             time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ing.max_ts / 1000)),
                             rate / 2**20, f' - history {left}' if left else '')
                    last_note, last_off = now_t, off
                continue
            pending += raw                    # partial line at EOF: keep, wait for the rest
            if not follow:
                break
            if lines:
                ing.flush(fid, off, lines, idx, first_ts)
                lines, idx, last_commit = 0, [], time.time()
            on_idle()
            try:
                st = os.stat(path)
                moved = st.st_ino != ino
                if not moved and st.st_size < off:             # rotated with copytruncate: same file, emptied
                    log.info('%s: truncated in place (copytruncate rotation), starting again from the top', path)
                    break
            except FileNotFoundError:
                moved = True
            if moved:
                rotated_at = rotated_at or time.time()
                if time.time() - rotated_at > 5:   # drained the old inode for 5 s after rotation
                    break
            time.sleep(0.5)
    finally:
        if lines:
            ing.flush(fid, off, lines, idx, first_ts)
        fh.close()
    return off


def prune(con):
    now = int(time.time() * 1000)
    free = shutil.disk_usage(os.path.dirname(db.DB_PATH)).free
    days = dict(db.RETENTION)
    for t in ('traffic', 'utm_app', 'utm_web', 'utm_ips', 'utm_av', 'utm_other', 'event'):
        days[t] = max(1, int(settings.load().get('retention_days') or 30))
    if free < DISK_MIN_FREE:
        oldest = con.execute('SELECT min(ts) FROM traffic').fetchone()[0]
        if oldest:
            days['traffic'] = max(7, (now - oldest) // DAY - 1)
            log.warning('disk free %.1f GB < %.0f GB: traffic retention cut to %d days',
                        free / 2**30, DISK_MIN_FREE / 2**30, days['traffic'])
    for table, keep in days.items():
        col, cutoff = db.TS_COL[table], now - keep * DAY
        if table.startswith('r_') or table == 'file_index':
            con.execute(f'DELETE FROM {table} WHERE {col} < ?', (cutoff,))
            continue
        while not _stop:
            n = con.execute(f'DELETE FROM {table} WHERE rowid IN '
                            f'(SELECT rowid FROM {table} WHERE ts < ? LIMIT 50000)', (cutoff,)).rowcount
            if n < 50000:
                break
    con.execute('DELETE FROM seen_src WHERE last_ts < ?', (now - 90 * DAY,))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('last_prune', ?), ('disk_free', ?)", (str(now), str(free)))


def backfill_cfg_changes(con):
    """One-time: copy configuration-change events already stored in `event` (30-day retention) into cfg_change."""
    if con.execute("SELECT 1 FROM meta WHERE k = 'cfg_change_backfill'").fetchone():
        return
    rows = []
    for ts, ext, fid, off in con.execute("SELECT ts, ext, fid, off FROM event WHERE ext LIKE '%FTNTFGTcfgpath=%'"):
        r = cfglive.row(cfglive.ext_fields(ext), ts, fid, off)
        if r:
            rows.append(r)
    con.execute('BEGIN')
    con.executemany(f'INSERT OR IGNORE INTO cfg_change VALUES ({",".join("?" * 13)})', rows)
    con.execute("INSERT OR REPLACE INTO meta VALUES ('cfg_change_backfill', ?)", (str(int(time.time() * 1000)),))
    con.execute('COMMIT')
    log.info('cfg_change: back-filled %d configuration changes from the event table', len(rows))


def run(follow):
    con = db.connect()
    backfill_cfg_changes(con)
    ing = Ingest(con)
    batch = 5_000 if follow else 100_000
    last_prune = 0

    def maybe_prune():
        nonlocal last_prune
        if time.time() - last_prune > 3600:
            prune(con)
            last_prune = time.time()

    while not _stop:
        for path in log_files():
            if _stop or not os.path.exists(path):
                continue
            reg = register(con, path)
            if reg is None:
                continue
            fid, off, done = reg
            live = path == LOG_BASE
            if (not live and not done and off == 0 and settings.BACKFILL_DAYS > 0
                    and os.path.getmtime(path) < time.time() - settings.BACKFILL_DAYS * 86400):
                con.execute('UPDATE files SET done=1 WHERE fid=?', (fid,))     # older than the first-start window
                log.info('%s: skipped (last written more than %g days ago, VIGIL_BACKFILL_DAYS)', path, settings.BACKFILL_DAYS)
                continue
            if done or (not live and not path.endswith('.gz') and off >= os.path.getsize(path)):
                if not live and not done:
                    con.execute('UPDATE files SET done=1 WHERE fid=?', (fid,))
                continue
            if path.endswith('.gz') and off > 0:
                log.info('%s: resuming inside compressed file at %d', path, off)
            log.info('%s: ingest from offset %d', path, off)
            end = ingest_file(con, ing, path, fid, off, follow and live, batch, maybe_prune)
            if not _stop and (not live or follow):     # EOF of a rotated file, or the live file rotated away
                con.execute('UPDATE files SET done=1, off=? WHERE fid=?', (end, fid))
                log.info('%s: done at offset %d', path, end)
        maybe_prune()
        if not follow:
            break
        time.sleep(1)
    log.info('stopped; %d lines this run, last event %s', ing.lines,
             time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ing.max_ts / 1000)) if ing.max_ts else '-')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    m = ap.add_mutually_exclusive_group(required=True)
    m.add_argument('--backfill', action='store_true')
    m.add_argument('--tail', action='store_true')
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    lock = open(LOCK_PATH, 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('another forti-ingest is running (lock %s) - stop the service before --backfill' % LOCK_PATH)
    run(follow=a.tail)


if __name__ == '__main__':
    main()
