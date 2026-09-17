"""SQLite schema and connection helpers shared by ingest and dashboard."""
import os
import sqlite3

from . import settings

DB_PATH = settings.DB_PATH

# days to keep; raw tables are pruned by ts, rollups by bucket
RETENTION = {
    'traffic': 30, 'utm_app': 30, 'utm_web': 30, 'utm_ips': 30, 'utm_av': 30, 'utm_other': 30, 'event': 30,
    'r_1m': 35, 'r_pol_5m': 90, 'r_app_5m': 365, 'r_deny_5m': 365,
    'r_src_1h': 90, 'r_dom_1h': 90, 'r_in_1h': 90, 'r_web_1h': 90,
    'r_deny_src_1h': 3, 'r_deny_port_1h': 3, 'r_deny_src_1d': 90, 'r_deny_port_1d': 90,
    'file_index': 45, 'cfg_change': 400,
}
TS_COL = {t: ('b' if t.startswith('r_') else 'ts') for t in RETENTION}

SCHEMA = """
PRAGMA journal_mode=WAL;

-- raw rows (non-noise); fid/off point at the original line in /var/log/syslog*
CREATE TABLE IF NOT EXISTS traffic(
  ts INTEGER NOT NULL, kind TEXT, dir TEXT, inif TEXT, outif TEXT,
  src TEXT, spt INTEGER, dst TEXT, dpt INTEGER, tdst TEXT, tdpt INTEGER, proto INTEGER,
  policyid INTEGER, act TEXT, utmact TEXT, app TEXT, appcat TEXT,
  scountry TEXT, dcountry TEXT, isdb TEXT, shost TEXT,
  sent INTEGER, rcvd INTEGER, dur INTEGER, sess INTEGER, fid INTEGER, off INTEGER);
CREATE INDEX IF NOT EXISTS traffic_ts  ON traffic(ts);
CREATE INDEX IF NOT EXISTS traffic_pol ON traffic(policyid, ts);
CREATE INDEX IF NOT EXISTS traffic_src ON traffic(src, ts);

CREATE TABLE IF NOT EXISTS utm_app(
  ts INTEGER NOT NULL, dir TEXT, policyid INTEGER, applist TEXT, appid INTEGER, app TEXT, svc TEXT, appcat TEXT,
  apprisk TEXT, act TEXT, evtype TEXT, src TEXT, spt INTEGER, dst TEXT, dpt INTEGER, proto INTEGER,
  scountry TEXT, dhost TEXT, url TEXT, sess INTEGER, fid INTEGER, off INTEGER);
CREATE INDEX IF NOT EXISTS utm_app_ts  ON utm_app(ts);
CREATE INDEX IF NOT EXISTS utm_app_pol ON utm_app(policyid, ts);

CREATE TABLE IF NOT EXISTS utm_web(
  ts INTEGER NOT NULL, dir TEXT, policyid INTEGER, profile TEXT, evtype TEXT, act TEXT,
  src TEXT, spt INTEGER, dst TEXT, dpt INTEGER, dhost TEXT, root TEXT, url TEXT, method TEXT, reqapp TEXT,
  sent INTEGER, rcvd INTEGER, sess INTEGER, fid INTEGER, off INTEGER);
CREATE INDEX IF NOT EXISTS utm_web_ts   ON utm_web(ts);
CREATE INDEX IF NOT EXISTS utm_web_root ON utm_web(root, ts);

CREATE TABLE IF NOT EXISTS utm_ips(
  ts INTEGER NOT NULL, dir TEXT, policyid INTEGER, attack TEXT, attackid INTEGER, severity TEXT, level TEXT,
  act TEXT, src TEXT, spt INTEGER, dst TEXT, dpt INTEGER, proto INTEGER, scountry TEXT, dhost TEXT,
  url TEXT, profile TEXT, ref TEXT, sess INTEGER, fid INTEGER, off INTEGER);
CREATE INDEX IF NOT EXISTS utm_ips_ts ON utm_ips(ts);

CREATE TABLE IF NOT EXISTS utm_av(
  ts INTEGER NOT NULL, dir TEXT, policyid INTEGER, virus TEXT, act TEXT, level TEXT,
  src TEXT, dst TEXT, dpt INTEGER, dhost TEXT, url TEXT, filename TEXT, profile TEXT,
  sess INTEGER, fid INTEGER, off INTEGER);
CREATE INDEX IF NOT EXISTS utm_av_ts ON utm_av(ts);

-- low-volume categories kept with their full extension text
CREATE TABLE IF NOT EXISTS utm_other(
  ts INTEGER NOT NULL, cat TEXT, evtype TEXT, act TEXT, level TEXT, policyid INTEGER,
  src TEXT, dst TEXT, dpt INTEGER, dhost TEXT, msg TEXT, ext TEXT, fid INTEGER, off INTEGER);
CREATE INDEX IF NOT EXISTS utm_other_ts ON utm_other(ts);

CREATE TABLE IF NOT EXISTS event(
  ts INTEGER NOT NULL, cat TEXT, level TEXT, logdesc TEXT, act TEXT, usr TEXT,
  src TEXT, dst TEXT, msg TEXT, ext TEXT, fid INTEGER, off INTEGER);
CREATE INDEX IF NOT EXISTS event_ts ON event(ts);

-- rollups (b = bucket start, epoch ms). Every line counts in r_1m, noise included.
CREATE TABLE IF NOT EXISTS r_1m(b INTEGER, cat TEXT, act TEXT, n INTEGER,
  PRIMARY KEY(b, cat, act)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS r_pol_5m(b INTEGER, dir TEXT, policyid INTEGER, act TEXT, app TEXT,
  dpt INTEGER, proto INTEGER, country TEXT, n INTEGER, sent INTEGER, rcvd INTEGER,
  PRIMARY KEY(b, dir, policyid, act, app, dpt, proto, country)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS r_app_5m(b INTEGER, dir TEXT, policyid INTEGER, applist TEXT, app TEXT,
  act TEXT, evtype TEXT, n INTEGER,
  PRIMARY KEY(b, dir, policyid, applist, app, act, evtype)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS r_src_1h(b INTEGER, dir TEXT, policyid INTEGER, src TEXT, country TEXT,
  n INTEGER, drops INTEGER, sent INTEGER, rcvd INTEGER,
  PRIMARY KEY(b, dir, policyid, src)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS r_dom_1h(b INTEGER, src TEXT, root TEXT, dhost TEXT,
  n INTEGER, blocked INTEGER, sent INTEGER, rcvd INTEGER,
  PRIMARY KEY(b, src, root, dhost)) WITHOUT ROWID;

-- inbound (WAN-sourced, non-noise) sessions per source / server / port: rule evidence, brute-force detection
CREATE TABLE IF NOT EXISTS r_in_1h(b INTEGER, src TEXT, dst TEXT, dpt INTEGER, proto INTEGER, policyid INTEGER, country TEXT,
  n INTEGER, short INTEGER, drops INTEGER, bytes INTEGER, maxdur INTEGER, maxbytes INTEGER,
  PRIMARY KEY(b, src, dst, dpt, proto, policyid)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS r_in_1h_pol ON r_in_1h(policyid, b);
CREATE TABLE IF NOT EXISTS r_web_1h(b INTEGER, profile TEXT, evtype TEXT, act TEXT, n INTEGER,
  PRIMARY KEY(b, profile, evtype, act)) WITHOUT ROWID;

-- scanner noise (inbound/local-in denies): aggregates only, raw lines stay in /var/log/syslog*
-- ports/srcs are distinct counts within an hour (daily rows keep the max hourly value, i.e. a lower bound)
CREATE TABLE IF NOT EXISTS r_deny_5m(b INTEGER, cat TEXT, inif TEXT, policyid INTEGER,
  n INTEGER, PRIMARY KEY(b, cat, inif, policyid)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS r_deny_src_1h(b INTEGER, src TEXT, inif TEXT, policyid INTEGER, country TEXT,
  n INTEGER, ports INTEGER, psample TEXT, PRIMARY KEY(b, src, inif, policyid)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS r_deny_src_1d(b INTEGER, src TEXT, inif TEXT, policyid INTEGER, country TEXT,
  n INTEGER, ports INTEGER, psample TEXT, PRIMARY KEY(b, src, inif, policyid)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS r_deny_port_1h(b INTEGER, inif TEXT, dpt INTEGER, proto INTEGER, policyid INTEGER,
  n INTEGER, srcs INTEGER, PRIMARY KEY(b, inif, dpt, proto, policyid)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS r_deny_port_1d(b INTEGER, inif TEXT, dpt INTEGER, proto INTEGER, policyid INTEGER,
  n INTEGER, srcs INTEGER, PRIMARY KEY(b, inif, dpt, proto, policyid)) WITHOUT ROWID;

-- investigation tracker: session-id and destination lookups
CREATE INDEX IF NOT EXISTS traffic_sess ON traffic(sess);
CREATE INDEX IF NOT EXISTS traffic_dst  ON traffic(dst, ts);
CREATE INDEX IF NOT EXISTS traffic_tdst ON traffic(tdst, ts) WHERE tdst IS NOT NULL;
CREATE INDEX IF NOT EXISTS utm_app_sess ON utm_app(sess);
CREATE INDEX IF NOT EXISTS utm_app_src  ON utm_app(src, ts);
CREATE INDEX IF NOT EXISTS utm_app_dst  ON utm_app(dst, ts);
CREATE INDEX IF NOT EXISTS utm_web_sess ON utm_web(sess);
CREATE INDEX IF NOT EXISTS utm_web_src  ON utm_web(src, ts);
CREATE INDEX IF NOT EXISTS utm_web_dst  ON utm_web(dst, ts);
CREATE INDEX IF NOT EXISTS utm_web_pol  ON utm_web(policyid, ts);
CREATE INDEX IF NOT EXISTS utm_ips_sess ON utm_ips(sess);
CREATE INDEX IF NOT EXISTS r_deny_src_1h_src ON r_deny_src_1h(src, b);
CREATE INDEX IF NOT EXISTS r_deny_src_1d_src ON r_deny_src_1d(src, b);
CREATE INDEX IF NOT EXISTS utm_web_blocked ON utm_web(ts) WHERE act NOT IN ('passthrough', 'pass', 'allow');

-- configuration changes logged by the FortiGate (event:system "Object attribute configured"), kept long-term:
-- replayed over the config backup to keep Inbound Security live (cfglive.py)
CREATE TABLE IF NOT EXISTS cfg_change(ts INTEGER NOT NULL, tsn TEXT, cfgtid INTEGER, act TEXT, path TEXT, obj TEXT,
  attr TEXT, usr TEXT, ui TEXT, logid TEXT, msg TEXT, fid INTEGER, off INTEGER, UNIQUE(fid, off));
CREATE INDEX IF NOT EXISTS cfg_change_ts ON cfg_change(ts);

-- first/last seen
CREATE TABLE IF NOT EXISTS seen_src(src TEXT PRIMARY KEY, country TEXT, first_ts INTEGER, last_ts INTEGER,
  n_acc INTEGER DEFAULT 0, n_deny INTEGER DEFAULT 0, first_acc_ts INTEGER, last_acc_ts INTEGER) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS seen_dom(root TEXT PRIMARY KEY, first_ts INTEGER, last_ts INTEGER,
  n INTEGER DEFAULT 0, first_src TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS host(ip TEXT PRIMARY KEY, name TEXT, os TEXT, mac TEXT, vendor TEXT, devtype TEXT,
  last_ts INTEGER) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS policy(policyid INTEGER PRIMARY KEY, name TEXT, uuid TEXT, ptype TEXT,
  dir TEXT, applists TEXT, first_ts INTEGER, last_ts INTEGER, n INTEGER DEFAULT 0);

-- ingest bookkeeping
CREATE TABLE IF NOT EXISTS files(fid INTEGER PRIMARY KEY, path TEXT, ino INTEGER, head TEXT UNIQUE,
  off INTEGER DEFAULT 0, lines INTEGER DEFAULT 0, first_ts INTEGER, last_ts INTEGER, done INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS file_index(fid INTEGER, ts INTEGER, off INTEGER, PRIMARY KEY(fid, off)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


# SQLite memory guards. The heap limit is process-wide: a query that would exceed it fails with "out of memory"
# instead of pushing the VM into the kernel OOM killer.
HEAP_LIMIT_MB = int(os.environ.get('VIGIL_SQLITE_HEAP_MB', '1024'))


def connect(path=DB_PATH, readonly=False):
    if readonly:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=30, check_same_thread=False)
        con.execute('PRAGMA query_only=1')
        con.execute('PRAGMA cache_size=-16384')      # 16 MB per reader thread (the OS page cache does the heavy lifting)
        con.execute('PRAGMA temp_store=FILE')        # big sorts / GROUP BYs spill to disk, not RAM
    else:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        con = sqlite3.connect(path, timeout=60, isolation_level=None)
        con.executescript(SCHEMA)
        con.execute('PRAGMA synchronous=NORMAL')
        con.execute('PRAGMA cache_size=-65536')      # 64 MB
        con.execute('PRAGMA temp_store=MEMORY')
    con.execute('PRAGMA mmap_size=0')
    con.execute(f'PRAGMA soft_heap_limit={HEAP_LIMIT_MB * 3 // 4 << 20}')
    con.execute(f'PRAGMA hard_heap_limit={HEAP_LIMIT_MB << 20}')
    return con
