"""Paths and user settings. Everything Vigil stores lives under VIGIL_DATA (default /data in the container).

    /data/vigil.db               SQLite database (logs, rollups, change history)
    /data/logs/fortigate.log     raw syslog written by the built-in receiver (rotated + gzipped)
    /host-logs/<file>            file input: the host's existing syslog file, mounted read-only (never modified)
    /data/config/fortigate.yaml  uploaded configuration backup, secrets removed (optional)
    /data/settings.json          settings edited in the UI
    /data/auth.json              admin account (password hash), created by the first-run setup
"""
import json
import os
import threading
import time

APP_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
DATA = os.environ.get('VIGIL_DATA', '/data')
DB_PATH = os.environ.get('VIGIL_DB', os.path.join(DATA, 'vigil.db'))
DEMO = os.environ.get('VIGIL_DEMO', '0') == '1'
# Where FortiGate logs come from:
#   receiver  the built-in syslog receiver (UDP/TCP 5514 in the container) writes /data/logs/fortigate.log
#   file      the host already runs a syslog server that receives the FortiGate (port 514 is taken) and writes a file;
#             Vigil reads that file and its .1 / .2.gz rotations read-only from the /host-logs mount, never writing to it
INPUT = os.environ.get('VIGIL_INPUT', 'receiver').strip().lower()
if INPUT not in ('receiver', 'file') or DEMO:            # demo traffic is sent to the built-in receiver
    INPUT = 'receiver'
if INPUT == 'file':
    LOG_DIR = os.environ.get('VIGIL_HOST_LOG_MOUNT', '/host-logs')
    LOG_BASE = os.path.join(LOG_DIR, os.environ.get('VIGIL_LOG_NAME') or 'syslog')
    HOST_LOG_FILE = os.environ.get('VIGIL_HOST_LOG_FILE') or LOG_BASE      # path as seen on the host (display only)
else:
    LOG_DIR = os.environ.get('VIGIL_LOG_DIR', os.path.join(DATA, 'logs'))
    LOG_BASE = os.environ.get('VIGIL_LOG', os.path.join(LOG_DIR, 'fortigate.log'))
    HOST_LOG_FILE = None
# First start: rotated files last modified more than this many days ago are skipped (a busy host keeps weeks of
# syslog on disk). 0 = read everything. Default: 1 day for an existing host file, everything for the receiver.
BACKFILL_DAYS = float(os.environ.get('VIGIL_BACKFILL_DAYS') or ('1' if INPUT == 'file' else '0'))
CONFIG_PATH = os.environ.get('VIGIL_CONFIG', os.path.join(DATA, 'config', 'fortigate.yaml'))
SETTINGS_PATH = os.path.join(DATA, 'settings.json')
AUTH_PATH = os.path.join(DATA, 'auth.json')

DEFAULTS = {
    # shown in the UI; learned from the logs when empty
    'firewall_name': '',
    # interface name -> {"role": "wan|lan|dmz", "subnet": "10.0.0.0/24", "label": "..."} (optional, improves hop view)
    'interfaces': {},
    # VPN client pools (CIDR list) so VPN users are recognised in investigations
    'vpn_pools': [],
    # policy id -> list of applications you expect on it (anything else is flagged as unexpected)
    'expected_apps': {},
    # outbound domain allow-list (root domains); domains outside it are highlighted on the Outbound page
    'domain_allowlist': [],
    # days of raw rows to keep (rollups are kept longer)
    'retention_days': int(os.environ.get('VIGIL_RETENTION_DAYS', '30')),
    # the timezone offset of the FortiGate clock, used only for backup file-name timestamps
    'device_tz_hours': 0,
}

_lock = threading.Lock()
_cache = {'t': 0, 'mtime': None, 'v': None}


def load():
    """Settings merged over the defaults (re-read at most every 5 s)."""
    now = time.time()
    if _cache['v'] is not None and now - _cache['t'] < 5:
        return _cache['v']
    try:
        mt = os.path.getmtime(SETTINGS_PATH)
    except OSError:
        mt = None
    if mt != _cache['mtime'] or _cache['v'] is None:
        user = {}
        if mt is not None:
            try:
                with open(SETTINGS_PATH) as f:
                    user = json.load(f)
            except (OSError, ValueError):
                user = {}
        v = dict(DEFAULTS)
        v.update({k: user[k] for k in DEFAULTS if k in user})
        _cache.update(v=v, mtime=mt)
    _cache['t'] = now
    return _cache['v']


def save(patch):
    """Merge `patch` (known keys only) into settings.json atomically. Returns the new settings."""
    with _lock:
        cur = dict(load())
        for k, v in patch.items():
            if k in DEFAULTS:
                cur[k] = v
        os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
        tmp = SETTINGS_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({k: cur[k] for k in DEFAULTS}, f, indent=2)
        os.replace(tmp, SETTINGS_PATH)
        _cache.update(t=0, mtime=None, v=None)
        return load()


def ensure_dirs():
    for d in (DATA, os.path.dirname(CONFIG_PATH), os.path.dirname(DB_PATH)) + ((LOG_DIR,) if INPUT == 'receiver' else ()):
        os.makedirs(d, exist_ok=True)
