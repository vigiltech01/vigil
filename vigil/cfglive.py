"""Live FortiGate configuration from the logs: the YAML backup is the baseline, and every configuration change the
FortiGate logged afterwards is replayed on top of it in order.

FortiOS logs each GUI / CLI / API change as event:system logid 0100044547 "Object attribute configured":
    act=Edit|Add|Delete|Move  FTNTFGTcfgpath=firewall.policy  FTNTFGTcfgobj=21  FTNTFGTcfgattr=status[enable->disable]
    duser=<admin>  sproc=jsconsole(<ip>) | sso(<ip>) | GUI(<ip>) ...
Singleton settings (vpn.ssl.settings, system.global) come without cfgobj.

Replay is order-preserving and idempotent (every edit sets the logged new value), so replaying a few hours before the
backup time is harmless and covers time-zone uncertainty in the backup file name.

What the logs cannot tell: the new position of a moved or newly added rule ("Move" carries no position), changes made
while logs were not received, and bulk operations such as a configuration restore. Those are reported, not guessed.
"""
import copy
import os
import re
import time
from collections import OrderedDict

from .cef import to_int

KEY_SPLIT = re.compile(r'(?:^|\s)(\w+)=')
ATTR = re.compile(r'([a-z0-9][\w-]*)\[(.*?)\](?=[a-z0-9][\w-]*\[|\s*$)', re.S)
TABLES = {'firewall.policy': 'firewall_policy', 'firewall.local-in-policy': 'firewall_local-in-policy',
          'firewall.address': 'firewall_address', 'firewall.addrgrp': 'firewall_addrgrp', 'firewall.vip': 'firewall_vip',
          'firewall.vipgrp': 'firewall_vipgrp', 'firewall.service.custom': 'firewall_service_custom',
          'firewall.service.group': 'firewall_service_group', 'system.interface': 'system_interface',
          'application.list': 'application_list', 'ips.sensor': 'ips_sensor'}
SINGLE = {'vpn.ssl.settings': 'vpn_ssl_settings', 'system.global': 'system_global'}
RULE_PATHS = ('firewall.policy', 'firewall.local-in-policy')
LIST_FIELDS = {'srcaddr', 'dstaddr', 'srcaddr6', 'dstaddr6', 'service', 'srcintf', 'dstintf', 'intf', 'member',
               'internet-service-src-name', 'internet-service-name', 'internet-service-src-group', 'allowaccess',
               'mappedip', 'groups', 'users', 'poolname'}
INT_FIELDS = {'admin-sport', 'admin-port', 'admin-ssh-port', 'port'}
RISK_FIELDS = {'status', 'action', 'srcaddr', 'dstaddr', 'service', 'srcintf', 'dstintf', 'srcaddr-negate', 'utm-status',
               'ips-sensor', 'application-list', 'av-profile', 'webfilter-profile', 'internet-service-src-name',
               'internet-service-src', 'intf', 'allowaccess', 'admin-sport', 'extip', 'mappedip', 'member', 'subnet',
               'type', 'country', 'tcp-portrange', 'udp-portrange'}
LABEL = {'srcaddr': 'Source', 'dstaddr': 'Destination', 'service': 'Service', 'srcintf': 'From interface',
         'dstintf': 'To interface', 'application-list': 'App control', 'ips-sensor': 'IPS', 'av-profile': 'Antivirus',
         'webfilter-profile': 'Web filter', 'ssl-ssh-profile': 'SSL inspection', 'internet-service-src-name': 'Source internet service',
         'member': 'Members', 'allowaccess': 'Management access', 'schedule': 'Schedule', 'nat': 'NAT', 'comments': 'Comment'}
# YAML backups omit values that are at their FortiOS default
DEFAULTS = {'status': 'enable', 'action': 'deny', 'utm-status': 'disable', 'srcaddr-negate': 'disable',
            'dstaddr-negate': 'disable', 'service-negate': 'disable', 'nat': 'disable', 'logtraffic': 'utm',
            'internet-service-src': 'disable', 'internet-service': 'disable'}
TEXT_FIELDS = {'comment', 'comments', 'description', 'name'}       # free text may itself contain '->'
BUILTIN_NAMES = {'all', 'ALL', 'ALL_TCP', 'ALL_UDP', 'ALL_ICMP', 'any', 'none', 'always'}
DEVICE_TZ_H = float(os.environ.get('VIGIL_DEVICE_TZ_HOURS', '0'))      # FortiGate clock offset, only for backup file names
REPLAY_MARGIN_MS = 6 * 3_600_000


# ---------------------------------------------------------------- ingest side
def ext_fields(ext):
    kv = KEY_SPLIT.split(ext or '')
    return {k: v.strip() for k, v in zip(kv[1::2], kv[2::2])}


def row(d, ts, fid, off):
    """cfg_change row for a parsed CEF record, or None if it is not a configuration change."""
    path = d.get('FTNTFGTcfgpath')
    if not path:
        return None
    return (ts, d.get('FTNTFGTeventtime') or str(ts * 1_000_000), to_int(d.get('FTNTFGTcfgtid')), d.get('act'), path,
            d.get('FTNTFGTcfgobj'), d.get('FTNTFGTcfgattr'), d.get('duser') or d.get('suser') or d.get('FTNTFGTuser'),
            d.get('sproc') or d.get('FTNTFGTui'), d.get('FTNTFGTlogid'), d.get('msg'), fid, off)


# ---------------------------------------------------------------- parsing
def parse_attr(text):
    """'status[enable->disable]srcaddr[a b->c]' -> [(name, old or None, new)]"""
    out = []
    for m in ATTR.finditer(text or ''):
        name, val = m.group(1), m.group(2)
        if '->' in val:
            old, new = val.split('->', 1)
        else:
            old, new = None, val
        out.append((name, old, new))
    return out


def split_names(s, known):
    """Space-separated object names where names may themselves contain spaces ('India USA' vs 'India' 'USA'):
    fewest pieces made of known names; unknown single words are kept but cost more."""
    toks = [t for t in (s or '').split(' ') if t]
    n = len(toks)
    best = [None] * (n + 1)
    best[0] = (0, [])
    for i in range(n):
        if best[i] is None:
            continue
        for j in range(i + 1, min(n, i + 8) + 1):
            cand = ' '.join(toks[i:j])
            cost = 1 if cand in known else (3 if j == i + 1 else None)
            if cost is None:
                continue
            c = (best[i][0] + cost, best[i][1] + [cand])
            if best[j] is None or c[0] < best[j][0]:
                best[j] = c
    return best[n][1] if n else []


def _value(name, raw, known):
    if raw is None or raw == '':
        return None
    if name in LIST_FIELDS:
        return split_names(raw, known)
    if name in INT_FIELDS and raw.isdigit():
        return int(raw)
    return raw


def _norm(v):
    """Comparable form: the YAML backup stores a one-element list as a plain scalar ('all'), the log parser as ['all']."""
    if v is None or v == '' or v == []:
        return None
    return tuple(sorted(str(x) for x in v)) if isinstance(v, list) else (str(v),)


# ---------------------------------------------------------------- replay
def baseline_ms(source):
    """Backup file name FGT-EDGE_7-4_2829_202601150930.conf -> epoch ms (device local time -> UTC)."""
    m = re.search(r'_(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})\.conf', source or '')
    if not m:
        return None
    import calendar
    t = calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0, 0))
    return int((t - DEVICE_TZ_H * 3600) * 1000)


def _known(state, singles):
    k = set(BUILTIN_NAMES)
    for sec in ('firewall_address', 'firewall_addrgrp', 'firewall_vip', 'firewall_vipgrp', 'firewall_service_custom',
                'firewall_service_group', 'system_interface'):
        k.update(state[sec].keys())
    return k


def build(d, changes):
    """Replay change rows (dicts, oldest first) over the YAML dict d. Returns (new dict, change records)."""
    state = {sec: OrderedDict((str(k), copy.deepcopy(v or {})) for item in (d.get(sec) or []) if isinstance(item, dict)
                              for k, v in item.items())
             for sec in TABLES.values()}
    singles = {sec: copy.deepcopy(d.get(sec) or {}) for sec in SINGLE.values()}
    known = _known(state, singles)
    records = []
    for c in changes:
        path, obj, act = c['path'] or '', c['obj'], (c['act'] or '').lower()
        attrs = parse_attr(c['attr'])
        rec = {'ts': c['ts'], 'user': c['usr'], 'via': c['ui'], 'act': c['act'], 'path': path, 'obj': obj,
               'attrs': [{'name': n, 'old': o, 'new': v} for n, o, v in attrs if o is None or o != v]}
        base = path.split(':', 1)[0]
        sec = TABLES.get(path) or SINGLE.get(path)
        if ':' in path:
            rec['status'] = 'sub-setting (not modelled)'
        elif sec is None:
            rec['status'] = 'not used for scoring'
        elif path in SINGLE:
            target = singles[sec]
            rec['status'] = _apply_attrs(target, attrs, known)
        elif act == 'delete':
            rec['status'] = 'applied' if state[sec].pop(str(obj), None) is not None else 'already absent'
            known.discard(str(obj))
        elif act == 'move':
            rec['status'] = 'order unknown'
        else:
            tbl = state[sec]
            if str(obj) not in tbl:
                if act == 'add':
                    tbl[str(obj)] = {}
                    if path in RULE_PATHS:
                        rec['order_unknown'] = True
                else:
                    rec['status'] = 'object not in backup'
            if 'status' not in rec:
                st = _apply_attrs(tbl[str(obj)], attrs, known)
                rec['status'] = 'applied' if act == 'add' else st
                if sec in ('firewall_address', 'firewall_addrgrp', 'firewall_vip', 'firewall_vipgrp',
                           'firewall_service_custom', 'firewall_service_group'):
                    known.add(str(obj))
        rec['risk'] = any(a['name'] in RISK_FIELDS for a in rec['attrs']) or act in ('add', 'delete', 'move')
        rec['text'] = describe(rec)
        for a in rec['attrs']:                                   # keep API payloads small (member lists can be huge)
            a['old'] = a['old'][:300] if a['old'] else a['old']
            a['new'] = a['new'][:300] if a['new'] else a['new']
        records.append(rec)
    out = dict(d)
    for sec, tbl in state.items():
        if sec in d or tbl:
            out[sec] = [{k: v} for k, v in tbl.items()]
    for sec, v in singles.items():
        if sec in d or v:
            out[sec] = v
    return out, records


def _apply_attrs(target, attrs, known):
    """Set the logged new values. 'backup differed' = the value before the change was neither the logged old value
    nor already the new one (a change was missed, or the object differs from the backup)."""
    differs = False
    for name, old, new in attrs:
        cur = target.get(name)
        newv = _value(name, new, known)
        if old is not None and old != new and name not in TEXT_FIELDS and _norm(cur) != _norm(newv):
            if _norm(cur if cur is not None else DEFAULTS.get(name)) != _norm(_value(name, old, known)):
                differs = True
        if newv is None:
            target.pop(name, None)
        else:
            target[name] = newv
    return 'applied (backup differed)' if differs else 'applied'


# ---------------------------------------------------------------- plain words
def _obj_label(path, obj):
    if path == 'firewall.policy':
        return f'Rule {obj}'
    if path == 'firewall.local-in-policy':
        return f'Local-in rule {obj}'
    kind = {'firewall.address': 'Address', 'firewall.addrgrp': 'Address group', 'firewall.vip': 'VIP',
            'firewall.vipgrp': 'VIP group', 'firewall.service.custom': 'Service', 'firewall.service.group': 'Service group',
            'system.interface': 'Interface', 'application.list': 'App control sensor', 'ips.sensor': 'IPS sensor',
            'vpn.ssl.settings': 'SSL-VPN settings', 'system.global': 'Global settings'}.get(path.split(':')[0], path)
    return f'{kind} {obj}' if obj else kind


def describe(rec):
    act = (rec['act'] or '').lower()
    who = _obj_label(rec['path'], rec['obj'])
    if act == 'delete':
        return f'{who} deleted'
    if act == 'move':
        return f'{who} moved (the new position is not in the log)'
    parts = []
    attrs = {a['name']: a for a in rec['attrs']}
    if act == 'add':
        keys = [k for k in ('action', 'status', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'ips-sensor',
                            'application-list') if k in attrs]
        desc = ', '.join(f"{LABEL.get(k, k)} {attrs[k]['new']}" for k in keys)
        return f'{who} created' + (f': {desc}' if desc else '')
    for a in rec['attrs']:
        n, o, v = a['name'], a['old'], a['new']
        if n == 'status':
            parts.append('disabled' if v == 'disable' else 'enabled' if v == 'enable' else f'status {v}')
        elif n == 'action':
            parts.append(f'action {o or "?"} → {v}')
        elif n == 'utm-status':
            parts.append('security profiles turned ' + ('on' if v == 'enable' else 'off'))
        elif n in ('srcaddr', 'dstaddr', 'service', 'member', 'srcintf', 'dstintf', 'allowaccess', 'internet-service-src-name'):
            ov, nv = set((o or '').split(' ')), set((v or '').split(' '))
            add, rem = [x for x in (v or '').split(' ') if x and x not in ov], [x for x in (o or '').split(' ') if x and x not in nv]
            if not add and not rem:
                continue
            short = lambda xs: ' '.join(xs[:8]) + (f' (+{len(xs) - 8} more)' if len(xs) > 8 else '')
            parts.append(f"{LABEL.get(n, n).lower()}: " + ', '.join(filter(None, ['+ ' + short(add) if add else '',
                                                                                  '− ' + short(rem) if rem else ''])))
        elif n in ('application-list', 'ips-sensor', 'av-profile', 'webfilter-profile', 'ssl-ssh-profile'):
            lbl = LABEL.get(n, n)
            parts.append(f'{lbl} removed (was {o})' if not v else f'{lbl} set to {v}' if not o else f'{lbl} {o} → {v}')
        elif n == 'name':
            parts.append(f'renamed to “{v}”')
        elif n in ('comment', 'comments', 'description'):
            parts.append('comment changed')
        elif n in ('uuid', 'uuid-idx'):
            continue
        else:
            parts.append(f"{LABEL.get(n, n)} {o} → {v}" if o is not None else f"{LABEL.get(n, n)} = {v}")
    return f"{who}: {'; '.join(parts)}" if parts else f'{who} edited (no effective change)'


# ---------------------------------------------------------------- dashboard side
_ver = {'t': 0, 'v': None}


def version():
    """Cheap change detector: (rows, newest rowid) of cfg_change, re-read at most every 3 s."""
    if time.time() - _ver['t'] < 3 and _ver['v'] is not None:
        return _ver['v']
    from .queries import q
    try:
        r = q('SELECT count(*) AS n, max(rowid) AS m FROM cfg_change', one=True)
        v = (r.get('n') or 0, r.get('m') or 0)
    except Exception:
        v = (0, 0)
    _ver.update(t=time.time(), v=v)
    return v


CHUNK_HEAD = re.compile(r'^\[(\d{3})\]: ')
CHUNK_TAIL = re.compile(r' \[(\d{3})\]$')


def merge_chunks(rows):
    """FortiOS splits a cfgattr longer than ~1020 characters over several log lines: every part but the last ends with
    ' [NNN]' and the next part starts with '[NNN]: ' (words may be cut in the middle). Join them back into one change."""
    out, open_ = [], {}
    for r in rows:
        key = (r['cfgtid'], r['path'], r['obj'], r['act'])
        attr = r['attr'] or ''
        m = CHUNK_HEAD.match(attr)
        if m and key in open_:
            g = open_[key]
            g['attr'] = CHUNK_TAIL.sub('', g['attr']) + attr[m.end():]
            if not CHUNK_TAIL.search(attr):
                del open_[key]
            continue
        r = dict(r)
        out.append(r)
        if CHUNK_TAIL.search(attr):
            open_[key] = r
    return out


def changes_since(ms):
    from .queries import q
    try:
        rows = q("""SELECT ts, tsn, cfgtid, act, path, obj, attr, usr, ui FROM cfg_change WHERE ts >= ?
                    ORDER BY ts, CAST(tsn AS INTEGER), rowid""", (ms,))
    except Exception:
        return []
    return merge_chunks(rows)
