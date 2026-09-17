"""Import a FortiGate configuration backup (FortiOS CLI `.conf` or YAML) for rule analysis.

Only the sections Vigil needs are kept (policies, local-in policies, addresses, groups, VIPs, services, sensor names,
interfaces, admin and SSL-VPN ports) and every secret-looking value is removed before anything is written to disk:
passwords, pre-shared keys, private keys, certificates, tokens, SNMP communities and all `ENC ...` values.
Multi-VDOM backups: global settings plus the chosen VDOM (default `root`).
"""
import re
import shlex
import time

import yaml

KEEP = {
    'system_global': {'hostname', 'admin-sport', 'admin-port', 'admin-ssh-port', 'admin-https-redirect', 'timezone', 'alias'},
    'system_interface': {'ip', 'allowaccess', 'role', 'alias', 'type', 'vdom', 'status', 'interface', 'vlanid', 'description'},
    'vpn_ssl_settings': {'status', 'port', 'source-interface', 'source-address', 'source-address-negate'},
    'firewall_policy': None, 'firewall_local-in-policy': None, 'firewall_address': None, 'firewall_addrgrp': None,
    'firewall_vip': None, 'firewall_vipgrp': None, 'firewall_service_custom': None, 'firewall_service_group': None,
    'application_list': set(), 'ips_sensor': set(), 'webfilter_profile': set(), 'antivirus_profile': set(),
}
SECRET_KEY = re.compile(r'pass|secret|psk|private|key|cert|token|community|auth-pwd|md5|sha|cookie|hash|salt', re.I)
INT_FIELDS = {'admin-sport', 'admin-port', 'admin-ssh-port', 'port'}
HEADER = re.compile(r'#config-version=([A-Z0-9]+)-(\d+)\.(\d+)-FW-build(\d+)')


class ConfigError(ValueError):
    pass


# ---------------------------------------------------------------- CLI format
def _logical_lines(text):
    """Join lines that are inside an open double quote (certificates, long comments)."""
    buf = ''
    for raw in text.splitlines():
        buf = f'{buf}\n{raw}' if buf else raw
        if _quote_open(buf):
            continue
        yield buf.strip()
        buf = ''
    if buf:
        yield buf.strip()


def _quote_open(s):
    n, esc = 0, False
    for ch in s:
        if esc:
            esc = False
        elif ch == '\\':
            esc = True
        elif ch == '"':
            n += 1
    return n % 2 == 1


def parse_cli(text):
    root = {}
    stack = [('node', root)]                      # ('config', dict) | ('edit', dict) | ('node', dict)
    for line in _logical_lines(text):
        if not line or line.startswith('#'):
            continue
        try:
            tok = shlex.split(line, posix=True)
        except ValueError:
            continue
        cmd = tok[0]
        kind, cur = stack[-1]
        if cmd == 'config' and len(tok) >= 2:
            name = ' '.join(tok[1:])
            node = cur.setdefault(name, {'__edits__': None})
            stack.append(('config', node))
        elif cmd == 'edit' and len(tok) >= 2 and kind == 'config':
            if cur.get('__edits__') is None:
                cur['__edits__'] = {}
            node = cur['__edits__'].setdefault(tok[1], {})
            stack.append(('edit', node))
        elif cmd == 'set' and len(tok) >= 2:
            vals = tok[2:]
            cur[tok[1]] = vals[0] if len(vals) == 1 else vals
        elif cmd == 'next' and kind == 'edit':
            stack.pop()
        elif cmd == 'end':
            while stack and stack[-1][0] == 'edit':         # tolerate a missing "next"
                stack.pop()
            if len(stack) > 1:
                stack.pop()
    return _normalise(root)


def _normalise(node):
    """{'__edits__': {id: {...}}} -> [{id: {...}}]; settings blocks -> dict; nested configs recursively."""
    if not isinstance(node, dict):
        return node
    edits = node.get('__edits__')
    attrs = {k: _normalise(v) for k, v in node.items() if k != '__edits__'}
    if edits is not None:
        return [{k: _normalise(v)} for k, v in edits.items()]
    return attrs


# ---------------------------------------------------------------- filtering
def _clean_value(v):
    if isinstance(v, list):
        return [x for x in (_clean_value(i) for i in v) if x is not None]
    if isinstance(v, str) and (v.startswith('ENC ') or v.startswith('-----BEGIN')):
        return None
    return v


def _clean_attrs(attrs, allowed):
    out = {}
    for k, v in (attrs or {}).items():
        if isinstance(v, (dict, list)) and not isinstance(v, list) or (isinstance(v, list) and v and isinstance(v[0], dict)):
            continue                                        # nested config blocks (entries, dns-entry...) are not needed
        if allowed is not None and k not in allowed:
            continue
        if SECRET_KEY.search(k) and k not in ('ips-sensor', 'application-list', 'ssl-ssh-profile', 'webfilter-profile',
                                              'av-profile', 'dnsfilter-profile', 'emailfilter-profile', 'file-filter-profile'):
            continue
        v = _clean_value(v)
        if v is None:
            continue
        if k in INT_FIELDS and isinstance(v, str) and v.isdigit():
            v = int(v)
        out[k] = v
    return out


def _filter(tree):
    out = {}
    for sec, allowed in KEEP.items():
        v = tree.get(sec)
        if v is None:
            continue
        if isinstance(v, list):
            out[sec] = [{k: _clean_attrs(a, allowed)} for item in v for k, a in item.items()]
        elif isinstance(v, dict):
            out[sec] = _clean_attrs(v, allowed)
    return out


def _flatten_cli(tree, vdom):
    """CLI tree -> {'firewall_policy': [...], ...}; multi-VDOM: global + chosen VDOM."""
    def keyed(t):
        return {k.replace(' ', '_'): v for k, v in t.items()}
    if 'vdom' in tree and isinstance(tree['vdom'], list):
        vdoms = {k: v for item in tree['vdom'] for k, v in item.items() if isinstance(v, dict) and v}
        chosen = vdoms.get(vdom) or next(iter(vdoms.values()), {})
        merged = keyed(tree.get('global') or {})
        merged.update(keyed(chosen))
        return merged, sorted(vdoms)
    return keyed(tree), []


# ---------------------------------------------------------------- entry point
def import_backup(data, filename='backup.conf', backup_ms=None, vdom='root'):
    """bytes/str of a FortiOS backup -> (clean dict ready to save as YAML, summary). Raises ConfigError."""
    text = data.decode('utf-8', 'replace') if isinstance(data, bytes) else data
    if len(text) < 20:
        raise ConfigError('The file is empty.')
    head = text[:4096]
    info = {'filename': filename, 'format': None, 'model': None, 'version': None, 'build': None, 'vdoms': []}
    m = HEADER.search(head)
    if m:
        info.update(model=m.group(1), version=f'{int(m.group(2))}.{int(m.group(3))}', build=m.group(4))
    if 'config firewall policy' in text or head.lstrip().startswith('#config-version'):
        info['format'] = 'cli'
        tree, info['vdoms'] = _flatten_cli(parse_cli(text), vdom)
    else:
        try:
            tree = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ConfigError(f'Not a FortiOS configuration backup (CLI or YAML): {e}') from e
        if not isinstance(tree, dict):
            raise ConfigError('Not a FortiOS configuration backup (CLI or YAML).')
        info['format'] = 'yaml'
    clean = _filter(tree)
    if not clean.get('firewall_policy'):
        raise ConfigError('No firewall policies found - is this a full configuration backup of the right VDOM?')
    now = int(time.time() * 1000)
    clean = {'_source': filename, '_backup_ms': int(backup_ms or now), '_uploaded_ms': now,
             '_model': info['model'], '_version': info['version'], **clean}
    info.update(policies=len(clean.get('firewall_policy') or []), local_in=len(clean.get('firewall_local-in-policy') or []),
                addresses=len(clean.get('firewall_address') or []), vips=len(clean.get('firewall_vip') or []),
                hostname=(clean.get('system_global') or {}).get('hostname'))
    return clean, info


def dump(clean):
    return yaml.safe_dump(clean, sort_keys=False, allow_unicode=True, width=200)
