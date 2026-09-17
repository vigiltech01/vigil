"""FortiGate configuration model and static inbound-rule risk analysis.

Config file: /data/config/fortigate.yaml, written by the UI upload (Settings -> Firewall configuration) from a FortiOS
backup (.conf CLI text or YAML). Secrets are removed on upload; only policies, local-in policies, VIPs, addresses,
services, profiles, interfaces and admin/VPN ports are kept.
Defaults omitted by FortiOS backups: a policy without `action` is DENY, without `status` is enabled.
"""
import ipaddress
import os
import re
import threading
import time

import yaml

from . import cfglive, settings
from .threatkb import KB, classify_service

CONFIG_PATH = settings.CONFIG_PATH
LIVE = os.environ.get('VIGIL_CONFIG_LIVE', '1') == '1'        # replay logged configuration changes over the backup
_cache = {'mtime': None, 'd': None, 'key': None, 'model': None}
_lock = threading.Lock()


def _items(d, sec):
    out = []
    for e in d.get(sec) or []:
        if isinstance(e, dict) and len(e) == 1:
            (k, v), = e.items()
            out.append((str(k), v or {}))
    return out


def _list(v):
    if v is None:
        return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]


def _ports(spec):
    """'25 587' / '1-65535' / '80:1024-65535' / 8383 -> list of (lo, hi)."""
    out = []
    toks = [str(x) for x in spec] if isinstance(spec, list) else re.split(r'\s+', str(spec or '').strip())
    for tok in toks:
        if not tok:
            continue
        tok = tok.split(':')[0]
        lo, _, hi = tok.partition('-')
        try:
            out.append((int(lo), int(hi or lo)))
        except ValueError:
            pass
    return out


def _expand(ranges, limit=50):
    """(lo, hi) ranges -> individual ports; wide ranges (e.g. 1-65535) are skipped."""
    return [x for lo, hi in ranges if hi - lo < limit for x in range(lo, hi + 1)]


def load(path=None):
    """Configuration model = backup extract + every configuration change logged since (when LIVE).
    Rebuilt only when the file or the change log changes."""
    path = path or CONFIG_PATH
    if not os.path.exists(path):
        return None
    mt = os.path.getmtime(path)
    key = (path, mt, cfglive.version() if LIVE else None)
    if _cache['key'] == key:
        return _cache['model']
    with _lock:
        if _cache['key'] == key:
            return _cache['model']
        if _cache['mtime'] != (path, mt):
            with open(path) as f:
                _cache.update(d=yaml.safe_load(f), mtime=(path, mt))
        d = _cache['d']
        src = str(d.get('_source') or '')                # e.g. FGT-EDGE_7-4_2829_202601150930.conf
        dt = re.search(r'_(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})\.conf', src)
        base = int(d.get('_backup_ms') or 0) or cfglive.baseline_ms(src) or int(mt * 1000)
        records = []
        if LIVE:
            d, records = cfglive.build(d, cfglive.changes_since(base - cfglive.REPLAY_MARGIN_MS))
        m = Model(d)
        m.path = path
        m.backup = ('backup ' + time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(int(d['_backup_ms']) / 1000)) if d.get('_backup_ms') else
                    f'backup {dt.group(1)}-{dt.group(2)}-{dt.group(3)} {dt.group(4)}:{dt.group(5)}' if dt else
                    'file from ' + time.strftime('%Y-%m-%d %H:%M', time.localtime(mt)))
        m.live = _live_summary(records, base, key[2])
        n = m.live['changes_since_backup']
        m.loaded = m.backup + (f' + {n} change{"s" if n != 1 else ""} from the firewall logs' if LIVE else '')
        _cache.update(key=key, model=m)
        return m


def _live_summary(records, base, version):
    since = [r for r in records if r['ts'] >= base]
    by_rule, moved = {}, {}
    for r in since:
        if r['path'] in ('firewall.policy', 'firewall.local-in-policy') and str(r['obj'] or '').isdigit():
            rid = int(r['obj']) + (100_000 if r['path'] == 'firewall.local-in-policy' else 0)
            by_rule.setdefault(rid, []).append(r)
            if r['status'] == 'order unknown' or r.get('order_unknown'):
                moved[rid] = {'ts': r['ts'], 'user': r['user'], 'why': 'moved' if r['status'] == 'order unknown' else 'added'}
    return {'enabled': LIVE, 'version': list(version) if version else None, 'baseline_ms': base,
            'changes_since_backup': len(since), 'risk_changes': sum(1 for r in since if r['risk']),
            'last_change': since[-1] if since else None,
            'unverified': sum(1 for r in since if r['status'] in ('applied (backup differed)', 'object not in backup')),
            'recent': list(reversed(since))[:300],
            'by_rule': {k: list(reversed(v))[:6] for k, v in by_rule.items()},
            'position_unknown': moved}


class Model:
    def __init__(self, d):
        g = d.get('system_global') or {}
        self.admin_port = g.get('admin-sport', 443)
        self.admin_ssh_port = g.get('admin-ssh-port', 22)
        self.hostname = g.get('hostname')
        self.interfaces = dict(_items(d, 'system_interface'))
        self.wan = {k for k, v in self.interfaces.items() if v.get('role') == 'wan' or self._public(v.get('ip'))}
        self.addresses = dict(_items(d, 'firewall_address'))
        self.groups = {k: _list(v.get('member')) for k, v in _items(d, 'firewall_addrgrp')}
        self.services = dict(_items(d, 'firewall_service_custom'))
        self.svc_groups = {k: _list(v.get('member')) for k, v in _items(d, 'firewall_service_group')}
        self.vips = dict(_items(d, 'firewall_vip'))
        self.vip_groups = {k: _list(v.get('member')) for k, v in _items(d, 'firewall_vipgrp')}
        self.ips_sensors = {k for k, _ in _items(d, 'ips_sensor')}
        self.app_lists = dict(_items(d, 'application_list'))
        self.sslvpn = d.get('vpn_ssl_settings') or {}
        self.policies = []
        for seq, (pid, v) in enumerate(_items(d, 'firewall_policy'), 1):
            if str(pid).isdigit():
                self.policies.append(dict(v, id=int(pid), seq=seq, action=v.get('action', 'deny'),
                                          status=v.get('status', 'enable')))
        self.local_in = [dict(v, id=int(pid), seq=seq, action=v.get('action', 'deny'), status=v.get('status', 'enable'))
                         for seq, (pid, v) in enumerate(_items(d, 'firewall_local-in-policy'), 1) if str(pid).isdigit()]
        self.by_id = {p['id']: p for p in self.policies}
        # mapped (internal) IP -> list of VIPs publishing it
        self.vip_by_mapped = {}
        for name, v in self.vips.items():
            for mip in _list(v.get('mappedip')):
                self.vip_by_mapped.setdefault(mip.split('-')[0], []).append((name, v))

    @staticmethod
    def _public(ip):
        try:
            a = ipaddress.ip_address(_list(ip)[0]) if ip else None
            return bool(a and a.is_global)
        except ValueError:
            return False

    # ---------------------------------------------------------- addresses
    def expand_addr(self, names, depth=0):
        out = []
        for n in _list(names):
            if n in self.groups and depth < 8:
                out += self.expand_addr(self.groups[n], depth + 1)
            else:
                out.append(n)
        return out

    def describe_addr(self, name):
        if name == 'all':
            return {'name': name, 'kind': 'any', 'value': 'any address'}
        a = self.addresses.get(name)
        if a is None:
            if name in self.vips:
                v = self.vips[name]
                return {'name': name, 'kind': 'vip', 'value': f"{v.get('extip')} -> {_list(v.get('mappedip'))}"}
            return {'name': name, 'kind': 'unknown', 'value': None}
        t = a.get('type', 'ipmask')
        if t == 'geography':
            return {'name': name, 'kind': 'country', 'value': a.get('country')}
        if t == 'fqdn':
            return {'name': name, 'kind': 'fqdn', 'value': a.get('fqdn')}
        if t == 'iprange':
            return {'name': name, 'kind': 'range', 'value': f"{a.get('start-ip')}-{a.get('end-ip')}"}
        if t == 'ipmask':
            sub = _list(a.get('subnet'))
            try:
                net = ipaddress.ip_network('/'.join(sub[:2]), strict=False) if len(sub) >= 2 else ipaddress.ip_network(sub[0], strict=False)
                return {'name': name, 'kind': 'host' if net.prefixlen == 32 else 'subnet', 'value': str(net),
                        'size': net.num_addresses}
            except (ValueError, IndexError):
                return {'name': name, 'kind': 'subnet', 'value': ' '.join(sub)}
        return {'name': name, 'kind': t, 'value': a.get('comment')}

    # ---------------------------------------------------------- services
    def expand_svc(self, names, depth=0):
        out = []
        for n in _list(names):
            if n in self.svc_groups and depth < 8:
                out += self.expand_svc(self.svc_groups[n], depth + 1)
            else:
                out.append(n)
        return out

    def describe_svc(self, name):
        s = self.services.get(name, {})
        tcp, udp = _ports(s.get('tcp-portrange')), _ports(s.get('udp-portrange'))
        proto = s.get('protocol')
        if name.upper() in ('ALL', 'ALL_TCP', 'ALL_UDP') or (proto == 'IP' and not tcp and not udp):
            return {'name': name, 'all': True, 'tcp': [(1, 65535)] if name.upper() != 'ALL_UDP' else [],
                    'udp': [(1, 65535)] if name.upper() != 'ALL_TCP' else [], 'label': 'all ports'}
        label = ', '.join([f"tcp/{a}" if a == b else f"tcp/{a}-{b}" for a, b in tcp] +
                          [f"udp/{a}" if a == b else f"udp/{a}-{b}" for a, b in udp]) or proto or name
        return {'name': name, 'all': False, 'tcp': tcp, 'udp': udp, 'label': label}

    # ---------------------------------------------------------- destinations
    def publish(self, dst_names):
        """Internal destination objects -> [{server, name, public: [ip:port...]}] using VIPs (central NAT) or VIP names."""
        out = []
        for n in self.expand_addr(dst_names):
            if n in self.vips or n in self.vip_groups:
                for vn in (self.vip_groups.get(n) or [n]):
                    v = self.vips.get(vn, {})
                    out.append({'name': vn, 'server': ', '.join(_list(v.get('mappedip'))), 'public': [self._vip_pub(v)]})
                continue
            desc = self.describe_addr(n)
            ip = (desc.get('value') or '').split('/')[0] if desc['kind'] == 'host' else None
            vips = self.vip_by_mapped.get(ip, []) if ip else []
            out.append({'name': n, 'server': desc.get('value'), 'kind': desc['kind'],
                        'public': [self._vip_pub(v) for _, v in vips]})
        return out

    @staticmethod
    def _vip_pub(v):
        ext = v.get('extip')
        return f"{ext}:{v.get('extport')}" if v.get('portforward') == 'enable' else str(ext)


# ---------------------------------------------------------- analysis
COUNTRY = {'IN': 'India', 'US': 'USA', 'GB': 'UK', 'CN': 'China', 'RU': 'Russia', 'UA': 'Ukraine', 'AF': 'Afghanistan',
           'BD': 'Bangladesh', 'ID': 'Indonesia', 'PK': 'Pakistan', 'SY': 'Syria', 'DE': 'Germany', 'SG': 'Singapore',
           'IR': 'Iran', 'KP': 'North Korea', 'BR': 'Brazil', 'NL': 'Netherlands', 'CA': 'Canada', 'AU': 'Australia'}


def _names(names, n=3):
    return ', '.join(names[:n]) + (f' +{len(names) - n} more' if len(names) > n else '')


def source_scope(m, p):
    """Who can reach the rule, in plain words, with a score (higher = broader)."""
    isdb = _list(p.get('internet-service-src-name'))
    names = m.expand_addr(p.get('srcaddr'))
    negate = p.get('srcaddr-negate') == 'enable'
    descs = [m.describe_addr(n) for n in names]
    kinds = {d['kind'] for d in descs}
    countries = [COUNTRY.get(d['value'], d['value']) or d['name'] for d in descs if d['kind'] == 'country']
    hosts = [d for d in descs if d['kind'] in ('host', 'subnet', 'range', 'fqdn')]
    if negate:
        return {'scope': 'negated', 'label': f"anyone EXCEPT {', '.join(names[:6])}", 'score': 38, 'detail': descs, 'isdb': isdb}
    if 'any' in kinds and not isdb:
        return {'scope': 'any', 'label': 'Anyone on the internet', 'score': 40, 'detail': descs, 'isdb': isdb}
    if isdb:
        cdn = all(re.search(r'cloudflare|akamai|fastly', s, re.I) for s in isdb)
        return {'scope': 'cdn' if cdn else 'cloud', 'isdb': isdb, 'detail': descs,
                'label': (f"Only via {', '.join(isdb)}" if cdn else
                          f"Anyone with a server on {', '.join(isdb)} (cloud ranges anyone can rent)"),
                'score': 10 if cdn else 25}
    if re.search(r'cloudflare', ' '.join(names), re.I):
        return {'scope': 'cdn', 'label': 'Only via Cloudflare', 'score': 10, 'detail': descs, 'isdb': isdb}
    if countries and len(countries) == len(descs):
        return {'scope': 'geo', 'label': f"Anyone in {', '.join(countries)} (incl. cloud servers there)", 'score': 28,
                'detail': descs, 'isdb': isdb}
    big = sum(d.get('size', 1) for d in hosts)
    if countries:
        return {'scope': 'geo', 'label': f"Anyone in {', '.join(countries)} + {len(hosts)} specific address(es)",
                'score': 28, 'detail': descs, 'isdb': isdb}
    if 'unknown' in kinds and not hosts:
        return {'scope': 'unknown', 'label': f"Address objects {', '.join(names[:5])}", 'score': 15, 'detail': descs, 'isdb': isdb}
    return {'scope': 'restricted', 'label': f"Only approved addresses: {_names(names)}" + (f" ({big:,} IPs)" if big > len(names) else ''),
            'score': 5 if big <= 16 else 12, 'detail': descs, 'isdb': isdb}


def analyze_rule(m, p):
    scope = source_scope(m, p)
    svc_names = m.expand_svc(p.get('service'))
    svcs = [m.describe_svc(n) for n in svc_names]
    ports = sorted({x for s in svcs for x in _expand(s['tcp'] + s['udp'])})
    classes = []
    for s in svcs:
        sp = _expand(s['tcp'] + s['udp'])
        for c in (['all'] if s['all'] else classify_service(s['name'], sp)):
            if c not in classes:
                classes.append(c)
    classes.sort(key=lambda c: -KB[c]['weight'])
    ips = p.get('ips-sensor')
    app = p.get('application-list')
    factors = [(scope['score'], f"Source: {scope['label']}")]
    top = KB[classes[0]] if classes else KB['other']
    factors.append((top['weight'], f"Service: {top['title']}"))
    if any(KB[c]['known_exploited'] for c in classes):
        factors.append((10, 'Software on this service has actively exploited vulnerabilities (CISA KEV)'))
    if not ips:
        factors.append((12, 'No IPS sensor: exploit attempts are not inspected or blocked'))
    if not app:
        factors.append((5, 'No application control: any protocol can use the allowed ports'))
    elif app == 'default' or 'monitor' in app.lower():
        factors.append((3, f"Application control '{app}' only monitors"))
    if scope['scope'] in ('restricted', 'cdn'):
        factors = [(s if not t.startswith('Service') else round(s * 0.5), t) for s, t in factors]   # narrow source dampens service risk
    score = min(100, sum(s for s, _ in factors))
    level = 'critical' if score >= 70 else 'high' if score >= 50 else 'medium' if score >= 30 else 'low'
    published = m.publish(p.get('dstaddr'))
    attacks, cves, prevent = [], [], []
    for c in classes:
        k = KB[c]
        attacks += [{'service': k['title'], 'name': a, 'text': t, 'attck': tid} for a, t, tid in k['attacks']]
        cves += [{'id': i, 'text': t, 'kev': dt, 'service': k['title']} for i, t, dt in k['cves']]
        prevent += [x for x in k['prevent'] if x not in prevent]
    if scope['scope'] in ('any', 'geo', 'cloud', 'negated') and not any('source' in x.lower() for x in prevent[:1]):
        prevent.insert(0, 'Narrow the source: replace broad sources with the exact partner / office / provider addresses.')
    if not ips:
        prevent.insert(1, "Attach an IPS sensor to this rule (e.g. 'protect_http_server' or 'protect_email_server').")
    return {
        'id': p['id'], 'seq': p['seq'], 'name': p.get('name'), 'enabled': p['status'] == 'enable', 'action': p['action'],
        'srcintf': _list(p.get('srcintf')), 'dstintf': _list(p.get('dstintf')), 'source': scope,
        'services': [{'name': s['name'], 'label': s['label'], 'all': s['all']} for s in svcs], 'ports': ports[:40],
        'classes': classes, 'service_titles': [KB[c]['title'] for c in classes],
        'destinations': published, 'ips': ips, 'app': app, 'av': p.get('av-profile'), 'webfilter': p.get('webfilter-profile'),
        'ssl': p.get('ssl-ssh-profile'), 'log': p.get('logtraffic', 'utm'), 'comments': p.get('comments'),
        'score': score, 'level': level, 'factors': [{'points': s, 'text': t} for s, t in factors],
        'attacks': attacks, 'cves': cves, 'prevent': prevent, 'cli': _cli(p, scope, ips, app, classes),
    }


def _cli(p, scope, ips, app, classes):
    lines = [f'# Suggested hardening for policy {p["id"]} "{p.get("name")}" - review before applying', 'config firewall policy',
             f'    edit {p["id"]}']
    if scope['scope'] in ('any', 'geo', 'cloud'):
        lines.append('        set srcaddr "<trusted-sources-group>"      # replace with the real partner/office address group')
        if scope.get('isdb'):
            lines.append('        unset internet-service-src-name')
    if not ips:
        lines += ['        set utm-status enable',
                  f'        set ips-sensor "{"protect_email_server" if any(c in ("smtp", "mail_auth") for c in classes) else "protect_http_server"}"']
    if not app or app == 'default' or 'monitor' in app.lower():
        lines.append('        set application-list "<strict-sensor-for-this-service>"   # see Rule assistant for observed apps')
    lines += ['    next', 'end']
    return '\n'.join(lines)


def inbound_rules(m):
    return [p for p in m.policies if set(_list(p.get('srcintf'))) & m.wan]


def local_in(m):
    out = []
    for p in m.local_in:
        svcs = [m.describe_svc(n) for n in m.expand_svc(p.get('service'))]
        scope = source_scope(m, p)
        ports = {x for s in svcs for x in _expand(s['tcp'])}
        what = 'FortiGate admin GUI' if m.admin_port in ports or any('ADMIN' in s['name'].upper() for s in svcs) else \
            'SSL-VPN' if int(m.sslvpn.get('port') or 0) in ports else ', '.join(s['label'] for s in svcs)
        out.append({'id': p['id'], 'seq': p['seq'], 'intf': _list(p.get('intf')), 'action': p['action'], 'enabled': p['status'] == 'enable',
                    'source': scope['label'], 'scope': scope['scope'], 'names': _list(p.get('srcaddr')),
                    'services': [s['label'] for s in svcs], 'what': what})
    return out


def admin_plane(m):
    """Plain-English posture of the firewall's own management plane."""
    li = local_in(m)
    admin_rules = [r for r in li if r['what'] == 'FortiGate admin GUI' and r['enabled']]
    allows = [r for r in admin_rules if r['action'] == 'accept']
    deny_all_after = any(r['action'] == 'deny' and r['scope'] == 'any' and r['seq'] > max([a['seq'] for a in allows] or [0])
                         for r in admin_rules)
    wan_access = {k: _list(v.get('allowaccess')) for k, v in m.interfaces.items() if k in m.wan}
    findings = []
    if any(r['scope'] == 'any' for r in allows):
        findings.append(('critical', 'Admin login page is open to the whole internet', KB['fg_admin']))
    elif allows and deny_all_after:
        findings.append(('good', f"Admin login (port {m.admin_port}) is only allowed from "
                                 f"{', '.join(n for r in allows for n in r['names'])}; everyone else is denied", None))
    elif allows:
        findings.append(('medium', 'Admin access is restricted but no explicit deny-all local-in rule follows', None))
    ssl_on = m.sslvpn.get('status', 'enable') != 'disable'
    findings.append(('high' if ssl_on else 'good', 'SSL-VPN is enabled on the internet interface' if ssl_on else
                     f"SSL-VPN is disabled (scanners still probe port {m.sslvpn.get('port')})", KB['sslvpn'] if ssl_on else None))
    for intf, acc in wan_access.items():
        risky = [a for a in acc if a in ('http', 'telnet', 'ssh', 'snmp', 'fgfm')]
        if risky:
            findings.append(('high', f"{intf} allows {', '.join(risky)} management from the internet", None))
    return {'admin_port': m.admin_port, 'admin_ssh_port': m.admin_ssh_port, 'local_in': li, 'wan_allowaccess': wan_access,
            'sslvpn_enabled': ssl_on, 'sslvpn_port': m.sslvpn.get('port'),
            'findings': [{'level': lv, 'text': t, 'cves': [{'id': c[0], 'text': c[1], 'kev': c[2]} for c in (kb or {}).get('cves', [])]}
                         for lv, t, kb in findings]}
