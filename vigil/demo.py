"""Demo mode: a fictional FortiGate ("FGT-DEMO") that sends realistic syslog to Vigil's own receiver.

Everything here is invented. Public addresses come only from the IETF documentation ranges (RFC 5737:
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); internal hosts use 10.20.0.0/16. Users, hosts, rules and domains are
made up (well-known public SaaS domains are used only as outbound browsing examples).

What it produces (so every page has something to show):
  * internet scanners hitting closed ports and the firewall itself (implicit deny, local-in deny)
  * allowed inbound traffic to published web / mail / SSH / RDP services, password guessing on SSH and RDP
  * IPS detections on the web server, a few UTM-blocked sessions and wrong-protocol (port-violation) events
  * outbound browsing with web-filter and application-control logs, a few blocked categories
  * SSL-VPN logins, admin logins and configuration changes (Inbound Security picks them up live)
History: VIGIL_DEMO_HISTORY_HOURS (default 48) is generated quickly at start, then live traffic at VIGIL_DEMO_EPS.
Format: VIGIL_DEMO_FORMAT = cef | default | mixed (default mixed: exercises both parsers).
"""
import json
import logging
import math
import os
import random
import socket
import time
import uuid
import zlib
from datetime import datetime, timezone

from . import fgconf, settings
from .cef import IP_TOKEN

log = logging.getLogger('vigil.demo')
HOST = os.environ.get('VIGIL_DEMO_TARGET', '127.0.0.1')
PORT = int(os.environ.get('VIGIL_SYSLOG_PORT', '5514'))
EPS = float(os.environ.get('VIGIL_DEMO_EPS', '25'))
HISTORY_H = float(os.environ.get('VIGIL_DEMO_HISTORY_HOURS', '48'))
FORMAT = os.environ.get('VIGIL_DEMO_FORMAT', 'mixed')
DEVNAME, DEVID, VERSION = 'FGT-DEMO', 'FGVM02TM00DEMO01', '7.4.4'
TZ = '+0000'

COUNTRIES = ['United States', 'China', 'Russian Federation', 'Netherlands', 'Germany', 'Brazil', 'India', 'Viet Nam',
             'Korea, Republic of', 'United Kingdom', 'France', 'Singapore', 'Iran, Islamic Republic of', 'Bulgaria',
             'Romania', 'Hong Kong', 'Seychelles', 'Canada', 'Japan', 'Ukraine']
CW = [18, 16, 9, 7, 6, 5, 6, 4, 3, 4, 3, 3, 2, 2, 2, 2, 1, 2, 2, 2]
SCAN_PORTS = [23, 22, 3389, 445, 80, 8080, 443, 5900, 3306, 1433, 6379, 2323, 81, 8443, 5555, 37215, 52869, 9200, 11211,
              21, 25, 53, 110, 143, 161, 1723, 5060, 8000, 8888, 9000, 10000, 60001, 7547, 49152, 2375, 27017]
SW = [14, 12, 10, 8, 6, 5, 5, 4, 4, 3, 3, 3, 2, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1]
WEB_VIP, MAIL_VIP, SSH_VIP, RDP_VIP = '203.0.113.10', '203.0.113.20', '203.0.113.30', '203.0.113.40'
WEB_SRV, MAIL_SRV, SFTP_SRV, JUMP_SRV = '10.20.30.10', '10.20.30.20', '10.20.30.30', '10.20.30.40'
WAN_IP = '203.0.113.2'
POLICIES = {1: ('web-servers-https', 'dmz'), 2: ('mail-smtp-inbound', 'dmz'), 3: ('mail-clients-imaps', 'dmz'),
            4: ('partner-sftp', 'dmz'), 5: ('rdp-jump-host', 'internal'), 6: ('block-high-risk-countries', 'dmz'),
            7: ('lan-to-internet', 'wan1')}
POLUUID = {pid: str(uuid.UUID(int=0xD0D0 << 64 | pid)) for pid in POLICIES}
HOSTS = [(f'10.20.10.{i}', f'LAPTOP-{i:03d}', random.Random(i).choice(['Windows', 'Windows', 'macOS', 'Linux']),
          f'02:00:5e:10:{i // 256:02x}:{i % 256:02x}') for i in range(11, 71)]
USERS = ['alex.morgan', 'sam.lee', 'jordan.patel', 'casey.nguyen', 'riley.kim', 'taylor.brooks', 'morgan.diaz']
DOMAINS = [('microsoft.com', 'Information Technology'), ('office.com', 'Information Technology'), ('github.com', 'Information Technology'),
           ('google.com', 'Search Engines and Portals'), ('youtube.com', 'Streaming Media and Download'),
           ('slack.com', 'Instant Messaging'), ('zoom.us', 'Web Conferencing'), ('wikipedia.org', 'Reference'),
           ('amazon.com', 'Shopping'), ('dropbox.com', 'File Sharing and Storage'), ('cloudflare.com', 'Information Technology'),
           ('salesforce.com', 'Business'), ('linkedin.com', 'Social Networking'), ('apple.com', 'Information Technology'),
           ('adobe.com', 'Information Technology'), ('bbc.co.uk', 'News and Media'), ('stackoverflow.com', 'Information Technology')]
BLOCKED = [('free-games-portal.example', 'Games'), ('torrent-tracker.example', 'Peer-to-peer File Sharing'),
           ('malware-drop.example', 'Malicious Websites'), ('phish-login.example', 'Phishing')]
APPS = [('Microsoft.Office.365', 41469, 'Collaboration', 'medium', 'pass'), ('Microsoft.Teams', 43541, 'Collaboration', 'low', 'pass'),
        ('YouTube', 31077, 'Video/Audio', 'medium', 'pass'), ('Slack', 34876, 'Collaboration', 'low', 'pass'),
        ('Zoom', 41888, 'Video/Audio', 'low', 'pass'), ('Dropbox', 17152, 'Storage.Backup', 'high', 'pass'),
        ('BitTorrent', 16185, 'P2P', 'critical', 'block'), ('Tor', 16429, 'Proxy', 'critical', 'block'),
        ('HTTPS.BROWSER', 40568, 'Web.Client', 'medium', 'pass'), ('DNS', 15896, 'Network.Service', 'elevated', 'pass')]
IPS = [('Apache.Log4j.Error.Log.Remote.Code.Execution', 51006, 'critical'), ('PHPUnit.Eval-stdin.PHP.Remote.Code.Execution', 44574, 'critical'),
       ('Nmap.Script.Scanner', 20925, 'low'), ('WordPress.xmlrpc.php.System.Multicall.Brute.Force', 45219, 'medium'),
       ('Apache.HTTP.Server.cgi-bin.Path.Traversal', 50799, 'high'), ('Generic.Path.Traversal.Detection', 12301, 'medium')]


class Rng(random.Random):
    def country(self):
        return self.choices(COUNTRIES, CW)[0]


R = Rng(20260115)
BRUTE_SSH, BRUTE_RDP = ('198.51.100.66', 'Russian Federation'), ('198.51.100.77', 'Viet Nam')
_SPECIAL = {'198.51.100.66', '198.51.100.77', '198.51.100.201', '198.51.100.202', '198.51.100.203'}   # attackers with a fixed story
SCANNERS = [(ip, R.country()) for ip in [f'198.51.100.{i}' for i in range(1, 255)] + [f'192.0.2.{i}' for i in range(1, 200)]
            if ip not in _SPECIAL]
CLIENTS = [(f'192.0.2.{i}', R.choice(['United States', 'United Kingdom', 'Canada', 'Germany'])) for i in range(200, 255)]


# ---------------------------------------------------------------- rendering
def _ns(ts):
    return str(int(ts * 1_000_000))


def render(ts, rec, fmt):
    """rec: CEF-named fields incl. 'cat' and 'act'. Returns the syslog message bytes."""
    rec = dict(rec, deviceExternalId=DEVID, FTNTFGTeventtime=_ns(ts), FTNTFGTtz=TZ, FTNTFGTvd='root')
    dt = datetime.fromtimestamp(ts / 1000, timezone.utc)
    if fmt == 'cef':
        logid = rec.get('FTNTFGTlogid', '0000000013')
        sig = f"{rec['cat']} {rec.get('act', '')}".strip()
        ext = ' '.join(f"{k}={str(v).replace(chr(92), chr(92) * 2).replace('=', chr(92) + '=')}"
                       for k, v in rec.items() if v is not None and v != '')
        body = f"{dt.strftime('%b %d %H:%M:%S')} {DEVNAME} CEF: 0|Fortinet|Fortigate|v{VERSION}|{logid[-5:]}|{sig}|3|{ext}"
    else:
        inv = {'src': 'srcip', 'spt': 'srcport', 'dst': 'dstip', 'dpt': 'dstport', 'act': 'action', 'app': 'service',
               'externalId': 'sessionid', 'out': 'sentbyte', 'in': 'rcvdbyte', 'deviceInboundInterface': 'srcintf',
               'deviceOutboundInterface': 'dstintf', 'dhost': 'hostname', 'request': 'url', 'duser': 'user',
               'deviceExternalId': 'devid', 'shost': 'srcname', 'requestClientApplication': 'agent', 'msg': 'msg',
               'sproc': 'ui', 'transip': 'transip'}
        typ, _, sub = rec['cat'].partition(':')
        parts = [f"date={dt.strftime('%Y-%m-%d')}", f"time={dt.strftime('%H:%M:%S')}", f'devname="{DEVNAME}"']
        kv = {'logid': rec.get('FTNTFGTlogid', '0000000013'), 'type': typ, 'subtype': sub}
        if typ == 'utm':
            kv['type'], kv['subtype'] = 'utm', sub
        for k, v in rec.items():
            if k in ('cat', 'FTNTFGTlogid') or v is None or v == '':
                continue
            if k == 'destinationTranslatedAddress':
                kv['tranip'], kv['trandisp'] = v, 'dnat'
            elif k == 'destinationTranslatedPort':
                kv['tranport'] = v
            elif k == 'FTNTFGTapp':
                kv['app'] = v
            elif k in inv:
                kv[inv[k]] = v
            elif k.startswith('FTNTFGT'):
                kv[k[7:]] = v
        for k, v in kv.items():                     # like FortiOS: numbers and IP addresses bare, every other value quoted
            s = str(v)
            parts.append(f'{k}={s}' if s.isdigit() or IP_TOKEN.fullmatch(s)
                         else '{}="{}"'.format(k, s.replace('"', '\\"')))
        body = ' '.join(parts)
    return f'<189>{body}'.encode()


# ---------------------------------------------------------------- event builders
_sess = [700_000_000]


def sid():
    _sess[0] += R.randint(1, 9)
    return _sess[0]


def scan_deny(ts):
    src, ctry = R.choice(SCANNERS)
    dpt = R.choices(SCAN_PORTS, SW)[0]
    if R.random() < 0.12:                                    # probes aimed at the firewall itself
        dpt = R.choice([8443, 10443, 22, 23, 161, 541])
        return {'cat': 'traffic:local', 'act': 'deny', 'src': src, 'spt': R.randint(1024, 65535), 'dst': WAN_IP, 'dpt': dpt,
                'proto': 6 if dpt != 161 else 17, 'deviceInboundInterface': 'wan1', 'deviceOutboundInterface': 'root',
                'FTNTFGTsrcintfrole': 'wan', 'FTNTFGTdstintfrole': 'undefined', 'FTNTFGTpolicyid': 0,
                'FTNTFGTpolicytype': 'local-in-policy', 'FTNTFGTsrccountry': ctry, 'FTNTFGTdstcountry': 'Reserved',
                'externalId': sid(), 'app': f'tcp/{dpt}', 'FTNTFGTlogid': '0001000014', 'FTNTFGTcrscore': 5, 'FTNTFGTcrlevel': 'low'}
    return {'cat': 'traffic:forward', 'act': 'deny', 'src': src, 'spt': R.randint(1024, 65535),
            'dst': R.choice([WEB_VIP, MAIL_VIP, SSH_VIP, RDP_VIP, '203.0.113.50', '203.0.113.60']), 'dpt': dpt,
            'proto': 17 if dpt in (53, 161, 5060) else 6, 'deviceInboundInterface': 'wan1', 'deviceOutboundInterface': 'unknown-0',
            'FTNTFGTsrcintfrole': 'wan', 'FTNTFGTdstintfrole': 'undefined', 'FTNTFGTpolicyid': 0, 'FTNTFGTpolicytype': 'policy',
            'FTNTFGTsrccountry': ctry, 'FTNTFGTdstcountry': 'Reserved', 'externalId': sid(), 'app': f'tcp/{dpt}',
            'FTNTFGTlogid': '0000000013', 'FTNTFGTcrscore': 30, 'FTNTFGTcrlevel': 'high'}


SWEEPERS = [('198.51.100.201', 'China'), ('198.51.100.202', 'Netherlands'), ('198.51.100.203', 'United States')]


def port_sweep(ts):
    """A scanner walking through many ports of one public address (what port-scan detection looks for)."""
    src, ctry = SWEEPERS[int(ts / 3_600_000) % len(SWEEPERS)]
    dst = R.choice([WEB_VIP, MAIL_VIP])
    out = []
    for dpt in R.sample(SCAN_PORTS, 24):
        rec = scan_deny(ts)
        rec.update(cat='traffic:forward', src=src, FTNTFGTsrccountry=ctry, dst=dst, dpt=dpt, deviceOutboundInterface='unknown-0',
                   FTNTFGTpolicytype='policy', app=f'tcp/{dpt}', FTNTFGTlogid='0000000013')
        out.append(rec)
    return out


def _inbound(ts, pid, src, ctry, vip, srv, dpt, app, appcat, act='close', dur=None, sent=None, rcvd=None, utm=None):
    dur = dur if dur is not None else R.randint(1, 240)
    sent = sent if sent is not None else R.randint(800, 60_000)
    rcvd = rcvd if rcvd is not None else R.randint(2_000, 900_000)
    rec = {'cat': 'traffic:forward', 'act': act, 'src': src, 'spt': R.randint(1024, 65535), 'dst': vip, 'dpt': dpt, 'proto': 6,
           'deviceInboundInterface': 'wan1', 'deviceOutboundInterface': POLICIES[pid][1], 'FTNTFGTsrcintfrole': 'wan',
           'FTNTFGTdstintfrole': 'dmz' if POLICIES[pid][1] == 'dmz' else 'lan', 'FTNTFGTpolicyid': pid,
           'FTNTFGTpolicyname': POLICIES[pid][0], 'FTNTFGTpoluuid': POLUUID[pid], 'FTNTFGTpolicytype': 'policy',
           'destinationTranslatedAddress': srv, 'destinationTranslatedPort': dpt, 'FTNTFGTtrandisp': 'dnat',
           'FTNTFGTsrccountry': ctry, 'FTNTFGTdstcountry': 'Reserved', 'externalId': sid(), 'FTNTFGTduration': dur,
           'out': sent, 'in': rcvd, 'FTNTFGTsentpkt': max(1, sent // 900), 'FTNTFGTrcvdpkt': max(1, rcvd // 1300),
           'app': app, 'FTNTFGTapp': app, 'FTNTFGTappcat': appcat, 'FTNTFGTapplist': 'default', 'FTNTFGTlogid': '0000000013'}
    if utm:
        rec['FTNTFGTutmaction'] = utm
    return rec


def inbound_allowed(ts):
    x = R.random()
    if x < 0.45:
        src, ctry = R.choice(CLIENTS + SCANNERS[:40])
        return [_inbound(ts, 1, src, ctry, WEB_VIP, WEB_SRV, R.choice([443, 443, 443, 80]), 'HTTPS.BROWSER', 'Web.Client')]
    if x < 0.65:
        src, ctry = R.choice(SCANNERS[40:120])
        return [_inbound(ts, 2, src, ctry, MAIL_VIP, MAIL_SRV, 25, 'SMTP', 'Email', dur=R.randint(1, 30))]
    if x < 0.82:
        src, ctry = R.choice(CLIENTS)
        return [_inbound(ts, 3, src, ctry, MAIL_VIP, MAIL_SRV, R.choice([993, 465, 587]), 'IMAPS', 'Email')]
    if x < 0.9:
        src, ctry = R.choice(CLIENTS[:6])
        return [_inbound(ts, 4, src, ctry, SSH_VIP, SFTP_SRV, 22, 'SSH', 'Network.Service', dur=R.randint(30, 900))]
    src, ctry = R.choice(CLIENTS[6:20])
    return [_inbound(ts, 5, src, ctry, RDP_VIP, JUMP_SRV, 3389, 'RDP', 'Remote.Access', dur=R.randint(60, 3600))]


def brute_force(ts):
    if R.random() < 0.5:
        src, ctry = BRUTE_SSH
        return [_inbound(ts, 4, src, ctry, SSH_VIP, SFTP_SRV, 22, 'SSH', 'Network.Service', act='client-rst', dur=1,
                         sent=R.randint(600, 2200), rcvd=R.randint(900, 1800))]
    src, ctry = BRUTE_RDP
    return [_inbound(ts, 5, src, ctry, RDP_VIP, JUMP_SRV, 3389, 'RDP', 'Remote.Access', act='client-rst', dur=R.randint(0, 2),
                     sent=R.randint(900, 3000), rcvd=R.randint(700, 1500))]


def ips_attack(ts):
    src, ctry = R.choice(SCANNERS)
    attack, aid, sev = R.choices(IPS, [3, 2, 5, 2, 2, 3])[0]
    s = sid()
    ips = {'cat': 'utm:ips', 'act': 'dropped', 'src': src, 'spt': R.randint(1024, 65535), 'dst': WEB_SRV, 'dpt': 443, 'proto': 6,
           'deviceInboundInterface': 'wan1', 'deviceOutboundInterface': 'dmz', 'FTNTFGTsrcintfrole': 'wan', 'FTNTFGTdstintfrole': 'dmz',
           'FTNTFGTpolicyid': 1, 'FTNTFGTpolicytype': 'policy',
           'FTNTFGTattack': attack, 'FTNTFGTattackid': aid, 'FTNTFGTseverity': sev, 'FTNTFGTprofile': 'protect_http_server',
           'FTNTFGTsrccountry': ctry, 'dhost': 'www.demo.example', 'request': '/', 'externalId': s, 'FTNTFGTlogid': '0419016384',
           'FTNTFGTeventtype': 'signature', 'FTNTFGTref': f'http://www.fortinet.com/ids/VID{aid}', 'FTNTFGTlevel': 'alert',
           'FTNTFGTincidentserialno': R.randint(10**8, 10**9)}
    tr = _inbound(ts, 1, src, ctry, WEB_VIP, WEB_SRV, 443, 'HTTPS', 'Web.Client', act='client-rst', dur=1,
                  sent=R.randint(900, 4000), rcvd=0, utm='block')
    tr['externalId'] = s
    return [ips, tr]


def protocol_abuse(ts):
    src, ctry = R.choice(SCANNERS[120:200])
    s = sid()
    return [{'cat': 'utm:app-ctrl', 'act': 'block', 'src': src, 'spt': R.randint(1024, 65535), 'dst': MAIL_SRV, 'dpt': 25, 'proto': 6,
             'deviceInboundInterface': 'wan1', 'deviceOutboundInterface': 'dmz', 'FTNTFGTsrcintfrole': 'wan', 'FTNTFGTdstintfrole': 'dmz',
             'FTNTFGTpolicyid': 2, 'FTNTFGTpolicytype': 'policy',
             'FTNTFGTapp': R.choice(['RDP', 'SSH', 'HTTP.BROWSER']), 'FTNTFGTappid': 15951, 'FTNTFGTappcat': 'Remote.Access',
             'FTNTFGTapprisk': 'elevated', 'FTNTFGTapplist': 'mail-inbound-strict', 'FTNTFGTeventtype': 'port-violation',
             'FTNTFGTsrccountry': ctry, 'app': 'SMTP', 'externalId': s, 'FTNTFGTlogid': '1059028705', 'msg': 'Port violation'}]


def outbound(ts):
    ip, name, os_, mac = R.choice(HOSTS)
    blocked = R.random() < 0.04
    dom, cat = R.choice(BLOCKED) if blocked else R.choice(DOMAINS)
    host = R.choice(['www.', '', 'api.', 'cdn.']) + dom
    dst = f'198.51.100.{(zlib.crc32(dom.encode()) % 200) + 20}'
    s = sid()
    sent, rcvd = R.randint(500, 40_000), R.randint(2_000, 3_000_000)
    web = {'cat': 'utm:webfilter', 'act': 'blocked' if blocked else 'passthrough', 'src': ip, 'spt': R.randint(49152, 65535),
           'dst': dst, 'dpt': 443, 'proto': 6, 'deviceInboundInterface': 'internal', 'deviceOutboundInterface': 'wan1',
           'FTNTFGTpolicyid': 7, 'FTNTFGTpolicytype': 'policy', 'FTNTFGTprofile': 'default-web', 'dhost': host,
           'request': f'https://{host}/', 'FTNTFGThttpmethod': 'GET', 'requestClientApplication': 'Mozilla/5.0',
           'FTNTFGTeventtype': 'ftgd_blk' if blocked else 'ftgd_allow', 'FTNTFGTcatdesc': cat, 'externalId': s,
           'out': sent, 'in': rcvd, 'FTNTFGTlogid': '0316013057', 'shost': name}
    app, aid, acat, risk, aact = R.choice(APPS)
    out = [web, {'cat': 'traffic:forward', 'act': 'client-rst' if blocked else R.choice(['close', 'close', 'timeout']),
                 'src': ip, 'spt': web['spt'], 'dst': dst, 'dpt': 443, 'proto': 6, 'deviceInboundInterface': 'internal',
                 'deviceOutboundInterface': 'wan1', 'FTNTFGTsrcintfrole': 'lan', 'FTNTFGTdstintfrole': 'wan', 'FTNTFGTpolicyid': 7,
                 'FTNTFGTpolicyname': POLICIES[7][0], 'FTNTFGTpoluuid': POLUUID[7], 'FTNTFGTpolicytype': 'policy',
                 'FTNTFGTsrccountry': 'Reserved', 'FTNTFGTdstcountry': R.choice(['United States', 'United States', 'Ireland', 'Netherlands']),
                 'externalId': s, 'FTNTFGTduration': R.randint(1, 600), 'out': sent, 'in': rcvd, 'app': 'HTTPS', 'FTNTFGTapp': app,
                 'FTNTFGTappcat': acat, 'shost': name, 'FTNTFGTosname': os_, 'FTNTFGTsrcmac': mac, 'FTNTFGTsrchwvendor': 'Demo',
                 'FTNTFGTdevtype': 'Laptop', 'FTNTFGTutmaction': 'block' if blocked else 'allow', 'FTNTFGTlogid': '0000000013',
                 'transip': WAN_IP}]
    if R.random() < 0.35:
        out.append({'cat': 'utm:app-ctrl', 'act': aact, 'src': ip, 'spt': web['spt'], 'dst': dst, 'dpt': 443, 'proto': 6,
                    'deviceInboundInterface': 'internal', 'deviceOutboundInterface': 'wan1', 'FTNTFGTpolicyid': 7,
                    'FTNTFGTpolicytype': 'policy', 'FTNTFGTapp': app, 'FTNTFGTappid': aid, 'FTNTFGTappcat': acat,
                    'FTNTFGTapprisk': risk, 'FTNTFGTapplist': 'outbound-default', 'FTNTFGTeventtype': 'signature',
                    'app': 'HTTPS', 'dhost': host, 'externalId': s, 'FTNTFGTlogid': '1059028704'})
    return out


def vpn_event(ts):
    user = R.choice(USERS)
    src, ctry = R.choice(CLIENTS)
    up = R.random() < 0.55
    return [{'cat': 'event:vpn', 'act': 'tunnel-up' if up else 'tunnel-down', 'FTNTFGTlogdesc': 'SSL VPN tunnel up' if up else 'SSL VPN tunnel down',
             'duser': user, 'FTNTFGTgroup': 'vpn-staff', 'FTNTFGTremip': src, 'FTNTFGTtunneltype': 'ssl-tunnel',
             'FTNTFGTassignip': f'10.99.0.{USERS.index(user) + 10}', 'FTNTFGTlevel': 'information', 'FTNTFGTlogid': '0101039424',
             'FTNTFGTvpntunnel': 'ssl-vpn', 'msg': 'SSL tunnel established' if up else 'SSL tunnel shutdown'}]


def admin_login(ts):
    return [{'cat': 'event:system', 'act': 'login', 'FTNTFGTlogdesc': 'Admin login successful', 'duser': 'admin',
             'sproc': 'https(10.20.10.12)', 'src': '10.20.10.12', 'dst': '10.20.0.1', 'FTNTFGTprofile': 'super_admin',
             'FTNTFGTlevel': 'information', 'FTNTFGTlogid': '0100032001', 'msg': 'Administrator admin logged in successfully from https(10.20.10.12)'}]


CHANGES = [  # (path, obj, attr, act) - realistic edits a demo admin makes over time
    ('firewall.policy', '5', 'srcaddr[all->admins-home]', 'Edit'),
    ('firewall.address', 'partner-3', 'type[ipmask]subnet[192.0.2.214 255.255.255.255]', 'Add'),
    ('firewall.addrgrp', 'partners', 'member[partner-1 partner-2->partner-1 partner-2 partner-3]', 'Edit'),
    ('firewall.policy', '2', 'ips-sensor[->protect_email_server]', 'Edit'),
    ('firewall.policy', '5', 'status[enable->disable]', 'Edit'),
    ('firewall.policy', '5', 'status[disable->enable]', 'Edit'),
    ('firewall.policy', '3', 'application-list[default->mail-clients-strict]', 'Edit'),
    ('firewall.policy', '5', 'srcaddr[admins-home->all]', 'Edit'),
]


def config_change(ts, i):
    path, obj, attr, act = CHANGES[i % len(CHANGES)]
    return [{'cat': 'event:system', 'act': act, 'FTNTFGTlogdesc': 'Object attribute configured', 'duser': 'admin',
             'sproc': 'GUI(10.20.10.12)', 'FTNTFGTcfgtid': 1000 + i, 'FTNTFGTcfgpath': path, 'FTNTFGTcfgobj': obj,
             'FTNTFGTcfgattr': attr, 'FTNTFGTlevel': 'information', 'FTNTFGTlogid': '0100044547', 'msg': f'{act} {path} {obj}'}]


def batch(ts, rate_scale=1.0):
    """Events for one 'tick' of traffic around time ts."""
    x = R.random()
    if x < 0.004:
        return port_sweep(ts)
    if x < 0.50:
        return [scan_deny(ts)]
    if x < 0.66:
        return inbound_allowed(ts)
    if x < 0.93:
        return outbound(ts)
    if x < 0.97:
        return brute_force(ts) if (int(ts / 3_600_000) % 5) in (1, 2) else [scan_deny(ts)]
    if x < 0.985:
        return ips_attack(ts)
    if x < 0.992:
        return protocol_abuse(ts)
    if x < 0.998:
        return vpn_event(ts)
    return admin_login(ts)


# ---------------------------------------------------------------- config backup for the demo
DEMO_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'demo', 'fgt-demo.conf')


def install_demo_config(backup_ms):
    if os.path.exists(settings.CONFIG_PATH):
        return
    with open(DEMO_CONFIG, 'rb') as f:
        clean, info = fgconf.import_backup(f.read(), 'FGT-DEMO_7-4_2662_demo.conf', backup_ms)
    os.makedirs(os.path.dirname(settings.CONFIG_PATH), exist_ok=True)
    with open(settings.CONFIG_PATH, 'w') as f:
        f.write(fgconf.dump(clean))
    log.info('demo configuration installed (%d policies)', info['policies'])


# ---------------------------------------------------------------- main loop
def _fmt(i):
    return FORMAT if FORMAT in ('cef', 'default') else ('cef' if i % 2 == 0 else 'default')


def run():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    settings.ensure_dirs()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    marker = os.path.join(settings.DATA, 'status', 'demo-history.done')
    progress = os.path.join(settings.DATA, 'status', 'demo-history.json')
    now = time.time() * 1000
    state = {}
    try:                                                     # resume an interrupted history run instead of duplicating it
        with open(progress) as f:
            state = json.load(f)
    except (OSError, ValueError):
        pass
    start = state.get('start') or now - HISTORY_H * 3_600_000
    install_demo_config(int(start + 60_000))
    n, change_i = state.get('n', 0), state.get('change_i', 0)
    if not os.path.exists(marker) and HISTORY_H > 0:
        log.info('generating %.0f h of demo history%s', HISTORY_H, ' (resuming)' if state else '')
        t, sent_since, t0 = state.get('t') or start, 0, time.time()
        next_change = state.get('next_change') or start + 3 * 3_600_000
        os.makedirs(os.path.dirname(progress), exist_ok=True)
        while t < now - 5_000:
            if n % 20_000 < 3:
                with open(progress, 'w') as f:
                    json.dump({'start': start, 't': t, 'n': n, 'change_i': change_i, 'next_change': next_change}, f)
            hour = datetime.fromtimestamp(t / 1000, timezone.utc).hour
            diurnal = 0.45 + 0.55 * max(0.0, math.sin((hour - 6) / 24 * 2 * math.pi))
            for rec in batch(t):
                sock.sendto(render(t + R.random() * 50, rec, _fmt(n)), (HOST, PORT))
                n += 1
                sent_since += 1
            if t >= next_change:
                for rec in config_change(t, change_i):
                    sock.sendto(render(t, rec, _fmt(n)), (HOST, PORT))
                change_i += 1
                next_change += R.uniform(4, 9) * 3_600_000
            t += 1000 / (EPS * 0.35 * diurnal) * R.uniform(0.5, 1.5)
            if sent_since >= 2000:                            # keep the burst gentle on the UDP receiver
                time.sleep(0.12)
                sent_since = 0
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        with open(marker, 'w') as f:
            f.write(str(n))
        log.info('demo history done: %d messages in %.0f s', n, time.time() - t0)
    log.info('live demo traffic at ~%.0f events/s (%s format)', EPS, FORMAT)
    next_change = time.time() + 900
    while True:
        t = time.time() * 1000
        for rec in batch(t):
            sock.sendto(render(t, rec, _fmt(n)), (HOST, PORT))
            n += 1
        if time.time() >= next_change:
            for rec in config_change(t, change_i):
                sock.sendto(render(t, rec, _fmt(n)), (HOST, PORT))
            change_i += 1
            next_change = time.time() + R.uniform(900, 1800)
        time.sleep(max(0.0, R.expovariate(EPS)))


if __name__ == '__main__':
    run()
