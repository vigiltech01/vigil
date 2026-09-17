"""FortiGate syslog parsing - both FortiOS log formats end up as the same dict (CEF field names).

1. CEF (`config log syslogd setting / set format cef`):
     <ts> <host> CEF: 0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward deny|3|src=198.51.100.7 spt=51514 ...
   Extension values are not quoted and may contain spaces ("FTNTFGTsrccountry=United States"); a value runs until
   the next " key=". Literal '=' and '\\' inside values are escaped.

2. Default key=value (`set format default`, the FortiOS factory setting):
     <ts> <host> date=2026-01-15 time=10:02:03 devname="FGT-EDGE" devid="FG100F..." eventtime=1768471323123456789
     tz="+0100" logid="0000000013" type="traffic" subtype="forward" srcip=198.51.100.7 srcport=51514 action="deny" ...
   Keys are translated to the CEF names FortiOS itself uses (srcip -> src, dstport -> dpt, sessionid -> externalId,
   everything else -> FTNTFGT<key>), so the rest of Vigil only knows one schema.

Every parsed record also carries '_sig' (e.g. 'traffic:forward deny'), '_devname', '_devid' and '_version' when known.
Time: FTNTFGTeventtime (epoch s/ms/us/ns) is preferred; the syslog header clock is often local time mislabelled UTC.
"""
import re
from datetime import datetime, timedelta, timezone

KEY_SPLIT = re.compile(r'(?:^|\s)(\w+)=')
KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
IP_TOKEN = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:]+')

# default-format key -> CEF extension key (FortiOS CEF mapping); unlisted keys become FTNTFGT<key>
KV2CEF = {
    'srcip': 'src', 'srcport': 'spt', 'dstip': 'dst', 'dstport': 'dpt', 'proto': 'proto', 'action': 'act',
    'service': 'app', 'sessionid': 'externalId', 'sentbyte': 'out', 'rcvdbyte': 'in', 'srcintf': 'deviceInboundInterface',
    'dstintf': 'deviceOutboundInterface', 'hostname': 'dhost', 'url': 'request', 'msg': 'msg', 'user': 'duser',
    'devid': 'deviceExternalId', 'srcname': 'shost', 'filename': 'fname', 'agent': 'requestClientApplication',
    'transip': 'sourceTranslatedAddress', 'transport': 'sourceTranslatedPort', 'ui': 'sproc',
}
# keys the code reads under their FTNTFGT name even though CEF maps some of them elsewhere
KEEP_FTNT = {'app': 'FTNTFGTapp'}
UTM_TYPES = {'ips', 'app-ctrl', 'webfilter', 'virus', 'anomaly', 'dlp', 'dns', 'ssl', 'waf', 'emailfilter', 'file-filter',
             'voip', 'icap', 'ssh', 'cifs'}


def _unescape(v):
    return v.replace('\\=', '=').replace('\\\\', '\\') if '\\' in v else v


def _parse_cef(line, i):
    parts = line[i:].split('|', 7)
    if len(parts) < 8:
        return None
    kv = KEY_SPLIT.split(parts[7].rstrip('\r\n'))
    d = {k: _unescape(v.strip()) for k, v in zip(kv[1::2], kv[2::2])}
    d['_sig'] = parts[5]
    d['_version'] = parts[3].lstrip('vV')
    head = line[:i].split()
    if head and not IP_TOKEN.fullmatch(head[-1]):                     # skip a sender IP written by the receiver
        d['_devname'] = head[-1]
    if d.get('deviceExternalId'):
        d['_devid'] = d['deviceExternalId']
    return d


def _parse_kv(line):
    raw = {}
    for k, v in KV.findall(line):
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1].replace('\\"', '"')
        raw[k] = v
    if 'logid' not in raw or 'type' not in raw:
        return None
    d = {}
    for k, v in raw.items():
        if k in ('date', 'time'):
            continue
        if k in KEEP_FTNT:
            d[KEEP_FTNT[k]] = v
        elif k in KV2CEF:
            d[KV2CEF[k]] = v
        else:
            d['FTNTFGT' + k] = v
    # destination NAT (VIP) is reported as tranip/tranport with trandisp=dnat
    if raw.get('tranip') and 'dnat' in raw.get('trandisp', ''):
        d['destinationTranslatedAddress'] = raw['tranip']
        if raw.get('tranport'):
            d['destinationTranslatedPort'] = raw['tranport']
    if raw.get('cfgpath'):                                      # config-change events: same names as CEF
        for k in ('cfgpath', 'cfgobj', 'cfgattr', 'cfgtid'):
            if k in raw:
                d['FTNTFGT' + k] = raw[k]
    typ, sub = raw.get('type', ''), raw.get('subtype', '')
    cat = f'{typ}:{sub}' if sub else typ
    if typ == 'utm' and sub:                                    # CEF uses utm:<subtype>, e.g. utm:ips, utm:app-ctrl
        cat = f'utm:{sub}'
    elif typ in UTM_TYPES:                                      # older FortiOS: type="ips" subtype="signature"
        cat = f'utm:{typ}'
    d['cat'] = cat
    d['_sig'] = f"{cat} {raw.get('action', '')}".strip()
    if raw.get('devname'):
        d['_devname'] = raw['devname']
    if raw.get('devid'):
        d['_devid'] = raw['devid']
    if 'eventtime' not in raw and raw.get('date') and raw.get('time'):
        try:
            tz = raw.get('tz', '+0000')
            off = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * (1 if tz[0] == '+' else -1)
            local = datetime.fromisoformat(f"{raw['date']}T{raw['time']}").replace(tzinfo=timezone(off))
            d['FTNTFGTeventtime'] = str(int(local.timestamp() * 1_000_000_000))
        except (ValueError, IndexError):
            pass
    return d


def parse(line):
    """Return the record as a dict (CEF names + '_sig'), or None if the line is not a FortiGate log."""
    i = line.find('CEF:')
    if i >= 0:
        return _parse_cef(line, i)
    if 'logid=' in line and 'type=' in line:
        return _parse_kv(line)
    return None


CEF2KV = {v: k for k, v in KV2CEF.items()}
DENY_PATS = (b' act=deny ', b' action="deny"', b' action=deny ')


def needles(key, value, lead=b' '):
    """Byte patterns that find `key=value` in raw lines of either format, e.g. ('src', '1.2.3.4') ->
    b' src=1.2.3.4 ', b' srcip=1.2.3.4 ', b' srcip="1.2.3.4" '. `key` is the CEF name; a value can end the line in CEF."""
    kv_key = CEF2KV.get(key) or (key[7:] if key.startswith('FTNTFGT') else key)
    v = str(value).encode()
    out = [lead + key.encode() + b'=' + v + b' ', lead + kv_key.encode() + b'=' + v + b' ',
           lead + kv_key.encode() + b'="' + v + b'"']
    return tuple(dict.fromkeys(out))


def has_any(raw, pats):
    return any(p in raw for p in pats)


def event_ms(d, line):
    """Event time in epoch milliseconds (UTC)."""
    et = d.get('FTNTFGTeventtime', '')
    if et.isdigit() and len(et) >= 10:       # s / ms / us / ns -> ms
        return int(et[:13]) if len(et) >= 13 else int(et) * 10 ** (13 - len(et))
    # fallback: receive time written by Vigil's syslog receiver (true UTC)
    try:
        return int(datetime.fromisoformat(line[:25]).timestamp() * 1000)
    except (ValueError, IndexError):
        return None


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
