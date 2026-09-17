"""Both FortiOS syslog formats must produce the same record."""
import pytest

from vigil import cef, demo

CEF_LINE = ('2026-01-15T10:02:03+00:00 FGT-EDGE CEF: 0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward deny|3|'
            'deviceExternalId=FG100FTK00000001 FTNTFGTeventtime=1768471323123456789 FTNTFGTtz=+0100 FTNTFGTlogid=0000000013 '
            'cat=traffic:forward src=198.51.100.7 spt=51514 deviceInboundInterface=wan1 FTNTFGTsrcintfrole=wan '
            'dst=203.0.113.10 dpt=3389 deviceOutboundInterface=unknown-0 FTNTFGTsrccountry=United States '
            'externalId=12345 proto=6 act=deny FTNTFGTpolicyid=0 FTNTFGTpolicytype=policy app=tcp/3389')
KV_LINE = ('2026-01-15T10:02:03+00:00 192.0.2.1 date=2026-01-15 time=11:02:03 devname="FGT-EDGE" devid="FG100FTK00000001" '
           'eventtime=1768471323123456789 tz="+0100" logid="0000000013" type="traffic" subtype="forward" level="notice" '
           'vd="root" srcip=198.51.100.7 srcport=51514 srcintf="wan1" srcintfrole="wan" dstip=203.0.113.10 dstport=3389 '
           'dstintf="unknown-0" srccountry="United States" sessionid=12345 proto=6 action="deny" policyid=0 '
           'policytype="policy" service="tcp/3389"')
KEYS = ('cat', 'src', 'spt', 'dst', 'dpt', 'act', 'proto', 'externalId', 'FTNTFGTpolicyid', 'FTNTFGTsrccountry',
        'deviceInboundInterface', 'FTNTFGTsrcintfrole', 'app', 'deviceExternalId')


def test_cef_and_default_formats_are_equivalent():
    a, b = cef.parse(CEF_LINE), cef.parse(KV_LINE)
    assert a and b
    for k in KEYS:
        assert a.get(k) == b.get(k), k
    assert a['_sig'] == b['_sig'] == 'traffic:forward deny'
    assert cef.event_ms(a, CEF_LINE) == cef.event_ms(b, KV_LINE) == 1768471323123
    assert a['_devname'] == b['_devname'] == 'FGT-EDGE'
    assert a['_version'] == '7.4.3'


def test_values_with_spaces_and_escapes():
    d = cef.parse('x CEF: 0|Fortinet|Fortigate|v7.4.3|1|event:system|2|msg=a b\\=c FTNTFGTcfgattr=srcaddr[all->USA India] act=Edit')
    assert d['msg'] == 'a b=c'
    assert d['FTNTFGTcfgattr'] == 'srcaddr[all->USA India]'
    kv = cef.parse('date=2026-01-15 time=10:00:00 logid="0100044547" type="event" subtype="system" '
                   'cfgpath="firewall.policy" cfgobj="21" cfgattr="srcaddr[all->USA India]" msg="Edit \\"x\\""')
    assert kv['FTNTFGTcfgattr'] == 'srcaddr[all->USA India]' and kv['msg'] == 'Edit "x"'


def test_non_fortigate_lines_are_ignored():
    assert cef.parse('2026-01-15T10:00:00+00:00 host sshd[1]: Accepted publickey for root') is None


def test_kv_without_eventtime_uses_date_time_and_tz():
    d = cef.parse('date=2026-01-15 time=11:00:00 tz="+0100" logid="0000000013" type="traffic" subtype="forward" action="accept"')
    assert cef.event_ms(d, '') == 1768471200000


@pytest.mark.parametrize('gen', [demo.scan_deny, demo.inbound_allowed, demo.brute_force, demo.ips_attack, demo.outbound,
                                 demo.vpn_event, demo.admin_login, demo.protocol_abuse, lambda t: demo.config_change(t, 0)])
def test_demo_records_round_trip_in_both_formats(gen):
    ts = 1768471323123
    recs = gen(ts)
    recs = recs if isinstance(recs, list) else [recs]
    for rec in recs:
        a = cef.parse('2026-01-15T10:02:03+00:00 127.0.0.1 ' + demo.render(ts, rec, 'cef').decode())
        b = cef.parse('2026-01-15T10:02:03+00:00 127.0.0.1 ' + demo.render(ts, rec, 'default').decode()[5:])
        assert a and b, rec['cat']
        for k in ('cat', 'src', 'dst', 'dpt', 'act', 'FTNTFGTpolicyid', 'FTNTFGTapp', 'FTNTFGTattack', 'FTNTFGTcfgattr',
                  'destinationTranslatedAddress', 'dhost', 'duser'):
            assert str(a.get(k)) == str(b.get(k)), (rec['cat'], k, a.get(k), b.get(k))
        assert cef.event_ms(a, '') == cef.event_ms(b, '') == ts


def test_raw_needles_match_both_formats():
    """Raw-log pre-filters (live graph, scanner search, correlation) must not assume the CEF spelling."""
    from vigil.graph3d import WAN_ROLE
    for line in (CEF_LINE, KV_LINE):
        raw = line.encode()
        assert cef.has_any(raw, WAN_ROLE)
        assert cef.has_any(raw, cef.DENY_PATS)
        assert cef.has_any(raw, cef.needles('src', '198.51.100.7'))
        assert cef.has_any(raw, cef.needles('dst', '203.0.113.10'))
        assert cef.has_any(raw, cef.needles('dpt', 3389))
        assert cef.has_any(raw, cef.needles('FTNTFGTpolicyid', 0))
        assert not cef.has_any(raw, cef.needles('src', '198.51.100.70'))
        assert not cef.has_any(raw, cef.needles('dpt', 338))


def test_demo_default_format_quotes_strings_like_fortios():
    line = demo.render(1768471323123, demo.scan_deny(1768471323123), 'default').decode()
    assert 'srcintfrole="wan"' in line and 'action="deny"' in line
    assert ' srcip=' in line and ' srcip="' not in line
