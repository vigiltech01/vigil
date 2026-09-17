"""Configuration backup import (CLI + YAML), secret stripping, rule analysis and live change replay."""
import os

import pytest
import yaml

from vigil import cfglive, fgconf, rules

DEMO_CONF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vigil', 'demo', 'fgt-demo.conf')


@pytest.fixture(scope='module')
def demo():
    with open(DEMO_CONF, 'rb') as f:
        return fgconf.import_backup(f.read(), 'FGT-DEMO.conf', 1768471200000)


def test_cli_import_counts(demo):
    clean, info = demo
    assert info['format'] == 'cli' and info['model'] == 'FGVM64' and info['version'] == '7.4'
    assert info['policies'] == 7 and info['local_in'] == 2 and info['vips'] == 4
    assert clean['system_global']['admin-sport'] == 8443
    assert [list(p)[0] for p in clean['firewall_policy']][:2] == ['6', '1']          # order preserved


def test_secrets_are_removed(demo):
    text = fgconf.dump(demo[0])
    for bad in ('ENC ', 'BEGIN', 'password', 'psksecret', 'private-key', 'demoNotReal', 'system_admin', 'demo-server-cert'):
        assert bad not in text, bad


def test_multi_vdom_and_yaml():
    cli = '''#config-version=FG100F-7.02-FW-build1234-220101:opmode=0:vdom=1:user=admin
config global
config system global
    set hostname "MV"
    set admin-sport 443
end
end
config vdom
edit root
config firewall policy
    edit 9
        set srcintf "port1"
        set dstintf "port2"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
next
end
'''
    clean, info = fgconf.import_backup(cli, 'mv.conf')
    assert info['vdoms'] == ['root'] and clean['system_global']['hostname'] == 'MV'
    assert clean['firewall_policy'] == [{'9': {'srcintf': 'port1', 'dstintf': 'port2', 'action': 'accept', 'srcaddr': 'all',
                                               'dstaddr': 'all', 'service': 'ALL'}}]
    y = yaml.safe_dump({'firewall_policy': [{3: {'srcaddr': 'all', 'action': 'accept', 'password': 'x'}}]})
    clean, info = fgconf.import_backup(y, 'b.yaml')
    assert info['format'] == 'yaml' and 'password' not in fgconf.dump(clean)


def test_not_a_backup():
    with pytest.raises(fgconf.ConfigError):
        fgconf.import_backup(b'hello world, this is not a firewall configuration', 'x.txt')


def test_rule_analysis(demo):
    m = rules.Model(demo[0])
    inbound = {p['id']: rules.analyze_rule(m, p) for p in rules.inbound_rules(m)}
    assert set(inbound) == {1, 2, 3, 4, 5, 6}
    rdp = inbound[5]
    assert rdp['source']['scope'] == 'any' and 'rdp' in rdp['classes'] and rdp['level'] in ('critical', 'high')
    assert inbound[4]['source']['scope'] == 'restricted'
    assert inbound[3]['source']['scope'] == 'geo'
    assert inbound[6]['action'] == 'deny'
    assert any(d['public'] for d in inbound[1]['destinations'])
    admin = rules.admin_plane(m)
    assert admin['admin_port'] == 8443 and admin['sslvpn_enabled'] and admin['sslvpn_port'] == 10443


def test_live_change_replay_and_chunks(demo):
    d = demo[0]
    rows = [
        {'ts': 1768471300000, 'tsn': '1', 'cfgtid': 1, 'act': 'Edit', 'path': 'firewall.policy', 'obj': '5', 'attr': 'status[enable->disable]', 'usr': 'admin', 'ui': 'GUI'},
        {'ts': 1768471300001, 'tsn': '2', 'cfgtid': 2, 'act': 'Edit', 'path': 'firewall.addrgrp', 'obj': 'partners',
         'attr': 'member[partner-1 partner-2->partner-1 part [001]', 'usr': 'admin', 'ui': 'GUI'},
        {'ts': 1768471300001, 'tsn': '3', 'cfgtid': 2, 'act': 'Edit', 'path': 'firewall.addrgrp', 'obj': 'partners',
         'attr': '[001]: ner-2 partner-3]', 'usr': 'admin', 'ui': 'GUI'},
        {'ts': 1768471300002, 'tsn': '4', 'cfgtid': 3, 'act': 'Move', 'path': 'firewall.policy', 'obj': '4', 'attr': None, 'usr': 'admin', 'ui': 'GUI'},
    ]
    merged = cfglive.merge_chunks(rows)
    assert len(merged) == 3 and merged[1]['attr'] == 'member[partner-1 partner-2->partner-1 partner-2 partner-3]'
    new, recs = cfglive.build(d, merged)
    m = rules.Model(new)
    assert m.by_id[5]['status'] == 'disable'
    assert m.groups['partners'] == ['partner-1', 'partner-2', 'partner-3']
    assert [r['status'] for r in recs] == ['applied', 'applied', 'order unknown']
    assert recs[0]['text'] == 'Rule 5: disabled'
    assert 'partner-3' in recs[1]['text']
