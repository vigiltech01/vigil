"""Plain-English threat knowledge base for exposed services.

CVE entries were verified against the CISA Known Exploited Vulnerabilities (KEV) catalog via NVD; `kev` is the date CISA
added them. Sources: cisa.gov/known-exploited-vulnerabilities-catalog, nvd.nist.gov, docs.fortinet.com (FortiOS 7.4
hardening, local-in policy, DoS policy, SSL-VPN best practices), vendor security recommendations, MITRE ATT&CK,
Zeek scan / SSH brute-force defaults.
"""

# service class -> knowledge
KB = {
    'fg_admin': {
        'title': 'FortiGate admin login page',
        'what': 'The web page used to manage the firewall itself.',
        'weight': 30, 'known_exploited': True,
        'attacks': [
            ('Firewall takeover', 'A crafted request can bypass the login on unpatched FortiOS and give the attacker full '
             'admin rights over the firewall.', 'T1190'),
            ('Password guessing', 'Bots try common admin usernames and passwords.', 'T1110'),
        ],
        'cves': [('CVE-2022-40684', 'Admin interface authentication bypass', '2022-10-11'),
                 ('CVE-2024-55591', 'Node.js websocket bypass gives super-admin', '2025-01-14'),
                 ('CVE-2025-59718', 'FortiCloud SSO login bypass (FortiOS 7.4.0-7.4.8)', '2025-12-16'),
                 ('CVE-2026-24858', 'FortiCloud SSO: another FortiCloud account can log in', '2026-01-27')],
        'prevent': ['Allow the admin port only from trusted IPs with a local-in policy, then deny all.',
                    'Enable virtual patching on the local-in policy and keep FortiOS on the latest patch of its branch.',
                    'Disable FortiCloud SSO admin login if it is not used.'],
    },
    'sslvpn': {
        'title': 'SSL-VPN portal', 'what': 'Remote-access VPN login on the firewall.', 'weight': 30, 'known_exploited': True,
        'attacks': [('Remote code execution', 'Several SSL-VPN bugs let attackers run code on the firewall without logging in.', 'T1190'),
                    ('Credential stuffing', 'Stolen passwords are tried against VPN accounts.', 'T1110.004')],
        'cves': [('CVE-2022-42475', 'SSL-VPN heap overflow RCE', '2022-12-13'),
                 ('CVE-2023-27997', 'SSL-VPN pre-auth RCE', '2023-06-13'),
                 ('CVE-2024-21762', 'SSL-VPN out-of-bounds write RCE', '2024-02-09'),
                 ('CVE-2025-25249', 'Heap overflow via crafted packets (FortiOS 7.4.0-7.4.8)', '2026-09-09')],
        'prevent': ['Keep SSL-VPN disabled if it is not used.',
                    'If needed: restrict source addresses, require MFA, set login-attempt-limit, plan the move to IPsec.'],
    },
    'rmm': {
        'title': 'Remote management server (e.g. ManageEngine Endpoint Central)', 'what': 'Software that controls and pushes programs to every managed PC.',
        'weight': 30, 'known_exploited': True,
        'attacks': [('Server takeover, then all PCs', 'Known flaws let an attacker run code on the server; from there they can '
                     'push malware or ransomware to every managed computer.', 'T1190, T1072'),
                    ('Console password guessing', 'Bots try technician logins on the web console.', 'T1110')],
        'cves': [('CVE-2020-10189', 'ManageEngine Desktop Central deserialization RCE (only if used)', '2021-11-03'),
                 ('CVE-2021-44515', 'ManageEngine Desktop Central authentication bypass (only if used)', '2021-12-10'),
                 ('CVE-2022-47966', 'ManageEngine SAML remote code execution (only if SAML SSO is configured)', '2023-01-23')],
        'prevent': ['Do not expose the management server itself: publish the vendor gateway / relay component in a DMZ instead.',
                    'Restrict the rule source to office / agent IP ranges instead of "all".',
                    'Attach an IPS sensor (e.g. protect_http_server) to the rule and enable 2FA for technicians.'],
    },
    'smtp': {
        'title': 'Inbound mail (SMTP 25)', 'what': 'Receives email from other mail servers - it has to accept the internet.',
        'weight': 10, 'known_exploited': False,
        'attacks': [('Spam and phishing delivery', 'Malicious mail is delivered straight to users.', 'T1566'),
                    ('Mail-server exploits', 'Unpatched mail software (e.g. Exim, Zimbra) can be exploited through SMTP.', 'T1190'),
                    ('Relay abuse', 'A misconfigured server can be used to send spam.', 'T1584')],
        'cves': [('CVE-2019-10149', 'Exim remote command execution (only if Exim is used)', '2022-01-10'),
                 ('CVE-2026-73570', 'Zimbra SMTP command injection when zimbra-snmp is enabled (only if Zimbra is used)', '2026-08-21')],
        'prevent': ['Keep port 25 open only on the MX rule; attach IPS protect_email_server and anti-spam.',
                    'Enforce the SMTP application on the port (application control, enforce-default-app-port).'],
    },
    'mail_auth': {
        'title': 'Mail login (SMTPS / submission / IMAPS / POP3)', 'what': 'Users log in here to send or read mail.',
        'weight': 18, 'known_exploited': False,
        'attacks': [('Password spraying', 'A few common passwords are tried against many mailboxes; a hit gives mailbox access '
                     'and a trusted account to send spam or phishing.', 'T1110.003, T1078'),
                    ('Brute force', 'Many password guesses against one account.', 'T1110.001')],
        'cves': [],
        'prevent': ['Restrict login ports to office IPs or the cloud provider that really uses them.',
                    'IPS sensor with SMTP/IMAP brute-force signatures; MFA on mailboxes.'],
    },
    'web': {
        'title': 'Web site / web app (HTTP/HTTPS)', 'what': 'A web server or reverse proxy (e.g. HAProxy).',
        'weight': 12, 'known_exploited': False,
        'attacks': [('Web application attacks', 'Vulnerability scanners try SQL injection, path traversal and known app exploits.', 'T1190, T1595.002'),
                    ('Login brute force', 'Automated password guessing on login pages.', 'T1110'),
                    ('Bypassing the CDN / WAF', 'If a site behind a CDN or WAF also accepts direct connections, attackers skip the protection and hit the origin.', 'T1190'),
                    ('HTTP flood', 'Large request volumes to take the site down.', 'T1498')],
        'cves': [],
        'prevent': ['Sites behind a CDN or WAF: allow only the provider ranges (FortiGate Internet Service Database) as source.',
                    'Test and staging sites: allow office IPs only.', 'Attach IPS protect_http_server; consider a DoS policy.'],
    },
    'ssh': {
        'title': 'SSH / SFTP', 'what': 'Remote shell or file transfer login.', 'weight': 20, 'known_exploited': False,
        'attacks': [('Password brute force', 'Bots try thousands of passwords; a hit gives a shell on the server.', 'T1110.001, T1021.004'),
                    ('Geo rules are weak', 'Country restrictions do not stop attackers renting servers inside the allowed countries.', 'T1133')],
        'cves': [],
        'prevent': ['Allow only the specific admin / partner IPs; use key-only authentication.',
                    'IPS sensor with SSH.Connection.Brute.Force.'],
    },
    'db': {
        'title': 'Database / file sharing (SQL, SMB)', 'what': 'Data stores and Windows file shares.', 'weight': 30,
        'known_exploited': False,
        'attacks': [('Data theft', 'Direct database or share access exposes data if credentials are weak or leaked.', 'T1190, T1078'),
                    ('Ransomware entry', 'SMB and SQL are common ransomware entry and spread points.', 'T1210')],
        'cves': [], 'prevent': ['Never expose databases or SMB to the internet; use a VPN or private link.',
                                 'Restrict to exact partner IPs and attach an IPS sensor.'],
    },
    'rdp': {
        'title': 'Remote Desktop', 'what': 'Windows remote desktop.', 'weight': 25, 'known_exploited': False,
        'attacks': [('Brute force / ransomware entry', 'RDP is a top ransomware entry point via password guessing.', 'T1110, T1133')],
        'cves': [], 'prevent': ['Do not expose RDP; use VPN with MFA.'],
    },
    'voip': {
        'title': 'VoIP / SIP (PBX)', 'what': 'Phone system signalling.', 'weight': 18, 'known_exploited': False,
        'attacks': [('Toll fraud', 'Attackers register fake extensions and make paid calls.', 'T1110'),
                    ('SIP scanning', 'Bots probe extensions and passwords.', 'T1595')],
        'cves': [], 'prevent': ['Allow only the SIP trunk provider IP ranges.', 'Use a VoIP profile and IPS sensor.'],
    },
    'devtools': {
        'title': 'Developer tool (CI, code quality, artifact repository)', 'what': 'Internal engineering tool with source-code data.', 'weight': 20,
        'known_exploited': False,
        'attacks': [('Source-code exposure', 'Default or weak logins on developer tools expose code and secrets.', 'T1213'),
                    ('Tool exploits', 'Unpatched tools can be exploited remotely.', 'T1190')],
        'cves': [], 'prevent': ['Allow office / pipeline IPs only; remove broad country or cloud-provider sources.'],
    },
    'all': {
        'title': 'Every port and protocol', 'what': 'The rule allows all services to the destination.', 'weight': 35,
        'known_exploited': False,
        'attacks': [('Everything on the server is exposed', 'Any service listening on the server, including admin ports, '
                     'is reachable.', 'T1190, T1133')],
        'cves': [], 'prevent': ['Replace service ALL with the exact ports the application needs.'],
    },
    'other': {
        'title': 'Custom service', 'what': 'A custom TCP/UDP port.', 'weight': 12, 'known_exploited': False,
        'attacks': [('Unknown service exposure', 'Attackers fingerprint unusual ports and try known exploits for the software found.', 'T1046, T1190')],
        'cves': [], 'prevent': ['Confirm the port is still needed and restrict the source.'],
    },
}

PORT_CLASS = {25: 'smtp', 465: 'mail_auth', 587: 'mail_auth', 993: 'mail_auth', 995: 'mail_auth', 143: 'mail_auth',
              110: 'mail_auth', 80: 'web', 443: 'web', 8080: 'web', 8443: 'web', 22: 'ssh', 2222: 'ssh',
              8383: 'rmm', 8027: 'rmm', 1433: 'db', 3306: 'db', 5432: 'db', 1521: 'db', 27017: 'db',
              6379: 'db', 445: 'db', 139: 'db', 3389: 'rdp', 5060: 'voip', 5061: 'voip', 5080: 'voip', 9000: 'devtools',
              10443: 'sslvpn'}
NAME_CLASS = {'endpointcentral': 'rmm', 'sonar': 'devtools', 'freepbx': 'voip', 'sip': 'voip',
              'ms-sql': 'db', 'mysql': 'db', 'smb': 'db', 'rdp': 'rdp', 'ssh': 'ssh', 'imap': 'mail_auth', 'pop3': 'mail_auth',
              'smtps': 'mail_auth', 'smtp': 'smtp', 'https': 'web', 'http': 'web'}
# short names for commonly scanned ports (used for closed-port "doors" in the 3D graph)
WELL_KNOWN = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 69: 'TFTP', 80: 'HTTP', 81: 'HTTP-alt', 88: 'Kerberos',
              110: 'POP3', 111: 'RPC', 123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
              389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 502: 'Modbus', 587: 'Submission', 623: 'IPMI', 873: 'rsync',
              993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MS-SQL', 1521: 'Oracle DB', 1723: 'PPTP', 1883: 'MQTT',
              1900: 'SSDP', 2222: 'SSH-alt', 2323: 'Telnet-alt', 2375: 'Docker API', 2379: 'etcd', 3128: 'Proxy', 3306: 'MySQL',
              3389: 'RDP', 4899: 'Radmin', 5060: 'SIP', 5061: 'SIP-TLS', 5353: 'mDNS', 5432: 'PostgreSQL', 5555: 'Android ADB',
              5900: 'VNC', 5901: 'VNC', 5985: 'WinRM', 6379: 'Redis', 6443: 'Kubernetes API', 7547: 'TR-069 (routers)',
              8000: 'HTTP-alt', 8080: 'HTTP-proxy', 8081: 'HTTP-alt', 8088: 'HTTP-alt', 8291: 'MikroTik Winbox', 8443: 'HTTPS-alt',
              8888: 'HTTP-alt', 9000: 'HTTP-alt', 9200: 'Elasticsearch', 10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB',
              37215: 'Huawei router exploit', 52869: 'UPnP exploit', 60001: 'DVR exploit'}

AUTH_PORTS = {22, 2222, 465, 587, 993, 995, 143, 110, 3389, 8383, 8443, 10443, 5060, 5061}

# detection heuristics (sources: Zeek scan.zeek defaults 15 ports / 25 hosts in 5 min; Zeek SSH brute force 30 failures
# in 30 min; FortiGate DoS policy defaults)
SCAN_PORTS = 15
BRUTE_SHORT_PER_HOUR = 30


def classify_service(name, ports):
    """Service object name + ports -> KB class (most sensitive wins)."""
    classes = set()
    low = (name or '').lower()
    if low in ('all', 'all_tcp', 'all_udp'):
        return ['all']
    for key, cls in NAME_CLASS.items():
        if key in low:
            classes.add(cls)
            break
    for p in ports:
        if p in PORT_CLASS:
            classes.add(PORT_CLASS[p])
    return sorted(classes or {'other'}, key=lambda c: -KB[c]['weight'])
