# Connecting a FortiGate

Vigil only needs the FortiGate's syslog. Nothing is installed on the firewall and Vigil never logs in to it.

## 1. Send syslog to Vigil

### CLI (recommended)

```
config log syslogd setting
    set status enable
    set server "192.0.2.50"        # the machine running Vigil
    set port 514                   # VIGIL_SYSLOG_PORT, 514 by default
    set format default             # "cef" works too
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set anomaly enable
end
```

- **TCP instead of UDP:** add `set mode reliable` to `config log syslogd setting`. Vigil listens on both.
- **Source interface:** if the FortiGate should use a specific interface, add `set source-ip <ip>` or
  `set interface-select-method specify` + `set interface <name>`.
- **Slot already in use?** FortiOS has four syslog slots: `syslogd`, `syslogd2`, `syslogd3`, `syslogd4`. Use a free one.

### GUI

*Log & Report → Log Settings → Remote Logging and Archiving*: enable **Send logs to syslog**, enter the Vigil address.
The GUI does not expose every option (format, port, filter); the CLI above is more predictable.

## 2. Log the traffic that makes Vigil useful

Vigil can only show what the FortiGate logs. These settings are recommended:

```
config log setting
    set fwpolicy-implicit-log enable      # denied traffic that matches no policy (internet scanners)
    set local-in-deny-unicast enable      # blocked connections to the firewall itself
end
```

On every **internet-facing policy**, log all sessions (not only security events):

```
config firewall policy
    edit <policy-id>
        set logtraffic all
    next
end
```

Security profiles (IPS, application control, web filter, antivirus) log to syslog automatically once the filter above is
enabled.

## 3. Check that logs arrive

Open **Connect a FortiGate** from the account menu in Vigil. The live checklist turns green step by step:

1. Vigil is running
2. Syslog receiver listening
3. Syslog arriving — shows the sender address
4. FortiGate logs recognised — shows the firewall name and newest log
5. Configuration backup (optional)

On the FortiGate you can generate test logs:

```
diagnose log test
```

## 4. Optional: upload a configuration backup

Rule grading, exposed-service analysis and live change tracking need the configuration:

1. FortiGate GUI → click the admin name (top right) → **Configuration → Backup** → download the file (`.conf`, or YAML).
   Leave encryption off - Vigil cannot read encrypted backups.
2. Vigil → **Settings → Configuration backup** → drop the file.
3. Set **Backup taken at** to when you downloaded it. Changes the firewall logged after that moment are replayed on top.

Vigil keeps only policies, local-in policies, addresses and groups, services, VIPs, interfaces and security-profile names.
Passwords, pre-shared keys, private keys, certificates, SNMP communities and every `ENC` value are removed **before** the file
is written to disk.

After that, keep configuration change logging enabled (it is on by default) - Vigil reads FortiOS event log
`0100044547 "Object attribute configured"` to follow every change.

## Multiple FortiGates and VDOMs

- **Several firewalls** can send to one Vigil. The dashboard shows them together; the firewall name is learned from the logs.
  For strict separation, run one Vigil per firewall on different ports (`VIGIL_SYSLOG_PORT`, `VIGIL_HTTP_PORT`).
- **VDOMs:** logs from all VDOMs are accepted. For the configuration upload, choose the VDOM on the upload form (default `root`).
- **FortiAnalyzer / FortiManager-managed firewalls** work the same way; FortiAnalyzer can also forward syslog to Vigil.

## Which log format?

Both are fully supported and produce identical results:

| | `default` | `cef` |
|---|---|---|
| FortiOS factory setting | yes | no |
| Line size | smaller | larger |
| Other SIEM tools | FortiGate-aware tools | generic CEF tools |

If another tool already consumes the syslog stream, keep its format - Vigil adapts.
