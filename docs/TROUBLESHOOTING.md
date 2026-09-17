# Troubleshooting

Start with **Health** in the Vigil menu and the **Connect a FortiGate** checklist - they show exactly which step is missing.

## No logs arrive ("Waiting for logs")

1. **Is syslog reaching the host?**
   ```bash
   sudo tcpdump -ni any port 514
   ```
   No packets: check the FortiGate settings (`show log syslogd setting`), routing, and any firewall between the FortiGate and
   this host - including the FortiGate's own outbound policy if syslog leaves through a data interface.
2. **Packets arrive but Vigil shows no senders.** Another program owns the port (`sudo ss -ulpn | grep :514`), or Docker's port
   mapping is missing (`docker compose ps`). Use another port - see [INSTALL.md](INSTALL.md#port-514-already-in-use).
3. **Senders appear but "FortiGate logs recognised" stays open.** The lines are not FortiGate logs (for example a different
   device on the same port), or `VIGIL_SYSLOG_ALLOW` excludes the firewall. Check `docker compose logs vigil`.

## Only some traffic is visible

- Denied internet scans missing → `set fwpolicy-implicit-log enable` under `config log setting`.
- Sessions on a rule missing → `set logtraffic all` on that policy.
- Blocked connections to the firewall itself missing → `set local-in-deny-unicast enable`.

## Timestamps are off by hours

Vigil uses the `eventtime` field, which FortiOS writes in UTC nanoseconds. If times are wrong, check the FortiGate clock (`get
system status`, NTP). The UI shows your browser's local time; switch to UTC in the top bar.

## Configuration upload fails

- "No firewall policies found" - the file is not a full backup, or policies live in another VDOM (set the VDOM on the form).
- Encrypted backups cannot be read. Download the backup without a password.

## Rule order may have changed

A rule was moved or re-created on the firewall. The FortiGate log does not record the new position; upload a fresh backup to
clear the warning.

## Forgot the admin password

```bash
docker exec -it vigil python -m vigil reset-password admin
```

## High memory or disk usage

- Lower `VIGIL_RETENTION_DAYS` in `.env` and restart; old rows are pruned hourly.
- Raw syslog files rotate at 512 MB and 14 compressed files are kept (`VIGIL_LOG_ROTATE_MB`, `VIGIL_LOG_KEEP`).
- The web process restarts itself if it exceeds `VIGIL_MAX_RSS_MB`; `docker compose logs` shows it.

## Collect diagnostics for an issue

```bash
docker compose ps
docker compose logs --tail 200 vigil
docker exec vigil python -m vigil --version
```

Remove IP addresses and names you do not want to share before posting logs publicly.
