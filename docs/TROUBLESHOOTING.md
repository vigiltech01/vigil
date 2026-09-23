# Troubleshooting

Start with **Health** in the Vigil menu and the **Connect a FortiGate** checklist - they show exactly which step is missing.

## Docker errors during install

| Message | Cause | Fix |
|---|---|---|
| `Command 'docker' not found` | Docker is not installed | [Install Docker](INSTALL.md#install-docker) |
| `unknown shorthand flag: 'd' in -d` | Docker is installed but the **Compose v2 plugin** is missing, so `docker compose` is not a command | Ubuntu packages: `sudo apt install -y docker-compose-v2`. Docker's packages: `sudo apt install -y docker-compose-plugin` |
| `Package 'docker-compose-plugin' has no installation candidate` | That package only exists in Docker's repository; a stock Ubuntu calls it `docker-compose-v2` | `sudo apt install -y docker-compose-v2`, or switch to Docker's packages with `curl -fsSL https://get.docker.com \| sudo sh` |
| `permission denied while trying to connect to the Docker daemon socket` | Your user is not in the `docker` group | `sudo usermod -aG docker "$USER"` then log out and back in (or `newgrp docker`), or prefix commands with `sudo` |
| `Cannot connect to the Docker daemon ... Is the docker daemon running?` | The service is stopped | `sudo systemctl enable --now docker` |
| `docker-compose: command not found` | Old guides use the v1 `docker-compose` (hyphen) command | Vigil uses `docker compose` (space) - install the v2 plugin as above |
| `failed to bind host port 0.0.0.0:514/tcp: address already in use` | Another syslog server on this machine already owns port 514 - usually because the FortiGate already sends here | Run `./install.sh`: it finds the FortiGate log file and lets Vigil read it read-only, and retries by itself if a port turns out to be taken. See [Existing syslog server](INSTALL.md#existing-syslog-server-port-514-in-use) |
| The log says `starting: receiver, ingest, web` and `listening on udp/tcp 5514` although `.env` has `VIGIL_INPUT=file` | The container image is older than the file-input feature, so it ignores the setting | `docker compose pull && docker compose up -d --force-recreate` (or `./install.sh`, which refreshes the image). In file mode the startup line reads `starting: ingest, web` followed by `input: reading the host syslog file ...` |
| `WARN Docker Compose is configured to build using Bake, but buildx isn't installed` | Only matters when building the image locally; the published image is pulled instead | Harmless - ignore it, or `sudo apt install docker-buildx` |
| `cd: vigil: No such file or directory` after cloning | You are already inside the cloned `vigil` folder (it also contains a `vigil/` code folder) | Run `docker compose up -d` in the folder that contains `docker-compose.yml` |

## No logs arrive ("Waiting for logs")

1. **Is syslog reaching the host?**
   ```bash
   sudo tcpdump -ni any port 514
   ```
   No packets: check the FortiGate settings (`show log syslogd setting`), routing, and any firewall between the FortiGate and
   this host - including the FortiGate's own outbound policy if syslog leaves through a data interface.
2. **Packets arrive but Vigil shows no senders.** Another program owns the port (`sudo ss -ulpn | grep :514`), or Docker's port
   mapping is missing (`docker compose ps`). If that program is a syslog server writing the FortiGate logs to a file, let Vigil
   read the file - see [Existing syslog server](INSTALL.md#existing-syslog-server-port-514-in-use); `./install.sh` sets it up.
3. **Senders appear but "FortiGate logs recognised" stays open.** The lines are not FortiGate logs (for example a different
   device on the same port), or `VIGIL_SYSLOG_ALLOW` excludes the firewall. Check `docker compose logs vigil`.
4. **Reading an existing syslog file (`VIGIL_INPUT=file`) and nothing appears.** Health → *Syslog file* must say readable and
   recently written. "not found": check `VIGIL_HOST_LOG_DIR` / `VIGIL_LOG_NAME` in `.env`. "NOT readable": the file or its
   directory is not readable by group `VIGIL_HOST_LOG_GID` (`ls -l` it) - see the permissions note in the install guide.

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
