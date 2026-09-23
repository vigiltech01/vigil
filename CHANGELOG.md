# Changelog

## Unreleased

- **Any backup a FortiGate hands out.** CLI or YAML, single or multi-VDOM, plain, gzipped, UTF-16 or BOM-prefixed,
  any model and FortiOS version (two- and three-part versions). A multi-VDOM export reads only the VDOM asked for and
  lists the VDOMs it holds if that one has no policies; an encrypted backup says so instead of failing obscurely, and
  a file that is not a FortiOS backup names what was found. Verified against 20 real backups of two models.

- **Inbound now means "from the internet", not only "to a published server".** On a branch or SD-WAN firewall nothing is
  published, and the whole exposed surface is traffic aimed at the firewall itself (SSL-VPN portal, admin ports,
  scanners), which FortiOS logs as traffic:local from a WAN interface. Every inbound view counted only forwarded
  traffic, so those firewalls showed "0 inbound requests" while the attack tables were full. Inbound totals, the
  timeline, per-rule evidence, insights and detections now include it, and LAN traffic to the firewall stays out.
- Tables that find nothing collapse to one quiet line instead of an empty table, and the interface is denser
  (smaller rail, top bar, cards, charts and base font).

- **Fixed: YAML configuration backups were rejected** with "No firewall policies found". Both the CLI backup and the YAML
  export start with `#config-version=`, so YAML files were parsed as CLI. The format is now decided by the body, and the
  YAML loader copes with what FortiOS actually writes: escapes YAML does not define (' inside quoted values), keys that
  start with an indicator (`- *.bat:` in file filters) and three-part versions in the header (7.4.11). If a section is
  still unreadable, the sections Vigil needs are loaded one by one so the policies always come through.
- Inbound Security explains itself on a firewall that publishes nothing to the internet (branch or SD-WAN office
  firewall) instead of showing an empty grade.

- **Works next to an existing syslog server.** New `install.sh` checks Docker and port 514 before starting. When the host
  already receives the FortiGate with rsyslog/syslog-ng (port 514 taken), Vigil reads that log file and its rotations
  read-only (`VIGIL_INPUT=file`) instead of failing with "address already in use"; the syslog server and the FortiGate are
  left unchanged. Health, Settings and the Connect checklist show the file source.
- **Fixed:** `install.sh` could report "port 514 is free" on machines where its `ss` call did not work (missing tool, older
  `ss` without `-H`, or a restricted `PATH`), and the container then failed with "address already in use". The port check
  now tries `ss`, `netstat`, the kernel tables in `/proc/net` and finally a real bind, never treats an unverifiable port as
  free, and if `docker compose up -d` still hits a used port it switches to the existing syslog file (or a free port) and
  retries once.
- **Backfill progress.** While Vigil reads the log history already on the machine, the status shows how far it is and
  roughly how long is left (`meta.backfill`, written by ingest every 30 s); the ingest log and the Connect checklist say
  the same, and `install.sh` prints the size of the history and an estimate before you start waiting.
- `install.sh` refreshes the container image (`docker compose pull`) before starting, so an image left from an earlier
  install is not silently reused - that could run a version older than the settings just written. `--no-pull` keeps it.
- Ingest follows `copytruncate` log rotation; `VIGIL_BACKFILL_DAYS` limits how much old rotated syslog is read on first start.
- Docs: installing Docker with the Compose v2 plugin, and a troubleshooting table for common Docker install errors.

- Community & investors: contact form in the app (Settings, Welcome page) and on the website, delivered by email to the team.
- GitHub Sponsors button and daily repository statistics workflow.

## 1.0.1 - 2026-09-17

- Project moved to github.com/vigiltech01/vigil; Docker image is now `ghcr.io/vigiltech01/vigil`.
- Documentation site on GitHub Pages; README and blog lead with the live 3D view and the one-minute integration.

## 1.0.0 - 2026-09-17

First public release.

- Built-in syslog receiver (UDP/TCP) and exactly-once ingest of FortiOS `default` and `cef` log formats.
- Home overview with security grade, live totals and what needs attention.
- Live 3D traffic view with deny reasons, replay timeline, freeze / slow motion and single-request capture.
- Inbound security: rule risk scoring, exposed services, known exploited vulnerabilities, hardening suggestions,
  attack detections and firewall admin-plane checks.
- Live configuration tracking from the FortiGate change log on top of an uploaded (sanitised) backup.
- Investigation tracker with natural-language search over 30 days, correlation, hop-by-hop path and entity traces.
- Activity, inbound, outbound, threats, log explorer, rule assistant and health pages.
- First-run admin setup, signed session cookies, login rate limiting, settings UI.
- Demo mode with a fictional firewall.
- Single Docker image with health check and resource guards.
