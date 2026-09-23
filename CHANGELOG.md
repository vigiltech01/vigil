# Changelog

## Unreleased

- **Works next to an existing syslog server.** New `install.sh` checks Docker and port 514 before starting. When the host
  already receives the FortiGate with rsyslog/syslog-ng (port 514 taken), Vigil reads that log file and its rotations
  read-only (`VIGIL_INPUT=file`) instead of failing with "address already in use"; the syslog server and the FortiGate are
  left unchanged. Health, Settings and the Connect checklist show the file source.
- **Fixed:** `install.sh` could report "port 514 is free" on machines where its `ss` call did not work (missing tool, older
  `ss` without `-H`, or a restricted `PATH`), and the container then failed with "address already in use". The port check
  now tries `ss`, `netstat`, the kernel tables in `/proc/net` and finally a real bind, never treats an unverifiable port as
  free, and if `docker compose up -d` still hits a used port it switches to the existing syslog file (or a free port) and
  retries once.
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
