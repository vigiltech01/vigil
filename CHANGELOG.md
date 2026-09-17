# Changelog

## Unreleased

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
