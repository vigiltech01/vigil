# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository. Include the Vigil version, steps to reproduce and the impact.
You will get an acknowledgement within a few days; fixes are released as soon as they are ready and credited if you wish.

## Supported versions

Security fixes are made for the latest release.

## Deployment recommendations

- Expose the web UI only to administrators - a management network or VPN, and HTTPS through a reverse proxy
  ([INSTALL.md](docs/INSTALL.md#https)).
- Restrict syslog senders with `VIGIL_SYSLOG_ALLOW` and the host firewall; syslog is unauthenticated by design.
- Create the admin account right after installing (the first visitor to `/setup` creates it), or pre-create it with
  `VIGIL_ADMIN_USER` / `VIGIL_ADMIN_PASSWORD`.
- Treat the `vigil-data` volume as sensitive: it contains firewall logs and (sanitised) configuration.
- Keep the image up to date (`docker compose pull && docker compose up -d`).

## What Vigil does to protect your data

- No outbound network connections, no telemetry. The optional contact form sends only what a person types, by email
  to the Vigil team, when they press Send.
- Configuration backups are sanitised before they are stored (passwords, keys, certificates, `ENC` values removed).
- Password hashes use PBKDF2-SHA256 with 600,000 iterations; session cookies are signed, HttpOnly and SameSite=Lax.
- The container runs as a non-root user.
