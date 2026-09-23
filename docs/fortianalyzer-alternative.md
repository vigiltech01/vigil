# Is Vigil a FortiAnalyzer alternative?

Short answer: **for some jobs yes, for the jobs FortiAnalyzer exists for, no.** This page is the honest version,
because sending you down the wrong path wastes your afternoon and our reputation.

Vigil is a free, open-source, self-hosted dashboard for FortiGate syslog. It runs as one Docker container, reads the
logs your firewall already sends, and answers the daily questions: who is hitting us from the internet, what got
through, which rule allowed it, and what changed on the firewall. Nothing leaves the machine.

## Where each one fits

| What you need | FortiAnalyzer | Vigil |
|---|---|---|
| Long-term log archival and retention policies | **Yes** — built for it | 30 days of detail by default, summaries longer |
| Compliance reporting (PCI, ISO, audit packs) | **Yes** | No |
| Multi-device, multi-tenant, ADOMs | **Yes** | Single firewall per instance |
| High availability, clustering | **Yes** | No — one container |
| Vendor support and warranty | **Yes** | Community, GitHub issues |
| FortiView, SOC automation, playbooks | **Yes** | No |
| Cost | Licensed appliance or VM | Free, Apache-2.0 |
| Time to first screen | Deploy and licence | `docker compose up -d`, about a minute |
| Runs next to an existing syslog server | — | Yes, reads its file read-only |
| Live traffic view | Dashboards | 3D view where each particle is one real log line you can click |
| Rule risk grading from your config | Reports | Upload a backup; graded, then kept current from the change log |
| Plain-English "why was this blocked?" | Log search | Investigation tracker with the hop-by-hop path |

**Use FortiAnalyzer** when you must keep logs for a year, produce audit reports, or manage many firewalls under one
roof. Nothing here replaces that.

**Use Vigil** when there is no FortiAnalyzer — the site is too small, the budget went elsewhere, or the logs land on
a syslog VM nobody reads — and you still want to see what the internet is doing to you today.

Plenty of people run both: FortiAnalyzer for retention and reporting, Vigil on the syslog box for the live view.

## Compared with rolling your own ELK

The usual free answer is Elasticsearch + Logstash + Kibana with FortiGate parsers.

| | ELK stack | Vigil |
|---|---|---|
| Moving parts | Elasticsearch, Logstash, Kibana, parser configs | One container, SQLite |
| Memory | Several GB, JVM tuning | Fits a 1–2 GB VM |
| Time to a useful screen | Days of dashboard building | Minutes, dashboards included |
| FortiGate knowledge built in | You write the parsers and panels | Field semantics, rule grading and detections included |
| Flexible for any log source | **Yes** — that is the point | FortiGate only |

If you already run ELK and enjoy it, keep it. If you want FortiGate answers today without becoming an
Elasticsearch operator, that is the gap Vigil fills.

## What Vigil is honestly not

- Not a log archive — detail is pruned (30 days by default), summaries kept longer.
- Not multi-tenant, not clustered, no HA.
- Not a compliance product — no audit report packs.
- Not an agent or an API integration — it reads syslog. It never logs in to your firewall and changes nothing on it.
- Not a FortiAnalyzer feature-for-feature clone, and it does not try to be.

## What it does well

- **One minute to running.** One container. If port 514 is already taken by rsyslog or syslog-ng, it reads that
  server's file read-only instead, so the firewall configuration stays untouched.
- **Both FortiOS log formats**, CEF and the default `key=value`, with the field semantics that trip up home-grown
  parsers (event time in nanoseconds, `FTNTFGTapp` versus `app=`, security-profile blocks that never say `deny`).
- **Config-aware rule review.** Upload a configuration backup — CLI or YAML, single or multi-VDOM — and every
  internet-facing rule is graded: who can reach it, what it exposes, whether IPS is on, which CVEs apply. Secrets are
  stripped before anything is stored: passwords, keys, certificates and every `ENC` value.
- **Changes tracked from the firewall's own logs.** Disable a rule and the grade follows within seconds, because
  FortiOS logs the change (`logid 0100044547`) with the old and new value.
- **Attack detections out of the box** — port scanners, password guessing against login services, sources denied
  first and allowed later, exploit attempts, protocol abuse, traffic spikes, new countries.
- **Works on firewalls that publish nothing.** A branch or SD-WAN unit exposes the firewall itself — SSL-VPN portal,
  admin ports. Vigil grades that exposure instead of grading rules it does not have.
- **Self-hosted and quiet.** No cloud, no telemetry, no account, no outbound calls.

## Try it

```bash
git clone https://github.com/vigiltech01/vigil.git && cd vigil && ./install.sh
```

Or without a firewall to hand, explore the demo data:

```bash
VIGIL_DEMO=1 docker compose up -d
```

Then open `http://<host>:8080`. [Install guide](INSTALL.md) · [FortiGate setup](FORTIGATE.md) ·
[Source on GitHub](https://github.com/vigiltech01/vigil)
