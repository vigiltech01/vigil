# Vigil launch kit — where to post, what to post

One rule decides whether this works: **communities remove promotion, but they keep useful technical content.**
Posting the same advert to fifty groups in one day gets the accounts banned, the domain filtered and the project
remembered as spam. Posting five good, venue-specific write-ups over three weeks is what gets stars and users.

So: no blast. A schedule, one voice per venue, and every post answers "what does this do for me?" before it names Vigil.

---

## Before the first post (half a day of work, worth more than any post)

- [ ] README opens with a screenshot or the 20-second demo, then the one-line install. People decide in 8 seconds.
- [ ] Screenshots from **demo mode only** (`VIGIL_DEMO=1`, `scripts/screenshots.py`) - never a real firewall.
- [ ] `docker compose up -d` verified on a clean host, and `./install.sh` on a box where port 514 is taken.
- [ ] Issues enabled, a `good first issue` or two, and an answer ready for "why not just use FortiAnalyzer?"
- [ ] A 20-30 s screen capture (live 3D view → click a particle → the real log line). Short, no music, no logo intro.

## The honest positioning

Vigil is not a SIEM and not FortiAnalyzer. Say so first - it disarms the top comment before it is written.

> FortiAnalyzer is the product for long-term log archival and compliance. Vigil is a small self-hosted dashboard you
> can run in a minute when you do not have one: it reads the syslog you already send somewhere, and answers "who is
> hitting us, what got in, and which rule let it".

Facts you can defend (do not exaggerate beyond these):

- One container, one command, no cloud, no telemetry, Apache-2.0.
- Reads FortiOS syslog in both formats (CEF and default key=value), live, or from a file an existing rsyslog writes.
- Config-aware: upload a backup (CLI or YAML, single or multi-VDOM) to grade internet-facing rules; changes are then
  followed from the FortiGate's own change log.
- Tested against real backups from two FortiGate models across seven months of versions, and against live syslog
  from a hosting edge and a branch firewall.
- Works on a firewall that publishes nothing: then it grades remote access and the management plane instead.

What it is **not** (say it before someone else does): not multi-tenant, not HA, not a log archive, no FortiAnalyzer
parity, single node, and the 3D view is a way to see traffic - the numbers underneath are what you act on.

---

## Venues, in order

### 1. Show HN (day 1, Tue-Thu, 08:00-10:00 ET)

Title: `Show HN: Vigil – self-hosted FortiGate log dashboard you can run in a minute`

HN rules: no marketing adjectives, no emoji, explain what it is and why you built it, then stay in the thread for
the whole day and answer every comment. Link to the repo, not to a landing page.

> I run a couple of FortiGates and got tired of the gap between "the firewall logs everything" and "nobody looks at
> it". FortiAnalyzer is the right answer for archival and compliance; I wanted something I could stand up in a minute
> on a spare VM and actually read.
>
> Vigil ingests FortiOS syslog (CEF or the default key=value format), stores it in SQLite, and gives you: a live 3D
> view where every particle is one real log line you can click through to the raw record; a 30-day investigation
> search ("why was 203.0.113.9 blocked?") that walks back through the history under a time budget; and rule grading
> from a configuration backup, kept current by replaying the FortiGate's own change log.
>
> It runs as one container with no cloud dependency. If the host already receives the firewall's syslog on 514, it
> reads that file read-only instead of taking the port.
>
> Repo: https://github.com/vigiltech01/vigil - Apache-2.0. Happy to answer anything about the parsing or the schema.

### 2. r/fortinet (day 2)

**Read the sidebar rules first - if self-promotion needs mod approval, message the mods and wait.** This is the most
valuable audience and the easiest one to lose. Lead with the problem, not the product, and answer comments fast.

Title: `I built a small self-hosted dashboard for FortiGate syslog (open source) - feedback wanted`

> We send FortiGate syslog to a VM and nobody read it. Over a few weeks I built a dashboard around the questions I
> actually ask: who is hitting the WAN side, what got through, which rule allowed it, and what changed on the firewall.
>
> It is one container. If your log host already runs rsyslog on 514 it reads that file instead of fighting for the
> port, so nothing on the FortiGate changes.
>
> Two things that might interest this sub specifically:
> - It reads both FortiOS log formats, and uses `FTNTFGTeventtime` rather than the syslog header time (the header is
>   local time labelled +00:00 on the units I have).
> - Upload a config backup and it grades internet-facing rules, then follows `logid 0100044547` change events so a
>   rule you disable is reflected within seconds.
>
> Not a FortiAnalyzer replacement - no archival, no compliance reporting, single node.
>
> Repo and install: https://github.com/vigiltech01/vigil - I would like to hear which panel you would throw away first.

### 3. r/selfhosted (day 4) and r/homelab (day 6)

These reward "here is the thing running in my lab" with a screenshot and no pitch. Post the 3D view screenshot, keep
the text short, mention resource use (it fits in a small VM), and link the repo in the body, not the title.

Title: `Self-hosted dashboard for FortiGate firewall logs - one container, no cloud`

### 4. Fortinet Community (community.fortinet.com), day 8

Vendor-run: third-party tools belong in the user forums, never in product boards, and the tone is technical. Check
their terms on linking to external tools first; if in doubt post the write-up and let people ask for the link.

### 5. r/networking / r/sysadmin weekly threads (day 10+)

Both restrict standalone promotion. Use their recurring "what are you working on" / self-promotion threads only.

### 6. Mastodon infosec.exchange, LinkedIn, X (day 1, your own channels)

The LinkedIn post and the 51-second video are ready in `marketing/LinkedIn-post.md`. On Mastodon, `#fortinet
#fortigate #infosec #selfhosted`. These are yours - no gatekeeping, post whenever.

### 7. Later, once there are users: dev.to / blog post

"What a FortiGate's YAML backup really looks like" or "exactly-once ingest of 15M syslog lines a day in SQLite" -
technical write-ups that stand alone and mention Vigil once. This is what keeps bringing people in after launch week.

---

## Comment answers to have ready

| They say | You say |
|---|---|
| "Just use FortiAnalyzer." | Right tool for archival and compliance. This is for the sites that do not have one, and it runs in a minute. |
| "Why SQLite?" | One file, no daemon, survives restarts, and the queries are bounded - a 30-day search has a time budget and reads summary tables first. |
| "Is my config uploaded anywhere?" | Nothing leaves the host. Secrets are stripped before the backup is stored: passwords, keys, certificates and every `ENC` value. |
| "Security of the dashboard itself?" | Login with a signed session cookie, rate-limited, no cloud calls, read-only access to the log file. |
| "Does it work with my model?" | FortiOS 7.x CEF and default formats; tested on real backups from two models. If yours differs, open an issue with a sanitised sample - that is the fastest way to broaden support. |
| "3D is a gimmick." | Fair. It is how you spot a pattern in a second; the tables under it are what you act on. Everything in the view is a real log line you can click. |

## Rules of engagement

- One venue per day, never the same text twice - each post rewritten for that audience.
- Reply to every comment for the first 48 hours. The thread is worth more than the post.
- Never argue with criticism; ship the fix and say you did.
- No sock puppets, no asking friends to upvote, no DMs to strangers. One ban ends the launch.
- Never paste a real firewall's name, IP, rule name or log line. Demo mode only.
