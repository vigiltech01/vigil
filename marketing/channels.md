# Where the users actually are

Posts spike for a day. Listings, app stores and search results bring people in every week for years. Do the evergreen
ones first, then the posts.

Two separate audiences, and they need different words:

| | FortiGate / network admins & MSPs | Self-hosters & homelabbers |
|---|---|---|
| They search for | "FortiAnalyzer alternative", "see FortiGate blocked traffic", "SSL-VPN brute force" | "self-hosted firewall dashboard", "syslog dashboard docker" |
| They care about | no cloud, no licence, rule review, who attacked us | one container, small VM, screenshots, no Java |
| Reach them via | Fortinet Community, r/fortinet, r/msp, LinkedIn, comparison directories | awesome-selfhosted, app stores, r/selfhosted, Discord |

---

## 1. Evergreen listings - do these first (a day of work, works for years)

| Where | Why it matters | Notes |
|---|---|---|
| **awesome-selfhosted** | The list every self-hoster greps | One item per PR, description under 250 chars, sentence case, approved licence (Apache-2.0 qualifies), project must be actively maintained, and search closed PRs first |
| **AlternativeTo** | Ranks for "FortiAnalyzer alternative" | List as an alternative to FortiAnalyzer, FortiSIEM, Graylog; ask three users to upvote honestly |
| **SourceForge / Slashdot / PeerSpot alternative pages** | They already own that search term | Free vendor listings; add the repo, screenshots and the honest "not an archival product" line |
| **opensourcealternative.to, LibHunt, StackShare** | Cheap, indexed, durable | Same copy each time |
| **GitHub topics** | Free discovery | `fortigate` `fortinet` `syslog` `firewall` `siem` `self-hosted` `docker` `network-security` |
| **GHCR / Docker Hub description** | People land there from `docker pull` | First two lines must show the compose snippet |
| **Product Hunt** | One-day spike, permanent backlink | Launch Tue-Thu 00:01 PT, have the video ready |

## 2. App stores - where self-hosted installs really come from

Getting into these is worth more than any single post, because the install is one click:

- **Unraid Community Applications** (a template XML + a forum thread)
- **CasaOS App Store**, **Runtipi**, **Umbrel** (each takes a small manifest PR)
- **Portainer app template** (JSON entry)
- **Proxmox community helper scripts** (huge in homelabs; a script that spins the container up)
- **TrueNAS SCALE apps** (a chart, more effort - do it after the others land)

## 3. Communities beyond Reddit and the Fortinet forum

- **Lawrence Systems** (forum + YouTube): covers self-hosted and network gear; a mention there moves real numbers.
  Approach: post in their forum, do not beg for a video.
- **r/msp**: MSPs run dozens of FortiGates. Their promo rules are strict - read the sidebar, lead with the problem.
- **Spiceworks**: sysadmin-heavy, tolerant of "I built this, here's how" write-ups.
- **Discord**: homelab, selfhosted, and networking servers (most have a #projects or #showcase channel).
- **Facebook groups**: "FortiGate Firewall" admin groups are large in Asia, the Middle East and Latin America - often
  more active than Reddit for this product, and far more tolerant of tool posts. Post the 51-second video natively.
- **Telegram / WhatsApp** network-admin groups (India, MEA): same, share the video and the repo link.
- **LinkedIn groups** for Fortinet and network security, plus commenting usefully on Fortinet's own posts.
- **Mastodon (infosec.exchange)** and **Bluesky** infosec circles.
- **Local user groups and meetups**: a 10-minute lightning talk gets more depth than 1,000 impressions.

## 4. Content that keeps pulling (write once, link forever)

Each of these stands alone as useful, mentions Vigil once, and ranks:

1. **"FortiAnalyzer alternative"** page in the docs - an honest comparison table (archival, compliance, HA, multi-tenant:
   FortiAnalyzer; one-minute install, live view, rule grading: Vigil). Honesty is what makes it credible and shareable.
2. **"What a FortiGate YAML backup actually contains"** - the `\'` escapes and `*.bat` keys that break strict parsers.
3. **"Reading 1.2 GB of FortiGate syslog a day on one small VM"** - exactly-once ingest, rollups, bounded queries.
4. **"What an SSL-VPN brute force looks like in the logs"** - 9,000 short sessions in an hour, and how to spot the
   one that succeeded. Sanitised, no customer data.
5. **YouTube**: the 51-second ad, plus a 5-minute walkthrough titled for search ("FortiGate log dashboard - install
   in one minute, self-hosted").

## 5. Paid, only if you want speed

Small budgets go furthest where intent is highest:

- **Google Search ads** on "fortianalyzer alternative", "fortigate log dashboard", "fortigate syslog viewer".
  Low volume, high intent; a few dollars a click. Send them to the comparison page, not the repo.
- **Reddit ads** targeted at r/fortinet, r/sysadmin, r/networking: cheap impressions, works only with a screenshot.
- **Newsletter sponsorship** in a self-hosted or sysadmin newsletter: one slot, modest cost, well-matched readers.
- **Skip LinkedIn ads** unless you are selling support - the cost per click does not fit a free tool.

## 6. The one thing that converts all of it

Every channel sends people to the same page. If the README does not show a screenshot and the one-line install
above the fold, the traffic is wasted. Fix that before spending a single hour on promotion.
