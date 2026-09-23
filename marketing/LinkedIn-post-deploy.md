# LinkedIn post — "deploy on a Linux VM" (narrated video)

**Asset:** `Vigil-deploy-1080x1350.mp4` — 97 s, 1080×1350 portrait, voice-over plus burnt-in captions (LinkedIn
autoplays muted, so the captions carry the message on their own).
**Thumbnail:** `Vigil-deploy-cover.jpg`
**Video title when uploading:** `Deploy Vigil on a Linux VM in about a minute`

Upload the MP4 as a **native video** — never a YouTube link; LinkedIn suppresses posts that send people off-platform.
Put the repository link in the **first comment**, not in the post body, for the same reason.

---

## Post (copy everything between the lines)

---

Your FortiGate logged everything today. Nobody read a line of it.

That is not negligence — it is volume. One firewall writes more log lines in a day than a team can read in a year,
and the interesting ones are buried: the source that knocked on 30 closed ports, the SSL-VPN portal taking 9,000
login attempts in an hour, the rule somebody disabled at 07:15.

So we built Vigil, and this video is the whole install.

One Linux VM. Two vCPU, two gigabytes of RAM, Docker. Clone the repo, run the installer:

→ it checks Docker and the Compose plugin
→ it checks port 514 — and if rsyslog already receives your firewall there, it reads that file read-only instead
→ it starts, and tells you how much log history it has to read and how long that takes
→ you open port 8080 and create the admin account

Nothing is installed on the FortiGate. No agent, no API key, no configuration change. It reads the syslog your
firewall already sends.

Then you get:

🔵 Live inbound traffic in 3D — every particle is one real log line, click it and read the record
🛡️ Every internet-facing rule graded from your config backup: who can reach it, what it exposes, which known
exploited CVEs apply, and how to tighten it
🔍 Plain-English investigations across 30 days — "why was this IP blocked?" answered hop by hop
📡 Detections that run themselves: port scanners, password guessing, sources denied first and allowed later

Free. Open source (Apache-2.0). Self-hosted. No cloud, no telemetry, no account, no paid tier.

It is not a FortiAnalyzer replacement — no archival, no compliance reporting, single node. Plenty of people run
both: FortiAnalyzer for retention, Vigil for the live view on the syslog box they already have.

If you run a FortiGate and your logs land on a VM nobody opens, this takes a minute to try. I would genuinely like
to hear what breaks on your setup — different models, older FortiOS, multi-VDOM.

Repository link in the comments 👇

#FortiGate #Fortinet #NetworkSecurity #SelfHosted #OpenSource #SysAdmin #InfoSec #Firewall #SOC #DevOps #Docker #Homelab #CyberSecurity #NetworkEngineer #SIEM

---

## First comment (post immediately after)

> Source, install guide and screenshots: https://github.com/vigiltech01/vigil
>
> Runs on any Linux box with Docker. If port 514 is already taken on that host, the installer detects it and reads
> the existing syslog file read-only instead — nothing on the firewall changes.

---

## Why the post is shaped this way

- **First two lines decide everything.** LinkedIn truncates at roughly 140 characters; "Your FortiGate logged
  everything today. Nobody read a line of it." is the whole hook and it works without the video playing.
- **No link in the body.** Posts with external links get materially less reach; the link goes in comment one.
- **Captions burnt in.** Most feeds play muted. The video is fully understandable with no sound.
- **Native upload.** LinkedIn pushes its own player far harder than a YouTube embed.
- **15 hashtags, mixed reach.** Broad (#CyberSecurity, #DevOps) for volume, narrow (#FortiGate, #Fortinet) for the
  people who actually care. LinkedIn indexes the first few most heavily, so the specific ones come first.
- **The honest limitation is in the post.** "Not a FortiAnalyzer replacement" stops the predictable top comment and
  earns more trust than any superlative would.

## Posting notes

- Best windows: Tue–Thu, 08:00–10:00 local, or 17:00–18:30. Avoid Friday afternoon and weekends.
- Reply to every comment in the first two hours — early engagement decides how far it travels.
- Ask three or four colleagues to comment something real (a question, an objection). Likes do far less than comments.
- Repost to relevant LinkedIn groups a day later, not the same hour.
- If it performs, the same video works on X, Mastodon (#fortinet #selfhosted), Facebook FortiGate admin groups and
  Telegram network-admin groups — those are often more active than LinkedIn for this product in Asia and the Gulf.

## Rebuilding or editing the video

Everything is reproducible from `marketing/ad-deploy/` (`slides.html` + `build.sh`):

```bash
cd marketing/ad-deploy && ./build.sh          # needs ffmpeg, edge-tts, Chrome or Edge
VOICE=en-GB-RyanNeural ./build.sh             # different narrator
```

Edit the narration in the `LINES` array and the matching slide in `slides.html` — the build re-times captions, audio
and slides automatically, so the three can never drift apart.
