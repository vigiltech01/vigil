# Showing the product inside the rules

The Fortinet Community forbids self-promotion and asks you to clear anything promotional first. That still leaves
four legitimate ways for people to find the tool — all of them used by open-source maintainers on vendor forums.
The order matters: 1 and 2 need no permission, 3 needs relevance and a disclosure, 4 needs a written yes.

---

## 1. Your profile (passive, no permission needed)

A profile is not a solicitation. Fill it in once and every helpful answer you post carries it quietly.

**Display name:** your real name
**About me / bio:**

> Network and security engineer. I work with FortiGate syslog and maintain a free, open-source dashboard for it
> (Apache-2.0). Happy to talk about FortiOS log formats, parsing and rule review.

**Website field:** `https://github.com/vigiltech01/vigil`

If the platform offers a signature, keep it to one plain line — no slogans, no emoji:

> Free & open-source FortiGate syslog dashboard — github.com/vigiltech01/vigil

## 2. Be the person who answers (this is what actually works)

Ten good answers with no link earn more installs than any post with one. People click your profile when your answer
helped them — that is the profile doing the work.

Threads to watch for, and what you already know cold:

| Thread type | What you can answer from experience |
|---|---|
| "My log filter matches nothing" | `app=` is the service label; the detected application is `FTNTFGTapp` |
| "Blocked sessions missing from reports" | Security-profile blocks show `client-rst`/`close` + `FTNTFGTutmaction=block`, never `act=deny` |
| "Timestamps are hours out" | Use `FTNTFGTeventtime` (nanoseconds) and `FTNTFGTtz`, not the syslog header |
| "Who changed this rule?" | `logid 0100044547` with `cfgpath`, `cfgobj`, `cfgattr` showing `old->new`, plus the user and source IP |
| "SSL-VPN being brute-forced" | Thousands of sub-second `traffic:local` denies to the portal port; watch for the one long session that follows |
| "Alternative to FortiAnalyzer?" | This is the one thread where a disclosed link is on-topic — see below |

## 3. The disclosed, on-topic answer

When someone **asks** for a tool, answering is not solicitation — provided you disclose that you wrote it, you
answer the question first, and you name the alternatives honestly. Template:

> For archival and compliance reporting the right answer is FortiAnalyzer; free alternatives people use are an ELK
> stack with FortiGate parsers, or Graylog.
>
> Disclosure: I maintain a free, open-source one as well — one container, reads the syslog you already send, shows
> inbound activity and grades internet-facing rules from a config backup. Apache-2.0, no cloud, no paid tier. Happy
> to link it if that is allowed here, or you can search "vigil fortigate" on GitHub.
>
> Whichever you pick, two things to get right: index on `FTNTFGTeventtime`, and count `FTNTFGTutmaction=block` as a
> block — otherwise security-profile blocks vanish from your numbers.

Note the shape: **answer, disclose, offer rather than paste.** If a moderator has already approved links, paste the
URL directly instead of the "happy to link" line.

Do not do this more than occasionally, never in a thread where nobody asked, and never twice in the same thread.

## 4. Written permission for a proper post

Send the email in `launch-kit.md` to `community@fortinet.com`. If they approve, the article in
`fortinet-community-article.md` goes up with its footer restored, and the link target should be the comparison page
(`docs/fortianalyzer-alternative.md`) rather than the bare repo — it sets expectations and reduces "this is not
FortiAnalyzer" replies.

---

## Lines that stay honest (use these words)

- "Free and open source (Apache-2.0), self-hosted, no paid tier, no telemetry."
- "Not a FortiAnalyzer replacement — no archival, no compliance reporting, single node."
- "It reads syslog. It never logs in to your firewall and changes nothing on it."
- "Secrets are stripped from an uploaded backup before it is stored."
- "Tested on FortiOS 7.4 across two models; tell me where it breaks on yours."

## Lines that get you removed (never use)

- "Best FortiGate dashboard", "replace FortiAnalyzer", "enterprise-grade", any superlative.
- Any link in a thread where nobody asked for a tool.
- The same message in several groups on the same day.
- A reply whose only content is a link.
- Screenshots containing a real firewall name, IP, rule name or log line — demo mode only.

## If a moderator removes a post

Do not repost, do not argue in public. One message: "Understood, sorry — I misread the guidelines. Is there a place
where sharing a free open-source tool is acceptable, or would you prefer I only answer questions?" Maintainers who
respond like that get invited back; the ones who argue get banned.
