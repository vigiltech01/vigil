# Fortinet Community — article + forum post

Two pieces below. **A** is the long article (Community article / blog style). **B** is a shorter forum topic.
Both are useful on their own; neither needs the product to make its point.

**Before posting:** the Community Guidelines say *"Solicitations are rarely relevant. If you have something you want
members to join, participate in, or buy, ask us first."* Having posting access is not the same as having promotional
clearance. So:

- Post the article **with the footer removed** — it is pure technical content and breaks no rule.
- In parallel, email `community@fortinet.com` (draft in `launch-kit.md`) and ask whether a repo link is acceptable.
- If they say yes, edit the post and add the footer back. If they say no, you have still published something that
  people will find useful, and your name is now attached to it.

Every IP below is from the documentation ranges (RFC 5737). Never paste a real customer address, hostname or rule name.

---

# A. Article

## Five things in FortiGate syslog that decide whether your filters work

**Suggested title:** Reading FortiGate syslog: five fields that quietly break log filters
**Tags:** FortiGate, logging, syslog, FortiOS 7.4, troubleshooting

I spent several weeks parsing FortiGate syslog from two firewalls — a hosting edge and a branch unit — for a
dashboard I maintain. Most of that time went on five details that are easy to miss and that silently produce wrong
results: filters that match nothing, timestamps an hour out, and "blocked" traffic that was never blocked. None of
this is exotic; it just is not obvious until your numbers disagree with the GUI.

### 1. The header time is not the event time

A syslog line carries two clocks: the one the syslog daemon writes at the start of the line, and
`FTNTFGTeventtime`, which the FortiGate itself sets:

```
Sep 23 13:49:22 FGT CEF: 0|Fortinet|Fortigate|v7.4.11|00013|traffic:forward close|3|
  FTNTFGTeventtime=1790151563039304497 FTNTFGTtz=+0530 ...
```

`FTNTFGTeventtime` is **nanoseconds** since the epoch — divide by 1,000,000 for milliseconds. `FTNTFGTtz` tells you
the device's offset (`+0530` above).

Why it matters: on one unit I worked with, the header time was local time while the receiving side treated it as
UTC, so everything landed in the database shifted by hours and no one noticed until a "last 24 hours" view
disagreed with the FortiGate GUI. If you index by the header time, you are indexing by whatever the relay believed.
Use `eventtime`, and keep `tz` if you need to display local time.

In the default (non-CEF) format the same field is simply `eventtime=`, and older builds may not send it at all — in
that case fall back to `date=` + `time=` **with** `tz=`, not to the header.

### 2. `app=` is not the application

In CEF output there are two fields that look like the application:

```
app=HTTPS FTNTFGTapp=Microsoft.Portal
```

`app=` is the **service label** (roughly the port/service), while `FTNTFGTapp` is what application control actually
detected. A filter written against `app=` will look like it works — it matches something — and will quietly never
match the application you meant. In the default format these are `service=` and `appid`/`app=` respectively, which
is its own source of confusion when you compare the two formats side by side.

### 3. Application control blocks do not say `act=deny`

Application-control verdicts live in their own log type, where the verdict is `act=pass` or `act=block`:

```
cat=utm:app-ctrl ... FTNTFGTapp=BitTorrent act=block FTNTFGTapplist=block-p2p
```

The matching **traffic** log for that same session does not say `deny`. It shows a normal-looking session end plus a
marker:

```
cat=traffic:forward act=client-rst ... FTNTFGTutmaction=block FTNTFGTduration=2
```

So if you count "blocked" as `act=deny`, every session killed by a security profile is missing from your numbers —
and those are exactly the ones worth reviewing. Count `act IN (deny, block, blocked, dropped, reset)` **or**
`FTNTFGTutmaction=block`.

### 4. Traffic to the firewall itself is a different log type

Requests aimed at the FortiGate — SSL-VPN portal, admin ports, and every scanner knocking on them — are
`cat=traffic:local`, not `traffic:forward`, and they carry `FTNTFGTpolicytype=local-in-policy`. Their policy IDs are
a **separate ID space**: local-in policy 1 and firewall policy 1 are unrelated. If you merge them into one "policy"
column without a prefix, your per-rule totals are wrong.

This matters most on branch firewalls that publish nothing to the internet. There, `traffic:forward` from the WAN is
almost empty and *all* the interesting inbound activity is `traffic:local`. A dashboard that only looks at forwarded
traffic will show a comforting zero while the SSL-VPN portal is being hammered.

What that hammering looks like, sanitised:

```
cat=traffic:local  src=198.51.100.7  dst=203.0.113.10  dpt=10443  act=deny
  FTNTFGTpolicyid=0  FTNTFGTpolicytype=local-in-policy  FTNTFGTsrccountry=...  FTNTFGTduration=0
```

Thousands of those per hour from one source, each a second or less, is a password-guessing run against the portal.
The one to worry about is the source that suddenly shows a **long** session with real byte counts after hundreds of
short ones — that pattern is worth an immediate look at who logged in.

### 5. Configuration changes are already in your logs

You do not need extra tooling to know who changed what. FortiOS logs every configuration change as
`logid 0100044547`:

```
cat=event:system FTNTFGTlogdesc=Object attribute configured act=Edit
  FTNTFGTcfgpath=firewall.policy FTNTFGTcfgobj=21
  FTNTFGTcfgattr=status[enable->disable] duser=admin@example.net sproc=jsconsole(198.51.100.25)
```

You get the object, the attribute, the **old and new value**, who did it and from where. `act` is `Edit`, `Add`,
`Delete` or `Move`. Two caveats worth knowing:

- `Move` records that a rule moved but not to which position, so rule **order** cannot be reconstructed from logs alone.
- Long attribute lists are split across several lines with `[NNN]` continuation markers, so a naive parser truncates
  address-group changes.

If you keep a config backup plus these events, you have an audit trail that shows exactly when a rule was disabled —
which is usually the answer to "it worked yesterday".

### Bonus: the YAML backup is not valid YAML

FortiOS can export the configuration as YAML, which is far easier to work with than the CLI format — except that
strict YAML parsers reject it. Two reasons I hit on every file I tried:

- Values contain escapes YAML does not define, e.g. `"An administrator\'s session ..."` (`\'` is not a YAML escape).
- File-filter entries are keys that start with `*`, e.g. `- *.bat:`, which YAML reads as an alias reference.

Also note the header version can have three parts (`7.4.11`), which a two-part regex silently fails to match, and
both the CLI and YAML exports start with the same `#config-version=` line — so you cannot use that line to tell the
two formats apart. Look at the body: `config <section>` blocks mean CLI, top-level `section_name:` keys mean YAML.

### Quick checklist

- Index on `FTNTFGTeventtime` (ns), keep `FTNTFGTtz`, ignore the syslog header time.
- Match applications on `FTNTFGTapp`, not `app=`.
- Count a block as `act IN (deny, block, blocked, dropped, reset)` **or** `FTNTFGTutmaction=block`.
- Keep `traffic:local` separate from `traffic:forward`, and namespace local-in policy IDs.
- Watch `logid 0100044547` for your change audit trail; remember `Move` has no position.

Happy to compare notes if your units behave differently — I have only seen FortiOS 7.4 on two models, and I would
like to know where these assumptions break.

<!-- FOOTER — add back only if Fortinet Community approves a link:
I maintain a free, open-source dashboard that applies all of the above to a live syslog feed
(one container, self-hosted, Apache-2.0): https://github.com/vigiltech01/vigil — not a FortiAnalyzer replacement,
no archival or compliance reporting; it is aimed at sites that do not have one.
-->

---

# B. Forum topic (shorter, invites replies)

**Title:** Does anyone else count application-control blocks wrong? Two FortiOS log fields worth double-checking

> While building log parsing for two FortiGates (7.4, one edge and one branch) I got two things wrong for a while,
> and I suspect I am not alone:
>
> **1. Blocks that do not say deny.** A session killed by application control shows `act=client-rst` (or `close`) in
> the traffic log plus `FTNTFGTutmaction=block`; the `act=block` verdict is in the `utm:app-ctrl` log instead. If you
> count blocks as `act=deny`, every security-profile block is missing from your reports.
>
> **2. The application field.** `app=` in CEF is the service label; the detected application is `FTNTFGTapp`. A filter
> on `app=` matches something, so it looks like it works.
>
> Two more that cost me time: `FTNTFGTeventtime` (nanoseconds) is the real event time — the syslog header can be the
> device's local time depending on your relay — and traffic aimed at the firewall itself is `cat=traffic:local` with
> local-in policy IDs in a separate ID space from firewall policy IDs.
>
> Are these consistent on your units and FortiOS versions? I have only verified 7.4 on two models, and I would like
> to know where it differs — especially whether anyone sees `Move` config-change events (`logid 0100044547`) that
> include the new position, because on mine they do not.

Replying to answers here is what earns the right to post anything promotional later. Answer every reply.
