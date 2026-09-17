'use strict';
/* Home (#home) and first-run onboarding (#welcome). Uses app.js helpers. */

const GRADE = {A: [1, 'var(--good)', 'Protected'], B: [0.75, 'var(--blue-2)', 'Mostly protected'], C: [0.5, 'var(--warning)', 'Needs attention'],
  D: [0.25, 'var(--critical)', 'Needs attention now']};

function gaugeH(grade, sub) {
  const [frac, color] = GRADE[grade] || [0, 'var(--faint)'];
  const r = 44, c = 2 * Math.PI * r;
  return `<svg viewBox="0 0 100 100">
      <circle class="orbit" cx="50" cy="50" r="49" fill="none" stroke-width=".6"/>
      <circle class="ring-bg" cx="50" cy="50" r="${r}" fill="none" stroke-width="2.2"/>
      <circle class="ring" id="hm-ring" cx="50" cy="50" r="${r}" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round"
        stroke-dasharray="${c}" stroke-dashoffset="${c}" transform="rotate(-90 50 50)" data-off="${c * (1 - frac)}"/>
    </svg>
    <div class="center"><div class="grade">${esc(grade || '–')}</div><div class="glabel">Security grade</div><div class="gsub">${sub || ''}</div></div>`;
}

PAGES.home = {
  layout: () => `<section class="hero" id="hm-hero">
      <div>
        <div class="fw" id="hm-fw">&nbsp;</div>
        <h2 id="hm-head"><span class="sk w50" style="display:inline-block;height:40px;width:260px"></span></h2>
        <div class="lead" id="hm-lead"><div class="sk w70"></div></div>
        <div class="stats" id="hm-stats"></div>
        <div class="actions"><a class="primary" href="#graph">Watch live traffic</a><a class="secondary" href="#security">Review inbound rules</a>
          <a class="secondary" href="#investigate">Investigate</a></div>
      </div>
      <div class="gauge" id="hm-gauge">${gaugeH('', '')}</div>
    </section>
    ${card('hm-tl', 'Inbound requests', {w: 'w8', chart: '', sub: 'Every request from the internet in the selected range - allowed, denied by the firewall, or stopped by a security profile. Markers: ☣ IPS threat, 🔑 password guessing.'})}
    <section class="card w4"><header><h3>Needs attention</h3><span class="sub">Most important first</span></header><div class="body"><ul class="attention" id="hm-att">${SKEL}</ul></div></section>
    <div class="feature-grid" id="hm-feat"></div>
    ${card('hm-src', 'Most active attackers', {w: 'w6', sub: 'Sources the firewall blocked the most (port scans and password guessing). Click one to trace it.'})}
    ${card('hm-chg', 'Recent configuration changes', {w: 'w6', sub: 'Read from the FortiGate change log - the security score already includes them'})}`,
  async load(sp) {
    if (S.meta && !S.meta.last_event_ts && !ls('welcomed')) { ls('welcomed', '1'); location.hash = '#welcome'; return; }
    const fw = S.meta.firewall || {};
    $('#hm-fw').textContent = [fw.name || 'FortiGate', fw.version ? 'FortiOS ' + fw.version : '', fw.model, S.meta.demo ? 'Demo data' : ''].filter(Boolean).join('  ·  ');
    const rangeTxt = S.range === 'custom' ? 'the selected period' : {'1h': 'the last hour', '6h': 'the last 6 hours', '24h': 'the last 24 hours',
      '7d': 'the last 7 days', '30d': 'the last 30 days'}[S.range] || 'this period';
    const [tl, sec] = await Promise.all([api('/api/graph3d/timeline', sp), api('/api/security', sp).catch(() => null)]);
    const sum = i => tl.buckets.reduce((a, b) => a + b[i], 0);
    const allowed = sum(1), denied = sum(2), blocked = sum(3), threats = sum(4);
    const p = sec && sec.posture, det = sec && sec.detections;
    const grade = p && sec.config.loaded ? p.grade : '';
    const attackers = det ? det.scanners.count + det.bruteforce.length : 0;
    const alarm = grade === 'C' || grade === 'D' || (det && det.bruteforce.some(b => b.possible_success));
    $('#hm-hero').classList.toggle('alarm', grade === 'D');
    $('#hm-head').textContent = !S.meta.last_event_ts ? 'Waiting for your FortiGate' : grade ? GRADE[grade][2] : alarm ? 'Needs attention' : 'Watching';
    $('#hm-lead').innerHTML = !S.meta.last_event_ts
      ? 'No logs have arrived yet. <a href="#welcome">Connect your FortiGate</a> - it takes two commands.'
      : `In ${rangeTxt} ${esc(fw.name || 'the firewall')} handled <b>${fmtK(allowed + denied + blocked)}</b> inbound requests and turned away
         <b>${fmtK(denied + blocked)}</b>${attackers ? ` from at least <b>${fmtN(attackers)}</b> scanning or attacking sources` : ''}.
         ${threats ? `<b>${fmtN(threats)}</b> exploit attempts were caught by IPS.` : 'No exploit attempts were detected.'}
         ${sec && !sec.config.loaded ? '<br><span class="muted">Upload a configuration backup in <a href="#settings">Settings</a> to grade your rules.</span>' : ''}`;
    $('#hm-stats').innerHTML = [[fmtK(denied + blocked), 'Blocked', `${allowed + denied + blocked ? Math.round(100 * (denied + blocked) / (allowed + denied + blocked)) : 0}% of inbound`],
      [fmtK(threats), 'Threats stopped', 'IPS detections'], [fmtK(allowed), 'Allowed in', 'to your published services']]
      .map(([n, l, d]) => `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div><div class="d">${d}</div></div>`).join('');
    $('#hm-gauge').innerHTML = gaugeH(grade, p ? `${p.levels.critical} critical · ${p.levels.high} high-risk rules` : 'no configuration loaded');
    requestAnimationFrame(() => requestAnimationFrame(() => { const r = $('#hm-ring'); if (r) r.style.strokeDashoffset = r.dataset.off; }));
    // timeline: fixed categorical order - allowed (slot 1), denied (slot 2), security block (slot 3)
    const series = [['Allowed', 1, C.s[0]], ['Denied', 2, C.s[1]], ['Stopped by security profile', 3, C.s[2]]].map(([name, i, color]) =>
      barSeries(name, tl.buckets.map(b => [b[0], b[i]]), color, 'x'));
    const marks = (tl.markers || []).slice(0, 60).map(m => ({coord: [m.t, 0], value: m.type === 'threat' ? '☣' : '🔑', label: m.label}));
    series[0].markPoint = {symbol: 'pin', symbolSize: 26, itemStyle: {color: '#2a2a2e'}, label: {fontSize: 11}, data: marks,
      tooltip: {formatter: q => esc(q.data.label)}};
    chart('hm-tl-c', Object.assign(base(sp), {series}), q => {
      if (q.componentType === 'markPoint') return;
      location.hash = '#graph';
    });
    // needs attention
    const items = [];
    (sec ? sec.priorities : []).forEach(x => items.push([x.level, x.title, x.fix, x.rule ? `#security?tab=rules` : '#security']));
    try {
      const ins = await api('/api/insights', sp);
      ins.alerts.forEach(a => items.unshift([a.severity, a.title, a.detail, '#health']));
    } catch (e) { /* optional */ }
    $('#hm-att').innerHTML = items.length ? items.slice(0, 6).map(([lv, t, d, go]) => `<li>${sevH(lv === 'critical' ? 'critical' : lv === 'high' ? 'high' : lv === 'medium' ? 'medium' : 'low')}
        <div><div class="t">${esc(t)}</div><div class="d">${esc(d || '')}</div></div><a class="golink" href="${go}">Open →</a></li>`).join('')
      : '<li class="ok">Nothing needs attention right now.</li>';
    // feature cards
    $('#hm-feat').innerHTML = [
      ['#graph', 'globe', 'Live traffic', 'Watch every inbound request hit a 3D model of your firewall. Click one to capture the exact log line.', '#3987e5'],
      ['#security', 'shield', 'Inbound security', grade ? `Grade ${grade}: ${p.open_to_anyone} rules open to anyone, ${p.no_ips} without IPS.` : 'Grade every internet-facing rule and see how it could be attacked.', '#d03b3b'],
      ['#investigate', 'search', 'Investigate', 'Ask “why was 203.0.113.9 blocked?” and follow the path hop by hop.', '#9085e9'],
      ['#utm', 'alert', 'Threats', 'IPS detections, application control, web filtering and admin activity.', '#c98500'],
    ].map(([href, ic, t, d, glow]) => `<a class="feature" href="${href}"><span class="glow" style="background:${glow}"></span>
        <span class="fi"><svg viewBox="0 0 24 24">${ICON[ic]}</svg></span><h4>${t}</h4><p>${esc(d)}</p><span class="go">Open →</span></a>`).join('');
    // attackers + changes
    const src = det ? det.scanners.top.map(r => ({src: r.src, country: r.country, n: r.n, what: `scanned ${r.ports}+ ports`}))
      .concat(det.bruteforce.map(b => ({src: b.src, country: b.country, n: b.short, what: `password guessing on ${b.service}`})))
      .sort((a, b) => b.n - a.n).slice(0, 8) : [];
    table('hm-src', [{k: 'src', t: 'Source', mono: true}, {k: 'country', t: 'Country'}, {k: 'what', t: 'Activity'}, {k: 'n', t: 'Attempts', num: true}],
      src, {onRow: r => location.hash = `#investigate?trace=ip:${encodeURIComponent(r.src)}`, empty: 'No scanners or password guessing in this range.', limit: 8});
    const chg = sec ? (sec.config.recent_changes || []).filter(c => c.risk).slice(0, 8) : [];
    table('hm-chg', [{k: 'ts', t: 'When', f: v => esc(fmtT(v, 'dhm'))}, {k: 'user', t: 'Who'}, {k: 'text', t: 'Change'}], chg,
      {onRow: () => location.hash = '#security?tab=changes', limit: 8,
        empty: sec && sec.config.loaded ? 'No configuration changes logged since the backup.' : 'Upload a configuration backup in Settings to track rule changes.'});
  },
};

// ------------------------------------------------------------------ onboarding
PAGES.welcome = {
  layout: () => `<div class="welcome">
      <section class="intro"><div class="eyebrow">Welcome to Vigil</div><h2>Connect your FortiGate</h2>
        <p>Vigil listens for FortiGate syslog and turns it into live threat views, rule risk scores and one-click investigations.
        Point the firewall at this machine - nothing is installed on the FortiGate and your logs never leave this machine.</p></section>
      <section class="card"><header><h3>1 · Send syslog to Vigil</h3><span class="sub">Paste into the FortiGate CLI (System → CLI console, or SSH). Replace the address if this machine is reached through a different one.</span></header>
        <div class="body"><div id="wl-mode"></div><div class="copyable"><pre class="cli" id="wl-cli"></pre><button id="wl-copy">Copy</button></div>
        <div class="note" style="margin-top:12px">Both FortiOS log formats work (<span class="mono">default</span> and <span class="mono">cef</span>). For TCP instead of UDP add
          <span class="mono">set mode reliable</span>. Several FortiGates can send to the same Vigil - use <span class="mono">syslogd2</span> … <span class="mono">syslogd4</span> if the first slot is taken.</div></div></section>
      <section class="card"><header><h3>Live checklist</h3><span class="sub">Updates automatically every few seconds</span></header>
        <div class="body"><ul class="steps" id="wl-steps">${SKEL}</ul></div></section>
      <section class="card"><header><h3>2 · Log the traffic that matters</h3><span class="sub">Recommended - makes denied scans, blocked admin logins and rule usage visible</span></header>
        <div class="body"><div class="copyable"><pre class="cli" id="wl-cli2">config log setting
    set fwpolicy-implicit-log enable
    set local-in-deny-unicast enable
end
# and on every internet-facing policy:
config firewall policy
    edit &lt;policy-id&gt;
        set logtraffic all
    next
end</pre><button id="wl-copy2">Copy</button></div></div></section>
      <section class="card"><header><h3>3 · Optional: upload a configuration backup</h3><span class="sub">Lets Vigil grade every inbound rule and track changes live</span></header>
        <div class="body"><p class="muted" style="margin-top:0">In the FortiGate GUI: <b>admin menu → Configuration → Backup</b>, then drop the file on
          <a href="#settings?s=config">Settings → Configuration</a>. Passwords, keys and certificates are removed on upload.</p>
          <p class="muted">Just exploring? Start Vigil with <span class="mono">VIGIL_DEMO=1</span> to see it working with a fictional firewall.</p>
          <a class="btn-primary" style="display:inline-block;padding:8px 18px;border-radius:999px" href="#home">Go to Home</a></div></section>
      <section class="card wl-contact"><header><h3>Stay in touch <span class="muted" style="font-weight:400">(optional)</span></h3><span class="sub">Vigil is built by a small startup. Tell us who you are - we share updates, answer questions, and investors and crowdfunding backers are very welcome.</span></header>
        <div class="body" id="wl-contact"></div></section>
    </div>`,
  async load() {
    clearInterval(S.welcomeTimer);
    const host = /^[\d.]+$|^\[?[0-9a-f:]+\]?$/i.test(location.hostname) || location.hostname.includes('.') ? location.hostname : '<this-host-ip>';
    const draw = async () => {
      if (S.page !== 'welcome') { clearInterval(S.welcomeTimer); return; }
      const [st, meta] = await Promise.all([api('/api/settings'), api('/api/meta')]);
      const inp = st.input || {mode: 'receiver'};
      const fileMode = inp.mode === 'file';
      const port = fileMode ? (inp.host_port || 514) : (st.syslog_port || 514);
      const modeH = fileMode ? `<div class="note" style="margin:0 0 12px">This machine already runs a syslog server on port ${port}, and Vigil reads the file it
          writes (<span class="mono">${esc(inp.file || '')}</span>, read-only). <b>If your FortiGate already sends syslog here, change nothing</b> -
          the commands below are only for a firewall that is not sending yet.</div>` : '';
      if ($('#wl-mode').innerHTML !== modeH) $('#wl-mode').innerHTML = modeH;
      const cli = `config log syslogd setting
    set status enable
    set server "${host}"
    set port ${port}
    set format default
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set anomaly enable
end`;
      if ($('#wl-cli').textContent !== cli) $('#wl-cli').textContent = cli;
      const rc = st.receiver || {};
      const senders = rc.senders || [];
      const fresh = inp.age_s != null && inp.age_s < 300;
      const steps = fileMode ? [
        [true, 'Vigil is running', `Web UI up, account “${st.account.user || 'local'}” ready`],
        [inp.exists && inp.readable, 'Reading the existing syslog file', !inp.exists
          ? `${inp.file} was not found - check VIGIL_HOST_LOG_DIR and VIGIL_LOG_NAME in .env, then docker compose up -d`
          : inp.readable ? `${inp.file} on this machine, read-only` : `${inp.file} exists but Vigil is not allowed to read it - see the install guide, “Existing syslog server”`],
        [inp.readable && fresh, 'Log file is growing', inp.age_s != null ? `last written ${ago(inp.mtime)} ago` : 'waiting for the file'],
        [!!meta.last_event_ts, 'FortiGate logs recognised', meta.last_event_ts ? `newest log ${ago(meta.last_event_ts)} ago from ${(meta.firewall || {}).name || 'your FortiGate'}` : fresh ? 'the file is growing but no FortiGate lines yet - is the firewall sending to this machine?' : 'after the file receives FortiGate logs'],
        [!!st.config.loaded, 'Configuration backup (optional)', st.config.loaded ? `${st.config.policies} policies from ${st.config.file}` : 'not uploaded - rule grading is off'],
      ] : [
        [true, 'Vigil is running', `Web UI up, account “${st.account.user || 'local'}” ready`],
        [!!rc.started, 'Syslog receiver listening', rc.started ? `UDP and TCP port ${port} on this machine` : 'starting…'],
        [senders.length > 0, 'Syslog arriving', senders.length ? `${fmtN(rc.messages)} messages from ${senders.map(s => s.ip).slice(0, 3).join(', ')}` : 'waiting for the first message - check the commands and any firewall between the FortiGate and this machine'],
        [!!meta.last_event_ts, 'FortiGate logs recognised', meta.last_event_ts ? `newest log ${ago(meta.last_event_ts)} ago from ${(meta.firewall || {}).name || 'your FortiGate'}` : senders.length ? 'messages arrive but none look like FortiGate logs yet' : 'after syslog arrives'],
        [!!st.config.loaded, 'Configuration backup (optional)', st.config.loaded ? `${st.config.policies} policies from ${st.config.file}` : 'not uploaded - rule grading is off'],
      ];
      const firstOpen = steps.findIndex(s => !s[0]);
      $('#wl-steps').innerHTML = steps.map(([ok, t, d], i) => `<li class="${ok ? 'done' : i === firstOpen ? 'wait' : ''}"><span class="n">${ok ? '✓' : i + 1}</span>
        <div><div class="t">${esc(t)}</div><div class="d">${esc(d)}</div></div></li>`).join('');
      if (meta.last_event_ts && !S.welcomeDone) {
        S.welcomeDone = true;
        notify('Connected', `Logs from ${(meta.firewall || {}).name || 'your FortiGate'} are arriving`, 'good');
      }
    };
    $('#wl-copy').onclick = e => copyText($('#wl-cli').textContent, e.target);
    $('#wl-copy2').onclick = e => copyText($('#wl-cli2').textContent, e.target);
    $('#wl-contact').innerHTML = contactFormH('cf-welcome');
    bindContactForm('cf-welcome', 'welcome');
    await draw();
    S.welcomeTimer = setInterval(() => draw().catch(() => {}), 3000);
  },
};
