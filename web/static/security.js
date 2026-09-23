'use strict';
/* Inbound Security page (#security): rule-by-rule exposure from the FortiGate config + what the logs show + attack
   detections, written for non-experts. Uses app.js helpers. */

const SEC = {tab: ls('sec.tab') || 'summary', filter: 'all', q: '', data: null};
const LV = {critical: ['Critical', 'bad'], high: ['High', 'bad'], medium: ['Medium', 'warn'], low: ['Low', 'info'], good: ['Good', 'good']};
const SCOPE = {any: ['Anyone on the internet', 'bad'], negated: ['Almost anyone', 'bad'], geo: ['Whole countries', 'warn'],
  cloud: ['Cloud provider ranges', 'warn'], cdn: ['Only via CDN', 'good'], restricted: ['Approved addresses only', 'good'], unknown: ['Named objects', 'info']};
const lvPill = (lv, score) => `<span class="pill ${LV[lv] ? LV[lv][1] : ''}">${lv === 'critical' ? '⛔' : lv === 'high' ? '▲' : lv === 'medium' ? '●' : lv === 'good' ? '✓' : '○'} ${esc(LV[lv] ? LV[lv][0] : lv)}${score != null ? ` · ${score}` : ''}</span>`;
const yesNo = (ok, yes, no) => ok ? `<span class="pill good">✓ ${esc(yes)}</span>` : `<span class="pill bad">✕ ${esc(no)}</span>`;

PAGES.security = {
  layout: () => `<div class="banner" id="sec-banner"><div style="flex:1">${SKEL}</div></div>
    <div class="tabs" id="sec-tabs"></div><div id="sec-body" style="grid-column:span 12;display:grid;gap:16px;grid-template-columns:repeat(12,minmax(0,1fr))">
    <div class="tiles">${'<div class="tile"><div class="sk w50"></div><div class="sk" style="height:30px"></div></div>'.repeat(6)}</div></div>`,
  async load(sp) {
    const d = await api('/api/security', sp);
    SEC.data = d;
    if (S.params.tab) SEC.tab = S.params.tab;
    const p = d.posture, det = d.detections;
    const attacks = det.bruteforce.length + det.recon_then_access.length + det.ips.length + det.protocol_abuse.length + det.spikes.length;
    if (!d.config.loaded) {
      banner($('#sec-banner'), 'Firewall configuration not loaded', 'Rule analysis needs the FortiGate configuration extract (fg-config.yaml). Attack detections below still work from the logs.', 'bad');
    } else {
      const worst = d.rules.filter(r => r.action === 'accept' && r.enabled)[0];
      const lv = d.config.live, last = lv && lv.last_change;
      const cfgLine = lv && lv.enabled
        ? `<div class="cfg-live"><span class="dot live"></span><b>Live config</b> = ${esc(d.config.backup)} + <b>${fmtN(lv.changes_since_backup)}</b> change${lv.changes_since_backup === 1 ? '' : 's'} from the firewall logs
           ${last ? ` · last: <a href="#security?tab=changes">${esc(last.text)}</a> <span class="muted">(${esc(fmtT(last.ts, 'dhm'))} by ${esc(last.user || '?')})</span>` : ''}
           ${Object.keys(lv.position_unknown || {}).length ? ` · <span class="warnt">⚠ rule order may have changed</span>` : ''}</div>`
        : `<span class="muted">Config ${esc(d.config.file || '')}.</span>`;
      if (!p.accept_rules) {    // a branch firewall publishes nothing, so it is graded on what it does expose
        const bfx = det.bruteforce.length, sslvpn = d.admin && d.admin.sslvpn_enabled;
        banner($('#sec-banner'), `Exposure grade ${p.grade} · nothing is published to the internet`,
          `None of the <b>${p.rules_total}</b> rules lets internet traffic in to a server, so the grade is about this
           firewall's own exposure: ${sslvpn ? `<b>SSL-VPN is reachable from the internet</b>` : 'remote access'},
           ${bfx ? `<b>${bfx}</b> source(s) guessing passwords on it,` : 'no password guessing,'} and who may reach the
           management plane - see <a href="#security?tab=admin">Firewall admin access</a>.
           What the internet actually reached is listed below. ${cfgLine}`,
          p.grade === 'D' ? 'bad' : p.grade === 'A' ? 'ok' : '');
      } else {
        banner($('#sec-banner'), `Inbound security grade ${p.grade} · ${p.levels.critical} critical and ${p.levels.high} high-risk rules`,
          `${p.accept_rules} rules let internet traffic in to ${p.servers} servers. <b>${p.open_to_anyone}</b> of them are open to anyone on the internet and
          <b>${p.no_ips}</b> have no intrusion prevention (IPS). ${worst ? `Riskiest: <b>rule ${worst.id} “${esc(worst.name)}”</b> - ${esc(worst.summary)}` : ''}
          ${cfgLine}`, p.levels.critical ? 'bad' : p.levels.high ? '' : 'ok');
      }
    }
    const lvc = d.config.live;
    const tabs = [['summary', 'Summary'], ['rules', 'Rules & exposure', p.accept_rules], ['attacks', 'Attacks detected', attacks],
      ['admin', 'Firewall admin access'], ['changes', 'Config changes', lvc && lvc.enabled ? lvc.changes_since_backup : null]];
    $('#sec-tabs').innerHTML = tabs.map(([k, t, n]) => `<button data-t="${k}" class="${SEC.tab === k ? 'on' : ''}">${t}${n != null ? `<span class="cnt">${n}</span>` : ''}</button>`).join('');
    $('#sec-tabs').onclick = e => { const b = e.target.closest('button'); if (b) { SEC.tab = b.dataset.t; ls('sec.tab', SEC.tab); drawSec(); } };
    drawSec();
    secPoll(sp);
  },
};

function drawSec() {
  if (!['summary', 'rules', 'attacks', 'admin', 'changes'].includes(SEC.tab)) SEC.tab = 'summary';
  document.querySelectorAll('#sec-tabs button').forEach(b => b.classList.toggle('on', b.dataset.t === SEC.tab));
  Object.keys(S.charts).filter(k => k.startsWith('sec-')).forEach(k => { S.charts[k].dispose(); delete S.charts[k]; });
  ({summary: secSummary, rules: secRules, attacks: secAttacks, admin: secAdmin, changes: secChanges})[SEC.tab]();
}

// ------------------------------------------------------------------ live configuration (from the firewall's change logs)
function secPoll(sp) {
  clearInterval(SEC.timer);
  const live = (SEC.data && SEC.data.config.live) || {};
  if (!live.enabled) return;
  SEC.cfgv = JSON.stringify(live.version);
  SEC.lastTs = (live.last_change || {}).ts || Date.now();
  SEC.timer = setInterval(async () => {
    if (S.page !== 'security') { clearInterval(SEC.timer); return; }
    if (document.hidden) return;
    try {
      const r = await api('/api/config/live', {since: SEC.lastTs});
      if (JSON.stringify(r.version) === SEC.cfgv) return;
      (r.new || []).slice(0, 3).reverse().forEach(c => secToast(`${c.text}`, `${fmtT(c.ts, 'hm')} · ${c.user || '?'} · ${c.via || ''}`, c.risk));
      const y = window.scrollY;
      await PAGES.security.load(sp);                         // re-scores against the new configuration
      window.scrollTo(0, y);
    } catch (e) { /* next tick */ }
  }, 10000);
}
function secToast(text, sub, risk) {
  let box = $('#sec-toasts');
  if (!box) { box = document.createElement('div'); box.id = 'sec-toasts'; document.body.appendChild(box); }
  const el = document.createElement('div');
  el.className = 'sec-toast' + (risk ? ' risk' : '');
  el.innerHTML = `<div class="st-h">⚙ Firewall configuration changed</div><div>${esc(text)}</div><div class="muted">${esc(sub)} · score updated</div>`;
  el.onclick = () => { el.remove(); SEC.tab = 'changes'; drawSec(); };
  box.prepend(el);
  setTimeout(() => el.classList.add('out'), 9000); setTimeout(() => el.remove(), 9600);
  while (box.children.length > 4) box.lastChild.remove();
}
const CHG_STATUS = {'applied': ['applied', 'good', 'Applied to the live configuration.'],
  'applied (backup differed)': ['applied · check', 'warn', 'Applied, but the value before the change did not match the backup - a change may have been missed (e.g. logs not received). Refresh the backup extract to be certain.'],
  'order unknown': ['position unknown', 'warn', 'FortiOS logs that a rule was moved but not where to. Rule order matters when a deny rule and an allow rule overlap.'],
  'object not in backup': ['not in backup', 'warn', 'The object was not in the backup and its creation was not logged - refresh the backup extract.'],
  'sub-setting (not modelled)': ['detail', '', 'A sub-setting (e.g. an application-control entry). Logged, but not used for the risk score.'],
  'not used for scoring': ['logged', '', 'Not part of the inbound risk model (e.g. admin profiles, DNS). Shown for awareness.'],
  'already absent': ['already absent', '', 'Deleted object was not in the backup.']};
function secChanges() {
  const d = SEC.data, el = $('#sec-body'), lv = d.config.live || {};
  if (!lv.enabled) { el.innerHTML = '<div class="card"><div class="body empty">Live configuration tracking is off (FORTI_CONFIG_LIVE=0).</div></div>'; return; }
  const all = d.config.recent_changes || [];
  const moved = Object.entries(lv.position_unknown || {});
  el.innerHTML = `<section class="card"><header><h3>Configuration changes from the firewall logs</h3>
      ${tipH('Every change made in the FortiGate GUI, CLI or API is logged (event "Object attribute configured"). The dashboard replays them over the backup, so the risk score and the Rules tab always reflect the current configuration - usually within seconds of the change.')}
      <span class="sub">Since ${esc(d.config.backup)} · ${fmtN(lv.changes_since_backup)} changes, ${fmtN(lv.risk_changes)} security-relevant · already included in the score</span>
      <div class="tools"><label class="switch"><input type="checkbox" id="chg-all" ${SEC.chgAll ? 'checked' : ''}><span></span>Show all changes</label></div></header>
    <div class="body">
      ${moved.length ? `<div class="alert high" style="margin-bottom:8px">${lvPill('medium')} <span>Rule order may have changed for ${moved.map(([id, m]) => `<a href="#security?tab=rules" data-rule="${id}">rule ${id}</a> (${esc(m.why)} ${esc(fmtT(m.ts, 'dhm'))})`).join(', ')}.
        The log does not record the new position; everything else about ${moved.length === 1 ? 'this rule' : 'these rules'} is current.</span></div>` : ''}
      ${lv.unverified ? `<div class="alert" style="margin-bottom:8px">⚠ <span>${lv.unverified} change(s) did not match the backup exactly - possibly a change made while logs were not received. Refresh the backup extract to be certain.</span></div>` : ''}
      <div id="chg-t"></div>
      <div class="note" style="margin-top:8px">Not visible in logs: the new position of moved rules, changes made while the dashboard was not receiving logs, and configuration restores.
        After such events, export a fresh backup and replace <span class="mono">fg-config.yaml</span> - the change history continues from there.</div></div></section>`;
  el.querySelectorAll('[data-rule]').forEach(a => a.onclick = e => { e.preventDefault(); openRule(+a.dataset.rule); });
  $('#chg-all').onchange = e => { SEC.chgAll = e.target.checked; secChanges(); };
  const rows = SEC.chgAll ? all : all.filter(c => c.risk);
  table('chg-t', [
    {k: 'ts', t: 'When', f: v => esc(fmtT(v, 'dhm')), v: r => r.ts},
    {k: 'user', t: 'Who', f: (v, r) => `${esc(v || '?')}<div class="muted" style="font-size:10.5px">${esc(r.via || '')}</div>`},
    {k: 'text', t: 'Change', f: (v, r) => `${r.risk ? '' : '<span class="muted">'}${esc(v)}${r.risk ? '' : '</span>'}`},
    {k: 'status', t: 'Status', f: v => { const s = CHG_STATUS[v] || [v, '', '']; return `<span class="pill ${s[1]}" title="${esc(s[2])}">${esc(s[0])}</span>`; }}],
    rows, {onRow: r => { if (r.path === 'firewall.policy' && /^\d+$/.test(r.obj || '')) openRule(+r.obj); }, sort: {k: 'ts', d: -1}, limit: 300,
      empty: SEC.chgAll ? 'No configuration changes logged since the backup.' : 'No security-relevant changes since the backup - tick “Show all changes”.'});
}

// ------------------------------------------------------------------ summary
function secSummary() {
  const d = SEC.data, p = d.posture, det = d.detections, el = $('#sec-body');
  el.innerHTML = `<div class="tiles" id="sec-tiles"></div>
    <section class="card w6"><header><h3>Fix these first</h3>${tipH('Ranked by risk: how many people can reach the service, how dangerous the service is, known exploited vulnerabilities, missing protection and attacks seen in the logs.')}
      <span class="sub">The most important changes, in plain words</span></header><div class="body" id="sec-prio"></div></section>
    <section class="card w6"><header><h3>Attacks happening</h3><span class="sub">Patterns found in the firewall logs for this period</span></header>
      <div class="body"><div class="det-grid" id="sec-det"></div></div></section>
    ${card('sec-exp', 'Your public entry points', {sub: 'Every server the internet can reach, through which rule, and who is allowed in. Sorted by risk.',
      tip: 'Built from firewall policies and VIPs in the configuration. Click a row to open the rule.'})}
    ${card('sec-probe', 'What attackers are looking for', {w: 'w6', chart: '', sub: 'Most-probed ports on your public IPs (blocked). Red = a port you really have open.'})}
    ${card('sec-scope', 'Who can reach your allowed rules', {w: 'w6', chart: '', sub: 'Allowed rules grouped by how wide their source is'})}`;
  const bf = det.bruteforce.length;
  tiles($('#sec-tiles'), [
    ['Security grade', `<span style="font-size:30px">${esc(p.grade)}</span>`, gradeText(p.grade), p.grade === 'A' ? 'good' : p.grade === 'B' ? 'info' : 'crit',
      'A = no high-risk rules. D = several critical rules (open to anyone + sensitive service + missing protection).'],
    ['Critical / high-risk rules', `${p.levels.critical} / ${p.levels.high}`, `of ${p.accept_rules} allow rules`, p.levels.critical ? 'crit' : 'warn', '', '#security?tab=rules'],
    ['Open to anyone', fmtN(p.open_to_anyone), 'rules with source "all"', p.open_to_anyone ? 'warn' : 'good', 'Any IP address on the internet can connect.'],
    ['Without IPS', fmtN(p.no_ips), 'rules not inspecting for exploits', p.no_ips ? 'warn' : 'good', 'Intrusion prevention blocks known exploit attempts. Rules without it let them straight through.'],
    ['Password-guessing sources', fmtN(bf), bf ? 'hammering login services' : 'none detected', bf ? 'crit' : 'good',
      '≥ 30 very short connections per hour from one IP to a login port (SSH, mail login, admin consoles).', '#security?tab=attacks'],
    ['Unused allow rules', fmtN(p.unused), 'no traffic in this period - remove to shrink exposure', p.unused ? 'info' : 'good'],
  ]);
  const prio = d.priorities;
  $('#sec-prio').innerHTML = prio.length ? prio.map((x, i) => `<div class="prio ${x.level}">
      <div class="num">${i + 1}</div><div><div class="pt">${lvPill(x.level)} <b>${esc(x.title)}</b></div>
      <div class="pw">${esc(x.why)}</div><div class="pf"><b>Fix:</b> ${esc(x.fix)}</div>
      ${x.rule ? `<button class="btn-ghost" data-rule="${x.rule}">Open rule ${x.rule} →</button>` : ''}</div></div>`).join('')
    : '<div class="empty">Nothing urgent. 👍</div>';
  $('#sec-prio').querySelectorAll('[data-rule]').forEach(b => b.onclick = () => openRule(+b.dataset.rule));
  const cards = [
    ['bruteforce', '🔑', 'Password guessing', det.bruteforce.length, 'IPs making many short login attempts', det.bruteforce.length ? 'bad' : 'good'],
    ['recon', '🕵️', 'Blocked first, then let in', det.recon_then_access.length, 'IPs that were scanning you and later got through a rule', det.recon_then_access.length ? 'bad' : 'good'],
    ['ips', '🛡️', 'Exploit attempts (IPS)', det.ips.reduce((a, r) => a + r.n, 0), 'Known attack signatures caught', det.ips.length ? 'warn' : 'good'],
    ['abuse', '🔀', 'Wrong protocol on a port', det.protocol_abuse.reduce((a, r) => a + r.n, 0), 'e.g. remote desktop sent over the mail port', det.protocol_abuse.length ? 'warn' : 'good'],
    ['scanners', '📡', 'Port scanners', det.scanners.count, `IPs trying ≥ 15 ports · ${fmtK(det.scanners.hits)} blocked attempts`, 'info'],
    ['spikes', '📈', 'Traffic spikes', det.spikes.length, 'Hours with 5× normal traffic to a server', det.spikes.length ? 'warn' : 'good'],
    ['countries', '🌍', 'New countries', det.new_countries.length, 'Allowed traffic from countries not seen the week before', det.new_countries.length ? 'warn' : 'good'],
  ];
  $('#sec-det').innerHTML = cards.map(([k, ic, t, n, s, tone]) => `<div class="det ${tone}" data-k="${k}"><div class="di">${ic}</div>
    <div><div class="dn">${fmtN(n)}</div><div class="dt">${t}</div><div class="ds">${s}</div></div></div>`).join('');
  $('#sec-det').querySelectorAll('.det').forEach(x => x.onclick = () => { SEC.tab = 'attacks'; drawSec(); setTimeout(() => {
    const t = document.getElementById('att-' + x.dataset.k); if (t) t.scrollIntoView({behavior: 'smooth', block: 'start'}); }, 50); });
  const exp = [];
  d.rules.filter(r => r.action === 'accept' && r.enabled).forEach(r => r.destinations.forEach(ds => exp.push({
    public: (ds.public || []).join(', '), server: ds.server || ds.name, rule: r.id, name: r.name, score: r.score, level: r.level,
    scope: r.source.scope, who: r.source.label, service: r.service_titles.join(', '), ports: r.services.map(s => s.label).join(', '),
    ips: !!r.ips, sessions: r.evidence.n || 0})));
  table('sec-exp', [
    {k: 'level', t: 'Risk', f: (v, r) => lvPill(v, r.score), v: r => r.score},
    {k: 'public', t: 'Public address', mono: true, f: v => v ? esc(v) : '<span class="muted">via central NAT</span>'},
    {k: 'server', t: 'Internal server', mono: true}, {k: 'service', t: 'Service', f: (v, r) => `${esc(v)}<div class="muted" style="font-size:11px">${esc(r.ports)}</div>`},
    {k: 'who', t: 'Who can connect', f: (v, r) => `<span class="pill ${SCOPE[r.scope] ? SCOPE[r.scope][1] : ''}">${esc(SCOPE[r.scope] ? SCOPE[r.scope][0] : r.scope)}</span><div class="muted" style="font-size:11px;max-width:320px">${esc(v)}</div>`},
    {k: 'ips', t: 'IPS', f: v => v ? '<span class="pill good">✓</span>' : '<span class="pill bad">✕ none</span>'},
    {k: 'sessions', t: 'Sessions', num: true, f: fmtK}, {k: 'rule', t: 'Rule', f: (v, r) => `#${v} ${esc(r.name || '')}`}],
    exp, {onRow: r => openRule(r.rule), sort: {k: 'level', d: -1}, limit: 200});
  // No rule publishes a server (branch / SD-WAN firewall): show what the internet actually reached instead of an
  // empty table - on those firewalls the target is the firewall itself (SSL-VPN portal, admin, probed ports).
  if (!exp.length && (d.entry_points || []).length) {
    $('#sec-exp-sub').textContent = 'No rule publishes a server, so this is what the internet actually reached on this firewall, from the logs.';
    table('sec-exp', [
      {k: 'dst', t: 'Reached', mono: true},
      {k: 'service', t: 'Service', f: (v, r) => `${esc(v)}<div class="muted" style="font-size:11px">port ${r.dpt}${r.proto === 17 ? '/udp' : ''}</div>`},
      {k: 'sources', t: 'Sources', num: true, f: fmtK},
      {k: 'countries', t: 'From', f: (v, r) => esc((v || []).join(', ') + (r.country_count > 4 ? ` +${r.country_count - 4}` : '')) || '—'},
      {k: 'allowed', t: 'Allowed', num: true, f: fmtK},
      {k: 'denied', t: 'Denied', num: true, f: (v) => v ? `<span class="drop">${fmtK(v)}</span>` : '0'},
      {k: 'short', t: 'Short/failed', num: true, f: fmtK, tip: 'Very short sessions - typical of scans and failed logins'},
      {k: 'policy', t: 'Matched', f: v => esc(v || '—')}],
      d.entry_points, {onRow: r => location.hash = `#investigate?q=${encodeURIComponent(r.dst)}+port+${r.dpt}`,
                       sort: {k: 'sessions', d: -1}, limit: 50, csv: 'entry-points'});
  }
  const probes = det.probed_top || [];
  hbar('sec-probe-c', probes.map(r => Object.assign({}, r, {label: `${r.dpt} ${r.service ? '· ' + r.service : ''}`})), r => r.label, r => ({value: r.n, itemStyle: {color: r.exposed ? C.crit : C.s[0]}}),
    r => location.hash = `#investigate?q=port+${r.dpt}+denied`);
  const scopes = {};
  d.rules.filter(r => r.action === 'accept' && r.enabled).forEach(r => { const k = SCOPE[r.source.scope] ? SCOPE[r.source.scope][0] : r.source.scope; scopes[k] = (scopes[k] || 0) + 1; });
  hbar('sec-scope-c', Object.entries(scopes).map(([k, n]) => ({k, n})).sort((a, b) => b.n - a.n), r => r.k, r => r.n,
    () => { SEC.tab = 'rules'; drawSec(); });
}
function gradeText(g) {
  return {A: 'No high-risk inbound rules', B: 'Some high-risk rules to tighten', C: 'Critical or many high-risk rules', D: 'Several critical exposures - act now'}[g] || '';
}

// ------------------------------------------------------------------ rules
function openRule(id) {
  SEC.tab = 'rules'; SEC.filter = 'all'; SEC.q = '#' + id; ls('sec.tab', 'rules');
  if (S.page !== 'security') { location.hash = '#security?tab=rules'; return; }
  drawSec();
  setTimeout(() => { const c = document.getElementById('rule-' + id); if (c) { c.scrollIntoView({behavior: 'smooth', block: 'start'}); c.classList.add('flash'); c.querySelector('details')?.setAttribute('open', ''); } }, 60);
}
function secRules() {
  const d = SEC.data, el = $('#sec-body');
  const filters = [['all', 'All rules'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'],
    ['any', 'Open to anyone'], ['noips', 'No IPS'], ['unused', 'Unused'], ['deny', 'Deny rules']];
  el.innerHTML = `<div class="rule-bar"><div class="seg">${filters.map(([k, t]) => `<button data-f="${k}" class="${SEC.filter === k ? 'on' : ''}">${t}</button>`).join('')}</div>
    <input id="sec-q" placeholder="Search rule, server, service…" value="${esc(SEC.q)}"><span class="muted" id="sec-cnt"></span></div>
    <div class="rule-grid" id="sec-rules"></div>`;
  el.querySelector('.rule-bar .seg').onclick = e => { const b = e.target.closest('button'); if (b) { SEC.filter = b.dataset.f; secRules(); } };
  $('#sec-q').oninput = e => { SEC.q = e.target.value; paint(); };
  const paint = () => {
    const q = SEC.q.trim().toLowerCase();
    const list = d.rules.filter(r => {
      const f = SEC.filter;
      if (f === 'deny' ? r.action !== 'deny' : (r.action !== 'accept')) return false;
      if (['critical', 'high', 'medium', 'low'].includes(f) && r.level !== f) return false;
      if (f === 'any' && r.source.scope !== 'any') return false;
      if (f === 'noips' && r.ips) return false;
      if (f === 'unused' && !r.unused) return false;
      if (!q) return true;
      if (q.startsWith('#')) return String(r.id) === q.slice(1);
      return JSON.stringify([r.id, r.name, r.service_titles, r.destinations, r.source.label, r.services]).toLowerCase().includes(q);
    });
    $('#sec-cnt').textContent = `${list.length} rule${list.length === 1 ? '' : 's'}`;
    $('#sec-rules').innerHTML = list.map(ruleCard).join('') || '<div class="empty">No rules match.</div>';
    $('#sec-rules').querySelectorAll('[data-copy]').forEach(b => b.onclick = () => copyText(d.rules.find(r => r.id === +b.dataset.copy).cli, b));
  };
  paint();
}
function ruleCard(r) {
  const e = r.evidence || {};
  const dst = r.destinations.map(x => `<div><span class="mono">${esc(x.server || x.name)}</span>${(x.public || []).length ? ` <span class="muted">← public ${esc(x.public.join(', '))}</span>` : ''}</div>`).join('');
  const sc = SCOPE[r.source.scope] || ['?', ''];
  const countries = (e.countries || []).slice(0, 4).map(([c, n]) => `${esc(c)} ${fmtK(n)}`).join(' · ');
  const deny = r.action !== 'accept';
  return `<article class="rule-card ${deny ? 'deny' : r.level}" id="rule-${r.id}">
    <header><div class="score ${r.level}"><b>${deny ? '—' : r.score}</b><span>${deny ? 'deny' : 'risk'}</span></div>
      <div class="rh"><div class="rt">#${r.id} ${esc(r.name || '')} ${deny ? '<span class="pill">deny rule</span>' : lvPill(r.level)}
        ${r.enabled ? '' : '<span class="pill bad">⏸ disabled</span>'}${r.unused ? '<span class="pill info">no traffic in period</span>' : ''}
        ${(r.changes || []).length ? `<span class="pill info" title="${esc(r.changes.map(c => `${fmtT(c.ts, 'dhm')} ${c.text} (${c.user || '?'})`).join('\n'))}">✎ changed ${esc(fmtT(r.changes[0].ts, 'dhm'))}</span>` : ''}
        ${r.position_unknown ? `<span class="pill warn" title="The firewall log shows this rule was ${esc(r.position_unknown.why)} but not its new position">⚠ position may have changed</span>` : ''}</div>
        <div class="rs">${esc(r.summary)}</div><div class="muted" style="font-size:11.5px">Rule position ${r.seq}${r.position_unknown ? ' (may be out of date)' : ''} · ${esc(r.srcintf.join(', '))} → ${esc(r.dstintf.join(', '))}</div></div></header>
    ${(r.changes || []).length ? `<div class="rule-chg"><div class="fk">Recent changes (from the firewall logs)</div>${r.changes.slice(0, 3).map(c =>
      `<div><span class="muted">${esc(fmtT(c.ts, 'dhm'))}</span> <b>${esc(c.text.replace(/^Rule \d+:\s*/, ''))}</b> <span class="muted">by ${esc(c.user || '?')}</span></div>`).join('')}</div>` : ''}
    <div class="facts">
      <div><div class="fk">Who can connect</div><span class="pill ${sc[1]}">${esc(sc[0])}</span><div class="fv">${esc(r.source.label)}</div></div>
      <div><div class="fk">What is exposed</div><div class="fv"><b>${esc(r.service_titles.join(', ') || '—')}</b><div class="muted">${esc(r.services.map(s => s.label).join(', '))}</div>${dst}</div></div>
      <div><div class="fk">Protection on this rule</div><div class="prot">${yesNo(r.ips, 'IPS: ' + (r.ips || ''), 'No IPS')}
        ${r.app ? `<span class="pill ${/monitor/i.test(r.app) || r.app === 'default' ? 'warn' : 'good'}">App control: ${esc(r.app)}</span>` : '<span class="pill bad">✕ No app control</span>'}
        ${r.av ? `<span class="pill good">✓ AV</span>` : ''}${r.ssl ? `<span class="pill">${esc(r.ssl)}</span>` : ''}</div></div>
      ${deny ? '' : `<div><div class="fk">Seen in the logs</div><div class="fv">${e.n ? `<b>${fmtK(e.n)}</b> sessions from <b>${fmtN(e.srcs)}</b> IPs` : 'No traffic in this period'}
        ${countries ? `<div class="muted">${countries}</div>` : ''}${(r.active || []).map(a => `<div class="drop">⚠ ${esc(a)}</div>`).join('')}</div></div>`}
    </div>
    ${deny ? '' : `<div class="two">
      <div><div class="fk">How an attacker could use this rule</div><ul class="atk">${r.attacks.slice(0, 4).map(a => `<li><b>${esc(a.name)}</b> - ${esc(a.text)} <span class="muted">(${esc(a.attck)})</span></li>`).join('')}</ul></div>
      <div><div class="fk">What to do</div><ul class="fix">${r.prevent.slice(0, 4).map(x => `<li>${esc(x)}</li>`).join('')}</ul></div></div>
    <details><summary>Why this score, known vulnerabilities and suggested config</summary>
      <table class="kvt" style="margin:6px 0">${r.factors.map(f => `<tr><td style="width:60px" class="num">+${f.points}</td><td>${esc(f.text)}</td></tr>`).join('')}
        <tr><td class="num"><b>${r.score}</b></td><td><b>Total risk score (0-100)</b></td></tr></table>
      ${r.cves.length ? `<div class="fk" style="margin-top:8px">Actively exploited vulnerabilities for this kind of software (CISA KEV)</div>
        <table class="kvt">${r.cves.map(c => `<tr><td class="mono">${esc(c.id)}</td><td>${esc(c.text)} <span class="muted">· added ${esc(c.kev)}</span></td></tr>`).join('')}</table>
        <div class="muted" style="font-size:11.5px">Only relevant if you run that product/version - confirm the installed version is patched.</div>` : ''}
      <div class="fk" style="margin-top:8px">Suggested FortiOS change</div><pre class="cli">${esc(r.cli)}</pre>
      <button data-copy="${r.id}">Copy config</button></details>`}
    <footer><a href="#investigate?q=policy+${r.id}">Investigate its traffic →</a><a href="#rule?policyid=${r.id}">Rule assistant →</a>
      <a href="#logs?table=traffic&policyid=${r.id}">Logs →</a></footer></article>`;
}

// ------------------------------------------------------------------ attacks
function secAttacks() {
  const det = SEC.data.detections, el = $('#sec-body');
  const sec = (id, title, sub, tip) => `<section class="card" id="att-${id}"><header><h3>${title}</h3>${tipH(tip)}<span class="sub">${sub}</span></header><div class="body" id="att-${id}-t"></div></section>`;
  el.innerHTML = [
    sec('bruteforce', '🔑 Password guessing on login services', 'An IP opened many very short connections to a login port. That is what password-guessing tools look like. “Maybe got in” = it also had a long or large session.',
      'Threshold: ≥ 30 short (≤ 2 s, < 4 KB) sessions in one hour to SSH, mail login, admin consoles, RDP or VPN ports (Zeek default for SSH brute force).'),
    sec('recon', '🕵️ Blocked first, then let in', 'These IPs were denied (scanning) and later got through an allow rule. Check what they did after getting in.'),
    sec('scanners', '📡 Port scanners', 'IPs that tried many different ports on your public addresses. They were blocked - this shows who is mapping your network.',
      'Threshold: ≥ 15 distinct ports from one IP in an hour/day (Zeek scan detection default).'),
    sec('probed', '🎯 Attackers probing ports you really have open', 'Ports scanners hit most that at least one of your allow rules exposes. These services are what attackers will try next.'),
    sec('ips', '🛡️ Exploit attempts caught by IPS', 'Known attack signatures seen on inbound rules that have an IPS sensor. Rules without IPS would not show (or stop) these.'),
    sec('abuse', '🔀 Wrong protocol on an allowed port', 'Application control saw a different application than the port is for - e.g. remote desktop over the mail port. Common for tunnelling and evasion.'),
    sec('spikes', '📈 Traffic spikes', 'Hours where a published server received more than 5× its normal traffic (and at least 2,000 sessions). Can be a flood or a campaign.'),
    sec('countries', '🌍 New countries on allowed rules', 'Allowed traffic from a country the rule did not see in the previous 7 days.'),
  ].join('');
  const inv = ip => location.hash = `#investigate?q=${encodeURIComponent(ip)}`;
  table('att-bruteforce-t', [{k: 'src', t: 'Attacker IP', mono: true}, {k: 'country', t: 'Country'},
    {k: 'service', t: 'Target service'}, {k: 'dst', t: 'Server', mono: true, f: (v, r) => `${esc(v)}:${esc(r.dpt)}`},
    {k: 'policy', t: 'Via rule', f: (v, r) => `#${r.policyid} ${esc(v || '')}`}, {k: 'short', t: 'Short attempts', num: true},
    {k: 'peak', t: 'Peak / hour', num: true}, {k: 'hours', t: 'Hours active', num: true},
    {k: 'possible_success', t: 'Maybe got in?', f: v => v ? '<span class="pill bad">⚠ long/large session seen</span>' : '<span class="pill good">no</span>'}],
    det.bruteforce, {onRow: r => inv(r.src), empty: 'No password-guessing pattern found in this period. 👍'});
  table('att-recon-t', [{k: 'src', t: 'IP', mono: true}, {k: 'country', t: 'Country'}, {k: 'n_deny', t: 'Times blocked', num: true},
    {k: 'n_acc', t: 'Times allowed', num: true}, {k: 'first_acc_ts', t: 'First let in', f: v => fmtT(v, 'dhm')},
    {k: 'policies', t: 'Allowed by rule', f: v => (v || []).map(p => `<span class="tag">#${p.id} ${esc(p.name || '')}</span>`).join('')}],
    det.recon_then_access, {onRow: r => inv(r.src), empty: 'None in this period.'});
  table('att-scanners-t', [{k: 'src', t: 'Scanner IP', mono: true}, {k: 'country', t: 'Country'}, {k: 'n', t: 'Blocked attempts', num: true},
    {k: 'ports', t: 'Ports tried', num: true}, {k: 'psample', t: 'Example ports', mono: true}],
    det.scanners.top, {onRow: r => inv(r.src), note: `${fmtN(det.scanners.count)} scanning IPs in total`});
  table('att-probed-t', [{k: 'dpt', t: 'Port', f: (v, r) => `<b>${esc(v)}</b> ${esc(PROTO[r.proto] || '')}`}, {k: 'service', t: 'Service'},
    {k: 'n', t: 'Blocked probes', num: true}, {k: 'srcs', t: '≥ IPs/hour', num: true},
    {k: 'rules', t: 'Open through rule', f: v => (v || []).map(p => `<div><span class="tag">#${p.id} ${esc(p.name || '')}</span> <span class="muted">${esc(p.source)}</span></div>`).join('')}],
    det.probed_exposed, {onRow: r => location.hash = `#investigate?q=port+${r.dpt}+denied`});
  table('att-ips-t', [{k: 'severity', t: 'Severity', f: v => sevH(['critical', 'high', 'medium'].includes(v) ? v : 'low')}, {k: 'attack', t: 'Attack'},
    {k: 'act', t: 'Action', f: v => actH(v)}, {k: 'policy', t: 'Rule', f: (v, r) => `#${r.policyid} ${esc(v || '')}`},
    {k: 'n', t: 'Events', num: true}, {k: 'srcs', t: 'IPs', num: true}, {k: 'last', t: 'Last', f: v => fmtT(v, 'dhm')}],
    det.ips, {onRow: r => location.hash = `#investigate?q=ips`, empty: 'No IPS events in this period.'});
  table('att-abuse-t', [{k: 'policy', t: 'Rule', f: (v, r) => `#${r.policyid} ${esc(v || '')}`}, {k: 'app', t: 'Application seen', f: appH},
    {k: 'evtype', t: 'Type', f: v => v === 'port-violation' ? '<span class="pill warn">wrong port</span>' : esc(v)},
    {k: 'act', t: 'Action', f: v => actH(v)}, {k: 'n', t: 'Sessions', num: true}],
    det.protocol_abuse, {onRow: r => location.hash = `#investigate?q=app=${encodeURIComponent(r.app)}+policy+${r.policyid}`, empty: 'None in this period.'});
  table('att-spikes-t', [{k: 'dst', t: 'Server', mono: true, f: (v, r) => `${esc(v)}:${esc(r.dpt)}`}, {k: 'peak', t: 'Peak sessions/hour', num: true},
    {k: 'median', t: 'Normal (median)', num: true}, {k: 'at', t: 'When', f: v => fmtT(v, 'dhm')}],
    det.spikes, {onRow: r => location.hash = `#investigate?q=${encodeURIComponent(r.dst)}+port+${r.dpt}`, empty: 'No unusual spikes.'});
  table('att-countries-t', [{k: 'country', t: 'Country'}, {k: 'policy', t: 'Rule', f: (v, r) => `#${r.policyid} ${esc(v || '')}`},
    {k: 'n', t: 'Sessions', num: true}, {k: 'srcs', t: 'IPs', num: true}],
    det.new_countries, {onRow: r => location.hash = `#investigate?q=policy+${r.policyid}+country=${encodeURIComponent(r.country)}`,
      empty: 'No new countries (needs at least 2 days of history).'});
}

// ------------------------------------------------------------------ firewall admin
function secAdmin() {
  const a = SEC.data.admin, det = SEC.data.detections, el = $('#sec-body');
  if (!a) { el.innerHTML = '<div class="card"><div class="body empty">Configuration not loaded.</div></div>'; return; }
  el.innerHTML = `<section class="card w6"><header><h3>Management access posture</h3><span class="sub">Can someone on the internet reach the firewall's own login pages?</span></header>
      <div class="body">${a.findings.map(f => `<div class="finding">${lvPill(f.level)} <span>${esc(f.text)}</span></div>`).join('')}
      <div class="note" style="margin-top:10px">Admin HTTPS port <b>${esc(a.admin_port)}</b>, admin SSH port <b>${esc(a.admin_ssh_port)}</b>, SSL-VPN ${a.sslvpn_enabled ? '<b>enabled</b>' : 'disabled'} (port ${esc(a.sslvpn_port)}).</div></div></section>
    <section class="card w6"><header><h3>Why this matters</h3><span class="sub">The firewall admin page and SSL-VPN are among the most attacked services on the internet</span></header>
      <div class="body" id="adm-cve"></div></section>
    ${card('adm-li', 'Local-in rules (traffic to the firewall itself)', {w: 'w6', sub: 'Evaluated top to bottom. Missing action = deny.'})}
    ${card('adm-acc', 'Accepted connections to management ports', {w: 'w6', sub: 'From the logs. Anything from an unexpected country here needs checking.'})}
    ${card('adm-if', 'Internet interfaces: allowed management protocols', {w: 'w6'})}`;
  const kb = [['CVE-2022-40684', 'Admin interface authentication bypass', '2022-10-11'], ['CVE-2024-55591', 'Websocket bypass gives super-admin', '2025-01-14'],
    ['CVE-2025-59718', 'FortiCloud SSO bypass (7.4.0-7.4.8)', '2025-12-16'], ['CVE-2026-24858', 'FortiCloud SSO cross-account login', '2026-01-27'],
    ['CVE-2024-21762', 'SSL-VPN out-of-bounds write (RCE)', '2024-02-09'], ['CVE-2025-25249', 'Heap overflow via crafted packets (7.4.0-7.4.8)', '2026-09-09']];
  $('#adm-cve').innerHTML = `<table class="kvt">${kb.map(([i, t, dt]) => `<tr><td class="mono">${i}</td><td>${esc(t)} <span class="muted">· CISA KEV ${dt}</span></td></tr>`).join('')}</table>
    <div class="note">${((S.meta || {}).firewall || {}).version ? `This firewall reports <b>FortiOS ${esc(S.meta.firewall.version)}</b> in its logs.` : 'The FortiOS version appears here once logs arrive.'}
    Compare it with the affected versions of each advisory on the Fortinet PSIRT site - version ranges change as new fixes are released.
    Best practice: admin port reachable only from trusted IPs (local-in policy), virtual patching on local-in, FortiCloud SSO admin login disabled if unused.</div>`;
  table('adm-li', [{k: 'seq', t: 'Order', num: true}, {k: 'id', t: 'ID', num: true}, {k: 'what', t: 'Protects'}, {k: 'source', t: 'From'},
    {k: 'action', t: 'Action', f: v => v === 'accept' ? '<span class="pill warn">allow</span>' : '<span class="pill good">deny</span>'},
    {k: 'enabled', t: 'Enabled', f: v => v ? '✓' : '✕'}], a.local_in);
  table('adm-acc', [{k: 'dpt', t: 'Port'}, {k: 'country', t: 'Country'}, {k: 'act', t: 'Result', f: v => actH(v)}, {k: 'n', t: 'Sessions', num: true}],
    det.admin_access, {empty: 'No accepted management connections from the internet in this period.'});
  table('adm-if', [{k: 'intf', t: 'Interface', mono: true}, {k: 'acc', t: 'Allowed management', f: v => v.length ? v.map(x =>
    `<span class="pill ${['http', 'telnet', 'ssh', 'snmp', 'fgfm'].includes(x) ? 'bad' : x === 'https' ? 'warn' : ''}">${esc(x)}</span>`).join(' ') : '<span class="pill good">none</span>'}],
    Object.entries(a.wan_allowaccess).map(([intf, acc]) => ({intf, acc})));
}
