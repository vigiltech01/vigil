'use strict';
/* Vigil UI: hash-routed single page, vanilla JS + ECharts. */

// ------------------------------------------------------------------ state & utils
const C = {
  s: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'],  // categorical, fixed order
  seq: ['#0d366b', '#184f95', '#256abf', '#3987e5', '#6da7ec', '#9ec5f4'],                       // sequential blue (dark)
  ink: '#ffffff', ink2: '#c3c2b7', muted: '#898781', grid: '#2c2c2a', axis: '#383835', surface: '#1a1a19',
  crit: '#d03b3b', warn: '#fab219', serious: '#ec835a', good: '#0ca30c',
};
const CAT_ORDER = ['traffic:forward', 'traffic:local', 'utm:app-ctrl', 'utm:webfilter', 'utm:ips', 'utm:virus', 'event', 'utm:other'];
const CAT_TABLE = {'traffic:forward': 'traffic', 'traffic:local': 'traffic', 'utm:app-ctrl': 'utm_app', 'utm:webfilter': 'utm_web',
  'utm:ips': 'utm_ips', 'utm:virus': 'utm_av', 'event': 'event', 'utm:other': 'utm_other'};
const PRESETS = {'15m': 9e5, '1h': 36e5, '6h': 216e5, '24h': 864e5, '7d': 6048e5, '30d': 2592e6};
const DROPS = new Set(['deny', 'block', 'blocked', 'dropped', 'reset', 'utm-block']);
const ENDS = new Set(['close', 'client-rst', 'server-rst', 'timeout']);
const PROTO = {6: 'tcp', 17: 'udp', 1: 'icmp'};

function ls(k, v) {
  try { if (v === undefined) return localStorage.getItem('vigil.' + k); localStorage.setItem('vigil.' + k, v); } catch (e) { return null; }
  return null;
}
const S = {range: ls('range') || '24h', tz: ls('tz') === 'utc' ? 'utc' : 'local', auto: ls('auto') !== '0', custom: null,
  polMap: {}, meta: null, charts: {}, page: null, params: {}, seq: 0};

const $ = (s, el = document) => el.querySelector(s);
const esc = v => v == null ? '' : String(v).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const nf = new Intl.NumberFormat('en-US');
const fmtN = n => n == null || n === '' ? '' : nf.format(n);
const fmtK = n => n == null ? '' : n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e4 ? Math.round(n / 1e3) + 'k' : nf.format(n);
function fmtB(b) {
  if (b == null) return '';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (b >= 1024 && i < 4) { b /= 1024; i++; }
  return (i ? b.toFixed(1) : b) + ' ' + u[i];
}
const tzName = () => S.tz === 'utc' ? 'UTC' : undefined;
const dtfCache = {};
function fmtT(ms, mode) {
  if (!ms) return '';
  const key = S.tz + mode;
  if (!dtfCache[key]) {
    const o = {timeZone: tzName(), hour12: false};
    if (mode === 'hm') Object.assign(o, {hour: '2-digit', minute: '2-digit'});
    else if (mode === 'dhm') Object.assign(o, {month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'});
    else Object.assign(o, {year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'});
    dtfCache[key] = new Intl.DateTimeFormat('sv-SE', o);
  }
  return dtfCache[key].format(new Date(ms));
}
function ago(ms) {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  return s < 90 ? Math.round(s) + 's' : s < 5400 ? Math.round(s / 60) + 'm' : s < 172800 ? Math.round(s / 3600) + 'h' : Math.round(s / 86400) + 'd';
}
function span() {
  if (S.range === 'custom' && S.custom) return S.custom;
  const to = Date.now();
  return {frm: to - PRESETS[S.range || '24h'], to};
}
function polLabel(id) {
  if (id == null || id === -1 || id === '') return '';
  id = +id;
  const p = S.polMap[id];
  const lab = id >= 900000 ? 'X-' + (id - 900000) : id >= 300000 ? 'SN-' + (id - 300000) : id >= 100000 ? 'LI-' + (id - 100000) : String(id);
  return lab + (p && p.name ? ' · ' + p.name : '');
}
const pol = id => `<span class="mono">${esc(polLabel(id))}</span>`;
function actH(a, utm) {
  if (DROPS.has(a) || utm === 'block') return `<span class="drop">✖ ${esc(a)}${utm === 'block' && a !== 'utm-block' ? ' (utm block)' : ''}</span>`;
  if (ENDS.has(a)) return `<span class="endst">${esc(a)}</span>`;
  return esc(a);
}
function appH(a) {
  if (!a) return '';
  if (/^(tcp|udp|TCP|UDP)[\/-]/.test(a)) return `<span class="uncl" title="app-ctrl never saw enough payload">unclassified (${esc(a)})</span>`;
  return esc(a);
}
const sevH = s => `<span class="sev ${s}">${{critical: '⛔', high: '▲', medium: '●', low: '○', info: 'ℹ', good: '✓'}[s] || ''} ${s}</span>`;
const portH = (p, pr) => `${esc(p)}/${esc(PROTO[pr] || pr)}`;

async function api(path, params = {}) {
  const u = new URL(path, location.origin);
  Object.entries(params).forEach(([k, v]) => v !== undefined && v !== null && v !== '' && u.searchParams.set(k, v));
  const r = await fetch(u);
  if (r.status === 401) { const j = await r.json().catch(() => ({})); location.href = j.setup ? '/setup' : '/login'; throw new Error('Session expired - please sign in again'); }
  const j = await r.json().catch(() => ({error: r.statusText}));
  if (!r.ok || j.error) throw new Error(j.error || j.detail || r.statusText);
  if (j && j._generated) S.generated = Math.min(S.generated || Infinity, j._generated);
  return j;
}

// ------------------------------------------------------------------ components
const tipH = t => t ? `<span class="tip" data-tip="${esc(t)}">?</span>` : '';
const SKEL = '<div class="sk w70"></div><div class="sk"></div><div class="sk w50"></div><div class="sk"></div>';
function card(id, title, o = {}) {
  return `<section class="card ${o.w || ''}"><header><h3>${esc(title)}</h3>${tipH(o.tip)}<span class="sub" id="${id}-sub">${esc(o.sub || '')}</span>
    <div class="tools" id="${id}-tools"></div></header><div class="body" id="${id}">${o.chart !== undefined ?
    `<div class="chart ${o.chart}" id="${id}-c"></div>` : SKEL}</div></section>`;
}
function tiles(el, list) {
  /* list: [label, value, sub, tone('crit'|'warn'|'good'|'info'), tip, onclickHash] */
  el.innerHTML = list.map(([k, v, s, tone, tip, go]) => `<div class="tile ${tone || ''} ${go ? 'click' : ''}" ${go ? `data-go="${esc(go)}"` : ''}>
    <div class="k">${esc(k)}${tipH(tip)}</div><div class="v">${v}</div><div class="s">${s || ''}</div></div>`).join('');
  el.querySelectorAll('[data-go]').forEach(t => t.onclick = () => location.hash = t.dataset.go);
}
function banner(el, title, text, tone = '') {
  const icon = tone === 'bad' ? '<path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'
    : tone === 'ok' ? '<path d="M20 6 9 17l-5-5"/>' : '<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v5h1"/>';
  el.className = 'banner ' + tone;
  el.innerHTML = `<span class="ic"><svg viewBox="0 0 24 24">${icon}</svg></span><div><h2>${title}</h2><p>${text}</p></div>`;
}
const ICON = {
  home: '<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/>',
  gauge: '<path d="M4 17a8 8 0 1 1 16 0"/><path d="m12 17 4-5"/><circle cx="12" cy="17" r="1.2"/>',
  chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3m0 14v3M4.2 4.2l2.1 2.1m11.4 11.4 2.1 2.1M2 12h3m14 0h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
  alert: '<path d="M12 3 2 20h20z"/><path d="M12 10v4m0 3h.01"/>',
  in: '<path d="M21 12H9m0 0 4-4m-4 4 4 4"/><path d="M3 4v16"/>',
  out: '<path d="M3 12h12m0 0-4-4m4 4-4 4"/><path d="M21 4v16"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  wand: '<path d="m15 4 5 5L9 20H4v-5z"/>',
  pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
};
/* [key, rail label, page title, description, icon] - null = separator */
const NAV = [
  ['home', 'Home', 'Home', 'Your firewall at a glance', 'home'],
  ['graph', 'Live', 'Live traffic', 'Every inbound request in real time on a 3D firewall - click one to capture it, scroll back to replay', 'globe'],
  ['security', 'Security', 'Inbound security', 'Which rules expose you, how they could be attacked, and what is attacking you', 'shield'],
  ['investigate', 'Investigate', 'Investigate', 'Why was it blocked? Follow any IP, session or rule step by step', 'search'],
  ['utm', 'Threats', 'Threats & UTM', 'IPS detections, application control, web filter and admin changes', 'alert'],
  null,
  ['overview', 'Activity', 'Activity', 'What the firewall logged and how sessions ended', 'chart'],
  ['inbound', 'Inbound', 'Inbound traffic', 'Traffic per inbound rule, country and port', 'in'],
  ['outbound', 'Outbound', 'Outbound traffic', 'What your machines connect to on the internet', 'out'],
  ['logs', 'Logs', 'Log explorer', 'Search the original FortiGate log records', 'list'],
  ['rule', 'Rules', 'Rule assistant', 'What a rule really carried, and the hardened configuration for it', 'wand'],
  null,
  ['health', 'Health', 'Health', 'Is the log pipeline working? Receiver, storage and memory', 'pulse'],
  ['settings', 'Settings', 'Settings', 'Firewall connection, configuration backup, account and preferences', 'gear'],
];
const PAGE_META = Object.fromEntries(NAV.filter(Boolean).map(([k, , t, d]) => [k, {title: t, desc: d}]));
PAGE_META.welcome = {title: 'Connect your FortiGate', desc: 'Two commands on the firewall and Vigil starts filling up'};
function renderNav() {
  $('#nav').innerHTML = NAV.map(n => n ? `<a href="#${n[0]}" data-p="${n[0]}" title="${esc(n[2])}"><svg viewBox="0 0 24 24">${ICON[n[4]]}</svg>${esc(n[1])}${n[0] === 'graph' ? '<i class="dot-live" hidden></i>' : ''}</a>`
    : '<div class="sep"></div>').join('');
  $('#nav').onclick = e => { if (e.target.closest('a')) $('#rail').classList.remove('open'); };
}
function liveStatus() {
  if (!S.meta) return;
  const pill = $('#status'), lag = (Date.now() - S.meta.last_event_ts) / 1000;
  const none = !S.meta.last_event_ts;
  pill.classList.toggle('demo', !!S.meta.demo);
  pill.querySelector('.dot').className = 'dot ' + (none ? 'wait' : lag < 120 ? 'live' : 'lag');
  const name = (S.meta.firewall && S.meta.firewall.name) || 'FortiGate';
  const bf = S.meta.backfill;
  if (bf && bf.active) {          // still reading the log files on disk: show how far it is and how long is left
    pill.querySelector('.dot').className = 'dot wait';
    $('#live-text').textContent = `Reading history · ${bf.percent}%` + (bf.eta_text ? ` · ~${bf.eta_text} left` : '');
    pill.title = `Reading the FortiGate logs already on this machine: ${fmtB(bf.done)} of ${fmtB(bf.total)}`
      + (bf.reading ? ` (${bf.reading})` : '') + (bf.rate ? ` at ${fmtB(bf.rate)}/s` : '')
      + '. Pages fill in as this progresses; once it finishes, new logs appear within seconds.';
  } else {
    $('#live-text').textContent = none ? 'Waiting for logs' : (S.meta.demo ? 'Demo · ' : '') + (lag < 120 ? `${name} · live` : `${name} · last log ${ago(S.meta.last_event_ts)} ago`);
    pill.title = none ? 'No FortiGate logs received yet - see Connect a FortiGate' : `Newest log ${Math.max(0, Math.round(lag))} s ago`;
  }
  const dl = document.querySelector('#nav .dot-live');
  if (dl) dl.hidden = none || lag > 120;
  $('#rangeinfo').textContent = S.generated && isFinite(S.generated) ? `Updated ${ago(S.generated)} ago` : '';
}
function notify(title, text, tone = '', ms = 6000) {
  const box = $('#toasts');
  const el = document.createElement('div');
  el.className = 'toast ' + tone;
  el.innerHTML = `<div class="eyebrow" style="margin-bottom:3px">${esc(title)}</div><div>${esc(text)}</div>`;
  el.onclick = () => el.remove();
  box.prepend(el);
  setTimeout(() => el.classList.add('out'), ms); setTimeout(() => el.remove(), ms + 600);
}

/* cols: [{k, t, num, f(v,row)->html, v(row)->sortable/csv value}] */
function table(id, cols, rows, o = {}) {
  const el = document.getElementById(id);
  if (!el) return;
  el._rows = rows; el._cols = cols; el._o = o;
  if (!el._sort) el._sort = o.sort || null;
  drawTable(el);
}
function drawTable(el) {
  const cols = el._cols, o = el._o;
  let rows = el._rows || [];
  const val = (c, r) => c.v ? c.v(r) : r[c.k];
  if (el._sort) {
    const c = cols.find(x => x.k === el._sort.k);
    if (c) {
      const d = el._sort.d;
      rows = [...rows].sort((a, b) => {
        const x = val(c, a), y = val(c, b);
        if (x == null) return 1; if (y == null) return -1;
        return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * d;
      });
    }
  }
  const lim = o.limit || 500;
  const shown = rows.slice(0, lim);
  const head = cols.map(c => `<th class="${c.num ? 'num' : ''}" data-k="${c.k}">${esc(c.t)}${el._sort && el._sort.k === c.k ? (el._sort.d > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('');
  const body = shown.map((r, i) => `<tr data-i="${i}" class="${o.onRow ? 'click' : ''}">${cols.map(c => {
    const v = val(c, r);
    return `<td class="${c.num ? 'num' : ''} ${c.mono ? 'mono' : ''}">${c.f ? c.f(v, r) : c.num ? fmtN(v) : esc(v)}</td>`;
  }).join('')}</tr>`).join('');
  el.innerHTML = (rows.length ? `<div class="tbl-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`
    : `<div class="empty">${esc(o.empty || 'No data in this range.')}</div>`) +
    `<div class="tbl-foot"><span>${fmtN(rows.length)} rows${rows.length > lim ? `, showing ${lim}` : ''}</span>${o.note ? `<span>· ${o.note}</span>` : ''}
     <span class="grow"></span>${rows.length ? '<button class="csv">CSV</button>' : ''}</div>`;
  el.querySelectorAll('th').forEach(th => th.onclick = () => {
    const k = th.dataset.k;
    el._sort = {k, d: el._sort && el._sort.k === k ? -el._sort.d : (cols.find(c => c.k === k).num ? -1 : 1)};
    drawTable(el);
  });
  if (o.onRow) el.querySelectorAll('tbody tr').forEach(tr => tr.onclick = () => o.onRow(shown[+tr.dataset.i]));
  const b = el.querySelector('.csv');
  if (b) b.onclick = () => csv(o.csv || el.id, cols, rows);
}
function csv(name, cols, rows) {
  const q = v => { v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  const lines = [cols.map(c => q(c.t)).join(',')].concat(rows.map(r => cols.map(c => {
    let v = c.csv ? c.csv(r) : c.v ? c.v(r) : r[c.k];
    if (c.k === 'policyid' || c.k === 'policies') v = r[c.k] != null ? String(r[c.k]).split(',').map(polLabel).join('; ') : '';
    if ((c.k === 'ts' || c.k === 'last' || c.k === 'first' || /_ts$/.test(c.k)) && typeof v === 'number') v = fmtT(v);
    return q(Array.isArray(v) ? v.map(x => Array.isArray(x) ? x.join(':') : x).join(' ') : v);
  }).join(',')));
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([lines.join('\n')], {type: 'text/csv'}));
  a.download = `vigil-${name}-${fmtT(Date.now()).replace(/[: ]/g, '')}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
}

function tooltipAxis(params) {
  if (!params.length) return '';
  const t = params[0].value[0];
  return `<b>${fmtT(t)}</b><br>` + params.filter(p => p.value[1]).sort((a, b) => b.value[1] - a.value[1])
    .map(p => `${p.marker} ${esc(p.seriesName)} <b style="float:right;margin-left:14px">${fmtN(p.value[1])}</b>`).join('<br>');
}
function base(sp) {
  const long = sp && sp.to - sp.frm > 2 * 864e5;
  return {
    backgroundColor: 'transparent', animation: false,
    textStyle: {color: C.ink2, fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif', fontSize: 11},
    grid: {left: 8, right: 16, top: 34, bottom: 8, containLabel: true},
    legend: {top: 0, left: 0, textStyle: {color: C.ink2}, icon: 'roundRect', itemWidth: 10, itemHeight: 10, type: 'scroll', pageTextStyle: {color: C.ink2}},
    tooltip: {trigger: 'axis', backgroundColor: '#262625', borderColor: C.axis, textStyle: {color: C.ink, fontSize: 12},
      axisPointer: {type: 'line', lineStyle: {color: C.muted}}, formatter: tooltipAxis, confine: true},
    xAxis: {type: 'time', min: sp && sp.frm, max: sp && sp.to, axisLine: {lineStyle: {color: C.axis}}, axisTick: {show: false},
      axisLabel: {color: C.muted, hideOverlap: true, formatter: v => fmtT(v, long ? 'dhm' : 'hm')}, splitLine: {show: false}},
    yAxis: {type: 'value', axisLabel: {color: C.muted, formatter: fmtK}, splitLine: {lineStyle: {color: C.grid}}, axisLine: {show: false}},
  };
}
function chart(id, opt, onClick) {
  const el = document.getElementById(id);
  if (!el) return;
  const c = echarts.getInstanceByDom(el) || echarts.init(el);
  c.setOption(opt, true);
  c.off('click');
  if (onClick) c.on('click', onClick);
  S.charts[id] = c;
}
const barSeries = (name, data, color, stack) => ({name, type: 'bar', stack, data, barMaxWidth: 18, large: data.length > 800,
  itemStyle: {color, borderColor: C.surface, borderWidth: stack && data.length < 120 ? 1 : 0, borderRadius: stack ? 0 : [4, 4, 0, 0]},
  emphasis: {focus: 'series'}});
function hbar(id, rows, labelFn, valFn, onClick, color = C.s[0]) {
  const r = rows.slice(0, 20).reverse();
  chart(id, {
    backgroundColor: 'transparent', animation: false, textStyle: {color: C.ink2, fontSize: 11},
    grid: {left: 8, right: 40, top: 4, bottom: 4, containLabel: true},
    tooltip: {trigger: 'item', backgroundColor: '#262625', borderColor: C.axis, textStyle: {color: C.ink},
      formatter: p => `${esc(p.name)}<br><b>${fmtN(p.value)}</b>`},
    xAxis: {type: 'value', axisLabel: {color: C.muted, formatter: fmtK}, splitLine: {lineStyle: {color: C.grid}}},
    yAxis: {type: 'category', data: r.map(labelFn), axisLabel: {color: C.ink2, width: 190, overflow: 'truncate'},
      axisLine: {lineStyle: {color: C.axis}}, axisTick: {show: false}},
    series: [{type: 'bar', data: r.map(valFn), barMaxWidth: 14, itemStyle: {color, borderRadius: [0, 4, 4, 0]},
      label: {show: true, position: 'right', color: C.ink2, formatter: p => fmtK(p.value)}}],
  }, p => onClick && onClick(r[p.dataIndex]));
}
function toLogs(f) {
  const p = new URLSearchParams();
  Object.entries(f).forEach(([k, v]) => v !== undefined && v !== null && v !== '' && p.set(k, v));
  location.hash = '#logs?' + p.toString();
}
function note(id, txt) { const e = document.getElementById(id + '-sub'); if (e) e.textContent = txt; }
function tools(id, html) { const e = document.getElementById(id + '-tools'); if (e) e.innerHTML = html; return e; }

// ------------------------------------------------------------------ pages
const PAGES = {};

const CAT_LABEL = {'traffic:forward': 'Firewall sessions', 'traffic:local': 'Traffic to the firewall itself', 'utm:app-ctrl': 'Application control',
  'utm:webfilter': 'Web filter', 'utm:ips': 'IPS (attacks)', 'utm:virus': 'Antivirus', 'event': 'System / VPN events', 'utm:other': 'Other security events'};
PAGES.overview = {
  layout: () => `<div class="banner" id="ov-banner"><div style="flex:1">${SKEL}</div></div><div class="alerts" id="alerts"></div>
    <div class="tiles" id="tiles">${'<div class="tile"><div class="sk w50"></div><div class="sk h" style="height:30px"></div></div>'.repeat(5)}</div>
    ${card('ov-cat', 'What the firewall logged', {w: 'w8', chart: '', sub: 'Log lines over time by type. Most of it is internet scanners being blocked - normal background noise. Click a bar to see those logs.',
      tip: 'Every FortiGate log line counted per time slice. Hover for exact numbers.'})}
    ${card('ov-cls', 'How sessions ended', {w: 'w4', sub: 'Blocked vs allowed vs closed normally',
      tip: 'client-rst / server-rst / close / timeout are normal ends of allowed sessions - they are not blocks.'})}
    ${card('ov-drop', 'Blocks on rules that normally allow traffic', {w: 'w6', chart: 'short',
      sub: 'Sessions stopped by application control or IPS on allowed rules. Spikes here can mean an attack - or a sensor blocking real users.',
      tip: 'Scanner denies (implicit deny) are not included here - these are real decisions on your accept rules.'})}
    ${card('ov-ins', 'Things to look at', {w: 'w6', sub: 'Automatic findings, most important first'})}
    ${card('ov-in', 'Busiest internet sources reaching your servers', {w: 'w6', sub: 'Allowed and security-blocked sessions from the internet'})}
    ${card('ov-out', 'Machines sending the most data out', {w: 'w6', sub: 'By bytes - unusual names here can mean data leaving'})}`,
  async load(sp) {
    const insP = api('/api/insights', sp);
    const d = await api('/api/overview', sp);
    const total = Object.values(d.cats).reduce((a, b) => a + b, 0);
    const realDrops = d.real_drops.reduce((a, x) => a + x[1], 0);
    const noise = d.classes.drop - realDrops;
    const lag = S.meta ? (Date.now() - S.meta.last_event_ts) / 1000 : 0;
    const rangeTxt = S.range === 'custom' ? 'the selected period' : `the last ${S.range}`;
    const noisePct = total ? Math.round(100 * noise / total) : 0;
    tiles($('#tiles'), [
      ['Log lines', fmtK(total), `${fmtK(Math.round(total / ((sp.to - sp.frm) / 1000)))} per second`, 'info', 'Everything the firewall reported in this period.'],
      ['Scanners & denied', fmtK(noise), `${noisePct}% of all traffic - blocked by default`, '', 'Internet scanners and traffic no rule allows. This is expected background noise.', '#inbound'],
      ['Security blocks on allowed rules', fmtN(realDrops), realDrops ? 'sessions stopped by a profile' : 'none - nothing blocked unexpectedly',
        realDrops ? 'crit' : 'good', 'App control or IPS stopped a session on a rule that normally allows it.', '#utm'],
      ['Allowed sessions', fmtK(d.classes.accept + d.classes.end), `${fmtK(d.classes.end)} closed normally`, 'good', 'Sessions your rules allowed.'],
      ['Log delay', lag < 1e6 ? (lag < 90 ? Math.round(lag) + ' s' : ago(S.meta.last_event_ts)) : '—', lag < 90 ? 'Receiving logs live' : 'Logs are delayed - check Health',
        lag > 90 ? 'crit' : 'good', 'Time since the newest FortiGate log arrived.', lag > 90 ? '#health' : ''],
    ]);
    banner($('#ov-banner'), 'Summary', `In ${rangeTxt} the firewall logged <b>${fmtK(total)}</b> events. <b>${noisePct}%</b> were blocked internet noise.
      ${realDrops ? `<b>${fmtN(realDrops)}</b> sessions were stopped by security profiles on allowed rules.` : 'No sessions were blocked unexpectedly on allowed rules.'}
      <span class="muted">Checking findings…</span>`);
    const cats = CAT_ORDER.filter(c => d.series[c]);
    chart('ov-cat-c', Object.assign(base(sp), {
      series: cats.map(c => barSeries(CAT_LABEL[c] || c, d.series[c], C.s[CAT_ORDER.indexOf(c)], 'a')),
    }), p => toLogs({table: CAT_TABLE[cats.find(c => (CAT_LABEL[c] || c) === p.seriesName)], frm: p.value[0], to: p.value[0] + d.step}));
    table('ov-cls', [{k: 'k', t: 'Outcome', f: (v, r) => r.h}, {k: 'n', t: 'Log lines', num: true, f: fmtK}, {k: 'p', t: 'Share', num: true, f: v => v.toFixed(1) + '%'}],
      [['drop', '<span class="drop">✕ Blocked / denied</span>'], ['accept', '✓ Allowed'], ['end', '<span class="endst">Closed normally (not a block)</span>'], ['other', 'Other']]
        .map(([k, h]) => ({k, h, n: d.classes[k], p: total ? 100 * d.classes[k] / total : 0})),
      {note: 'blocked includes internet scanners'});
    $('#ov-cls').insertAdjacentHTML('beforeend', `<div style="margin-top:10px">${cats.map(c =>
      `<span class="tag"><span style="color:${C.s[CAT_ORDER.indexOf(c)]}">■</span> ${esc(CAT_LABEL[c] || c)} ${fmtK(d.cats[c])}</span>`).join('')}</div>`);
    chart('ov-drop-c', Object.assign(base(sp), {legend: {show: false},
      series: [barSeries('blocked by a security profile', d.real_drops, C.crit)]}),
      p => toLogs({table: 'utm_app', act: 'block', frm: p.value[0], to: p.value[0] + d.step}));
    note('ov-drop', realDrops ? `${fmtN(realDrops)} blocked sessions · click a bar to see which` : 'Nothing blocked on allowed rules in this period - good.');
    insP.then(ins => {
      const crit = ins.insights.filter(i => i.severity === 'critical' || i.severity === 'high');
      $('#alerts').innerHTML = ins.alerts.map(a => `<div class="alert ${a.severity}">${sevH(a.severity)}<b>${esc(a.title)}</b>
        <span class="muted">${esc(a.detail)}</span>${linkH(a.link)}</div>`).join('');
      $('#ov-ins').innerHTML = insightsH(ins.insights);
      bindLinks($('#ov-ins')); bindLinks($('#alerts'));
      banner($('#ov-banner'), crit.length ? `${crit.length} finding${crit.length > 1 ? 's' : ''} need attention` : 'No urgent problems found',
        `In ${rangeTxt} the firewall logged <b>${fmtK(total)}</b> events; <b>${noisePct}%</b> were blocked internet noise.
        ${realDrops ? `<b>${fmtN(realDrops)}</b> sessions were stopped by security profiles on allowed rules.` : 'Nothing was blocked unexpectedly on allowed rules.'}
        ${crit.length ? `Most important: <b>${esc(crit[0].title)}</b>.` : ''} See <a href="#security">Inbound Security</a> for rule-by-rule risk.`,
        crit.length ? 'bad' : 'ok');
    }).catch(e => { $('#ov-ins').innerHTML = `<div class="err">${esc(e.message)}</div>`; });
    table('ov-in', [
      {k: 'src', t: 'Source', mono: true}, {k: 'country', t: 'Country'},
      {k: 'policies', t: 'Policies', f: v => (v || '').split(',').map(p => `<span class="tag">${esc(polLabel(p))}</span>`).join('')},
      {k: 'n', t: 'Hits', num: true}, {k: 'drops', t: 'Drops', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'},
      {k: 'bytes', t: 'Bytes', num: true, f: fmtB}], d.top_in, {onRow: r => toLogs({table: 'traffic', src: r.src})});
    table('ov-out', [
      {k: 'src', t: 'Machine', mono: true}, {k: 'host', t: 'Name'}, {k: 'n', t: 'Sessions', num: true},
      {k: 'sent', t: 'Sent', num: true, f: fmtB}, {k: 'rcvd', t: 'Received', num: true, f: fmtB},
      {k: 'drops', t: 'Denied', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'}], d.top_out,
      {onRow: r => toLogs({table: 'traffic', src: r.src})});
  },
};

function linkH(l) {
  if (!l || !Object.keys(l).length) return '';
  return `<a href="#" class="golink" data-l='${esc(JSON.stringify(l))}'>evidence →</a>`;
}
function bindLinks(el) {
  el.querySelectorAll('.golink').forEach(a => a.onclick = e => {
    e.preventDefault();
    const l = JSON.parse(a.dataset.l);
    if (l.page === 'rule') location.hash = '#rule?policyid=' + l.policyid;
    else if (l.page) location.hash = '#' + l.page;
    else toLogs(l);
  });
}
function insightsH(list) {
  if (!list.length) return '<div class="empty">No findings in this range.</div>';
  return list.map(i => `<div class="insight">${sevH(i.severity)}<div><div class="t">${esc(i.title)}</div>
    <div class="d">${esc(i.detail)}</div></div>${linkH(i.link)}</div>`).join('');
}

PAGES.inbound = {
  layout: () => `<div class="banner" id="in-banner"></div>
    ${card('in-pol', 'Traffic per inbound rule', {sub: 'What each internet-facing rule actually carried. Click a rule for the Rule assistant.',
      tip: 'Unexpected = applications seen that the rule was not meant for. App blocked = stopped by application control. Drops = any security block.'})}
    ${card('in-flow', 'Where inbound traffic goes', {chart: 'tall', sub: 'Country → rule → port → application for the busiest allowed flows. Click a box to see the logs.'})}
    ${card('in-ca', 'Allowed traffic by country', {w: 'w6', chart: '', sub: 'Countries your allowed rules accepted traffic from'})}
    ${card('in-cd', 'Blocked traffic by country', {w: 'w6', chart: '', sub: 'Mostly internet scanners hitting the default deny'})}
    ${card('in-new', 'New internet IPs allowed in', {w: 'w6', sub: 'First allowed in this period. ⚠ = the IP was blocked before it got in.'})}
    ${card('in-dp', 'Deny rules', {w: 'w6', sub: 'Blocked lines per deny rule (policy 0 = nothing matched, default deny)'})}
    ${card('in-dtl', 'Blocked traffic over time', {chart: 'short', sub: 'Sudden jumps can indicate a scan campaign or flood'})}
    ${card('in-ds', 'Top blocked sources', {w: 'w6', sub: 'IPs that were blocked the most. Click to read their blocked log lines.'})}
    ${card('in-dport', 'Most-probed ports', {w: 'w6', sub: 'What attackers are looking for on your public IPs'})}`,
  async load(sp) {
    banner($('#in-banner'), 'Detailed inbound numbers', 'This page shows raw traffic numbers. For a plain-English view of which rules expose you and what is attacking you, open <a href="#security">Inbound Security</a>.');
    const d = await api('/api/inbound', sp);
    table('in-pol', [
      {k: 'policyid', t: 'Policy', f: v => pol(v), v: r => r.policyid},
      {k: 'sensors', t: 'Sensor', f: v => (v || []).map(s => `<span class="tag">${esc(s)}</span>`).join('')},
      {k: 'hits', t: 'Hits', num: true}, {k: 'srcs', t: 'Sources', num: true}, {k: 'countries', t: 'Ctry', num: true},
      {k: 'apps', t: 'Apps seen', f: v => v.slice(0, 5).map(([a, n]) => `<span class="tag">${appH(a)} ${fmtK(n)}</span>`).join('')},
      {k: 'ports', t: 'Ports', f: v => v.slice(0, 4).map(([p, n]) => `<span class="tag">${esc(p)} ${fmtK(n)}</span>`).join('')},
      {k: 'unexpected', t: 'Unexpected', num: true, f: (v, r) => !r.has_expected ? '<span class="muted">no map</span>' : v ?
        `<span class="warnt" title="${esc(r.unexpected_apps.map(x => x.join(' ')).join(', '))}">⚠ ${fmtN(v)}</span>` : '0'},
      {k: 'blocked', t: 'App blocked', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'},
      {k: 'drops', t: 'Drops', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'},
      {k: 'bytes', t: 'Bytes', num: true, f: fmtB}, {k: 'last', t: 'Last seen', f: v => fmtT(v, 'dhm')},
    ], d.policies, {onRow: r => location.hash = '#rule?policyid=' + r.policyid, sort: {k: 'hits', d: -1}});
    // sankey
    const nodes = new Map(), links = [];
    const node = (name, layer) => { if (!nodes.has(name)) nodes.set(name, {name, layer, itemStyle: {color: C.s[[0, 2, 3, 6][layer]], borderColor: C.surface}}); };
    d.flows.forEach(f => {
      const a = '🌐 ' + (f.country || '?'), b = polLabel(f.policyid), c = ':' + f.dpt + '/' + (PROTO[f.proto] || f.proto), e = 'app ' + (f.app || '?');
      [[a, 0], [b, 1], [c, 2], [e, 3]].forEach(([n, l]) => node(n, l));
      links.push({source: a, target: b, value: f.n}, {source: b, target: c, value: f.n}, {source: c, target: e, value: f.n});
    });
    const agg = new Map(), SEP = '\u0001';
    links.forEach(l => { const k = l.source + SEP + l.target; agg.set(k, (agg.get(k) || 0) + l.value); });
    chart('in-flow-c', {backgroundColor: 'transparent', animation: false,
      tooltip: {trigger: 'item', backgroundColor: '#262625', borderColor: C.axis, textStyle: {color: C.ink},
        formatter: p => p.dataType === 'edge' ? `${esc(p.data.source)} → ${esc(p.data.target)}<br><b>${fmtN(p.data.value)}</b>` : `${esc(p.name)}<br><b>${fmtN(p.value)}</b>`},
      series: [{type: 'sankey', left: 8, right: 160, top: 8, bottom: 8, nodeGap: 6, nodeWidth: 10, draggable: false,
        data: [...nodes.values()], links: [...agg].map(([k, v]) => { const [s, t] = k.split(SEP); return {source: s, target: t, value: v}; }),
        label: {color: C.ink2, fontSize: 11}, lineStyle: {color: 'source', opacity: 0.3, curveness: 0.5},
        emphasis: {focus: 'adjacency'}, layoutIterations: 32}]},
      p => {
        if (p.dataType !== 'node') return;
        const n = p.name, l = nodes.get(n).layer;
        if (l === 0) toLogs({table: 'traffic', dir: 'in', country: n.slice(3)});
        else if (l === 1) location.hash = '#rule?policyid=' + d.flows.find(f => polLabel(f.policyid) === n).policyid;
        else if (l === 2) toLogs({table: 'traffic', dir: 'in', dpt: n.slice(1).split('/')[0]});
        else toLogs({table: 'utm_app', app: n.slice(4)});
      });
    hbar('in-ca-c', d.countries_acc, r => r.country || '?', r => r.n, r => toLogs({table: 'traffic', dir: 'in', country: r.country}));
    hbar('in-cd-c', d.countries_deny, r => r.country || '?', r => r.n, r => toLogs({table: 'noise', country: r.country, frm: Math.max(sp.frm, sp.to - 36e5), to: sp.to}));
    table('in-new', [
      {k: 'src', t: 'Source', mono: true}, {k: 'country', t: 'Country'},
      {k: 'policies', t: 'Policies', f: v => (v || '').split(',').filter(Boolean).map(p => `<span class="tag">${esc(polLabel(p))}</span>`).join('')},
      {k: 'first_acc_ts', t: 'First accepted', f: v => fmtT(v, 'dhm')}, {k: 'n_acc', t: 'Accepted', num: true},
      {k: 'n_deny', t: 'Denied', num: true, f: (v, r) => v ? `<span class="${r.first_ts < r.first_acc_ts ? 'warnt' : ''}">${fmtN(v)}${r.first_ts < r.first_acc_ts ? ' ⚠ before first accept' : ''}</span>` : '0'}],
      d.new_src, {onRow: r => toLogs({table: 'traffic', src: r.src}), sort: {k: 'first_acc_ts', d: -1}});
    table('in-dp', [{k: 'policyid', t: 'Policy', f: v => pol(v)}, {k: 'cat', t: 'Type'}, {k: 'inif', t: 'In iface'},
      {k: 'n', t: 'Denied lines', num: true}], d.deny_policies,
      {onRow: r => toLogs({table: 'noise', policyid: r.policyid, frm: Math.max(sp.frm, sp.to - 36e5), to: sp.to})});
    const pols = [...new Set(d.deny_timeline.map(r => r.policyid))];
    chart('in-dtl-c', Object.assign(base(sp), {
      series: pols.slice(0, 7).map((p, i) => barSeries(polLabel(p), d.deny_timeline.filter(r => r.policyid === p).map(r => [r.t, r.n]), C.s[i], 'd')),
    }), p => toLogs({table: 'noise', frm: p.value[0], to: p.value[0] + d.step}));
    table('in-ds', [{k: 'src', t: 'Source', mono: true}, {k: 'country', t: 'Country'}, {k: 'inif', t: 'In'},
      {k: 'policies', t: 'Policy', f: v => (v || '').split(',').map(p => `<span class="tag">${esc(polLabel(p))}</span>`).join('')},
      {k: 'n', t: 'Denied', num: true}, {k: 'ports', t: '≥ ports/h', num: true}, {k: 'psample', t: 'Ports (sample)', mono: true}],
      d.deny_src, {onRow: r => toLogs({table: 'noise', src: r.src, frm: Math.max(sp.frm, sp.to - 864e5), to: sp.to})});
    table('in-dport', [{k: 'dpt', t: 'Port', f: (v, r) => portH(v, r.proto)}, {k: 'inif', t: 'In'}, {k: 'n', t: 'Denied', num: true},
      {k: 'srcs', t: '≥ sources/h', num: true}], d.deny_port,
      {onRow: r => toLogs({table: 'noise', dpt: r.dpt, frm: Math.max(sp.frm, sp.to - 36e5), to: sp.to})});
  },
};

PAGES.outbound = {
  layout: () => `${card('ob-roots', 'Most-visited websites', {w: 'w6', chart: 'tall', sub: 'Root domains your machines requested (from the web filter hostname)'})}
    ${card('ob-heat', 'Which machine talks to which site', {w: 'w6', chart: 'tall', sub: 'Top 15 machines × top 20 domains. Darker = more requests.'})}
    ${card('ob-rt', 'All domains', {w: 'w6', sub: 'Requests, machines and bytes per domain'})}
    ${card('ob-new', 'Domains contacted for the first time', {w: 'w6', sub: 'New destinations are worth a quick look - malware often calls new domains'})}
    ${card('ob-pol', 'Outbound rules', {w: 'w4', sub: 'Traffic per outbound rule'})}
    ${card('ob-mach', 'Machines by data sent', {w: 'w8', sub: 'Unusually large uploads can mean data leaving the network'})}
    ${card('ob-uniq', 'Machines contacting many domains', {w: 'w4', sub: 'A sudden high count can indicate malware or a crawler'})}
    ${card('ob-tun', 'Hidden tunnels (Cloudflare / WARP)', {w: 'w4', sub: 'Traffic inside these tunnels is invisible to the web filter'})}
    ${card('ob-deny', 'Blocked outbound traffic', {w: 'w4', sub: 'Machines trying to reach something no rule allows'})}`,
  async load(sp) {
    const d = await api('/api/outbound', sp);
    const ogH = v => v === null ? '' : v ? '<span class="tag">allowed</span>' : '<span class="warnt">⚠ not on allow-list</span>';
    hbar('ob-roots-c', d.roots, r => r.root, r => r.n, r => toLogs({table: 'utm_web', root: r.root}));
    const hs = d.heat_src, hr = d.heat_root, max = Math.max(1, ...d.heat.map(x => x.n));
    chart('ob-heat-c', {backgroundColor: 'transparent', animation: false,
      tooltip: {backgroundColor: '#262625', borderColor: C.axis, textStyle: {color: C.ink},
        formatter: p => `${esc(hs[p.value[1]])} → ${esc(hr[p.value[0]])}<br><b>${fmtN(p.value[2])}</b> requests`},
      grid: {left: 8, right: 8, top: 8, bottom: 60, containLabel: true},
      xAxis: {type: 'category', data: hr, axisLabel: {color: C.ink2, rotate: 45, fontSize: 10}, axisLine: {lineStyle: {color: C.axis}}},
      yAxis: {type: 'category', data: hs, axisLabel: {color: C.ink2, fontSize: 10}, axisLine: {lineStyle: {color: C.axis}}},
      visualMap: {min: 0, max, calculable: false, orient: 'horizontal', left: 'center', bottom: 0, itemHeight: 120,
        inRange: {color: C.seq}, textStyle: {color: C.muted}, formatter: v => fmtK(Math.round(v))},
      series: [{type: 'heatmap', data: d.heat.map(x => [hr.indexOf(x.root), hs.indexOf(x.src), x.n]),
        itemStyle: {borderColor: C.surface, borderWidth: 2}}]},
      p => toLogs({table: 'utm_web', src: hs[p.value[1]], root: hr[p.value[0]]}));
    table('ob-rt', [{k: 'root', t: 'Root domain', mono: true}, {k: 'in_og', t: 'Allow-list', f: ogH}, {k: 'n', t: 'Requests', num: true},
      {k: 'srcs', t: 'Machines', num: true}, {k: 'hosts', t: 'FQDNs', num: true}, {k: 'bytes', t: 'Bytes', num: true, f: fmtB},
      {k: 'blocked', t: 'Blocked', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'}], d.roots,
      {onRow: r => toLogs({table: 'utm_web', root: r.root}), note: d.og_loaded ? '' : 'No domain allow-list set - add one in Settings to highlight unapproved destinations'});
    table('ob-new', [{k: 'root', t: 'Root domain', mono: true}, {k: 'in_og', t: 'Allow-list', f: ogH},
      {k: 'first_ts', t: 'First seen', f: v => fmtT(v, 'dhm')}, {k: 'first_src', t: 'First machine', mono: true},
      {k: 'n', t: 'Requests', num: true}], d.new_dom, {onRow: r => toLogs({table: 'utm_web', root: r.root}), sort: {k: 'first_ts', d: -1}});
    table('ob-pol', [{k: 'policyid', t: 'Policy', f: v => pol(v)}, {k: 'n', t: 'Lines', num: true}, {k: 'bytes', t: 'Bytes', num: true, f: fmtB},
      {k: 'drops', t: 'Denied', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'}], d.pol_split,
      {onRow: r => toLogs({table: 'traffic', policyid: r.policyid})});
    table('ob-mach', [{k: 'src', t: 'Machine', mono: true}, {k: 'host', t: 'Name'}, {k: 'os', t: 'OS'}, {k: 'n', t: 'Sessions', num: true},
      {k: 'sent', t: 'Sent', num: true, f: fmtB}, {k: 'rcvd', t: 'Received', num: true, f: fmtB}, {k: 'policies', t: 'Policies', num: true},
      {k: 'drops', t: 'Denied', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'}], d.machines,
      {onRow: r => toLogs({table: 'traffic', src: r.src, dir: 'out'})});
    table('ob-uniq', [{k: 'src', t: 'Machine', mono: true}, {k: 'roots', t: 'Domains', num: true}, {k: 'n', t: 'Requests', num: true}], d.uniq,
      {onRow: r => toLogs({table: 'utm_web', src: r.src})});
    table('ob-tun', [{k: 'src', t: 'Machine', mono: true}, {k: 'host', t: 'Name'}, {k: 'policy', t: 'Policy'}, {k: 'n', t: 'Sessions', num: true},
      {k: 'bytes', t: 'Bytes', num: true, f: fmtB}], d.tunnels, {onRow: r => toLogs({table: 'traffic', src: r.src})});
    table('ob-deny', [{k: 'policyid', t: 'Policy', f: v => pol(v)}, {k: 'dpt', t: 'Port', f: (v, r) => portH(v, r.proto)},
      {k: 'country', t: 'Dst country'}, {k: 'n', t: 'Denied', num: true}], d.denied,
      {onRow: r => toLogs({table: 'traffic', dir: 'out', act: 'drops', dpt: r.dpt})});
  },
};

PAGES.utm = {
  layout: () => `${card('u-tl', 'Application-control blocks over time', {chart: 'short', sub: 'Sessions stopped because the protocol was not allowed on that rule. Click a bar for details.'})}
    ${card('u-by', 'What application control blocked', {w: 'w8', sub: 'Per rule, sensor and application',
      tip: 'port-violation = a known application on the wrong port (e.g. RDP over the mail port) - a classic tunnelling / evasion trick.'})}
    ${card('u-sen', 'Sensor decisions', {w: 'w4', sub: 'pass vs block per application sensor'})}
    ${card('u-ips', 'Attacks detected by IPS', {w: 'w6', sub: 'Exploit attempts matched to known attack signatures'})}
    ${card('u-ipsr', 'Latest IPS events', {w: 'w6', sub: 'Click a row for the original log'})}
    ${card('u-web', 'Web filter decisions', {w: 'w4', sub: 'ftgd_err = web-filter licence expired (no categories)'})}
    ${card('u-webb', 'Web filter blocks and errors', {w: 'w8'})}
    ${card('u-oth', 'Other security events', {w: 'w6', sub: 'SSL certificate problems, VoIP and more'})}
    ${card('u-av', 'Antivirus', {w: 'w6', sub: 'Malware found in traffic'})}
    ${card('u-ev', 'System and VPN events', {w: 'w6', sub: 'Firewall health, updates and VPN tunnel status'})}
    ${card('u-adm', 'Admin logins and configuration changes', {w: 'w6', sub: 'Who logged in and what they changed'})}`,
  async load(sp) {
    const d = await api('/api/utm', sp);
    const pols = [...new Set(d.app_block_tl.map(r => r.policyid))];
    chart('u-tl-c', Object.assign(base(sp), {
      series: pols.slice(0, 8).map((p, i) => barSeries(polLabel(p), d.app_block_tl.filter(r => r.policyid === p).map(r => [r.t, r.n]), C.s[i], 'b')),
    }), p => toLogs({table: 'utm_app', act: 'block', frm: p.value[0], to: p.value[0] + d.step}));
    table('u-by', [{k: 'policyid', t: 'Policy', f: v => pol(v)}, {k: 'applist', t: 'Sensor', f: v => `<span class="tag">${esc(v)}</span>`},
      {k: 'app', t: 'App', f: appH}, {k: 'evtype', t: 'Type'}, {k: 'n', t: 'Blocked', num: true, f: v => `<span class="drop">✖ ${fmtN(v)}</span>`},
      {k: 'first', t: 'First', f: v => fmtT(v, 'dhm')}, {k: 'last', t: 'Last', f: v => fmtT(v, 'dhm')}], d.app_block_by,
      {onRow: r => toLogs({table: 'utm_app', act: 'block', policyid: r.policyid, app: r.app})});
    table('u-sen', [{k: 'applist', t: 'Sensor'}, {k: 'act', t: 'Verdict', f: v => actH(v)}, {k: 'n', t: 'Lines', num: true}], d.app_sensor);
    table('u-ips', [{k: 'severity', t: 'Severity', f: v => sevH(v === 'critical' ? 'critical' : v === 'high' ? 'high' : v === 'medium' ? 'medium' : 'low')},
      {k: 'attack', t: 'Signature'}, {k: 'act', t: 'Action', f: v => actH(v)}, {k: 'n', t: 'Events', num: true},
      {k: 'srcs', t: 'Sources', num: true}, {k: 'last', t: 'Last', f: v => fmtT(v, 'dhm')}], d.ips_by,
      {onRow: r => toLogs({table: 'utm_ips', q: r.attack})});
    table('u-ipsr', [{k: 'ts', t: 'Time', f: v => fmtT(v)}, {k: 'policyid', t: 'Policy', f: v => pol(v)}, {k: 'attack', t: 'Signature'},
      {k: 'act', t: 'Action', f: v => actH(v)}, {k: 'src', t: 'Source', mono: true}, {k: 'scountry', t: 'Country'},
      {k: 'dst', t: 'Dest', mono: true}, {k: 'dpt', t: 'Port'}], d.ips_recent, {onRow: showRaw});
    table('u-web', [{k: 'evtype', t: 'Event'}, {k: 'act', t: 'Action', f: v => actH(v)}, {k: 'profile', t: 'Profile'}, {k: 'n', t: 'Lines', num: true}],
      d.web_by, {note: 'ftgd_err = FortiGuard web-filter licence expired'});
    table('u-webb', [{k: 'ts', t: 'Time', f: v => fmtT(v)}, {k: 'policyid', t: 'Policy', f: v => pol(v)}, {k: 'src', t: 'Source', mono: true},
      {k: 'dhost', t: 'Host'}, {k: 'evtype', t: 'Event'}, {k: 'act', t: 'Action', f: v => actH(v)}], d.web_blocked, {onRow: showRaw});
    table('u-oth', [{k: 'cat', t: 'Category'}, {k: 'evtype', t: 'Event'}, {k: 'act', t: 'Action', f: v => actH(v)}, {k: 'n', t: 'Lines', num: true},
      {k: 'last', t: 'Last', f: v => fmtT(v, 'dhm')}], d.other_by, {onRow: r => toLogs({table: 'utm_other', q: r.evtype || r.cat})});
    table('u-av', [{k: 'ts', t: 'Time', f: v => fmtT(v)}, {k: 'virus', t: 'Virus'}, {k: 'act', t: 'Action', f: v => actH(v)},
      {k: 'src', t: 'Source', mono: true}, {k: 'dhost', t: 'Host'}, {k: 'filename', t: 'File'}], d.av_recent,
      {onRow: showRaw, empty: 'No antivirus events in range (none seen in the live logs so far).'});
    table('u-ev', [{k: 'cat', t: 'Category'}, {k: 'logdesc', t: 'Description'}, {k: 'act', t: 'Action'}, {k: 'n', t: 'Lines', num: true},
      {k: 'last', t: 'Last', f: v => fmtT(v, 'dhm')}], d.events_by, {onRow: r => toLogs({table: 'event', q: r.logdesc})});
    table('u-adm', [{k: 'ts', t: 'Time', f: v => fmtT(v)}, {k: 'logdesc', t: 'Event'}, {k: 'usr', t: 'User'}, {k: 'act', t: 'Action'},
      {k: 'ext', t: 'Detail', f: v => `<span class="mono">${esc((v || '').replace(/FTNTFGT/g, '').replace(/deviceExternalId=\S+ |eventtime=\S+ |tz=\S+ |logid=\S+ |vd=\S+ /g, '').slice(0, 260))}</span>`}],
      d.admin_events, {onRow: showRaw});
  },
};

PAGES.rule = {
  layout: () => `<section class="card"><header><h3>Rule-change assistant</h3><span class="sub">what a policy actually carried in the selected range → proposed strict sensor / source objects</span>
    <div class="tools"><select id="r-pol"></select></div></header><div class="body" id="r-sum"></div></section>
    ${card('r-apps', 'Applications (app-ctrl)', {w: 'w4'})}
    ${card('r-ports', 'Ports', {w: 'w4'})}
    ${card('r-ctry', 'Source countries', {w: 'w4'})}
    ${card('r-src', 'Sources', {w: 'w8'})}
    ${card('r-isdb', 'Internet service (ISDB), last 24 h', {w: 'w4'})}
    ${card('r-cli', 'Proposed FortiOS CLI (review before applying)')}`,
  async load(sp) {
    const sel = $('#r-pol');
    const pols = (S.meta.policies || []).filter(p => p.policyid < 100000 && p.policyid !== 0).sort((a, b) =>
      (a.dir === 'in' ? 0 : 1) - (b.dir === 'in' ? 0 : 1) || a.policyid - b.policyid);
    if (!sel.options.length) {
      sel.innerHTML = pols.map(p => `<option value="${p.policyid}">${esc(p.dir)} · ${esc(polLabel(p.policyid))}</option>`).join('');
      sel.onchange = () => location.hash = '#rule?policyid=' + sel.value;
    }
    const pid = +(S.params.policyid || sel.value || (pols[0] || {}).policyid || 0);
    sel.value = pid;
    const d = await api('/api/policy/' + pid, sp);
    const p = d.policy || {};
    $('#r-sum').innerHTML = `<div class="tiles" style="margin-top:4px">${[
      ['Policy', esc(polLabel(pid)), `${esc(p.dir || '')} · ${esc(p.ptype || '')}`],
      ['Sensors seen', esc(p.applists || '—'), ''],
      ['Hits in range', fmtN(d.hits), ''],
      ['Distinct sources', fmtN(d.n_sources), d.n_sources <= 25 && d.n_sources ? 'explicit source objects proposed' : ''],
      ['Expected apps', esc(d.expected ? d.expected.join(', ') || '(none - observe first)' : 'not set'), '<a href="#settings">set in Settings</a>'],
      ['Unexpected apps', fmtN(Object.keys(d.unexpected).length), esc(Object.keys(d.unexpected).join(', '))],
    ].map(([k, v, s]) => `<div class="tile"><div class="k">${k}</div><div class="v" style="font-size:16px">${v}</div><div class="s">${s}</div></div>`).join('')}</div>`;
    table('r-apps', [{k: 'app', t: 'App', f: (v, r) => appH(v) + (d.unexpected[v] ? ' <span class="warnt">⚠ unexpected</span>' : '')},
      {k: 'applist', t: 'Sensor'}, {k: 'n', t: 'Hits', num: true}, {k: 'blocked', t: 'Blocked', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'}],
      d.apps, {onRow: r => toLogs({table: 'utm_app', policyid: pid, app: r.app})});
    table('r-ports', [{k: 'dpt', t: 'Port', f: (v, r) => portH(v, r.proto)}, {k: 'n', t: 'Hits', num: true}, {k: 'bytes', t: 'Bytes', num: true, f: fmtB},
      {k: 'drops', t: 'Drops', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'}], d.ports,
      {onRow: r => toLogs({table: 'traffic', policyid: pid, dpt: r.dpt})});
    table('r-ctry', [{k: 'country', t: 'Country'}, {k: 'n', t: 'Hits', num: true}], d.countries,
      {onRow: r => toLogs({table: 'traffic', policyid: pid, country: r.country})});
    table('r-src', [{k: 'src', t: 'Source', mono: true}, {k: 'country', t: 'Country'}, {k: 'n', t: 'Hits', num: true},
      {k: 'drops', t: 'Drops', num: true, f: v => v ? `<span class="drop">✖ ${fmtN(v)}</span>` : '0'},
      {k: 'bytes', t: 'Bytes', num: true, f: fmtB}, {k: 'first', t: 'First', f: v => fmtT(v, 'dhm')}, {k: 'last', t: 'Last', f: v => fmtT(v, 'dhm')}],
      d.sources, {onRow: r => toLogs({table: 'traffic', policyid: pid, src: r.src}), note: d.n_sources > 500 ? 'top 500 shown' : ''});
    table('r-isdb', [{k: 'isdb', t: 'ISDB'}, {k: 'n', t: 'Sessions', num: true}], d.isdb);
    $('#r-cli').innerHTML = `<pre class="cli" id="cli-text">${esc(d.cli)}</pre>`;
    tools('r-cli', '<button id="cli-copy">Copy</button>').querySelector('button').onclick = () =>
      navigator.clipboard.writeText(d.cli).then(() => $('#cli-copy').textContent = 'Copied ✔');
  },
};

const LOG_TABLES = {traffic: 'Traffic (accepted / session / outbound deny)', noise: 'Scanner denies (raw syslog scan)',
  utm_app: 'App control', utm_web: 'Web filter', utm_ips: 'IPS', utm_av: 'Antivirus', utm_other: 'Other UTM', event: 'Events'};
const LOG_FIELDS = ['policyid', 'src', 'dst', 'dpt', 'app', 'act', 'country', 'dir', 'dhost', 'root', 'q'];
PAGES.logs = {
  layout: () => `<section class="card"><header><h3>Log explorer</h3><span class="sub" id="lx-info"></span></header><div class="body">
    <form class="q" id="lx-form">
      <label>Source<select name="table">${Object.entries(LOG_TABLES).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('')}</select></label>
      ${LOG_FIELDS.map(f => `<label>${f === 'q' ? 'free text' : f}<input name="${f}" ${f === 'act' ? 'list="acts"' : ''} placeholder="${f === 'act' ? 'drops / deny / block' : ''}"></label>`).join('')}
      <datalist id="acts"><option value="drops"><option value="deny"><option value="block"><option value="accept"><option value="pass"><option value="client-rst"></datalist>
      <button type="submit">Search</button><button type="button" id="lx-clear">Clear</button>
      <button type="button" id="lx-prev">◀</button><button type="button" id="lx-next">▶</button>
    </form></div></section>
    ${card('lx', 'Results', {sub: 'click a row → raw log line'})}`,
  async load(sp) {
    const f = $('#lx-form');
    const P = S.params;
    f.table.value = P.table || 'traffic';
    LOG_FIELDS.forEach(k => f[k].value = P[k] || '');
    f.onsubmit = e => {
      e.preventDefault();
      const o = {table: f.table.value};
      LOG_FIELDS.forEach(k => { if (f[k].value.trim()) o[k] = f[k].value.trim(); });
      if (P.frm) { o.frm = P.frm; o.to = P.to; }
      toLogs(o);
    };
    $('#lx-clear').onclick = () => location.hash = '#logs?table=' + f.table.value;
    const off = +(P.offset || 0);
    const move = n => { const q = new URLSearchParams(P); q.set('offset', Math.max(0, off + n)); location.hash = '#logs?' + q; };
    $('#lx-prev').onclick = () => move(-500); $('#lx-next').onclick = () => move(500);
    const r = {frm: P.frm || sp.frm, to: P.to || sp.to};
    const params = Object.assign({}, P, r, {limit: 500, offset: off});
    $('#lx-info').textContent = `${fmtT(+r.frm)} → ${fmtT(+r.to)} ${P.frm ? '(from the chart you clicked; overrides the range picker)' : ''}`;
    const d = await api('/api/logs', params);
    const hide = new Set(['fid', 'off']);
    const cols = d.columns.filter(c => !hide.has(c)).map(c => ({
      k: c, t: c, num: ['sent', 'rcvd', 'dur', 'n'].includes(c),
      mono: ['src', 'dst', 'tdst', 'url'].includes(c),
      f: c === 'ts' ? v => fmtT(v) : c === 'policyid' ? v => pol(v) : c === 'act' ? (v, row) => actH(v, row.utmact)
        : c === 'app' ? appH : ['sent', 'rcvd'].includes(c) ? fmtB : c === 'url' ? v => esc((v || '').slice(0, 120)) : undefined,
    }));
    table('lx', cols, d.rows, {onRow: showRaw, limit: 500, csv: 'logs-' + (P.table || 'traffic'),
      note: `${d.took_ms != null ? d.took_ms + ' ms' : 'scanned ' + d.scanned_mb + ' MB of raw syslog'}${d.truncated ? ' · more rows exist: narrow filters or page ▶' : ''}${off ? ' · offset ' + off : ''}`});
    note('lx', P.table === 'noise' ? 'scanner denies are kept as totals; individual lines are read from the raw syslog files (max 400 MB per search) · click a row → raw line'
      : 'click a row → raw log line');
  },
};

PAGES.health = {
  layout: () => `<div class="tiles" id="h-tiles"></div>
    ${card('h-day', 'Log lines per day', {w: 'w8', chart: 'short'})}
    ${card('h-svc', 'Components', {w: 'w4', sub: 'Processes inside the Vigil container (restarted automatically)'})}
    ${card('h-snd', 'Syslog senders', {w: 'w6', sub: 'Devices sending to the built-in receiver since it started (not tracked when reading a host syslog file)'})}
    ${card('h-tab', 'Raw tables', {w: 'w6'})}
    ${card('h-roll', 'Summaries', {w: 'w6'})}
    ${card('h-files', 'Ingested files', {w: 'w6'})}
    ${card('h-logs', 'Syslog files on disk', {w: 'w6'})}`,
  async load() {
    const d = await api('/api/health');
    const lag = (d.now - d.last_event_ts) / 1000, commit = (d.now - d.last_commit) / 1000;
    const disk = d.disk || {};
    const mem = d.mem || {};
    const rc = d.receiver || {};
    const inp = d.input || {mode: 'receiver'};
    const memLimit = mem.cgroup_max, memUsed = mem.cgroup_current;
    $('#h-tiles').innerHTML = [
      ['Events / s', fmtN(d.eps_5m), 'average, last 6 minutes'],
      ['Newest log', d.last_event_ts ? (lag < 90 ? Math.round(lag) + ' s ago' : ago(d.last_event_ts) + ' ago') : '—', d.last_event_ts ? fmtT(d.last_event_ts) : 'nothing received yet', lag > 120 || !d.last_event_ts ? 'crit' : 'good'],
      inp.mode === 'file'
        ? ['Syslog file', inp.exists ? fmtB(inp.bytes) : 'missing', inp.exists ? `${inp.file} · ${inp.readable ? `written ${ago(inp.mtime)} ago` : 'NOT readable'}` : `${inp.file} not found`, inp.readable && inp.age_s < 300 ? 'good' : 'crit']
        : ['Receiver', fmtK(rc.messages || 0), rc.rate_per_s != null ? `${rc.rate_per_s} msg/s · port ${rc.port}` : 'not running', rc.messages ? 'good' : 'warn'],
      ['Database', fmtB(d.db_bytes), `last write ${d.last_commit ? Math.round(commit) + ' s ago' : '—'}`, commit > 120 && d.last_commit ? 'warn' : ''],
      ['Disk free', fmtB(disk.free), disk.total ? Math.round(100 * disk.used / disk.total) + '% of the data volume used' : '', disk.free < 5 * 2 ** 30 ? 'warn' : ''],
      ['Memory', memUsed ? fmtB(memUsed) : fmtB(mem.MemAvailable), memUsed ? (memLimit ? 'of ' + fmtB(memLimit) + ' container limit' : 'container usage') : 'available on host', memLimit && memUsed > .85 * memLimit ? 'warn' : ''],
    ].map(([k, v, s, cls]) => `<div class="tile ${cls || ''}"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${esc(s)}</div></div>`).join('');
    const comps = ((d.supervisor || {}).components) || {};
    table('h-snd', [{k: 'ip', t: 'Sender', mono: true}, {k: 'messages', t: 'Messages', num: true}, {k: 'last_ts', t: 'Last message', f: v => v ? ago(v) + ' ago' : ''}],
      rc.senders || [], {empty: inp.mode === 'file' ? 'Logs are read from the host syslog file - the syslog server on this machine receives the senders.' : 'No syslog received yet. See Connect a FortiGate.'});
    chart('h-day-c', Object.assign(base({frm: d.now - 35 * 864e5, to: d.now}), {
      tooltip: Object.assign(base().tooltip, {formatter: ps => `<b>${fmtT(ps[0].value[0]).slice(0, 10)}</b><br>` + ps.map(p => `${p.marker} ${esc(p.seriesName)} <b>${fmtN(p.value[1])}</b>`).join('<br>')}),
      series: [barSeries('scanner / policy denies', d.per_day.map(r => [r.day, r.noise]), C.s[1], 'x'),
        barSeries('everything else', d.per_day.map(r => [r.day, r.n - r.noise]), C.s[0], 'x')],
    }));
    table('h-svc', [{k: 's', t: 'Component'}, {k: 'running', t: 'State', f: v => v ? '<span class="pill good">● running</span>' : '<span class="pill bad">✖ stopped</span>'},
      {k: 'restarts', t: 'Restarts', num: true}, {k: 'started', t: 'Up since', f: v => v ? ago(v) : ''}],
      Object.entries(comps).map(([s, v]) => Object.assign({s}, v)), {empty: 'Component status appears a few seconds after start.'});
    table('h-tab', [{k: 't', t: 'Table'}, {k: 'rows', t: '≈ rows', num: true}, {k: 'oldest', t: 'Oldest', f: v => fmtT(v, 'dhm')}],
      Object.entries(d.tables).map(([t, v]) => Object.assign({t}, v)));
    table('h-roll', [{k: 't', t: 'Rollup'}, {k: 'last', t: 'Latest bucket', f: v => fmtT(v, 'dhm')}, {k: 'oldest', t: 'Oldest', f: v => fmtT(v, 'dhm')}],
      Object.entries(d.rollups).map(([t, v]) => Object.assign({t}, v)));
    table('h-files', [{k: 'fid', t: 'id', num: true}, {k: 'path', t: 'Path', mono: true}, {k: 'lines', t: 'Lines', num: true},
      {k: 'off', t: 'Bytes read', num: true, f: fmtB}, {k: 'first_ts', t: 'First', f: v => fmtT(v, 'dhm')}, {k: 'last_ts', t: 'Last', f: v => fmtT(v, 'dhm')},
      {k: 'done', t: 'Done', f: v => v ? '✔' : 'live'}], d.files);
    table('h-logs', [{k: 'path', t: 'File', mono: true}, {k: 'bytes', t: 'Size', num: true, f: fmtB}, {k: 'mtime', t: 'Modified', f: v => fmtT(v, 'dhm')}], d.log_files);
  },
};

// ------------------------------------------------------------------ raw line modal
async function showRaw(r) {
  if (r.fid == null) return;
  $('#m-title').textContent = `Raw log line · file #${r.fid} @ ${r.off}`;
  $('#m-body').innerHTML = '<div class="muted">loading…</div>';
  $('#modal').hidden = false;
  try {
    const d = await api('/api/raw', {fid: r.fid, off: r.off});
    $('#m-body').innerHTML = d.error ? `<div class="err">${esc(d.error)}</div>` : d.archived
      ? `<div class="muted">${esc(d.path)} is compressed. Read the line from the host with:</div><pre>docker exec vigil sh -c '${esc(d.hint)}'</pre>`
      : `<div class="muted">${esc(d.path)}</div><pre>${esc(d.line).replace(/ (\w+)=/g, '\n<b>$1</b>=')}</pre>`;
  } catch (e) { $('#m-body').innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
$('#m-close').onclick = () => $('#modal').hidden = true;
$('#modal').onclick = e => { if (e.target.id === 'modal') $('#modal').hidden = true; };
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#modal').hidden = true; });

// ------------------------------------------------------------------ router / refresh
async function loadMeta(force) {
  if (S.meta && !force && Date.now() - S.metaAt < 60000) return;
  S.meta = await api('/api/meta');
  S.metaAt = Date.now();
  S.polMap = Object.fromEntries(S.meta.policies.map(p => [p.policyid, p]));
}
function parseHash() {
  const [p, q] = (location.hash.slice(1) || 'home').split('?');
  return {page: PAGES[p] ? p : 'home', params: Object.fromEntries(new URLSearchParams(q || ''))};
}
async function render(force) {
  const {page, params} = parseHash();
  const main = $('#main');
  if (page !== S.page || force === 'layout') {
    Object.values(S.charts).forEach(c => c.dispose()); S.charts = {};
    main.innerHTML = PAGES[page].layout();
    S.page = page;
  }
  S.params = params;
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.dataset.p === page));
  const meta = PAGE_META[page] || {title: page, desc: ''};
  $('#pg-title').textContent = meta.title;
  $('#pg-desc').textContent = meta.desc;
  document.title = `${meta.title} · Vigil`;
  const seq = ++S.seq;
  main.classList.add('loading');
  S.generated = null;
  try {
    await loadMeta();
    const sp = span();
    if (S.range !== 'custom') sp.preset = S.range;          // server serves preset ranges from its warm cache
    await PAGES[page].load(sp);
  } catch (e) {
    if (seq === S.seq) main.insertAdjacentHTML('afterbegin', `<div class="card"><div class="body err">⚠ ${esc(e.message)}</div></div>`);
  } finally {
    if (seq === S.seq) main.classList.remove('loading');
    liveStatus();
  }
}
function syncControls() {
  document.querySelectorAll('#ranges button').forEach(b => b.classList.toggle('on', b.dataset.r === S.range));
  document.querySelectorAll('#tzs button').forEach(b => b.classList.toggle('on', b.dataset.tz === S.tz));
  $('#custom').hidden = S.range !== 'custom';
  $('#auto').checked = S.auto;
}
document.querySelectorAll('#ranges button').forEach(b => b.onclick = () => {
  S.range = b.dataset.r; ls('range', S.range); syncControls();
  if (S.range !== 'custom') render();
});
document.querySelectorAll('#tzs button').forEach(b => b.onclick = () => {
  S.tz = b.dataset.tz; ls('tz', S.tz); syncControls(); render('layout');
});
$('#c-apply').onclick = () => {
  const f = Date.parse($('#c-from').value), t = Date.parse($('#c-to').value);   // browser-local input
  if (f && t && f < t) { S.custom = {frm: f, to: t}; render(); }
};
$('#auto').onchange = e => { S.auto = e.target.checked; ls('auto', S.auto ? '1' : '0'); };
$('#refresh').onclick = () => { loadMeta(true).then(() => render()); };
window.addEventListener('hashchange', () => render());
window.addEventListener('resize', () => Object.values(S.charts).forEach(c => c.resize()));
setInterval(() => { if (S.auto && !document.hidden && $('#modal').hidden && !['logs', 'investigate', 'graph', 'settings', 'welcome'].includes(S.page)) render(); }, 30000);
setInterval(liveStatus, 5000);
$('#menu').onclick = () => $('#rail').classList.toggle('open');
$('#av').onclick = e => { e.stopPropagation(); $('#menu-pop').hidden = !$('#menu-pop').hidden; };
document.addEventListener('click', e => { if (!e.target.closest('#menu-pop')) $('#menu-pop').hidden = true; });
fetch('/api/session').then(r => r.json()).then(s => {
  S.session = s;
  $('#who-user').textContent = s.user || '—';
  $('#who-ver').textContent = `Vigil ${s.version || ''}${s.demo ? ' · demo mode' : ''}`;
  $('#av').textContent = (s.user || 'V').slice(0, 1).toUpperCase();
  if (!s.auth) $('#logout-link').hidden = true;
}).catch(() => {});
renderNav();
syncControls();
document.addEventListener('DOMContentLoaded', () => render());   // after page modules (inv.js) have registered
