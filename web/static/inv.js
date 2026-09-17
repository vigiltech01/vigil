'use strict';
/* Firewall Investigation Tracker (#investigate). Builds on app.js globals (S, C, $, esc, fmt*, api, table, chart, polLabel,
   PROTO, toLogs, span, ls). Everything rendered is an interpretation of FortiGate log fields returned by /api/inv/*;
   missing values are shown as "Data unavailable", never filled in. */

const INV = {key: null, res: null, view: ls('inv.view') || 'timeline', facet: {}, cache: {}, tcache: {}, reqSeq: 0};
const VERD = {allowed: ['✓', 'Allowed'], blocked: ['✕', 'Blocked'], warning: ['⚠', 'Warning'], threat: ['☣', 'Threat'],
  info: ['ℹ', 'Info'], unknown: ['?', 'Unknown hop'], unavailable: ['–', 'Data unavailable'], notreached: ['·', 'Not reached']};
const STC = {allowed: '#0ca30c', blocked: '#d03b3b', warning: '#fab219', threat: '#9085e9', info: '#3987e5'};
const ADV = [['src', 'Source IP'], ['dst', 'Destination IP'], ['spt', 'Source port'], ['dpt', 'Destination port'], ['proto', 'Protocol'],
  ['domain', 'URL / domain'], ['user', 'Username'], ['device', 'Device / hostname'], ['mac', 'MAC address'], ['sess', 'Session ID'],
  ['reqid', 'Request ID'], ['policy', 'Policy ID / name'], ['action', 'Action'], ['app', 'Application'], ['category', 'Category'],
  ['country', 'Country'], ['iface', 'Interface'], ['vpn', 'VPN (1 = only VPN)'], ['threat', 'Threat / IPS (1)'], ['severity', 'Severity'],
  ['keyword', 'Any keyword']];
const FILTER_LABEL = Object.fromEntries(ADV);

const stH = (v, text, big) => `<span class="st ${v}${big ? ' big' : ''}">${(VERD[v] || [''])[0]} ${esc(text || (VERD[v] || ['', v])[1])}</span>`;
const na = v => v === null || v === undefined || v === '' ? '<span class="na">Data unavailable</span>' : esc(v);
const trBtn = (type, value, lbl) => value === null || value === undefined || value === '' ? '' :
  `<button class="tr-btn" data-tr="${esc(type)}" data-tv="${esc(value)}" title="Trace this ${esc(type)}">Trace ${esc(lbl || type)}</button>`;
function fmtNs(ns, short) {
  if (!ns) return '';
  ns = String(ns);
  const ms = Number(ns.slice(0, -6));
  const t = fmtT(ms);
  return (short ? t.slice(11) : t) + '.' + String(ms % 1000).padStart(3, '0') + ' ' + S.tz.toUpperCase();
}
const refTs = ref => Number(String(ref).split(':')[2]);
function invHash(p) {
  const q = new URLSearchParams();
  Object.entries(p).forEach(([k, v]) => v !== undefined && v !== null && v !== '' && q.set(k, v));
  return '#investigate' + (q.toString() ? '?' + q : '');
}
function copyText(txt, btn) {
  const done = () => { if (btn) { const o = btn.textContent; btn.textContent = 'Copied ✔'; setTimeout(() => btn.textContent = o, 1200); } };
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(txt).then(done);
  const ta = document.createElement('textarea');           // plain-http fallback
  ta.value = txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); done();
}

// ------------------------------------------------------------------ side panel
function panel(title, html, after) {
  let p = $('#inv-panel');
  if (!p) {
    document.body.insertAdjacentHTML('beforeend', `<aside id="inv-panel" class="off"><header><b id="ip-title"></b>
      <button id="ip-close">✕</button></header><div class="pb" id="ip-body"></div></aside>`);
    p = $('#inv-panel');
    $('#ip-close').onclick = () => p.classList.add('off');
    document.addEventListener('keydown', e => { if (e.key === 'Escape') p.classList.add('off'); });
  }
  $('#ip-title').innerHTML = title;
  $('#ip-body').innerHTML = html;
  p.classList.remove('off');
  if (after) after($('#ip-body'));
}
function kvTable(rows, hl = new Set()) {
  return `<table class="kvt">${rows.map(([k, v, kind]) => `<tr class="${hl.has(k) ? 'hl' : ''}"><td>${esc(k)}</td><td>${
    kind === 'ts' ? esc(fmtNs(v)) : Array.isArray(v) ? esc(v.join(', ')) : na(v)}</td></tr>`).join('')}</table>`;
}
const CORR_KEYS = new Set(['externalId', 'src', 'dst', 'spt', 'dpt', 'proto', 'FTNTFGTpolicyid', 'FTNTFGTeventtime',
  'destinationTranslatedAddress', 'dhost', 'FTNTFGTsessionid']);
function rawViewer(el, rec) {
  const f = rec.fields || {};
  el.innerHTML = `<div class="rawbox"><div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
      <input class="rv-q" placeholder="search fields…" style="flex:1;min-width:140px">
      <button class="rv-copy">Copy JSON</button><button class="rv-exp">Expand raw line</button></div>
    <div class="muted" style="font-size:11px;margin:4px 0">${esc(rec.path || '')} · ${rec.raw_available ? 'original syslog line' :
      'original line is in a compressed file - fields reconstructed from the database row'} · highlighted = correlation keys</div>
    <div class="rv-t"></div><pre class="rv-raw" hidden>${esc(rec.raw || '')}</pre></div>`;
  const draw = () => {
    const s = el.querySelector('.rv-q').value.toLowerCase();
    el.querySelector('.rv-t').innerHTML = kvTable(Object.entries(f).filter(([k, v]) => !s || k.toLowerCase().includes(s) ||
      String(v).toLowerCase().includes(s)), CORR_KEYS);
  };
  el.querySelector('.rv-q').oninput = draw;
  el.querySelector('.rv-copy').onclick = e => copyText(JSON.stringify(Object.assign({ref: rec.ref, ts_ns: rec.ts_ns}, f), null, 2), e.target);
  el.querySelector('.rv-exp').onclick = () => { const r = el.querySelector('.rv-raw'); r.hidden = !r.hidden; };
  draw();
}
async function openRaw(ref, title) {
  panel(esc(title || 'Raw FortiGate event'), '<div class="muted">loading…</div>');
  try {
    const r = await api('/api/inv/raw', {ref});
    panel(`${stH(r.verdict)} ${esc(r.label)}`, `<div class="muted">${esc(fmtNs(r.ts_ns))} · ${esc(r.cef_name || '')}</div>
      <div class="psec">Raw data</div><div id="rv"></div>`, b => rawViewer(b.querySelector('#rv'), r));
  } catch (e) { panel('Raw event', `<div class="err">${esc(e.message)}</div>`); }
}
async function openTrace(type, value) {
  panel(`Trace ${esc(type)}: <span class="mono">${esc(value)}</span>`, '<div class="muted">correlating…</div>');
  try {
    const sp = span();
    const k = `${type}|${value}|${S.range}|${S.custom && S.custom.frm}`;
    const d = INV.tcache[k] || (INV.tcache[k] = await api('/api/inv/trace', {type, value, frm: sp.frm, to: sp.to}));
    panel(`Trace ${esc(type)}: <span class="mono">${esc(value)}</span>`, tracePanelH(d), b => {
      b.querySelector('.full-trace').onclick = () => location.hash = invHash({trace: `${type}:${value}`});
      b.querySelector('.search-ent').onclick = () => {
        const key = {ip: 'ip', domain: 'domain', policy: 'policy', session: 'sess', user: 'user', device: 'device', mac: 'mac', app: 'app'}[type];
        location.hash = invHash({q: `${key}=${value}`});
      };
      bindTrace(b, d);
    });
  } catch (e) { panel('Trace', `<div class="err">${esc(e.message)}</div>`); }
}
function tracePanelH(d) {
  const e = d.entity || {};
  let h = `<div style="display:flex;gap:6px;margin:4px 0 8px"><button class="full-trace btn-primary">Open full trace</button>
    <button class="search-ent">Search events</button></div>`;
  h += `<div class="psec">Identity & activity</div>${chainH(d.chain || [])}`;
  if (d.identity) {
    const ho = d.identity.host || {}, v = d.identity.vpn || {}, se = d.identity.seen || {};
    h += `<div class="psec">Network</div>${kvTable([['IP', e.value], ['Device name', ho.name], ['MAC', ho.mac], ['OS', ho.os],
      ['Vendor', ho.vendor], ['VPN user', v.user], ['VPN tunnel', v.tunnel], ['Country (as source)', se.country],
      ['First seen', se.first_ts ? fmtT(se.first_ts) : null], ['Last seen', se.last_ts ? fmtT(se.last_ts) : null],
      ['Accepted / denied (all time)', se.n_acc != null ? `${fmtN(se.n_acc)} / ${fmtN(se.n_deny)}` : null]])}`;
  }
  const rel = [];
  (d.as_src || []).slice(0, 8).forEach(r => rel.push([`policy ${polLabel(r.policyid)} (${r.dir})`, `${fmtN(r.n)} lines, ${fmtN(r.drops)} drops`]));
  (d.deny || []).slice(0, 6).forEach(r => rel.push([`denied by ${polLabel(r.policyid)} on ${r.inif}`, `${fmtN(r.n)} · ports ${r.psample || ''}`]));
  (d.destinations || []).slice(0, 8).forEach(r => rel.push([`→ ${r.dst}:${r.dpt}`, `${fmtN(r.n)} sessions${r.blocked ? `, ${fmtN(r.blocked)} blocked` : ''}`]));
  (d.domains || []).slice(0, 8).forEach(r => rel.push([`→ ${r.root}`, `${fmtN(r.n)} requests`]));
  (d.as_dst || []).slice(0, 6).forEach(r => rel.push([`← ${r.src} :${r.dpt}`, `${fmtN(r.n)} (${r.country || ''})`]));
  (d.sources || []).slice(0, 10).forEach(r => rel.push([`← ${r.src}`, `${fmtN(r.n)}${r.drops ? `, ${fmtN(r.drops)} drops` : ''}`]));
  (d.threats || []).forEach(r => rel.push([`threat ${r.attack}`, `${fmtN(r.n)} ${r.severity} ${r.act}`]));
  if (rel.length) h += `<div class="psec">Relationships</div>${kvTable(rel)}`;
  if (d.resolved_ips) h += `<div class="psec">Resolved IPs</div><div class="note">${esc(d.how.join('; '))}</div>${kvTable(d.resolved_ips.map(i => ['IP', i]))}`;
  h += `<div class="psec">Raw data</div><button class="rv-copyall">Copy JSON</button>`;
  return h;
}
function bindTrace(b, d) {
  const c = b.querySelector('.rv-copyall');
  if (c) c.onclick = e => copyText(JSON.stringify(d || {}, null, 2), e.target);
}
function chainH(chain) {
  return `<div class="trace-chain">${chain.map((c, i) => `${i ? '<div class="darrow">↓</div>' : ''}<div class="tc ${c.status || ''}">
    <div class="k">${esc(c.label)}</div><div class="v">${esc(c.value)} ${c.trace ? trBtn(c.trace.type, c.trace.value) : ''}</div>
    ${c.sub ? `<div class="s">${esc(c.sub)}</div>` : ''}</div>`).join('')}</div>`;
}
document.addEventListener('click', e => {
  const b = e.target.closest('[data-tr]');
  if (b) { e.preventDefault(); e.stopPropagation(); openTrace(b.dataset.tr, b.dataset.tv); }
});

// ------------------------------------------------------------------ graphs
const GT = {ip: [C.s[0], 'circle'], user: [C.s[1], 'circle'], device: [C.s[2], 'roundRect'], policy: [C.s[3], 'diamond'],
  profile: [C.s[4], 'triangle'], domain: [C.s[5], 'circle'], application: [C.s[6], 'triangle'], threat: ['#9085e9', 'pin'],
  session: ['#6d6c66', 'rect'], firewall: ['#8a8983', 'rect'], interface: ['#6d6c66', 'roundRect'], mac: ['#6d6c66', 'circle'],
  verdict: ['#6d6c66', 'roundRect'], cluster: ['#4a4a46', 'circle']};
function drawGraph(id, g, onNode) {
  const cats = Object.keys(GT);
  const maxN = Math.max(1, ...g.nodes.map(n => n.n || 1));
  chart(id, {backgroundColor: 'transparent', animationDurationUpdate: 250,
    tooltip: {backgroundColor: '#262625', borderColor: C.axis, textStyle: {color: C.ink, fontSize: 12}, confine: true,
      formatter: p => p.dataType === 'edge' ? esc(p.data.lbl || '') : `<b>${esc(p.data.raw.label)}</b><br>${esc(p.data.raw.type)}${
        p.data.raw.n ? ' · ' + fmtN(p.data.raw.n) : ''}${p.data.raw.trace || p.data.raw.type === 'cluster' ? '<br><i>click to trace / expand</i>' : ''}`},
    legend: {data: cats.filter(c => g.nodes.some(n => n.type === c)), top: 0, left: 0, textStyle: {color: C.ink2}, itemWidth: 10, itemHeight: 10},
    series: [{type: 'graph', layout: 'force', roam: true, draggable: true, top: 30, bottom: 10, left: 10, right: 10,
      force: {repulsion: 320, edgeLength: [60, 150], gravity: 0.07, friction: 0.25},
      categories: cats.map(c => ({name: c, itemStyle: {color: GT[c][0]}, symbol: GT[c][1]})),
      data: g.nodes.map(n => ({name: n.id, raw: n, category: cats.indexOf(n.type in GT ? n.type : 'cluster'),
        symbolSize: n.center ? 34 : n.type === 'verdict' ? 30 : 14 + 16 * Math.sqrt((n.n || 1) / maxN),
        itemStyle: Object.assign({borderColor: C.surface, borderWidth: 2}, n.status && STC[n.status] ? {color: STC[n.status]} : {}),
        label: {show: true, position: 'right', color: C.ink2, fontSize: 11, formatter: String(n.label || '').slice(0, 30).replace(/[{}]/g, '')}})),
      links: g.edges.map(e => ({source: e.source, target: e.target, lbl: e.label,
        label: {show: !!e.label && g.edges.length < 40, formatter: String(e.label || '').replace(/[{}]/g, ''), color: C.muted, fontSize: 10},
        lineStyle: {width: e.n ? 1 + 3 * Math.sqrt(e.n / Math.max(1, ...g.edges.map(x => x.n || 1))) : 1.5}})),
      edgeSymbol: ['none', 'arrow'], edgeSymbolSize: 7,
      lineStyle: {color: 'source', opacity: 0.55, curveness: 0.12},
      emphasis: {focus: 'adjacency', lineStyle: {width: 3, opacity: 1}}}]},
    p => p.dataType === 'node' && onNode && onNode(p.data.raw));
}
function graphNodeClick(n) {
  if (n.trace) return openTrace(n.trace.type, n.trace.value);
  if (n.type === 'cluster' && n.expand) return n.expand();
  panel(esc(n.label), kvTable(Object.entries(n).filter(([k]) => !['trace', 'expand', 'center'].includes(k)).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : v])));
}

// ------------------------------------------------------------------ page
PAGES.investigate = {
  layout: () => `<div class="inv">
    <section class="inv-search">
      <form id="inv-form" autocomplete="off">
        <input class="big" id="inv-q" placeholder="Investigate: 10.0.0.25 → 8.8.8.8 · Why was 198.51.100.66 blocked? · policy 5 blocked · example.com · session 700012345 · port 3389 denied from China">
        <button class="btn-primary" type="submit">Investigate</button>
        <button class="btn-why" type="button" id="inv-why" title="Find the most recent blocked event for this query and explain it">WHY WAS THIS BLOCKED?</button>
        <button type="button" id="inv-adv-t">Filters ▾</button>
      </form>
      <div class="inv-adv" id="inv-adv" hidden>${ADV.map(([k, l]) => k === 'action'
        ? `<label>${l}<select name="${k}"><option value="">any</option><option value="allowed">Allowed</option><option value="blocked">Blocked / Denied</option></select></label>`
        : `<label>${l}<input name="${k}"></label>`).join('')}
        <label>&nbsp;<button type="button" id="inv-adv-go" class="btn-primary">Apply filters</button></label></div>
      <div class="inv-interp" id="inv-interp"></div>
    </section>
    <div id="inv-body" class="inv"></div></div>`,
  async load(sp) {
    const P = S.params;
    const form = $('#inv-form');
    if (document.activeElement !== $('#inv-q')) $('#inv-q').value = P.q || '';
    ADV.forEach(([k]) => { const el = $(`#inv-adv [name="${k}"]`); if (el) el.value = P[k] || ''; });
    form.onsubmit = e => { e.preventDefault(); submit(); };
    $('#inv-adv-go').onclick = () => submit();
    $('#inv-adv-t').onclick = () => { $('#inv-adv').hidden = !$('#inv-adv').hidden; };
    $('#inv-why').onclick = () => {
      if (P.ref && !P.cmp) { const w = $('#inv-whyc'); if (w) { w.scrollIntoView({behavior: 'smooth', block: 'center'}); w.animate([{boxShadow: '0 0 0 3px #d03b3b'}, {boxShadow: '0 0 0 0 #d03b3b'}], 900); } return; }
      submit({why: 1});
    };
    const body = $('#inv-body');
    Object.keys(S.charts).forEach(k => { if (!document.body.contains(S.charts[k].getDom())) { S.charts[k].dispose(); delete S.charts[k]; } });
    if (P.trace) return renderTrace(body, P.trace, sp);
    if (P.ref) return renderInvestigation(body, P, sp);
    if (P.q || ADV.some(([k]) => P[k])) return renderResults(body, P, sp);
    return renderLanding(body, sp);
  },
};

function submit(extra = {}) {
  const p = {q: $('#inv-q').value.trim()};
  $('#inv-adv').querySelectorAll('[name]').forEach(el => { if (el.value.trim()) p[el.name] = el.value.trim(); });
  if (extra.why) { p.action = 'blocked'; p.why = 1; }
  if (!p.q && Object.keys(p).length === 1) { $('#inv-q').focus(); return; }
  INV.facet = {};
  location.hash = invHash(p);
}

async function renderLanding(body, sp) {
  $('#inv-interp').innerHTML = '';
  body.innerHTML = `<div class="landing">${card('inv-start', 'Start an investigation', {})}${card('inv-recent', 'Latest blocked events (most recent hour)', {sub: 'click → full investigation'})}</div>`;
  $('#inv-start').innerHTML = `<p class="muted" style="margin-top:0">Type an IP, a pair of IPs, a domain, a policy, a session ID or a question.
    The tracker searches traffic, local-in, app control, web filter, IPS, antivirus, SSL, VPN/system events and the raw syslog
    (for scanner denies that are only aggregated), correlates the records and reconstructs the path and the decision.</p>
    <ul class="hint-list" id="inv-ex"><li><code>policy 21 blocked</code> - everything policy 21 dropped</li>
    <li><code>ips</code> - IPS / threat events in range</li><li><code>port 3389 denied from Russia</code></li>
    <li><code>app=Dropbox</code> - one application</li><li><code>10.20.10.12 github.com</code> - a machine and a domain</li></ul>
    <div class="note">Not available from FortiGate telemetry and therefore never shown as fact: switch/L2 hops, DNS query names
    (no DNS-filter logging), user identity outside VPN sessions, rule order and address or service objects when no configuration backup is uploaded.</div>`;
  const ex = $('#inv-ex');
  ex.onclick = e => { const c = e.target.closest('code'); if (c) { $('#inv-q').value = c.textContent; submit(); } };
  try {
    const r = await api('/api/inv/search', {q: 'blocked', frm: sp.to - 36e5, to: sp.to});
    const items = r.items.slice(0, 400);
    const bySrc = {};
    items.forEach(i => { if (i.src) bySrc[i.src] = (bySrc[i.src] || 0) + 1; });
    Object.entries(bySrc).sort((a, b) => b[1] - a[1]).slice(0, 3).forEach(([ip]) =>
      ex.insertAdjacentHTML('afterbegin', `<li><code>Why was ${esc(ip)} blocked?</code> - a top blocked source right now</li>`));
    table('inv-recent', [
      {k: 'ts', t: 'Time', f: v => fmtT(v).slice(5)}, {k: 'verdict', t: '', f: v => stH(v)}, {k: 'kind', t: 'Log'},
      {k: 'src', t: 'Source', mono: true, f: (v, r) => `${esc(v)}${r.spt ? ':' + r.spt : ''}`},
      {k: 'dst', t: 'Destination', mono: true, f: (v, r) => `${esc(r.domain || v)}:${esc(r.dpt)}`},
      {k: 'policy', t: 'Policy'}, {k: 'app', t: 'App', f: appH}],
      items.filter(i => i.table !== 'raw-deny').slice(0, 40).concat(items.filter(i => i.table === 'raw-deny').slice(0, 10)),
      {onRow: r => location.hash = invHash({q: r.src, ref: r.ref}), limit: 50});
  } catch (e) { $('#inv-recent').innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}

// ------------------------------------------------------------------ results
async function renderResults(body, P, sp) {
  const params = Object.assign({}, P);
  ['ref', 'v', 'why', 'cmp', 'trace'].forEach(k => delete params[k]);
  const key = JSON.stringify([params, S.range, S.custom]);
  const before = Number(params.before) || 0;
  delete params.before;
  if (INV.key !== key || !INV.res) {
    body.innerHTML = `<div class="card"><div class="body" style="padding:14px"><span class="muted">Correlating traffic, UTM, event and raw
      syslog records…</span></div></div>`;
    const seq = ++INV.reqSeq;
    const res = await api('/api/inv/search', Object.assign({}, params,
      {frm: sp.frm, to: before && before > sp.frm && before < sp.to ? before : sp.to}));
    if (seq !== INV.reqSeq) return;
    INV.res = res; INV.key = key;
  }
  const res = INV.res;
  interp(res);
  if (P.why) {
    const b = res.items.find(i => i.verdict === 'blocked' || i.verdict === 'threat');
    if (b) { location.replace(invHash(Object.assign({}, params, {ref: b.ref, why: 1}))); return; }
  }
  if (P.v) INV.view = P.v;
  body.innerHTML = `<section class="card"><header><h3>${fmtN(res.total)} correlated results</h3>
      <span class="sub">${res.truncated ? 'first ' + fmtN(res.total) + ' shown - narrow the query · ' : ''}${res.took_ms} ms · one row per session (records sharing session ID + IPs are merged)</span>
      <div class="tools"><div class="seg vseg" id="inv-vseg">${['timeline', 'graph', 'table'].map(v =>
        `<button data-v="${v}" class="${INV.view === v ? 'on' : ''}">${v[0].toUpperCase() + v.slice(1)} view</button>`).join('')}</div></div></header>
    <div class="body"><div class="res-bar" id="inv-srcs"></div><div class="facets" id="inv-facets" style="margin-top:8px"></div></div></section>
    ${P.why ? `<div class="alert high">${stH('info', 'No blocked event')} <span>No blocked or denied event matched this query in the selected range - showing all results.</span></div>` : ''}
    ${res.deny_aggregates && res.deny_aggregates.length ? card('inv-agg', 'Scanner denies for this source (aggregated - raw lines only for recent hours)', {}) : ''}
    <section class="card" id="inv-view-card"><div class="body" id="inv-view" style="padding-top:10px"></div></section>`;
  $('#inv-srcs').innerHTML = `<span class="muted" style="font-size:12px">Correlated sources:</span>` +
    Object.entries(res.counts).map(([k, n]) => `<span class="chip ${n ? 'on' : ''}">${esc(k)} <b>${fmtN(n)}</b></span>`).join('') +
    `<span class="chip">Firewall <b>${esc(((S.meta || {}).firewall || {}).name || 'FortiGate')}</b></span><span class="chip">VDOM <b>root</b></span>` +
    res.notes.map(n => `<span class="chip" style="border-color:#6b5314">⚠ ${esc(n)}</span>`).join('') +
    (res.searched && !res.searched.complete ? `<span class="chip on">Searched ${esc(fmtT(res.searched.frm, 'dhm'))} → ${esc(fmtT(res.searched.to, 'dhm'))}</span>
      <button class="btn-primary" id="inv-older" style="padding:2px 10px">Search older ↓</button>` : '');
  const older = $('#inv-older');
  if (older) older.onclick = () => { location.hash = invHash(Object.assign({}, P, {before: res.searched.frm})); };
  if (res.deny_aggregates && res.deny_aggregates.length) {
    table('inv-agg', [{k: 'policy', t: 'Policy'}, {k: 'inif', t: 'In'}, {k: 'country', t: 'Country'}, {k: 'n', t: 'Denied', num: true},
      {k: 'ports', t: '≥ ports/h', num: true}, {k: 'psample', t: 'Ports (sample)', mono: true},
      {k: 'first', t: 'First', f: v => fmtT(v, 'dhm')}, {k: 'last', t: 'Last', f: v => fmtT(v, 'dhm')}], res.deny_aggregates);
  }
  $('#inv-vseg').onclick = e => {
    const b = e.target.closest('button'); if (!b) return;
    INV.view = b.dataset.v; ls('inv.view', INV.view);
    $('#inv-vseg').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
    drawView(params);
  };
  drawFacets(params);
  drawView(params);
}

function interp(res) {
  const f = res.filters || {};
  $('#inv-interp').innerHTML = Object.keys(f).length ? `<span>Interpreted as</span>` + Object.entries(f).map(([k, v]) =>
    `<span class="chip">${esc(FILTER_LABEL[k] || k)} <b>${esc(v)}</b></span>`).join('') : '';
}

const FACETS = [['verdict', 'Action', i => i.verdict], ['kind', 'Log type', i => i.kind], ['policy', 'Policy', i => i.policy],
  ['src', 'Source', i => i.src], ['dst', 'Destination', i => i.domain || i.dst], ['app', 'Application', i => i.app],
  ['country', 'Country', i => i.country], ['inif', 'Interface', i => i.inif], ['proto', 'Protocol', i => PROTO[i.proto] || i.proto],
  ['severity', 'Severity', i => i.severity]];
function filtered() {
  const f = INV.facet;
  return INV.res.items.filter(i => FACETS.every(([k, , fn]) => !f[k] || String(fn(i)) === f[k]));
}
function drawFacets(params) {
  const items = INV.res.items;
  $('#inv-facets').innerHTML = FACETS.map(([k, l, fn]) => {
    const cnt = {};
    items.forEach(i => { const v = fn(i); if (v !== null && v !== undefined && v !== '') cnt[v] = (cnt[v] || 0) + 1; });
    const opts = Object.entries(cnt).sort((a, b) => b[1] - a[1]).slice(0, 60);
    if (opts.length < 2 && !INV.facet[k]) return '';
    return `<label>${l}<select data-f="${k}"><option value="">all (${opts.length})</option>${opts.map(([v, n]) =>
      `<option value="${esc(v)}" ${INV.facet[k] === String(v) ? 'selected' : ''}>${esc(v)} (${n})</option>`).join('')}</select></label>`;
  }).join('') + (Object.keys(INV.facet).length ? '<label>&nbsp;<button id="inv-fclear">Clear filters</button></label>' : '');
  $('#inv-facets').querySelectorAll('select').forEach(s => s.onchange = () => {
    if (s.value) INV.facet[s.dataset.f] = s.value; else delete INV.facet[s.dataset.f];
    drawFacets(params); drawView(params);
  });
  const c = $('#inv-fclear'); if (c) c.onclick = () => { INV.facet = {}; drawFacets(params); drawView(params); };
}
function openItem(item, params) { location.hash = invHash(Object.assign({}, params, {ref: item.ref, v: INV.view})); }

function drawView(params) {
  Object.keys(S.charts).filter(k => k.startsWith('inv-')).forEach(k => { S.charts[k].dispose(); delete S.charts[k]; });
  const el = $('#inv-view');
  const items = filtered();
  if (!items.length) { el.innerHTML = '<div class="empty">No results for this query and filter set in the selected range.</div>'; return; }
  if (INV.view === 'table') {
    el.innerHTML = '<div id="inv-tbl"></div>';
    table('inv-tbl', [{k: 'ts', t: 'Time', f: v => fmtT(v)}, {k: 'verdict', t: 'Action', f: v => stH(v)}, {k: 'kind', t: 'Log'},
      {k: 'src', t: 'Source', mono: true}, {k: 'spt', t: 'Sport', num: true, f: v => esc(v)}, {k: 'dst', t: 'Destination', mono: true},
      {k: 'dpt', t: 'Dport', num: true, f: v => esc(v)}, {k: 'proto', t: 'Proto', f: v => esc(PROTO[v] || v)}, {k: 'app', t: 'App', f: appH},
      {k: 'domain', t: 'Domain'}, {k: 'policy', t: 'Policy'}, {k: 'act', t: 'act', f: (v, r) => actH(v, r.utmact)},
      {k: 'country', t: 'Country'}, {k: 'inif', t: 'In'}, {k: 'outif', t: 'Out'}, {k: 'sess', t: 'Session', mono: true, f: v => esc(v)},
      {k: 'records', t: 'Logs', num: true}, {k: 'sources', t: 'Sources', f: v => esc((v || []).join(', '))}],
      items, {onRow: r => openItem(r, params), limit: 2000, csv: 'investigation'});
    return;
  }
  if (INV.view === 'graph') {
    el.innerHTML = `<div class="muted" style="font-size:12px">Aggregated entity graph: top sources and destinations, other entities folded into
      cluster nodes (click to expand). Drag, scroll to zoom, click a node to trace it.</div><div class="chart" id="inv-rg" style="height:600px"></div>`;
    let top = 25;
    const draw = () => drawGraph('inv-rg', resultGraph(items, top, () => { top += 25; draw(); }), graphNodeClick);
    draw();
    return;
  }
  // timeline: histogram + virtualised list
  el.innerHTML = `<div class="chart short" id="inv-hist"></div><div class="vlist" id="inv-vl"><div id="inv-vl-in"></div></div>
    <div class="tbl-foot"><span>${fmtN(items.length)} results · newest first · click a row → investigation</span></div>`;
  const ts = items.map(i => i.ts), t0 = Math.min(...ts), t1 = Math.max(...ts) + 1;
  const step = [6e4, 3e5, 9e5, 36e5, 108e5, 216e5, 864e5].find(s => (t1 - t0) / s <= 120) || 864e5;
  const series = ['allowed', 'blocked', 'warning', 'threat', 'info'].map(v => {
    const m = {};
    items.filter(i => i.verdict === v).forEach(i => { const b = i.ts - i.ts % step; m[b] = (m[b] || 0) + 1; });
    return barSeries(VERD[v][1], Object.entries(m).map(([b, n]) => [+b, n]).sort((a, b) => a[0] - b[0]), STC[v], 'v');
  }).filter(s => s.data.length);
  chart('inv-hist', Object.assign(base({frm: t0 - step, to: t1 + step}), {series}));
  const vl = $('#inv-vl'), inner = $('#inv-vl-in'), H = 34;
  inner.style.height = items.length * H + 'px';
  const row = (i, idx) => `<div class="vrow ${i.verdict}" style="top:${idx * H}px" data-i="${idx}">
    <span class="mono">${esc(fmtT(i.ts).slice(5))}</span><span>${stH(i.verdict)}</span><span class="muted">${esc(i.kind)}</span>
    <span class="mono">${esc(i.src || '')}${i.spt ? ':' + i.spt : ''} → ${esc(i.dst || '')}${i.dpt ? ':' + i.dpt : ''}${i.tdst && i.tdst !== i.dst ? ' ⇒ ' + esc(i.tdst) : ''}</span>
    <span>${i.domain ? esc(i.domain) : appH(i.app)}</span><span class="muted">${esc(i.policy || '')}</span>
    <span class="muted" title="${esc((i.sources || []).join(', '))}">×${i.records || 1}</span></div>`;
  const paint = () => {
    const a = Math.max(0, Math.floor(vl.scrollTop / H) - 10), b = Math.min(items.length, a + Math.ceil(vl.clientHeight / H) + 20);
    inner.innerHTML = items.slice(a, b).map((i, k) => row(i, a + k)).join('');
  };
  vl.onscroll = () => requestAnimationFrame(paint);
  inner.onclick = e => { const r = e.target.closest('.vrow'); if (r) openItem(items[+r.dataset.i], params); };
  paint();
}

function resultGraph(items, top, expand) {
  const nodes = new Map(), edges = new Map();
  const cnt = (fn) => { const m = {}; items.forEach(i => { const k = fn(i); if (k) m[k] = (m[k] || 0) + 1; }); return m; };
  const srcC = cnt(i => i.src), dstC = cnt(i => i.domain || i.dst || i.tdst);
  const topSrc = new Set(Object.entries(srcC).sort((a, b) => b[1] - a[1]).slice(0, top).map(x => x[0]));
  const topDst = new Set(Object.entries(dstC).sort((a, b) => b[1] - a[1]).slice(0, top).map(x => x[0]));
  const node = (id, type, label, extra = {}) => { const n = nodes.get(id) || Object.assign({id, type, label, n: 0}, extra); n.n++; nodes.set(id, n); return id; };
  const edge = (a, b, lbl, verdict) => { const k = a + '→' + b; const e = edges.get(k) || {source: a, target: b, label: lbl, n: 0, v: {}}; e.n++; e.v[verdict] = (e.v[verdict] || 0) + 1; edges.set(k, e); };
  items.forEach(i => {
    const d = i.domain || i.dst || i.tdst;
    const s = topSrc.has(i.src) ? node('s:' + i.src, 'ip', i.src, {trace: {type: 'ip', value: i.src}})
      : node('s:other', 'cluster', `${Object.keys(srcC).length - topSrc.size} other sources`, {expand});
    const p = node('p:' + i.policyid, 'policy', i.policy || 'no policy', i.policyid != null ? {trace: {type: 'policy', value: i.policyid}} : {});
    const v = node('v:' + i.verdict, 'verdict', VERD[i.verdict][1].toUpperCase(), {status: i.verdict});
    const t = topDst.has(d) ? node('d:' + d, i.domain ? 'domain' : 'ip', d, {trace: {type: i.domain ? 'domain' : 'ip', value: d}})
      : node('d:other', 'cluster', `${Object.keys(dstC).length - topDst.size} other destinations`, {expand});
    edge(s, p, '', i.verdict); edge(p, v, '', i.verdict); edge(v, t, '', i.verdict);
  });
  nodes.forEach(n => { if (n.type === 'cluster') n.label = n.label.replace(/^\d+/, m => m) + ` (${fmtN(n.n)} sessions)`; });
  return {nodes: [...nodes.values()], edges: [...edges.values()].map(e => Object.assign(e, {label: fmtN(e.n)}))};
}

// ------------------------------------------------------------------ investigation
async function getInv(ref) {
  return INV.cache[ref] || (INV.cache[ref] = await api('/api/inv/event', {ref}));
}
async function renderInvestigation(body, P, sp) {
  body.innerHTML = `<div class="card"><div class="body" style="padding:14px"><span class="muted">Building investigation: reading the event,
    correlating by session ID, 5-tuple and time window, scanning the raw syslog ±2 min…</span></div></div>`;
  let d, d2;
  try {
    d = await getInv(P.ref);
    if (P.cmp) d2 = await getInv(P.cmp);
  } catch (e) { body.innerHTML = `<div class="card"><div class="body err">⚠ ${esc(e.message)}</div></div>`; return; }
  const h = d.header, s = d.summary, st = h.status.toLowerCase();
  const back = Object.assign({}, P); delete back.ref; delete back.why; delete back.cmp;
  if (!P.q && s.source) $('#inv-q').value = s.source;
  body.innerHTML = `
  <div class="inv-head ${st}">
    <span class="id">Investigation #${esc(h.id)}</span>${stH(st, h.status)}
    <span class="kv">Severity<b>${sevH(h.severity)}</b></span>
    <span class="kv">Start time<b>${esc(fmtNs(h.start_ns, true))}</b></span>
    <span class="kv">Duration<b>${h.duration_ms < 1000 ? h.duration_ms.toFixed(0) + ' ms' : (h.duration_ms / 1000).toFixed(1) + ' s'}${h.session_duration_s ? ' · session ' + h.session_duration_s + ' s' : ''}</b></span>
    <span class="kv">Events<b>${fmtN(h.events)}</b></span><span class="kv">Related entities<b>${fmtN(h.entities)}</b></span>
    <span class="kv">Correlated logs<b>${fmtN(h.correlated)}</b></span>
    <span class="kv">Confidence<b>${h.confidence}%</b></span>
    <span class="tools">${P.q || P.src || P.ip ? `<button id="inv-back">← Results</button>` : ''}
      <button id="inv-go-why" class="btn-why">WHY?</button><button id="inv-go-graph">Graph view</button>
      <button id="inv-go-cmp">Compare</button><button id="inv-go-raw">View raw event</button></span>
  </div>
  <div style="display:grid;grid-template-columns:minmax(0,5fr) minmax(0,7fr);gap:12px" class="inv-top">
    <section class="card"><header><h3>Investigation summary</h3></header><div class="body">
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">${stH(st, h.status, true)}
        <span class="muted">${esc(s.direction)}</span></div>
      <dl class="sum-grid">
        <dt>Source</dt><dd class="mono">${na(s.source)}${s.source_port ? ':' + s.source_port : ''} ${trBtn('ip', s.source, 'IP')}${s.src_country ? ` <span class="muted">${esc(s.src_country)}</span>` : ''}</dd>
        <dt>User</dt><dd>${na(s.user)} ${trBtn('user', s.user, 'user')}</dd>
        <dt>Device</dt><dd>${na(s.device)} ${trBtn('device', s.device, 'device')}</dd>
        <dt>Destination</dt><dd>${na(s.destination)} ${trBtn(s.destination && s.destination !== s.destination_ip ? 'domain' : 'ip', s.destination, 'destination')}</dd>
        <dt>Resolved IP</dt><dd class="mono">${na(s.destination_ip)}${s.dst_country ? ` <span class="muted">${esc(s.dst_country)}</span>` : ''}</dd>
        ${s.translated_ip ? `<dt>Translated IP (NAT)</dt><dd class="mono">${esc(s.translated_ip)} ${trBtn('ip', s.translated_ip, 'server')}</dd>` : ''}
        <dt>Port</dt><dd>${na(s.port)}</dd><dt>Protocol</dt><dd>${na(s.protocol)}</dd>
        <dt>Application</dt><dd>${s.application ? appH(s.application) : na(null)} ${trBtn('app', s.application, 'app')}</dd>
        <dt>Action</dt><dd>${actH((s.action || '').toLowerCase())}</dd>
        <dt>Firewall</dt><dd>${esc(s.firewall)}</dd>
        <dt>Policy</dt><dd>${na(s.policy)} ${trBtn('policy', s.policy_id, 'policy')}</dd>
        <dt>Reason</dt><dd>${s.reason ? `<b>${esc(s.reason)}</b>` : na(null)}</dd>
        <dt>Timestamp</dt><dd class="mono">${esc(fmtNs(s.ts_ns))}</dd>
      </dl></div></section>
    <section class="card"><header><h3>What happened</h3><span class="sub">generated only from the correlated FortiGate records</span></header>
      <div class="body"><div class="explain ${h.status === 'BLOCKED' ? 'blocked' : ''}">${esc(d.explanation)}</div>
      <div class="psec">Correlation engine</div><div id="inv-corr"></div></div></section>
  </div>
  ${card('inv-path', 'Network path · SOURCE → PATH → FIREWALL → RULE → DECISION → DESTINATION', {sub: 'click any hop for details'})}
  <div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px" class="inv-mid">
    <section class="card" id="inv-whyc"><header><h3>${h.status === 'BLOCKED' ? 'Why was this blocked?' : 'Rule match explanation'}</h3>
      <span class="sub">decision chain · click a step for its evidence</span></header><div class="body" id="inv-chain"></div></section>
    <section class="card"><header><h3>Event timeline</h3><span class="sub">millisecond FortiGate event times · dimmed = context (same source, other flows)</span></header>
      <div class="body" id="inv-tl" style="max-height:620px;overflow:auto"></div></section>
  </div>
  <div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px" class="inv-mid">
    <section class="card"><header><h3>Request details</h3></header><div class="body" id="inv-req"></div></section>
    <section class="card" id="inv-graph-card"><header><h3>Investigation graph</h3><span class="sub">zoom · pan · click a node</span></header>
      <div class="body"><div class="chart" id="inv-g" style="height:430px"></div></div></section>
  </div>
  <section class="card" id="inv-cmp-card"><header><h3>Compare · allowed vs blocked</h3><span class="sub" id="inv-cmp-sub"></span>
    <div class="tools"><select id="inv-cmp-sel"></select></div></header><div class="body" id="inv-cmp"></div></section>
  ${card('inv-recs', 'Correlated records & confidence', {sub: 'click a record → raw FortiGate event'})}
  <section class="card"><header><h3>Raw FortiGate data · seed event</h3><span class="sub">the visualisation above is an interpretation of these fields</span></header>
    <div class="body" id="inv-raw"></div></section>`;
  const qp = new URLSearchParams(location.hash.split('?')[1] || '');
  if ($('#inv-back')) $('#inv-back').onclick = () => location.hash = invHash(back);
  $('#inv-go-why').onclick = () => $('#inv-whyc').scrollIntoView({behavior: 'smooth', block: 'center'});
  $('#inv-go-graph').onclick = () => $('#inv-graph-card').scrollIntoView({behavior: 'smooth', block: 'center'});
  $('#inv-go-cmp').onclick = () => $('#inv-cmp-card').scrollIntoView({behavior: 'smooth', block: 'center'});
  $('#inv-go-raw').onclick = () => openRaw(d.ref);
  drawCorr(d); drawPath(d); drawChain(d); drawTimeline(d); drawRequest(d);
  drawGraph('inv-g', d.graph, graphNodeClick);
  drawCompare(d, d2, P);
  table('inv-recs', [{k: 'ts_ns', t: 'Time', f: v => esc(fmtNs(v, true)), v: r => r.ts_ns}, {k: 'verdict', t: 'Action', f: v => stH(v)},
    {k: 'kind', t: 'Log'}, {k: 'label', t: 'Event'}, {k: 'confidence', t: 'Confidence', num: true, f: v => confH(v)},
    {k: 'method', t: 'Why correlated'}], d.records, {onRow: r => openRaw(r.ref), limit: 200});
  rawViewer($('#inv-raw'), d.records.find(r => r.ref === d.ref) || d.records[0]);
  if (P.why) setTimeout(() => $('#inv-whyc').scrollIntoView({behavior: 'smooth', block: 'center'}), 150);
  void qp;
}
function confH(v) {
  if (v === null || v === undefined) return '<span class="muted">derived</span>';
  const name = v >= 100 ? 'Exact' : v >= 95 ? 'Strong' : v >= 78 ? 'Probable' : v >= 52 ? 'Weak' : 'Context';
  return `<span class="conf"><i style="--w:${v}%"></i>${name} ${v}%</span>`;
}
function drawCorr(d) {
  const c = d.correlation;
  const kinds = Object.entries(c.by_kind).map(([k, n]) => `<span class="chip on">${esc(k)} <b>${n}</b></span>`).join('');
  $('#inv-corr').innerHTML = `<div class="srcs">${kinds}${c.raw_window_scanned ? '<span class="chip on">raw syslog ±2 min <b>scanned</b></span>' : ''}</div>
    <table class="kvt" style="margin-top:6px">${c.levels.map(l => `<tr><td>${confH(l.confidence)}</td><td>${esc(l.keys)} · <b>${fmtN(c.by_confidence[String(l.confidence)] || 0)}</b> records</td></tr>`).join('')}</table>
    <div class="srcs" style="margin-top:6px">${c.sources_checked.map(x => `<span class="chip on">${esc(x)}</span>`).join('')}
    ${c.not_available.map(x => `<span class="chip off" title="not present in the available FortiGate telemetry">${esc(x)}</span>`).join('')}</div>`;
}
function drawPath(d) {
  const el = $('#inv-path');
  const hops = d.path;
  let h = '<div class="path">';
  hops.forEach((p, i) => {
    if (i) {
      const prev = hops[i - 1];
      const cls = prev.status === 'blocked' ? 'cut' : (p.status === 'notreached' || p.status === 'unknown' || prev.status === 'unknown') ? 'dead'
        : d.header.status === 'BLOCKED' ? 'info' : '';
      h += `<div class="link ${cls}">${cls === 'cut' ? '<span>✕ BLOCKED</span>' : ''}</div>`;
    }
    h += `<div class="hop ${p.status}" data-i="${i}" title="${esc(p.note || '')}"><div class="ty">${esc(p.type)}</div>
      <div class="tt">${p.status === 'unknown' ? 'Unknown hop' : esc(p.title)}</div>
      ${(p.status === 'unknown' ? [p.title] : p.lines).map(l => `<div class="ln">${esc(l)}</div>`).join('')}
      <div style="margin-top:auto">${stH(p.status)}</div></div>`;
  });
  h += `</div><div class="path-legend"><span>${stH('allowed')} traffic passed</span><span>${stH('blocked')} decision point</span>
    <span>${stH('notreached')} traffic never got here</span><span>${stH('unknown')} not visible in FortiGate telemetry</span>
    <span>${stH('unavailable')} field not logged</span></div>`;
  el.innerHTML = h;
  el.querySelectorAll('.hop').forEach(x => x.onclick = () => {
    el.querySelectorAll('.hop').forEach(y => y.classList.toggle('sel', y === x));
    const p = hops[+x.dataset.i];
    panel(`${stH(p.status)} ${esc(p.type)} · ${esc(p.status === 'unknown' ? 'Unknown hop' : p.title)}`,
      `${p.note ? `<div class="note">${esc(p.note)}</div>` : ''}${p.status === 'notreached' ? '<div class="note">The session was stopped before this hop; details describe the intended path.</div>' : ''}
      ${p.details.length ? `<div class="psec">Details</div>${kvTable(p.details.map(([k, v]) => [k, v, k === 'Timestamp' ? 'ts' : undefined]))}` : ''}
      ${p.trace ? `<div class="psec">Trace</div>${trBtn(p.trace.type, p.trace.value, p.trace.type + ' ' + p.trace.value)}` : ''}
      ${p.refs.length ? `<div class="psec">Evidence</div>${p.refs.map(r => `<button class="ev" data-ref="${esc(r)}">View raw event</button>`).join(' ')}` : ''}`,
      b => b.querySelectorAll('.ev').forEach(x2 => x2.onclick = () => openRaw(x2.dataset.ref)));
  });
}
function drawChain(d) {
  const el = $('#inv-chain');
  el.innerHTML = `<div class="chain">${d.decision.map((n, i) => {
    const prevBlocked = i && d.decision[i - 1].status === 'blocked';
    const fin = n.label === 'FINAL ACTION';
    return `${i ? `<div class="darrow ${prevBlocked ? 'cut' : ''}">${prevBlocked && fin ? '✕' : '↓'}</div>` : ''}
    <div class="dnode ${n.status} ${fin ? 'final' : ''}" data-i="${i}"><span class="ic">${(VERD[n.status] || ['•'])[0]}</span>
      <span class="lb">${esc(n.label)}</span>${fin ? stH(n.status, n.detail.replace(/^[✕✓] /, ''), false) : '<span class="muted" style="font-size:11px">evidence →</span>'}
      <span class="dt">${esc(fin ? (d.summary.reason || '') : n.detail)}</span></div>`;
  }).join('')}</div>`;
  el.querySelectorAll('.dnode').forEach(x => x.onclick = () => {
    const n = d.decision[+x.dataset.i];
    panel(`${stH(n.status)} ${esc(n.label)}`, `<div class="note">${esc(n.detail)}</div><div class="psec">Rule matching</div>
      ${kvTable(Object.entries(n.fields))}<div class="psec">Evidence</div><button class="ev">View raw event</button>`,
      b => b.querySelector('.ev').onclick = () => openRaw(n.ref));
  });
}
function drawTimeline(d) {
  const el = $('#inv-tl');
  el.innerHTML = `<div class="tl">${d.timeline.map((e, i) => `<div class="tle ${e.verdict} ${e.context ? 'context' : ''} ${e.derived ? 'derived' : ''}" data-i="${i}">
    <div class="t">${esc(fmtNs(e.ts_ns, true))}${e.context ? ' · context' : ''}</div><div class="l">${esc(e.label)}</div>
    <div class="m">${esc(e.kind)} · ${e.derived ? 'derived' : confH(e.confidence)}</div></div>`).join('')}</div>`;
  el.querySelectorAll('.tle').forEach(x => x.onclick = () => openRaw(d.timeline[+x.dataset.i].ref));
}
function drawRequest(d) {
  $('#inv-req').innerHTML = d.request.map(g => `<details class="grp" ${g.open ? 'open' : ''}><summary>${esc(g.title)}</summary>
    ${kvTable(g.rows)}</details>`).join('');
}
function miniPath(x, other) {
  const s = x.summary, dif = (a, b) => other && String(a || '') !== String(b || '') ? 'diff' : '';
  const o = other ? other.summary : {};
  const prof = x.decision.filter(n => !['Traffic received', 'FINAL ACTION', 'Session end', 'Destination NAT (VIP)'].includes(n.label));
  const st = x.header.status.toLowerCase();
  return `<div class="side ${st}"><div style="display:flex;justify-content:space-between;align-items:center">
    <b class="mono">${esc(fmtNs(s.ts_ns, true))}</b>${stH(st, x.header.status)}</div>
    <div class="chain" style="margin-top:8px">
      <div class="dnode info"><span class="ic">●</span><span class="lb">Source</span><span></span><span class="dt ${dif(s.source, o.source)}">${esc(s.source)}${s.user ? ' · ' + esc(s.user) : ''}</span></div>
      <div class="darrow">↓</div>
      <div class="dnode info"><span class="ic">●</span><span class="lb">Destination</span><span></span><span class="dt ${dif(s.destination, o.destination)}">${esc(s.destination)} :<span class="${dif(s.port, o.port)}">${esc(s.port)}</span> ${esc(s.protocol || '')} · ${esc(s.application || '')}</span></div>
      ${prof.map(n => `<div class="darrow">↓</div><div class="dnode ${n.status}"><span class="ic">${(VERD[n.status] || ['•'])[0]}</span><span class="lb">${esc(n.label)}</span><span></span><span class="dt">${esc(n.detail)}</span></div>`).join('')}
      <div class="darrow ${st === 'blocked' ? 'cut' : ''}">${st === 'blocked' ? '✕' : '↓'}</div>
      <div class="dnode ${st === 'blocked' ? 'blocked' : 'allowed'} final"><span class="ic">${st === 'blocked' ? '✕' : '✓'}</span><span class="lb">${esc(x.header.status)}</span><span></span>
        <span class="dt ${dif(s.reason, o.reason)}">${esc(s.reason || 'no blocking decision')}</span></div>
    </div><div style="margin-top:6px"><button class="cmp-open" data-ref="${esc(x.ref)}">Open this investigation</button></div></div>`;
}
async function drawCompare(d, d2, P) {
  const sel = $('#inv-cmp-sel'), el = $('#inv-cmp');
  const cands = d.compare || [];
  const want = d.header.status === 'BLOCKED' ? 'allowed' : 'blocked';
  $('#inv-cmp-sub').textContent = cands.length ? `same source ${d.summary.source} · ${want} requests within ±24 h (same port first)` :
    `no ${want} request from ${d.summary.source || 'this source'} within ±24 h to compare with`;
  sel.innerHTML = `<option value="">choose a ${want} request…</option>` + cands.map(c =>
    `<option value="${esc(c.ref)}" ${P.cmp === c.ref ? 'selected' : ''}>${esc(fmtT(c.ts).slice(5))} → ${esc(c.dst)}:${esc(c.dpt)} · ${esc(c.policy || '')} · ${esc(c.act)}</option>`).join('');
  sel.onchange = () => { if (sel.value) location.hash = invHash(Object.assign({}, P, {cmp: sel.value})); };
  if (!d2 && cands.length) {
    el.innerHTML = '<div class="muted">loading comparison…</div>';
    try { d2 = await getInv(cands[0].ref); } catch (e) { el.innerHTML = `<div class="err">${esc(e.message)}</div>`; return; }
  }
  if (!d2) { el.innerHTML = '<div class="empty">Nothing to compare in range.</div>'; return; }
  const [a, b] = d.header.status === 'BLOCKED' ? [d2, d] : [d, d2];
  el.innerHTML = `<div class="muted" style="font-size:12px;margin-bottom:6px">Highlighted values differ between the two requests.</div>
    <div class="cmp">${miniPath(a, b)}${miniPath(b, a)}</div>`;
  el.querySelectorAll('.cmp-open').forEach(x => x.onclick = () => location.hash = invHash(Object.assign({}, P, {ref: x.dataset.ref, cmp: ''})));
}

// ------------------------------------------------------------------ full trace view
async function renderTrace(body, spec, sp) {
  const i = spec.indexOf(':'), type = spec.slice(0, i), value = spec.slice(i + 1);
  $('#inv-interp').innerHTML = `<span>Tracing</span><span class="chip">${esc(type)} <b>${esc(value)}</b></span>`;
  body.innerHTML = '<div class="card"><div class="body" style="padding:14px"><span class="muted">Tracing…</span></div></div>';
  let d;
  try { d = await api('/api/inv/trace', {type, value, frm: sp.frm, to: sp.to}); }
  catch (e) { body.innerHTML = `<div class="card"><div class="body err">⚠ ${esc(e.message)}</div></div>`; return; }
  if (d.ip_traces && d.ip_traces.length === 1) d = Object.assign(d.ip_traces[0], {resolved_from: d});
  body.innerHTML = `<div class="inv-head info"><span class="id">Trace ${esc(type)} · ${esc(value)}</span>
      ${d.resolved_from ? `<span class="chip">${esc(d.resolved_from.how.join('; '))}</span>` : ''}
      <span class="tools"><button id="tr-search" class="btn-primary">Search all events</button><button id="tr-why" class="btn-why">WHY BLOCKED?</button></span></div>
    <div style="display:grid;grid-template-columns:minmax(0,4fr) minmax(0,8fr);gap:12px">
      <section class="card"><header><h3>Trace chain</h3></header><div class="body">${chainH(d.chain || [])}</div></section>
      <section class="card"><header><h3>Investigation graph</h3><span class="sub">top relationships · clusters fold the rest · click to trace</span></header>
        <div class="body"><div class="chart" id="inv-tg" style="height:520px"></div></div></section></div>
    ${d.hist ? card('tr-hist', 'Activity over time (hourly)', {chart: 'short'}) : ''}
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:12px" id="tr-tables"></div>`;
  const ekey = {ip: 'ip', domain: 'domain', policy: 'policy', session: 'sess', app: 'app', user: 'user', device: 'device', mac: 'mac'}[type];
  $('#tr-search').onclick = () => location.hash = invHash({q: `${ekey}=${value}`});
  $('#tr-why').onclick = () => location.hash = invHash({q: `${ekey}=${value}`, action: 'blocked', why: 1});
  if (d.graph && d.graph.nodes.length) drawGraph('inv-tg', d.graph, graphNodeClick);
  else $('#inv-tg').innerHTML = '<div class="empty">No relationships for this entity in range.</div>';
  if (d.hist) {
    const sp2 = {frm: sp.frm, to: sp.to};
    chart('tr-hist-c', Object.assign(base(sp2), {series: [
      barSeries('allowed / logged', d.hist.map(r => [r.b, Math.max(0, r.n - (r.drops || 0))]), STC.allowed, 'h'),
      barSeries('blocked / denied', d.hist.map(r => [r.b, r.drops || 0]).sort((a, b) => a[0] - b[0]), STC.blocked, 'h')]}));
  }
  const T = $('#tr-tables');
  const add = (id, title, cols, rows, onRow) => {
    if (!rows || !rows.length) return;
    T.insertAdjacentHTML('beforeend', card(id, title, {}));
    table(id, cols, rows, {onRow});
  };
  const pc = {k: 'policyid', t: 'Policy', f: v => pol(v)};
  add('tr-src', 'Firewall sessions by policy', [{k: 'dir', t: 'Dir'}, pc, {k: 'n', t: 'Lines', num: true},
    {k: 'drops', t: 'Drops', num: true, f: v => v ? `<span class="drop">✕ ${fmtN(v)}</span>` : '0'}, {k: 'sent', t: 'Sent', num: true, f: fmtB},
    {k: 'rcvd', t: 'Rcvd', num: true, f: fmtB}], d.as_src, r => location.hash = invHash({q: `ip=${value} policy=${r.policyid}`}));
  add('tr-deny', 'Denied (scanner / deny rules, aggregated)', [pc, {k: 'inif', t: 'In'}, {k: 'n', t: 'Denied', num: true},
    {k: 'ports', t: '≥ ports/h', num: true}, {k: 'psample', t: 'Ports', mono: true}], d.deny,
    () => location.hash = invHash({q: `src=${value}`, action: 'blocked'}));
  add('tr-dst', 'Destinations (last 24 h of range)', [{k: 'dst', t: 'Destination', mono: true}, {k: 'dpt', t: 'Port', f: (v, r) => portH(v, r.proto)},
    {k: 'country', t: 'Country'}, {k: 'n', t: 'Sessions', num: true}, {k: 'blocked', t: 'Blocked', num: true, f: v => v ? `<span class="drop">✕ ${fmtN(v)}</span>` : '0'},
    {k: 'bytes', t: 'Bytes', num: true, f: fmtB}], d.destinations, r => location.hash = invHash({q: `${value} -> ${r.dst}:${r.dpt}`}));
  add('tr-asdst', 'Inbound to this IP (last 24 h)', [{k: 'src', t: 'Source', mono: true}, {k: 'dpt', t: 'Port'}, {k: 'country', t: 'Country'},
    pc, {k: 'n', t: 'Sessions', num: true}], d.as_dst, r => location.hash = invHash({q: `${r.src} -> ${value}`}));
  add('tr-dom', 'Domains', [{k: 'root', t: 'Root domain', mono: true}, {k: 'n', t: 'Requests', num: true}, {k: 'blocked', t: 'Blocked', num: true}],
    d.domains, r => openTrace('domain', r.root));
  add('tr-dns', 'DNS sessions (query names not logged)', [{k: 'dst', t: 'Resolver', mono: true}, {k: 'n', t: 'Sessions', num: true}], d.dns);
  add('tr-apps', 'Applications (app control, last 24 h)', [{k: 'app', t: 'App', f: appH}, {k: 'act', t: 'Verdict', f: v => actH(v)},
    {k: 'n', t: 'Detections', num: true}], d.apps);
  add('tr-thr', 'Threat events', [{k: 'attack', t: 'Signature'}, {k: 'severity', t: 'Severity'}, {k: 'act', t: 'Action', f: v => actH(v)},
    {k: 'n', t: 'Events', num: true}, {k: 'last', t: 'Last', f: v => fmtT(v, 'dhm')}], d.threats);
  add('tr-sources', 'Sources', [{k: 'src', t: 'Source', mono: true}, {k: 'country', t: 'Country'}, {k: 'dhost', t: 'Host'},
    {k: 'n', t: 'Hits', num: true}, {k: 'drops', t: 'Drops', num: true}], d.sources, r => openTrace('ip', r.src));
  add('tr-dips', 'Destination IPs seen for this domain', [{k: 'dst', t: 'IP', mono: true}, {k: 'n', t: 'Requests', num: true}], d.dst_ips,
    r => openTrace('ip', r.dst));
  add('tr-ports', 'Ports on this policy', [{k: 'dpt', t: 'Port', f: (v, r) => portH(v, r.proto)}, {k: 'act', t: 'act', f: v => actH(v)}, {k: 'n', t: 'Hits', num: true}], d.ports);
  add('tr-items', 'Session records', [{k: 'ts', t: 'Time', f: v => fmtT(v)}, {k: 'verdict', t: 'Action', f: v => stH(v)}, {k: 'kind', t: 'Log'},
    {k: 'src', t: 'Source', mono: true}, {k: 'dst', t: 'Destination', mono: true}, {k: 'app', t: 'App', f: appH}], d.items,
    r => location.hash = invHash({q: `session ${value}`, ref: r.ref}));
  add('tr-rows', 'Detections', [pc, {k: 'act', t: 'Verdict', f: v => actH(v)}, {k: 'src', t: 'Source', mono: true},
    {k: 'dst', t: 'Destination', mono: true}, {k: 'dpt', t: 'Port'}, {k: 'n', t: 'Hits', num: true}], d.rows);
}
