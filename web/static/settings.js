'use strict';
/* Settings (#settings): connection, configuration backup, preferences, network context, tuning, account. */

const SET_SECTIONS = [['connection', 'Connection'], ['config', 'Configuration backup'], ['general', 'General'], ['network', 'Network context'],
  ['detection', 'Detection tuning'], ['allowlist', 'Outbound allow-list'], ['account', 'Account'], ['about', 'About']];

async function sendJSON(method, url, body) {
  const r = await fetch(url, {method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || j.error || r.statusText);
  return j;
}

function field(label, help, control) {
  return `<div class="field"><div><div class="fl">${label}</div>${help ? `<div class="fh">${help}</div>` : ''}</div><div>${control}</div></div>`;
}

// "port1 wan 203.0.113.2/24 internet" per line  <->  {"port1": {"role": "wan", "ip": "203.0.113.2/24", "alias": "internet"}}
const ifToText = o => Object.entries(o || {}).map(([n, v]) => [n, v.role || '-', v.ip || '-', v.alias || ''].join(' ').trim()).join('\n');
function ifFromText(t) {
  const out = {};
  t.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')).forEach(l => {
    const [name, role, ip, ...alias] = l.split(/\s+/);
    out[name] = Object.fromEntries(Object.entries({role: role !== '-' ? role : '', ip: ip && ip !== '-' ? ip : '', alias: alias.join(' ')}).filter(([, v]) => v));
  });
  return out;
}
// "21: HTTPS, SSL" per line  <->  {"21": ["HTTPS", "SSL"]}
const expToText = o => Object.entries(o || {}).map(([p, apps]) => `${p}: ${apps.join(', ')}`).join('\n');
function expFromText(t) {
  const out = {};
  t.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')).forEach(l => {
    const [p, apps] = l.split(':');
    if (!/^\d+$/.test((p || '').trim())) throw new Error(`Expected applications: “${l}” - use “policy-id: App1, App2”`);
    out[p.trim()] = (apps || '').split(',').map(a => a.trim()).filter(Boolean);
  });
  return out;
}

PAGES.settings = {
  layout: () => `<div class="set-grid">
      <nav class="set-nav" id="set-nav">${SET_SECTIONS.map(([k, t]) => `<a href="#settings?s=${k}" data-s="${k}">${t}</a>`).join('')}</nav>
      <div class="set-body" id="set-body">${SKEL}</div></div>`,
  async load() {
    const d = await api('/api/settings');
    const s = d.settings, c = d.config, rc = d.receiver || {};
    const meta = S.meta || {};
    const fw = meta.firewall || {};
    $('#set-body').innerHTML = `
      <section class="set-sec" id="set-connection"><h3>Connection</h3><p>Where your FortiGate sends its logs, and what Vigil is receiving right now.</p>
        <dl class="kv-list">
          <dt>Syslog port</dt><dd><span class="mono">${esc(d.syslog_port)}</span> UDP and TCP on this machine</dd>
          <dt>Receiver</dt><dd>${rc.started ? `<span class="pill good">● listening</span> ${fmtN(rc.messages)} messages · ${rc.rate_per_s} msg/s` : '<span class="pill bad">not running</span>'}</dd>
          <dt>Allowed senders</dt><dd>${esc((rc.allow || ['any']).join(', '))} <span class="muted">(set VIGIL_SYSLOG_ALLOW in .env)</span></dd>
          <dt>Senders seen</dt><dd>${(rc.senders || []).map(x => `<span class="tag mono">${esc(x.ip)} · ${fmtK(x.messages)}</span>`).join('') || '<span class="muted">none yet</span>'}</dd>
          <dt>Firewall detected</dt><dd>${meta.last_event_ts ? `${esc(fw.name || '?')}${fw.version ? ' · FortiOS ' + esc(fw.version) : ''}${fw.serial ? ` · <span class="mono">${esc(fw.serial)}</span>` : ''}` : '<span class="muted">no FortiGate logs yet</span>'}</dd>
        </dl>
        <div class="save-row"><a class="btn-primary" style="padding:7px 16px;border-radius:999px" href="#welcome">Show FortiGate setup commands</a></div></section>

      <section class="set-sec" id="set-config"><h3>Configuration backup</h3>
        <p>Vigil grades every internet-facing rule from a FortiGate configuration backup, then keeps it current by replaying the configuration
          changes the firewall logs. Only policies, addresses, services, VIPs, interfaces and sensor names are kept - passwords, keys, certificates and every
          <span class="mono">ENC</span> value are removed before the file is stored.</p>
        ${c.loaded ? `<dl class="kv-list" style="margin-bottom:16px">
          <dt>Loaded</dt><dd>${esc(c.file || '')} ${c.model ? `· ${esc(c.model)}` : ''} ${c.version ? `· FortiOS ${esc(c.version)}` : ''}</dd>
          <dt>Backup taken</dt><dd>${c.backup_ms ? esc(fmtT(c.backup_ms)) : '—'}</dd>
          <dt>Contents</dt><dd>${fmtN(c.policies)} policies (${fmtN(c.inbound_rules)} from the internet) · ${fmtN(c.local_in)} local-in · ${fmtN(c.addresses)} addresses · ${fmtN(c.vips)} VIPs</dd>
          <dt>Live changes</dt><dd>${fmtN(c.changes_since_backup)} changes applied from the logs since the backup · <a href="#security?tab=changes">view</a></dd>
        </dl>` : '<div class="note" style="margin-bottom:16px">No configuration loaded - rule grading and change tracking are off.</div>'}
        <label class="drop-zone" id="cfg-drop"><input type="file" id="cfg-file" accept=".conf,.txt,.yaml,.yml" hidden>
          <b>Drop a backup file here</b> or click to choose<br><span style="font-size:12px">FortiGate GUI → admin menu → Configuration → Backup (.conf or YAML, max 50 MB)</span>
          <div id="cfg-name" class="mono" style="margin-top:8px"></div></label>
        ${field('Backup taken at', 'Changes logged after this moment are replayed on top of the backup', '<input type="datetime-local" id="cfg-time">')}
        ${field('VDOM', 'Multi-VDOM backups only', '<input type="text" id="cfg-vdom" value="root">')}
        <div class="save-row"><button class="btn-primary" id="cfg-up" disabled>Upload</button>${c.loaded ? '<button class="btn-danger" id="cfg-del">Remove configuration</button>' : ''}<span class="msg" id="cfg-msg"></span></div></section>

      <section class="set-sec" id="set-general"><h3>General</h3><p>How Vigil names and keeps things.</p>
        ${field('Firewall name', `Shown across the UI. Empty = detected automatically${fw.name ? ` (currently “${esc(fw.name)}”)` : ''}`, `<input type="text" id="g-name" value="${esc(s.firewall_name)}" maxlength="64" placeholder="${esc(fw.name || 'auto')}">`)}
        ${field('Keep detailed logs for', 'Days of individual log records. Summaries used for charts are kept longer.', `<input type="number" id="g-ret" min="1" max="365" value="${esc(s.retention_days)}" style="width:120px"> days`)}
        <div class="save-row"><button class="btn-primary" data-save="general">Save</button><span class="msg" id="msg-general"></span></div></section>

      <section class="set-sec" id="set-network"><h3>Network context</h3><p>Optional. Helps investigations explain the path a request took. Interfaces are read from the configuration backup when one is loaded; add or override them here.</p>
        ${field('Interfaces', 'One per line: <span class="mono">name role ip/prefix alias</span><br>e.g. <span class="mono">wan1 wan 203.0.113.2/24 internet</span>', `<textarea id="n-if" spellcheck="false" placeholder="wan1 wan 203.0.113.2/24 internet&#10;internal lan 10.0.0.1/24 office">${esc(ifToText(s.interfaces))}</textarea>`)}
        ${field('VPN address pools', 'One CIDR per line - addresses given to remote-access VPN users', `<textarea id="n-vpn" spellcheck="false" placeholder="10.99.0.0/24">${esc((s.vpn_pools || []).join('\n'))}</textarea>`)}
        <div class="save-row"><button class="btn-primary" data-save="network">Save</button><span class="msg" id="msg-network"></span></div></section>

      <section class="set-sec" id="set-detection"><h3>Detection tuning</h3><p>Tell Vigil which applications each policy is meant to carry. Anything else seen on that policy is flagged as unexpected on the Inbound and Rules pages.</p>
        ${field('Expected applications', 'One policy per line: <span class="mono">policy-id: App1, App2</span><br>Application names as FortiGate logs them (see the Rules page)', `<textarea id="d-exp" spellcheck="false" placeholder="1: HTTPS.BROWSER, HTTP.BROWSER&#10;3: IMAPS, SMTPS">${esc(expToText(s.expected_apps))}</textarea>`)}
        <div class="save-row"><button class="btn-primary" data-save="detection">Save</button><span class="msg" id="msg-detection"></span></div></section>

      <section class="set-sec" id="set-allowlist"><h3>Outbound allow-list</h3><p>Domains your organisation approves. On the Outbound page every other destination is highlighted, which makes new or unusual services easy to spot.</p>
        ${field('Approved domains', 'One root domain per line, e.g. <span class="mono">microsoft.com</span>', `<textarea id="a-dom" spellcheck="false" style="min-height:160px">${esc((s.domain_allowlist || []).join('\n'))}</textarea>`)}
        <div class="save-row"><button class="btn-primary" data-save="allowlist">Save</button><span class="msg" id="msg-allowlist"></span></div></section>

      <section class="set-sec" id="set-account"><h3>Account</h3><p>Signed in as <b>${esc(d.account.user || 'local')}</b>${d.account.changed ? ` · password last changed ${esc(fmtT(d.account.changed, 'dhm'))}` : ''}. Changing the password signs out every other session.</p>
        ${field('Current password', '', '<input type="password" id="p-cur" autocomplete="current-password">')}
        ${field('New password', 'At least 10 characters', '<input type="password" id="p-new" autocomplete="new-password">')}
        ${field('Repeat new password', '', '<input type="password" id="p-rep" autocomplete="new-password">')}
        <div class="save-row"><button class="btn-primary" id="p-save">Change password</button><span class="msg" id="msg-account"></span></div>
        <div class="note" style="margin-top:14px">Forgot the password? On the host run <span class="mono">docker exec -it vigil python -m vigil reset-password ${esc(d.account.user || 'admin')}</span></div></section>

      <section class="set-sec" id="set-about"><h3>About</h3>
        <dl class="kv-list"><dt>Version</dt><dd>Vigil ${esc(d.version)}</dd><dt>Mode</dt><dd>${d.demo ? '<span class="demo-badge">Demo · fictional data</span>' : 'Production'}</dd>
          <dt>License</dt><dd>Apache 2.0</dd><dt>Source &amp; docs</dt><dd><a href="https://github.com/vigiltech01/vigil" target="_blank" rel="noopener">github.com/vigiltech01/vigil</a></dd>
          <dt>Trademarks</dt><dd class="muted">FortiGate and FortiOS are trademarks of Fortinet, Inc. Vigil is an independent project, not affiliated with or endorsed by Fortinet.</dd></dl></section>`;
    // navigation + scroll-spy
    const secId = S.params.s;
    if (secId) setTimeout(() => { const el = document.getElementById('set-' + secId); if (el) el.scrollIntoView({behavior: 'smooth', block: 'start'}); }, 50);
    const navOn = k => document.querySelectorAll('#set-nav a').forEach(a => a.classList.toggle('on', a.dataset.s === k));
    navOn(secId || 'connection');
    document.querySelectorAll('#set-nav a').forEach(a => a.onclick = e => {
      e.preventDefault(); navOn(a.dataset.s);
      document.getElementById('set-' + a.dataset.s).scrollIntoView({behavior: 'smooth', block: 'start'});
    });
    // configuration upload
    const drop = $('#cfg-drop'), file = $('#cfg-file');
    const now = new Date(); now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    $('#cfg-time').value = now.toISOString().slice(0, 16);
    const pick = f => { S.cfgFile = f; $('#cfg-name').textContent = f ? `${f.name} · ${fmtB(f.size)}` : ''; $('#cfg-up').disabled = !f; };
    file.onchange = () => pick(file.files[0]);
    ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', e => pick(e.dataTransfer.files[0]));
    $('#cfg-up').onclick = async () => {
      const fd = new FormData();
      fd.append('file', S.cfgFile);
      const t = Date.parse($('#cfg-time').value);
      if (t) fd.append('backup_time', String(t));
      fd.append('vdom', $('#cfg-vdom').value || 'root');
      $('#cfg-up').disabled = true; $('#cfg-msg').textContent = 'Uploading…';
      try {
        const r = await fetch('/api/config/upload', {method: 'POST', body: fd});
        const j = await r.json();
        if (!r.ok) throw new Error(j.detail || j.error);
        notify('Configuration imported', `${j.imported.policies} policies · ${j.imported.addresses} addresses${j.imported.hostname ? ' · ' + j.imported.hostname : ''}`, 'good');
        S.cfgFile = null; PAGES.settings.load();
      } catch (e) { $('#cfg-msg').textContent = e.message; $('#cfg-up').disabled = false; }
    };
    const del = $('#cfg-del');
    if (del) del.onclick = async () => {
      if (!confirm('Remove the uploaded configuration? Rule grading and change tracking stop until a new backup is uploaded.')) return;
      await fetch('/api/config', {method: 'DELETE'});
      notify('Configuration removed', 'Upload a new backup any time', '');
      PAGES.settings.load();
    };
    // preference sections
    const saveSection = async (name, patch) => {
      const msg = $('#msg-' + name);
      msg.textContent = 'Saving…';
      try {
        await sendJSON('PUT', '/api/settings', patch());
        msg.textContent = 'Saved'; notify('Settings saved', SET_SECTIONS.find(x => x[0] === name)[1], 'good', 3000);
        await loadMeta(true);
      } catch (e) { msg.textContent = e.message; }
    };
    const patches = {
      general: () => ({firewall_name: $('#g-name').value.trim(), retention_days: parseInt($('#g-ret').value, 10)}),
      network: () => ({interfaces: ifFromText($('#n-if').value), vpn_pools: $('#n-vpn').value.split('\n').map(x => x.trim()).filter(Boolean)}),
      detection: () => ({expected_apps: expFromText($('#d-exp').value)}),
      allowlist: () => ({domain_allowlist: $('#a-dom').value.split(/[\n,\s]+/).map(x => x.trim()).filter(Boolean)}),
    };
    document.querySelectorAll('[data-save]').forEach(b => b.onclick = () => saveSection(b.dataset.save, patches[b.dataset.save]));
    $('#p-save').onclick = async () => {
      const msg = $('#msg-account');
      try {
        const r = await sendJSON('POST', '/api/account/password', {current: $('#p-cur').value, password: $('#p-new').value, confirm: $('#p-rep').value});
        msg.textContent = r.message; ['#p-cur', '#p-new', '#p-rep'].forEach(x => $(x).value = '');
        notify('Password changed', 'Other sessions were signed out', 'good');
      } catch (e) { msg.textContent = e.message; }
    };
  },
};
