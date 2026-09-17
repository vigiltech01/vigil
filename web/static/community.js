/* Vigil - contact / investors form and usage-statistics settings (shared by Settings and Welcome) */
'use strict';

const CC_CODES = ('AF AX AL DZ AS AD AO AI AQ AG AR AM AW AU AT AZ BS BH BD BB BY BE BZ BJ BM BT BO BQ BA BW BV BR IO BN BG BF BI CV KH CM CA KY CF TD CL CN CX CC CO KM CG CD CK CR CI HR CU CW CY CZ DK DJ DM DO EC EG SV GQ ER EE SZ ET FK FO FJ FI FR GF PF TF GA GM GE DE GH GI GR GL GD GP GU GT GG GN GW GY HT HM VA HN HK HU IS IN ID IR IQ IE IM IL IT JM JP JE JO KZ KE KI KP KR KW KG LA LV LB LS LR LY LI LT LU MO MG MW MY MV ML MT MH MQ MR MU YT MX FM MD MC MN ME MS MA MZ MM NA NR NP NL NC NZ NI NE NG NU NF MK MP NO OM PK PW PS PA PG PY PE PH PN PL PT PR QA RE RO RU RW BL SH KN LC MF PM VC WS SM ST SA SN RS SC SL SG SX SK SI SB SO ZA GS SS ES LK SD SR SJ SE CH SY TW TJ TZ TH TL TG TK TO TT TN TR TM TC TV UG UA AE GB US UM UY UZ VU VE VN VG VI WF EH YE ZM ZW').split(' ');
const COUNTRIES = (() => {
  try {
    const dn = new Intl.DisplayNames(['en'], {type: 'region'});
    return CC_CODES.map(c => dn.of(c)).filter(Boolean).sort((a, b) => a.localeCompare(b));
  } catch (e) { return []; }
})();
const INTERESTS = [['user', 'Using Vigil in my organisation'], ['investor', 'Investing in Vigil'], ['crowdfunding', 'Crowdfunding / sponsorship'],
  ['partner', 'Partnership / reseller / MSP'], ['feature', 'Feature request or support'], ['other', 'Something else']];
const SPONSOR_URL = 'https://github.com/sponsors/vigiltech01';

function contactFormH(id, url) {
  const inp = (k, label, type, req, extra = '') => `<label class="cf-f${req ? ' req' : ''}"><span>${label}</span>
    <input type="${type}" name="${k}" ${req ? 'required' : ''} maxlength="200" ${extra}></label>`;
  return `<form class="cf" id="${id}" novalidate>
    ${url ? '' : '<div class="note" style="margin-bottom:12px">The contact form is not connected in this build yet - please open an issue on <a href="https://github.com/vigiltech01/vigil" target="_blank" rel="noopener">GitHub</a> instead.</div>'}
    <div class="cf-grid">
      ${inp('name', 'Full name', 'text', true, 'autocomplete="name"')}
      ${inp('email', 'Work email', 'email', true, 'autocomplete="email"')}
      ${inp('company', 'Company', 'text', true, 'autocomplete="organization"')}
      <label class="cf-f req"><span>Country</span><input name="country" list="${id}-countries" required maxlength="80" autocomplete="country-name">
        <datalist id="${id}-countries">${COUNTRIES.map(c => `<option value="${esc(c)}">`).join('')}</datalist></label>
      ${inp('phone', 'Phone (with country code)', 'tel', false, 'autocomplete="tel" placeholder="+1 555 0100"')}
      <label class="cf-f req"><span>I'm interested in</span><select name="interest">${INTERESTS.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select></label>
      <label class="cf-f cf-wide"><span>Message</span><textarea name="message" maxlength="2000" rows="3" placeholder="How can we help?"></textarea></label>
      <label class="cf-hp" aria-hidden="true">Website<input name="website" tabindex="-1" autocomplete="off"></label>
    </div>
    <label class="cf-consent"><input type="checkbox" name="consent" required> I agree that the Vigil team may store these details and contact me about my request.</label>
    <div class="save-row"><button class="btn-primary" type="submit" ${url ? '' : 'disabled'}>Send</button><span class="msg"></span></div>
  </form>`;
}

function bindContactForm(id, url, source) {
  const form = document.getElementById(id);
  if (!form || !url) return;
  form.onsubmit = async e => {
    e.preventDefault();
    const msg = form.querySelector('.msg'), btn = form.querySelector('button[type=submit]');
    const d = Object.fromEntries(new FormData(form).entries());
    const bad = [];
    if (!String(d.name || '').trim()) bad.push('name');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(d.email || '').trim())) bad.push('a valid email');
    if (!String(d.company || '').trim()) bad.push('company');
    if (!String(d.country || '').trim()) bad.push('country');
    if (d.phone && !/^[+()\d\s.-]{6,25}$/.test(d.phone)) bad.push('a valid phone number');
    if (!d.consent) bad.push('consent');
    if (bad.length) { msg.textContent = 'Please add ' + bad.join(', '); return; }
    btn.disabled = true; msg.textContent = 'Sending…';
    const body = {type: 'contact', source, version: (S.session && S.session.version) || '', consent: true,
      ...Object.fromEntries(['name', 'email', 'company', 'country', 'phone', 'interest', 'message', 'website'].map(k => [k, String(d[k] || '').trim()]))};
    try {
      // Google Apps Script does not send CORS headers: a simple text/plain POST is delivered, the reply is opaque
      await fetch(url, {method: 'POST', mode: 'no-cors', headers: {'Content-Type': 'text/plain;charset=utf-8'}, body: JSON.stringify(body)});
      form.innerHTML = `<div class="cf-done"><b>Thank you, ${esc(body.name.split(' ')[0])}!</b><br>We received your message and will get back to you at ${esc(body.email)}.</div>`;
      notify('Message sent', 'The Vigil team will get back to you', 'good');
    } catch (err) {
      btn.disabled = false;
      msg.textContent = 'Could not reach the contact service from this browser - check the internet connection and try again.';
    }
  };
}

function communitySectionH(d) {
  const c = d.community || {}, t = c.telemetry || {};
  return `<section class="set-sec" id="set-community"><h3>Community &amp; investors</h3>
    <p><b>Vigil is built by a small startup.</b> We are building the best open-source security and SIEM tools, starting with FortiGate.
      <b>Investors</b> - we would love to talk. We are also <b>open to crowdfunding</b>: sponsor us on GitHub, or contact us below.</p>
    <div class="save-row" style="margin:0 0 18px"><a class="btn-primary" href="${SPONSOR_URL}" target="_blank" rel="noopener" style="display:inline-block;padding:8px 18px;border-radius:999px">♥ Sponsor Vigil</a>
      <a href="https://github.com/vigiltech01/vigil" target="_blank" rel="noopener" style="margin-left:6px">⭐ Star on GitHub</a></div>
    <h4 class="cf-h">Contact us</h4>
    ${contactFormH('cf-settings', c.url)}
    <h4 class="cf-h" style="margin-top:26px">Anonymous usage statistics</h4>
    ${field('Share anonymous usage', t.env_off ? 'Turned off on this host with <span class="mono">VIGIL_TELEMETRY=off</span>'
      : !t.available ? 'Not available in this build' : 'Once a day, helps a small team know how many installs exist. Never logs, IP addresses, names or configuration.',
      `<label class="switch"><input type="checkbox" id="tm-on" ${t.setting ? 'checked' : ''} ${t.env_off || !t.available ? 'disabled' : ''}><span></span>${t.enabled ? 'On' : 'Off'}</label>
       ${t.last_sent ? `<div class="muted" style="font-size:12px;margin-top:6px">Last sent ${esc(fmtT(t.last_sent, 'dhm'))}${t.last_ok === false ? ' (not delivered - offline?)' : ''}</div>` : ''}`)}
    ${field('Exactly what is sent', 'Nothing else leaves this machine', `<pre class="cf-pre">${esc(JSON.stringify(t.preview || {}, null, 2))}</pre>`)}
    <span class="msg" id="msg-community"></span>
  </section>`;
}

function bindCommunitySection(d) {
  bindContactForm('cf-settings', (d.community || {}).url, 'settings');
  const tm = document.getElementById('tm-on');
  if (tm) tm.onchange = async () => {
    try {
      await sendJSON('PUT', '/api/settings', {telemetry: tm.checked});
      notify(tm.checked ? 'Usage statistics on' : 'Usage statistics off', tm.checked ? 'Thank you for helping Vigil' : 'Nothing will be sent', 'good', 3000);
      PAGES.settings.load();
    } catch (e) { $('#msg-community').textContent = e.message; }
  };
}
