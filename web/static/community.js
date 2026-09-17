/* Vigil - "Community & investors" contact form (Settings and Welcome page). Sent by email via FormSubmit. */
'use strict';

const CONTACT_EMAIL = 'mrkk62396@gmail.com';
const CONTACT_ENDPOINT = `https://formsubmit.co/ajax/${CONTACT_EMAIL}`;
const SPONSOR_URL = 'https://github.com/sponsors/vigiltech01';
const CC_CODES = ('AF AX AL DZ AS AD AO AI AQ AG AR AM AW AU AT AZ BS BH BD BB BY BE BZ BJ BM BT BO BQ BA BW BV BR IO BN BG BF BI CV KH CM CA KY CF TD CL CN CX CC CO KM CG CD CK CR CI HR CU CW CY CZ DK DJ DM DO EC EG SV GQ ER EE SZ ET FK FO FJ FI FR GF PF TF GA GM GE DE GH GI GR GL GD GP GU GT GG GN GW GY HT HM VA HN HK HU IS IN ID IR IQ IE IM IL IT JM JP JE JO KZ KE KI KP KR KW KG LA LV LB LS LR LY LI LT LU MO MG MW MY MV ML MT MH MQ MR MU YT MX FM MD MC MN ME MS MA MZ MM NA NR NP NL NC NZ NI NE NG NU NF MK MP NO OM PK PW PS PA PG PY PE PH PN PL PT PR QA RE RO RU RW BL SH KN LC MF PM VC WS SM ST SA SN RS SC SL SG SX SK SI SB SO ZA GS SS ES LK SD SR SJ SE CH SY TW TJ TZ TH TL TG TK TO TT TN TR TM TC TV UG UA AE GB US UM UY UZ VU VE VN VG VI WF EH YE ZM ZW').split(' ');
const COUNTRIES = (() => {
  try {
    const dn = new Intl.DisplayNames(['en'], {type: 'region'});
    return [...new Set(CC_CODES.map(c => dn.of(c)).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  } catch (e) { return []; }
})();
const INTERESTS = [['Using Vigil in my organisation'], ['Investing in Vigil'], ['Crowdfunding / sponsorship'],
  ['Partnership / reseller / MSP'], ['Feature request or support'], ['Something else']].map(x => x[0]);

function contactFormH(id) {
  const inp = (k, label, type, req, extra = '') => `<label class="cf-f${req ? ' req' : ''}"><span>${label}</span>
    <input type="${type}" name="${k}" ${req ? 'required' : ''} maxlength="200" ${extra}></label>`;
  return `<form class="cf" id="${id}" novalidate>
    <div class="cf-grid">
      ${inp('name', 'Full name', 'text', true, 'autocomplete="name"')}
      ${inp('email', 'Work email', 'email', true, 'autocomplete="email"')}
      ${inp('company', 'Company', 'text', true, 'autocomplete="organization"')}
      <label class="cf-f req"><span>Country</span><input name="country" list="${id}-countries" required maxlength="80" autocomplete="country-name">
        <datalist id="${id}-countries">${COUNTRIES.map(c => `<option value="${esc(c)}">`).join('')}</datalist></label>
      ${inp('phone', 'Phone (with country code)', 'tel', false, 'autocomplete="tel" placeholder="+1 555 0100"')}
      <label class="cf-f req"><span>I'm interested in</span><select name="interest">${INTERESTS.map(l => `<option>${l}</option>`).join('')}</select></label>
      <label class="cf-f cf-wide"><span>Message</span><textarea name="message" maxlength="2000" rows="3" placeholder="How can we help?"></textarea></label>
      <label class="cf-hp" aria-hidden="true">Leave empty<input name="_honey" tabindex="-1" autocomplete="off"></label>
    </div>
    <label class="cf-consent"><input type="checkbox" name="consent" required> I agree that the Vigil team may store these details and contact me about my request.</label>
    <div class="save-row"><button class="btn-primary" type="submit">Send</button><span class="msg"></span></div>
    <div class="muted" style="font-size:12px;margin-top:8px">Or email us directly: <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></div>
  </form>`;
}

function bindContactForm(id, source) {
  const form = document.getElementById(id);
  if (!form) return;
  form.onsubmit = async e => {
    e.preventDefault();
    const msg = form.querySelector('.msg'), btn = form.querySelector('button[type=submit]');
    const d = Object.fromEntries([...new FormData(form).entries()].map(([k, v]) => [k, String(v).trim()]));
    const bad = [];
    if (!d.name) bad.push('name');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email || '')) bad.push('a valid email');
    if (!d.company) bad.push('company');
    if (!d.country) bad.push('country');
    if (d.phone && !/^[+()\d\s.-]{6,25}$/.test(d.phone)) bad.push('a valid phone number');
    if (!d.consent) bad.push('consent');
    if (bad.length) { msg.textContent = 'Please add ' + bad.join(', '); return; }
    btn.disabled = true; msg.textContent = 'Sending…';
    const body = {name: d.name, email: d.email, company: d.company, country: d.country, phone: d.phone || '-', interest: d.interest,
      message: d.message || '-', source: `Vigil app (${source}), version ${(S.session && S.session.version) || '?'}`,
      _subject: `Vigil contact: ${d.interest} - ${d.company}`, _replyto: d.email, _template: 'table', _honey: d._honey || ''};
    try {
      const r = await fetch(CONTACT_ENDPOINT, {method: 'POST', headers: {'Content-Type': 'application/json', Accept: 'application/json'},
        body: JSON.stringify(body)});
      const j = await r.json().catch(() => ({}));
      if (!r.ok || String(j.success) !== 'true') throw new Error(j.message || `HTTP ${r.status}`);
      form.innerHTML = `<div class="cf-done"><b>Thank you, ${esc(d.name.split(' ')[0])}!</b><br>We received your message and will get back to you at ${esc(d.email)}.</div>`;
      notify('Message sent', 'The Vigil team will get back to you', 'good');
    } catch (err) {
      btn.disabled = false;
      msg.innerHTML = `Could not send (${esc(err.message)}). Please email <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>.`;
    }
  };
}

function communitySectionH() {
  return `<section class="set-sec" id="set-community"><h3>Community &amp; investors</h3>
    <p><b>Vigil is built by a small startup.</b> We are building the best open-source security and SIEM tools, starting with FortiGate.
      <b>Investors</b> - we would love to talk. We are also <b>open to crowdfunding</b>: sponsor us on GitHub, or contact us below.</p>
    <div class="save-row" style="margin:0 0 18px"><a class="btn-primary" href="${SPONSOR_URL}" target="_blank" rel="noopener" style="display:inline-block;padding:8px 18px;border-radius:999px">♥ Sponsor Vigil</a>
      <a href="https://github.com/vigiltech01/vigil" target="_blank" rel="noopener" style="margin-left:6px">⭐ Star on GitHub</a></div>
    <h4 class="cf-h">Contact us</h4>
    ${contactFormH('cf-settings')}
  </section>`;
}
