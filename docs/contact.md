---
title: "Contact the Vigil team: investors, crowdfunding and partnerships"
description: "Vigil is built by a small startup building the best open-source SIEM tools. Investors, crowdfunding backers, partners and users - contact us."
---

# Contact us

**Vigil is built by a small startup.** We are building the best open-source security and SIEM tools, starting with the
live 3D FortiGate dashboard.

- **Investors:** we would love to talk.
- **Crowdfunding:** we are open to it. [Sponsor Vigil on GitHub](https://github.com/sponsors/vigiltech01) or leave your details below.
- **Organisations, MSPs and partners:** tell us what you need.

<form id="contact" data-email="mrkk62396@gmail.com" novalidate style="max-width:640px">
  <p><label>Full name *<br><input name="name" required maxlength="200" autocomplete="name" style="width:100%"></label></p>
  <p><label>Work email *<br><input name="email" type="email" required maxlength="200" autocomplete="email" style="width:100%"></label></p>
  <p><label>Company *<br><input name="company" required maxlength="200" autocomplete="organization" style="width:100%"></label></p>
  <p><label>Country *<br><input name="country" list="countries" required maxlength="80" autocomplete="country-name" style="width:100%"></label>
    <datalist id="countries"></datalist></p>
  <p><label>Phone (with country code)<br><input name="phone" type="tel" maxlength="25" autocomplete="tel" placeholder="+1 555 0100" style="width:100%"></label></p>
  <p><label>I'm interested in *<br><select name="interest" style="width:100%">
    <option>Investing in Vigil</option>
    <option>Crowdfunding / sponsorship</option>
    <option>Partnership / reseller / MSP</option>
    <option>Using Vigil in my organisation</option>
    <option>Feature request or support</option>
    <option>Something else</option>
  </select></label></p>
  <p><label>Message<br><textarea name="message" rows="4" maxlength="2000" style="width:100%"></textarea></label></p>
  <p style="position:absolute;left:-9999px" aria-hidden="true"><label>Leave empty<input name="_honey" tabindex="-1" autocomplete="off"></label></p>
  <p><label><input type="checkbox" name="consent" required> I agree that the Vigil team may store these details and contact me about my request.</label></p>
  <p><button type="submit">Send</button> <span id="contact-msg"></span></p>
</form>

<script>
(function () {
  var form = document.getElementById('contact'), msg = document.getElementById('contact-msg');
  var email = form.getAttribute('data-email'), url = 'https://formsubmit.co/ajax/' + email;
  try {
    var dn = new Intl.DisplayNames(['en'], {type: 'region'}), list = document.getElementById('countries'), names = [];
    'AF AX AL DZ AS AD AO AI AQ AG AR AM AW AU AT AZ BS BH BD BB BY BE BZ BJ BM BT BO BQ BA BW BV BR IO BN BG BF BI CV KH CM CA KY CF TD CL CN CX CC CO KM CG CD CK CR CI HR CU CW CY CZ DK DJ DM DO EC EG SV GQ ER EE SZ ET FK FO FJ FI FR GF PF TF GA GM GE DE GH GI GR GL GD GP GU GT GG GN GW GY HT HM VA HN HK HU IS IN ID IR IQ IE IM IL IT JM JP JE JO KZ KE KI KP KR KW KG LA LV LB LS LR LY LI LT LU MO MG MW MY MV ML MT MH MQ MR MU YT MX FM MD MC MN ME MS MA MZ MM NA NR NP NL NC NZ NI NE NG NU NF MK MP NO OM PK PW PS PA PG PY PE PH PN PL PT PR QA RE RO RU RW BL SH KN LC MF PM VC WS SM ST SA SN RS SC SL SG SX SK SI SB SO ZA GS SS ES LK SD SR SJ SE CH SY TW TJ TZ TH TL TG TK TO TT TN TR TM TC TV UG UA AE GB US UM UY UZ VU VE VN VG VI WF EH YE ZM ZW'.split(' ').forEach(function (c) { var n = dn.of(c); if (n) names.push(n); });
    Array.from(new Set(names)).sort().forEach(function (n) { var o = document.createElement('option'); o.value = n; list.appendChild(o); });
  } catch (e) {}
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var d = {};
    new FormData(form).forEach(function (v, k) { d[k] = String(v).trim(); });
    var bad = [];
    if (!d.name) bad.push('name');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email || '')) bad.push('a valid email');
    if (!d.company) bad.push('company');
    if (!d.country) bad.push('country');
    if (d.phone && !/^[+()\d\s.-]{6,25}$/.test(d.phone)) bad.push('a valid phone number');
    if (!d.consent) bad.push('consent');
    if (bad.length) { msg.textContent = 'Please add ' + bad.join(', '); return; }
    var body = {name: d.name, email: d.email, company: d.company, country: d.country, phone: d.phone || '-',
      interest: d.interest, message: d.message || '-', source: 'Vigil website',
      _subject: 'Vigil contact: ' + d.interest + ' - ' + d.company, _replyto: d.email, _template: 'table', _honey: d._honey || ''};
    msg.textContent = 'Sending…';
    fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json', 'Accept': 'application/json'}, body: JSON.stringify(body)})
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (String(j.success) !== 'true') throw new Error(j.message || 'not delivered');
        form.innerHTML = '<p><b>Thank you!</b> We received your message and will reply to ' + d.email.replace(/[<>&"]/g, '') + '.</p>';
      })
      .catch(function (err) {
        msg.innerHTML = 'Could not send (' + String(err.message).replace(/[<>&"]/g, '') + '). Please email <a href="mailto:' + email + '">' + email + '</a>.';
      });
  });
})();
</script>

---

Prefer email? Write to **[mrkk62396@gmail.com](mailto:mrkk62396@gmail.com)**. You can also open a GitHub
[issue](https://github.com/vigiltech01/vigil/issues) or [sponsor the project](https://github.com/sponsors/vigiltech01).
