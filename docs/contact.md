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

<form id="contact" data-endpoint="" novalidate style="max-width:640px">
  <p><label>Full name *<br><input name="name" required maxlength="200" autocomplete="name" style="width:100%"></label></p>
  <p><label>Work email *<br><input name="email" type="email" required maxlength="200" autocomplete="email" style="width:100%"></label></p>
  <p><label>Company *<br><input name="company" required maxlength="200" autocomplete="organization" style="width:100%"></label></p>
  <p><label>Country *<br><input name="country" list="countries" required maxlength="80" autocomplete="country-name" style="width:100%"></label>
    <datalist id="countries"></datalist></p>
  <p><label>Phone (with country code)<br><input name="phone" type="tel" maxlength="25" autocomplete="tel" placeholder="+1 555 0100" style="width:100%"></label></p>
  <p><label>I'm interested in *<br><select name="interest" style="width:100%">
    <option value="investor">Investing in Vigil</option>
    <option value="crowdfunding">Crowdfunding / sponsorship</option>
    <option value="partner">Partnership / reseller / MSP</option>
    <option value="user">Using Vigil in my organisation</option>
    <option value="feature">Feature request or support</option>
    <option value="other">Something else</option>
  </select></label></p>
  <p><label>Message<br><textarea name="message" rows="4" maxlength="2000" style="width:100%"></textarea></label></p>
  <p style="position:absolute;left:-9999px" aria-hidden="true"><label>Website<input name="website" tabindex="-1" autocomplete="off"></label></p>
  <p><label><input type="checkbox" name="consent" required> I agree that the Vigil team may store these details and contact me about my request.</label></p>
  <p><button type="submit">Send</button> <span id="contact-msg"></span></p>
</form>

<script>
(function () {
  var form = document.getElementById('contact'), msg = document.getElementById('contact-msg');
  var url = form.getAttribute('data-endpoint');
  try {
    var dn = new Intl.DisplayNames(['en'], {type: 'region'}), list = document.getElementById('countries'), names = [];
    for (var a = 65; a <= 90; a++) for (var b = 65; b <= 90; b++) {
      var code = String.fromCharCode(a, b), n = dn.of(code);
      if (n && n !== code && !/Unknown/.test(n)) names.push(n);
    }
    Array.from(new Set(names)).sort().forEach(function (n) { var o = document.createElement('option'); o.value = n; list.appendChild(o); });
  } catch (e) {}
  if (!url) { msg.textContent = 'The form is being connected - please use GitHub Issues for now.'; }
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
    if (!url) return;
    d.type = 'contact'; d.source = 'website'; d.consent = true;
    msg.textContent = 'Sending…';
    fetch(url, {method: 'POST', mode: 'no-cors', headers: {'Content-Type': 'text/plain;charset=utf-8'}, body: JSON.stringify(d)})
      .then(function () { form.innerHTML = '<p><b>Thank you!</b> We received your message and will reply to ' + d.email.replace(/[<>&"]/g, '') + '.</p>'; })
      .catch(function () { msg.textContent = 'Could not send - please check your connection and try again.'; });
  });
})();
</script>

---

Prefer GitHub? Open an [issue](https://github.com/vigiltech01/vigil/issues) or [sponsor the project](https://github.com/sponsors/vigiltech01).
