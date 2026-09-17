/**
 * Vigil community collector - a Google Apps Script web app bound to a Google Sheet.
 *
 * Receives three kinds of JSON POSTs and writes them to tabs of the spreadsheet:
 *   contact  - the "Contact us / investors" form (app + website). Also emails NOTIFY_EMAIL.
 *   ping     - the anonymous daily usage ping from Vigil installs (one row per install, updated daily).
 *   stats    - daily GitHub statistics from the repository's "Repository stats" workflow (needs STATS_SECRET).
 *
 * Setup: see README.md next to this file. Script properties used:
 *   NOTIFY_EMAIL  where contact requests are emailed (default: the Google account that owns the script)
 *   STATS_SECRET  shared secret the GitHub workflow sends with "stats" posts
 *   SHEET_ID      only for a standalone script (script.google.com → New project): the id from the sheet URL
 */

const TABS = {
  contact: ['received', 'interest', 'name', 'email', 'company', 'country', 'phone', 'message', 'source', 'version'],
  ping: ['first_seen', 'last_seen', 'pings', 'instance_id', 'version', 'arch', 'demo', 'days_installed', 'firewalls',
         'eps_bucket', 'config_loaded', 'login_enabled'],
  stats: ['received', 'date', 'stars', 'forks', 'watchers', 'open_issues', 'image_downloads', 'views_14d', 'unique_views_14d',
          'clones_14d', 'unique_clones_14d', 'views_yesterday', 'clones_yesterday', 'top_referrers', 'top_paths'],
};
const INTEREST = {user: 'Using Vigil', investor: 'INVESTOR', crowdfunding: 'Crowdfunding / sponsorship',
                  partner: 'Partnership / reseller', feature: 'Feature / support', other: 'Other'};

function doPost(e) {
  let d;
  try {
    d = JSON.parse(e.postData.contents);
  } catch (err) {
    return reply({ok: false, error: 'bad json'});
  }
  const type = String(d.type || '');
  if (!TABS[type]) return reply({ok: false, error: 'unknown type'});
  const props = PropertiesService.getScriptProperties();
  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    if (type === 'contact') return contact(d, props);
    if (type === 'ping') return ping(d);
    if (d.secret !== props.getProperty('STATS_SECRET')) return reply({ok: false, error: 'forbidden'});
    append('stats', TABS.stats.map(k => k === 'received' ? new Date() : clean(d[k], 2000)));
    return reply({ok: true});
  } finally {
    lock.releaseLock();
  }
}

function doGet() {
  return reply({ok: true, service: 'vigil-community'});
}

function contact(d, props) {
  if (d.website) return reply({ok: true});                       // honeypot field filled in: a bot
  const email = clean(d.email, 200);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !clean(d.name, 200) || !clean(d.country, 80)) {
    return reply({ok: false, error: 'missing fields'});
  }
  const cache = CacheService.getScriptCache();                   // at most one message per address every 10 minutes
  if (cache.get('c:' + email.toLowerCase())) return reply({ok: true, throttled: true});
  cache.put('c:' + email.toLowerCase(), '1', 600);
  const row = TABS.contact.map(k => k === 'received' ? new Date() : clean(k === 'interest' ? (INTEREST[d.interest] || 'Other') : d[k], 2000));
  append('contact', row);
  const to = props.getProperty('NOTIFY_EMAIL') || Session.getEffectiveUser().getEmail();
  const lines = TABS.contact.slice(1).map((k, i) => `${k}: ${row[i + 1]}`);
  MailApp.sendEmail({
    to: to,
    replyTo: email,
    subject: `Vigil contact - ${INTEREST[d.interest] || 'Other'} - ${clean(d.company, 80) || email}`,
    body: `New message from the Vigil ${clean(d.source, 40) || 'website'} contact form:\n\n${lines.join('\n')}\n\n` +
          `Reply to this email to answer ${clean(d.name, 200)} directly.\n${book().getUrl()}`,
  });
  return reply({ok: true});
}

function ping(d) {
  const id = clean(d.instance_id, 64);
  if (!/^[0-9a-f-]{36}$/i.test(id)) return reply({ok: false, error: 'bad id'});
  const sheet = tab('ping');
  const found = sheet.getRange('D:D').createTextFinder(id).matchEntireCell(true).findNext();
  const now = new Date();
  const values = ['version', 'arch', 'demo', 'days_installed', 'firewalls', 'eps_bucket', 'config_loaded', 'login_enabled'].map(k => clean(d[k], 40));
  if (found) {
    const r = found.getRow();
    const pings = Number(sheet.getRange(r, 3).getValue()) || 0;
    sheet.getRange(r, 2, 1, 2).setValues([[now, pings + 1]]);
    sheet.getRange(r, 5, 1, values.length).setValues([values]);
  } else {
    sheet.appendRow([now, now, 1, id].concat(values));
  }
  return reply({ok: true});
}

// bound script: the sheet it belongs to; standalone script: script property SHEET_ID (the long id in the sheet URL)
function book() {
  const id = PropertiesService.getScriptProperties().getProperty('SHEET_ID');
  return id ? SpreadsheetApp.openById(id) : SpreadsheetApp.getActiveSpreadsheet();
}

function tab(name) {
  const ss = book();
  let sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
    sheet.appendRow(TABS[name]);
    sheet.setFrozenRows(1);
    sheet.getRange(1, 1, 1, TABS[name].length).setFontWeight('bold');
  }
  return sheet;
}

function append(name, row) {
  tab(name).appendRow(row);
}

// strings only, limited length, and never let a value start a spreadsheet formula
function clean(v, max) {
  if (v === undefined || v === null) return '';
  if (typeof v === 'boolean' || typeof v === 'number') return v;
  let s = String(v).trim().slice(0, max);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return s;
}

function reply(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}

/** Run once from the editor to create the tabs and grant permissions (sends you a test email). */
function setup() {
  Object.keys(TABS).forEach(tab);
  const to = PropertiesService.getScriptProperties().getProperty('NOTIFY_EMAIL') || Session.getEffectiveUser().getEmail();
  MailApp.sendEmail(to, 'Vigil collector is ready', 'Contact requests from the Vigil app and website will arrive at this address.\n\n' +
                    book().getUrl());
}
