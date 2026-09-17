# Vigil community collector (Google Apps Script)

This is the small backend behind Vigil's **Contact us / investors** form, the **anonymous usage ping** and the daily
**repository statistics**. It runs free in the maintainers' Google account: every submission becomes a row in a
Google Sheet and contact requests are emailed to Gmail. There is no server to run.

| Tab | Filled by | One row per |
|---|---|---|
| `contact` | Contact form in the app (Settings → Community, Welcome page) and on the website | message (also emailed) |
| `ping` | Vigil installs, once a day, unless turned off | install (first seen, last seen, ping count, version, …) |
| `stats` | GitHub workflow `.github/workflows/stats.yml`, daily | day (stars, image downloads, views, clones, referrers) |

## Deploy (about 5 minutes)

1. Open [sheets.new](https://sheets.new) with the Google account that should receive the data. Name it *Vigil community*.
2. **Extensions → Apps Script.** Delete the sample code, paste [`Code.gs`](Code.gs), save.
3. **Project Settings (gear) → Script properties → Add:**
   - `NOTIFY_EMAIL` = the Gmail address that should receive contact requests
   - `STATS_SECRET` = a long random string (used by the GitHub workflow)
4. In the editor choose the function **`setup`** → **Run** → allow the permissions. You get a "collector is ready" email.
5. **Deploy → New deployment → type: Web app**
   - *Execute as:* **Me**
   - *Who has access:* **Anyone**
   - **Deploy**, then copy the **Web app URL** (`https://script.google.com/macros/s/…/exec`).
6. Put the URL into Vigil:
   - app default: `DEFAULT_URL` in [`vigil/community.py`](../../vigil/community.py)
   - website form: `data-endpoint=""` in [`docs/contact.md`](../../docs/contact.md)
   - GitHub: repository **variable** `COMMUNITY_URL` and **secret** `STATS_SECRET` (same value as step 3)

After editing `Code.gs` later, use **Deploy → Manage deployments → Edit → Version: New version** so the URL stays the same.

## Privacy

- The contact form stores only what people type in, after they tick the consent box.
- The usage ping contains a random install ID, version, CPU architecture, demo / configuration / login flags, days
  since install, number of sending firewalls and a coarse log-rate bucket. Apps Script never sees the sender's IP address.
- Installs can turn the ping off in Settings or with `VIGIL_TELEMETRY=off`.
