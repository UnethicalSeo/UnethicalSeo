# gsc-spam-audit

Finds which Search Console properties lost traffic to a Google update, across
every site a single account can read.

Defaults target the **August 2026 spam update** (rollout 18–21 August 2026).
Point `--update-start` / `--update-end` at any other update to reuse it.

## What it does

- Enumerates every property via `sites.list` — no list to maintain by hand.
- Compares two equal-length windows: before the rollout started, and since it
  finished. Windows are snapped to whole weeks, because search traffic is
  weekday-shaped and a 10-day window against another 10-day window can invent
  a drop that is really just two extra Sundays.
- Skips the days Search Console has not finalized yet (`--lag-days`, default 3).
- Classifies each property:

  | Verdict | Meaning |
  |---|---|
  | `SEVERE HIT` | Clicks down ≥60% with impressions down ≥40% — pages are being shown far less |
  | `HIT` | Clicks down past `--hit-threshold` with impressions also falling |
  | `VISIBILITY DOWN` | Impressions collapsed and average position worsened |
  | `CLICKS DOWN / IMPRESSIONS HELD` | Still shown as often, clicked less — SERP layout, AI Overviews, seasonality. A different cause, not a demotion |
  | `STABLE` / `UP` | No loss |
  | `LOW VOLUME` | Too little pre-update traffic to read |

- Drills into the worst properties: which pages and queries bled, and which
  **dropped out of the SERP entirely**.
- Writes `gsc-audit-<date>.csv` and `.json` next to the console report.

## Setup

1. [Google Cloud Console](https://console.cloud.google.com/) → new project →
   enable the **Search Console API**.
2. Credentials → **OAuth client ID** → type **Desktop app** → download the JSON.
3. Authorize once, on a machine with a browser, as the account that owns the
   properties:

   ```bash
   pip install -r requirements.txt
   python gsc_auth.py --client-secrets client_secret.json
   ```

   This writes `token.json` and prints a refresh token.

## Run

```bash
python gsc_spam_audit.py                                    # August 2026 spam update
python gsc_spam_audit.py --update-start 2026-03-24 --update-end 2026-03-25
python gsc_spam_audit.py --site sc-domain:example.com --drilldown-all
python gsc_spam_audit.py --hit-threshold 15 --max-window 21 --top 20
```

### Headless

Set these instead of shipping `token.json` around — `gsc_auth.py` prints them:

```
GSC_CLIENT_ID, GSC_CLIENT_SECRET, GSC_REFRESH_TOKEN
```

A refresh token is a long-lived credential for every property on the account.
Put it in a secret store or environment settings; never paste it into a chat,
a commit, or a ticket.

## Known limits

- **Manual actions and security issues are exposed by no API.** The API carries
  performance data only. A property flagged `SEVERE HIT` still has to be opened
  in the UI to tell an algorithmic demotion from a manual penalty.
- Duplicate properties (http/https/www, URL-prefix alongside domain) are listed
  as separate rows — they are separate properties to the API.
- Search Console keeps 16 months of history, so updates older than that cannot
  be compared.
- The report needs at least 7 finalized days after a rollout; it refuses to run
  rather than compare noise.

## Tests

```bash
python test_gsc_spam_audit.py     # or: python -m pytest test_gsc_spam_audit.py
```

Runs against a fake Search Console service — no credentials, no network.
