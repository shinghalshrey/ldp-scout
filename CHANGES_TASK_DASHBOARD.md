# CHANGES — Task Dashboard (Supabase → dashboard.html generator)

**Date:** 7 June 2026
**Deliverable:** `generate-dashboard.js` — a Node script that queries Supabase and
regenerates `dashboard.html` (the LDP Scout pilot-analytics page) with fresh data.

---

## What it does

`generate-dashboard.js` connects to Supabase with the **service-role key**, pulls
every relevant row, computes the analytics, and writes a fully self-contained
`dashboard.html` using the existing pilot-analytics design (the
`dashboard (1).html` template). All CSS, layout, and the Chart.js config are
reproduced byte-for-byte — only the data and KPI numbers are swapped in.

### Data it queries and shows

| # | Metric | Source | Where it appears |
|---|--------|--------|------------------|
| 1 | Total users | `user_profiles` (count) | "Signups" KPI + header |
| 2 | Signups by day | `user_profiles.created_at` grouped by date | "Daily signups" bar chart |
| 3 | School breakdown | `user_profiles.school_key` grouped | "By school" table + "Signups" sub-line |
| 4 | Onboarding status | `onboarding_completed_at` / `onboarding_skipped_at` / neither | "Onboarding status" panel |
| 5 | Résumés uploaded | `user_resumes` (count) | "Résumé uploaded" KPI |
| 6 | Scans completed | `user_scan_history` (count) | "Résumé uploaded" KPI sub-line |
| 7 | Applications + status | `user_applications` (count, grouped) | "Applications logged" KPI |
| 8 | Contacts logged | `user_contacts` (count) | "Power users" blurb |
| 9 | Top tracked programs | `user_applications.program_id` → `programs` (join, distinct users) | "Most-tracked programs" table |
| 10 | Per-user detail | `user_profiles` + aggregated resume/scan/app counts + program names | "Individual user activity" table |
| 11 | Power users | top 5 `user_profiles` by application count | "Power users" grid |

It also derives a few things from the same data: the activation funnel
(signed-up-only → uploaded → scanned → fully activated), "fully activated" count
(scanned **and** logged an app), average apps per active user, and median
time-to-scan (signup → first scan).

The date header shows **today's date** at runtime.

---

## How to run

The script reads the key from the `SUPABASE_SERVICE_KEY` environment variable.

**PowerShell (Windows):**
```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
$env:SUPABASE_SERVICE_KEY = "<your service_role key>"
node generate-dashboard.js
```

**bash / macOS / Linux:**
```bash
cd ~/Desktop/LDP-Scout-Master/ldp-scout
SUPABASE_SERVICE_KEY="<your service_role key>" node generate-dashboard.js
```

On success it writes `dashboard.html` next to the script and prints:

```
Cohort filter: signups on/after 2026-05-26 — 28 of 39 total profiles.
Output: C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout\dashboard.html
Dashboard generated: 28 users, 17 resumes, 17 scans, 60 apps
  (also: 1 contacts · 10 fully activated · 19 programs ranked)
```

(Numbers above are illustrative.)

### Environment variables

| Var | Required | Default | Purpose |
|-----|----------|---------|---------|
| `SUPABASE_SERVICE_KEY` | **Yes** | — | Supabase **service_role** key. Find it in Supabase → Project Settings → API → `service_role`. The **anon** key will NOT work (see below). |
| `COHORT_START` | No | `2026-05-26` | Only count users who signed up on/after this `YYYY-MM-DD`. Set `COHORT_START=all` to include **every** user (literal `COUNT(*)`). |
| `DASHBOARD_OUT` | No | `./dashboard.html` | Override the output path. |

### Why the service-role key (not anon)

Every user table (`user_profiles`, `user_resumes`, …) has Row-Level Security that
limits reads to `auth.uid() = user_id`. With the anon key the script would see
**zero** user rows. The service-role key bypasses RLS so the dashboard can
aggregate across all users. Keep this key secret — never commit it or put it in
client code. The script only reads it from the environment.

### Dependency

Uses `@supabase/supabase-js`, which is already installed under
`C:\Users\shrey\Desktop\node_modules` and resolves automatically from this folder.
If you ever see "`@supabase/supabase-js` is not installed", run:

```powershell
npm install @supabase/supabase-js
```

---

## Decisions worth knowing

### Cohort filter (default: pilot cohort, not all-time)
The template is written as a **pilot-cohort** story — the prose explicitly says
pre-launch testers/friends are excluded. To keep that narrative truthful, the
script defaults to counting only signups **on/after 2026-05-26** (the WhatsApp
launch invite). The console line states exactly how many of the total profiles
were included. To get a literal all-users `COUNT(*)`, run with `COHORT_START=all`
— the subtitle and prose adapt automatically ("All registered users").

### GA4 placeholders (left as static numbers)
Some cells on the template come from **Google Analytics 4, not Supabase**, so they
are intentionally left as static placeholder values and labelled as such:

- "Site visitors" KPI and the "50% conversion" badge
- "Traffic & reach" section — *Where users came from* and *Where users are located*
  (the geo table) — now tagged "· GA4 placeholder data"
- The events strip (Total events tracked / Tab views / Avg engagement / First visits)

Update these by hand from GA4, or wire them up later. Everything else on the page
is live from Supabase.

### PII / deployment caution
`dashboard.html` lists **individual user names, schools, and activity**. Do not
commit it to the public repo or deploy it to `ldpscout.com` without access
control — it would be reachable at a guessable URL. Options: keep it local, host
it behind auth, or add `dashboard.html` to `.gitignore`. It was **not** committed
as part of this task.

### Error handling
Each table is fetched independently inside a `try/catch`. If one query fails, the
error is logged (e.g. `! query failed for "user_contacts": …`) and that section
renders empty/zero instead of crashing the whole run.

---

## Daily automation (9am)

A Windows Scheduled Task regenerates the dashboard every morning at 9:00 AM.

- **Task name:** `LDP Scout Dashboard Daily` (runs only when logged on; catches up via *Start when available* if the PC missed 9am while off/asleep).
- **Wake from sleep:** task has *WakeToRun* enabled, and wake timers were turned on in the active power plan for AC **and** battery (they were off by default — AC was "important only", battery disabled): `powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1` (and `/SETDCVALUEINDEX ... 1`). It wakes from **sleep/hibernate** (not a full shutdown), runs, then returns to sleep on the normal idle timer (sleep is **not** force-triggered). To stop waking on battery, set the DC value back to `0`.
- **Wrapper:** `run-dashboard.cmd` — cd's here, runs the generator, appends output to `dashboard-gen.log` (gitignored). Reads `SUPABASE_SERVICE_KEY` from the process env, falling back to the persisted User-scope value.
- **Key:** stored once in the user environment via `setx SUPABASE_SERVICE_KEY "<service_role key>"`. To change it later, re-run `setx` — the task picks it up on its next run.
- **Verified:** triggered manually, `LastTaskResult = 0`, produced `Dashboard generated: 43 users, ...`.

Manage it (PowerShell):
```powershell
Get-ScheduledTaskInfo    -TaskName "LDP Scout Dashboard Daily"   # next/last run + result
Start-ScheduledTask      -TaskName "LDP Scout Dashboard Daily"   # run now
Disable-ScheduledTask    -TaskName "LDP Scout Dashboard Daily"   # pause
Unregister-ScheduledTask -TaskName "LDP Scout Dashboard Daily"   # remove
```

> Note: `dashboard-gen.log` may render `—`/`·` as garbled characters (console code-page quirk, log file only). The dashboard HTML is UTF-8 and displays correctly.

## Files

- **Added:** `generate-dashboard.js`
- **Added:** `CHANGES_TASK_DASHBOARD.md` (this file)
- **Generates (when run):** `dashboard.html`
- **Untouched (as required):** `app.js`, `styles.css`, `index.html`, `scan.js`, `ldp-proxy/`

> Note: `dashboard.html` is not included in this delivery because it requires the
> live `SUPABASE_SERVICE_KEY` to produce real numbers. Run the command above to
> generate it. The full pipeline (queries, aggregation, escaping, Chart.js render,
> CSS) was verified end-to-end with mock data and in the browser preview.
