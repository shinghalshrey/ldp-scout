# CHANGES — Task ADMIN: Careers-team admin dashboard

**Date:** 2026-06-07
**Author:** Claude (Opus 4.8)

Build a separate, authenticated admin dashboard (`admin.html`) for the careers
team, plus a nav link in the main app. School-scoped via Supabase RLS, anon key
only, GDPR-safe (no résumé content, no scan results).

---

## ⚠️ BLOCKER — must apply `admin_rls_recursion_fix.sql` first

While verifying, I found that the admin RLS policies added earlier today
(`admin_read_profiles/apps/scans/resumes`) introduced an **infinite recursion**
on `user_profiles` (Postgres error `42P17`). A policy *on* `user_profiles` that
sub-queries `user_profiles` re-enters itself forever. Because `programs_select`
and the other admin policies also read `user_profiles`, this currently breaks
**every authenticated read in the whole app** — programs, applications, resumes,
scans, and even a user reading their own profile.

Confirmed live on 2026-06-07 via the anon REST endpoint — all five tables
returned:

```
42P17: infinite recursion detected in policy for relation "user_profiles"
```

**Consequence for this task:** until the fix is applied, a real admin will *not*
see the nav link (their profile/role can't load) and `admin.html` will show
"Access restricted" / empty data. The dashboard **code is correct** (verified
against a mocked data layer — see Verification), but it cannot read live data
through broken RLS.

**Fix delivered:** [`admin_rls_recursion_fix.sql`](admin_rls_recursion_fix.sql)
— moves the admin lookup into `SECURITY DEFINER` helper functions (the Supabase-
recommended pattern), which bypass RLS and break the recursion while preserving
read-only, same-school scoping. **Review and run it in the Supabase SQL editor.**
I did **not** apply it automatically — it changes security policies on the live
database, which needs your explicit go-ahead.

---

## Files

| File | Change |
|------|--------|
| `admin.html` | **New.** Self-contained authenticated careers dashboard. |
| `app.js` | **Modified (small).** Surface role + inject the "📊 Careers Dashboard" nav link for admins. |
| `admin_rls_recursion_fix.sql` | **New.** Fix for the RLS recursion blocker above. |
| `CHANGES_TASK_ADMIN.md` | **New.** This file. |

Untouched, as required: `scan.js`, `styles.css`, `index.html`, `ldp-proxy/*`,
`generate-dashboard.js`.

---

## `admin.html`

A single self-contained HTML file (inline CSS + JS), modelled on `dashboard.html`
— its design sibling. Uses `@supabase/supabase-js@2` + Chart.js 4.4.1 from CDN.

**Auth gate (on load):**
1. `sb.auth.getSession()`. No session → `window.location.href = 'https://ldpscout.com'`.
2. Read the viewer's own profile (`own_profile_select` RLS) for `role` + school.
   `console.log('[ADMIN] role check:', role)`.
3. `role !== 'admin'` → show **"Access restricted to careers team"** and stop.
4. Admin → `console.log('[ADMIN] school_key filter:', schoolKey)`, then load.

The session is shared with the main app automatically: same origin + same
Supabase URL/anon key ⇒ same `localStorage` auth token. Sign in once at
ldpscout.com, then `admin.html` is already authenticated.

**Sections:**
- **Header** — "LDP Scout — Careers Dashboard", school name, today's date (live `new Date()`).
- **KPI row (5)** — Total students · Résumés uploaded · AI scans completed · Applications tracked · Active trackers (1+ application). Each with a context sub-line (% of students, avg per active student).
- **Student Activity table** — Name, Email, MBA Year, Signed Up, Onboarding, Résumé (Yes/No only), Scans (count only), Apps Tracked. **Sortable** (click any header), **filterable** (text search on name/email + MBA-year dropdown). **Click a row to expand** the programs that student is tracking, each with its pipeline-stage pill.
- **Program Targeting** — Program, Company, Function, Geo, # Students Tracking; sorted most-tracked first; joins `user_applications → programs` and also rolls up off-catalog ("custom") programs by name.
- **Application Pipeline** — horizontal Chart.js bar chart of applications at each stage (`shortlisted → … → rejected`, in `app.js` `STAGES` order), with a graceful HTML-funnel fallback if the CDN is blocked, plus a breakdown table of apps/students/who is at each stage.
- **GDPR footer** — the required notice verbatim.

`console.log('[ADMIN] loaded N students, M apps, K scans')` fires after load.

**Data model:** all reads go through the anon key; RLS scopes rows to the admin's
own school. "Students" = same-school profiles with `role !== 'admin'` (so careers-
team members don't inflate the counts). The admin's own apps/scans/résumé are
excluded from KPIs. Queries fail gracefully (errors logged, empty states shown)
rather than crashing — relevant while the RLS fix is pending.

**GDPR posture (deliberate):** the résumé and scan queries select **only**
metadata columns —
`user_resumes(user_id, file_name, uploaded_at)` and
`user_scan_history(id, user_id, created_at)`. `raw_text` and the scan `result`
JSON are **never requested or rendered**. The Résumé column is Yes/No; Scans is a
count.

## `app.js` (the only feature change)

1. `loadUserProfile()` — copy `role` into the in-memory `userProfile`
   (`role: data.role || 'student'`). The query already did `select('*')`; this
   just exposes the value to the UI.
2. `updateAuthUI()` — when `userProfile.role === 'admin'`, create and inject a
   "📊 Careers Dashboard" link into `.topbar-right` (opens `admin.html` in a new
   tab). `index.html` is frozen for this task, so the element is created in JS
   on demand rather than hardcoded; it is created once and shown/hidden on each
   call. Students and signed-out visitors never see it.

No dashboard logic lives in `app.js`.

---

## Design decision — palette/fonts match `dashboard.html`, not `styles.css`

The brief asked to "use the same color palette from styles.css: --green
`#2D4A3E`, --teal `#4A8C7F`, --cream `#F4F1EB` … DM Sans … Playfair Display."
Those tokens are **not** the student app's `styles.css` (which uses `--accent
#1d6a45`, Fraunces + Source Sans 3) — they are exactly **`dashboard.html`'s**
design system. Since the brief also said "self-contained … like dashboard.html",
I matched `dashboard.html` so the two careers-facing dashboards read as a matched
set. Verified the rendered tokens: header `#2D4A3E` / teal `#4A8C7F` border, body
DM Sans on `#F4F1EB`, headings + KPI numbers in Playfair Display.

---

## Verification

The live admin path needs a real admin JWT (and the RLS fix above), which I can't
mint here. So I verified the dashboard's full rendering/logic by running
`admin.html`'s **real, unmodified inline script** against a mocked Supabase data
layer (a throwaway harness, since deleted) in the browser preview, and asserting
on the DOM:

- ✅ Auth/role: logs `[ADMIN] role check: admin`, `[ADMIN] school_key filter: esade`, `[ADMIN] loaded 5 students, 6 apps, 3 scans`.
- ✅ KPIs compute correctly: 5 students, 3 résumés (60%), 3 scans, 6 apps, 3 active trackers.
- ✅ Student table: sort-by-apps puts the 3-app student on top; MBA-2025 filter → the two 2025 students; text filter "ben" → Ben only; null `full_name` falls back to the email prefix.
- ✅ Row expand: a student's 3 apps render with correct stage pills (Shortlisted/Networking/Applied).
- ✅ Targeting: most-tracked first; off-catalog program flagged "custom".
- ✅ Pipeline: per-stage app/student counts correct; empty stages dashed; Chart.js canvas present.
- ✅ Styling (via `preview_inspect`): all design tokens applied as above.
- ✅ `app.js` parses and runs (it executed in the preview with no syntax error).

Not verified end-to-end (documented rather than asserted): the live RLS-scoped
reads (blocked by `42P17`) and the no-session redirect (a 1-line path that would
navigate the preview away). The `preview_screenshot` capture was flaky on this
page; `preview_inspect`/DOM assertions were used instead (the tooling recommends
`preview_inspect` over screenshots for verifying styles anyway).

### To test live (after applying the SQL)
1. Run `admin_rls_recursion_fix.sql` in Supabase.
2. Set a test user: `update user_profiles set role='admin' where email='…';`
3. Sign in at ldpscout.com as that user → the "📊 Careers Dashboard" link appears → opens `admin.html`, scoped to that user's `school_key`.
4. Sign in as a normal student → no link; opening `admin.html` directly → "Access restricted".
