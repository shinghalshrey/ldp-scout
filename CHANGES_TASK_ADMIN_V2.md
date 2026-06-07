# CHANGES — Task ADMIN-V2

**Dashboard restructure: adoption funnel, stuck students, upcoming deadlines, cohort summary, global filter**

Date: 2026-06-07
File modified: `admin.html` (single self-contained SPA — +331 / −40 lines)
New file: `CHANGES_TASK_ADMIN_V2.md` (this document)

---

## Summary

`admin.html` (the school-scoped careers dashboard) was restructured from a flat
KPI-row + 3-table layout into **four labelled sections** driven by a single
**global cohort filter**. Five new analytics surfaces were added (Active-7-day &
Offers KPIs, activation funnel, upcoming deadlines, cohort summary, needs-attention)
and every existing section was made cohort-aware.

No database, RLS, or other-file changes — all work is inside `admin.html`. The page
still reads through the anon key with the existing admin RLS policies, and still
surfaces résumé **existence** and scan **counts** only (no `raw_text`, no scan
`result`) per the GDPR constraint in `DB_SCHEMA.md`.

---

## Page section order (top → bottom)

1. Header
2. Intro note
3. **Global cohort filter bar** *(new)*
4. **Section A — Product adoption:** 7 KPI cards *(was 5)* + **Activation funnel** *(new)*
5. **Section B — Student progress:** student activity table *(year filter removed)*
6. **Section C — Program intelligence:** program targeting + **Upcoming deadlines** *(new)*
7. **Section D — Pipeline + cohort comparison:** application pipeline + **Cohort summary** *(new)* + **Needs attention / stuck students** *(new)*
8. GDPR footer

---

## Data query changes (`loadData`)

Two selects were widened to supply columns the new surfaces need:

| Table | Added columns | Used by |
|-------|---------------|---------|
| `user_profiles` | `updated_at` | "Active last 7 days" KPI |
| `user_applications` | `deadline`, `updated_at` | Upcoming deadlines, "Active last 7 days", stuck students |

`user_scan_history.created_at` and `user_resumes.uploaded_at` were already selected,
so no change was needed there. Reads remain GDPR-safe (no `raw_text` / no scan `result`).

---

## 1. Global cohort filter

- New bar directly below the intro note: **Cohort** label + a `<select>` with
  `All cohorts` plus each distinct `mba_year` (most-recent first). A live note shows
  `Showing N of M students · <year>` (or `All cohorts · M students`).
- Selection is stored in module-level **`gYear`** (`''` = all cohorts).
- `onCohort()` logs `[ADMIN-V2] cohort filter changed: <gYear>` and calls `renderAll()`,
  which re-renders **every** section (KPIs, funnel, student table, targeting, deadlines,
  pipeline, cohort summary, stuck students).
- Two shared helpers keep filtering consistent:
  - `cohortStudents()` → `STUDENTS` narrowed to `gYear`.
  - `cohortApps()` → `studentApps` narrowed to those students.
- The old per-table MBA-year dropdown (`#flt-year`) was **removed**; the global filter
  replaces it. The student table keeps its own free-text search.

## 2. Section A — Product adoption

### 2a. KPI row — 7 cards
Kept the original 5; added two `good`-accent cards:
- **Active last 7 days** — students with *any* recent signal: `user_profiles.updated_at`,
  `user_applications.created_at`/`updated_at`, latest `user_scan_history.created_at`, or
  `user_resumes.uploaded_at` within the last 7 days (`isActiveLast7()` + `withinDays()`).
  Logs `[ADMIN-V2] active last 7d: <count>`.
- **Offers received** — count of cohort `user_applications` rows with `status === 'offer'`.

Grid changed to `repeat(auto-fill, minmax(160px, 1fr))` so 7 cards wrap naturally; the
fixed `repeat(3)` / `repeat(2)` KPI overrides in the media queries were removed (auto-fill
handles all widths). All 7 KPIs respect the cohort filter.

### 2b. Activation funnel *(new)*
CSS-only horizontal bars (reuses/extends the existing `.funnel-*` classes via a `.funnel.act`
modifier — no Chart.js). Every bar is proportional to the first row (**Signed up = 100%**),
with `count · pct%` shown per row and a progressively darker green palette. Stages:

| Stage | Definition |
|-------|------------|
| Signed up | `cohortStudents().length` |
| Résumé uploaded | cohort students in `resumeSet` |
| AI scan complete | cohort students with `scansByUser[uid] > 0` |
| Tracking 1+ app | cohort students with `appsByUser[uid].length > 0` |
| Interviewing | cohort students with any app `status === 'interview'` |
| Offer received | cohort students with any app `status === 'offer'` |

## 3. Section B — Student progress

Student activity table kept as-is (sortable, expandable rows, text search). The year
dropdown was removed from its filter bar; `filteredStudents()` now uses `cohortStudents()`
as its base and the count meta is relative to the active cohort.

## 4. Section C — Program intelligence

### 4a. Program targeting
Unchanged behaviour, now sourced from `cohortApps()` so it respects the cohort filter.

### 4b. Upcoming deadlines *(new)*
Table card (`Program | Student | Deadline | Days left | Stage`):
- Source: `cohortApps()` whose `deadline` is a valid date within `today … today+30 days`,
  sorted by deadline ascending.
- **Days left** pill colour-codes by urgency: `≤7` → `pill-orange`, `8–14` → `pill-teal`,
  `15–30` → `pill-grey`.
- Empty state: *"No tracked applications have deadlines in the next 30 days."*
- Logs `[ADMIN-V2] upcoming deadlines: <count>`.

## 5. Section D — Pipeline + cohort comparison

### 5a. Application pipeline
Existing chart + breakdown table, now sourced from `cohortApps()`. **Fix:** the Chart.js
instance is now tracked in `pipelineChart` and `.destroy()`-ed before each re-render, so
re-rendering on every filter change does not throw *"Canvas is already in use"* or leak.

### 5b. Cohort summary *(new)*
Table (`MBA Year | Students | Résumé % | Scanned % | Tracking % | Avg Apps | Interviews | Offers`),
one row per distinct `mba_year`, sorted most-recent-first, with null/empty years grouped as
**"Not set"**. This view **always shows all cohorts regardless of the global filter** — it is
the comparison view. The row matching the current filter is highlighted with
`background: var(--good-bg)` + `border-left: 3px solid var(--teal)`. *Avg Apps* = total
applications ÷ students in that cohort. Logs `[ADMIN-V2] cohort summary rows: <count>`.

### 5c. Needs attention / stuck students *(new)*
Table (`Student | Email | Last Activity | Apps Tracked | Furthest Stage`):
- Source: `cohortStudents()` with **1+ application** whose most-recent activity (max
  `user_applications.updated_at` across their apps) is **older than 14 days**.
- *Furthest Stage* = the latest stage in `STAGES` order across their apps.
- Sorted by last activity ascending (most stale first), limited to 20 rows (header notes
  *"showing 20 of N flagged"* when truncated).
- Empty state: *"All active students have recent activity — nothing flagged."*
- Logs `[ADMIN-V2] stuck students: <count>`.

---

## Styling

- Matches the existing palette and card styles; new tables use the `.table-card` pattern.
- New CSS: `.funnel.act` (wider labels + `count·%` value), `.cohort-bar*` (filter bar).
- Days-left pills reuse `.pill-orange/.pill-teal/.pill-grey`; stage pills reuse `.stage-pill`.

## Console diagnostics

All five required diagnostics are emitted:

```
[ADMIN-V2] cohort filter changed: <gYear>
[ADMIN-V2] active last 7d: <count>
[ADMIN-V2] upcoming deadlines: <count>
[ADMIN-V2] stuck students: <count>
[ADMIN-V2] cohort summary rows: <count>
```

---

## Verification

The dashboard requires a Supabase admin session, which a static preview can't perform, so
verification used a **temporary `?demo=1` gate** that injected synthetic data (14 students
across `MBA 2026` / `MBA 2025` / unset, mixed apps/scans/résumés/deadlines/activity). It was
**removed before commit** — the shipped file ends with the original `boot();` entry point.

Confirmed in a Chromium preview (`npx serve`, `node --check` for JS syntax — both clean,
zero console errors):

1. ✅ Page loads; all sections render (7 KPI cards, 6 funnel rows, deadlines, pipeline canvas,
   cohort summary, stuck students) with no JS errors.
2. ✅ Changing the cohort filter re-renders all 7 KPIs, funnel, student table, targeting,
   deadlines, pipeline, **and** stuck students (e.g. MBA 2026: KPIs → 8 students, deadlines
   10 → 8, stuck 9 → 6), and updates the bar note.
3. ✅ Cohort summary stays at all 3 cohorts regardless of the filter; the matching row is
   highlighted (computed `background rgb(235,245,239)`, `border-left 3px solid rgb(74,140,127)`).
4. ✅ Activation funnel bars are proportional (Signed up = 100% width); colours darken
   progressively (`#7BB5A8` → `#24382F`).
5. ✅ Stuck students only lists users with 1+ app **and** last activity > 14 days ago.
6. ✅ Upcoming deadlines only lists apps within the next 30 days, sorted ascending, with
   correct pill colours (3/6d orange, 9/12d teal, 15–30d grey).
7. ✅ Student-table text search still works; the year dropdown is gone from the table.

---

## Not touched

`scan.js`, `app.js`, `index.html`, `styles.css`, `ldp-proxy/*`, `generate-dashboard.js`,
`dashboard.html`, and all DB tables / columns / RLS policies.
