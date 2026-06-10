# Task ADMIN-V3 — Careers Dashboard redesign: layout + actionable insights

**File touched:** `admin.html` only (single self-contained file, as before). No changes to `app.js`, `index.html`, `styles.css`, `scan.js`, `data.js`, Supabase tables, or RLS policies. The Supabase URL, anon key, auth flow, and school-scoped data loading are untouched.

## What changed

### 1. Page sections reordered
The dashboard now reads top-down as "headline → insight → detail":

1. Header
2. Intro note (now with a "Data refreshed" timestamp)
3. Cohort filter bar
4. KPI row (all 7 cards unchanged)
5. Activation funnel (the hero visual)
6. **Recommended actions** ← new section
7. Program targeting (moved up)
8. Application pipeline chart + stage breakdown
9. Upcoming deadlines
10. Cohort summary
11. Needs attention (stuck students)
12. Student detail table (moved to the bottom — it's reference detail, not a headline)
13. GDPR footer

Previously the full student table sat second on the page and deadlines sat before the pipeline; everything else keeps its original markup.

### 2. New "Recommended actions" section
A card between the activation funnel and program targeting that turns the cohort's data into suggested next steps. Each row is an emoji icon + a bold one-line insight + a muted action suggestion. Insights are computed client-side from data already loaded (no new queries) and respect the global cohort filter:

- **📄 Résumé uploaded but no AI scan run** → reminder about the AI Fit Scan feature
- **👤 Signed up but no résumé uploaded** → may need onboarding help
- **🎯 Programs with 3+ students tracking** → recruiter info-session / panel opportunity
- **⏸️ Students gone quiet** (no application updates in 14+ days — same rule as the "Needs attention" table) → pointer to that section
- **🚪 Onboarding never completed** → signed up but never explored the tool
- **✅ Fallback "all engaged" row** when none of the above apply

Implemented as `computeInsights()` + `renderInsights()` in the inline script, with matching `.insight-row` styles using the existing palette variables.

### 3. Student table → "Student detail" at the bottom
The full table moved to the bottom of the page with a new section label: **Student detail · click any row to expand**. All functionality is intact — text search, column sorting, click-to-expand program lists, and the GDPR kicker note.

### 4. "Data refreshed" timestamp
The intro note now shows `Data refreshed: <date & time>` (en-GB format), set when the page loads.

### 5. Render wiring
`renderInsights()` was added to `renderAll()`, so the new section re-computes along with every other section whenever the cohort filter changes. The calls in `renderAll()` were reordered to mirror the new page order (cosmetic — each render is independent).

## What deliberately did not change

- The 7 KPI cards, activation funnel, pipeline chart, cohort summary, deadlines, and stuck-students logic
- `boot()` auth gate (no session → redirect; non-admin → restricted screen), `loadData()`, `buildIndexes()`, RLS scoping
- Color palette, typography, spacing, GDPR footer
- GDPR posture: still no résumé content or scan results anywhere on the page

## Verification performed

- Inline script extracted and syntax-checked with Node (`node --check`): clean
- Full script executed in a stubbed-DOM harness with fake cohort data: all 19 assertions passed — insight counts correct for all-cohorts / cohort-filtered / empty-cohort cases, and all render functions (including the new one) fire without errors on a `renderAll()` pass
- Section order in the markup confirmed against the spec
- Page served locally and loaded in a browser: parses with zero console errors; the unauthenticated visit correctly redirects to ldpscout.com, confirming the auth gate is untouched
- Live admin walkthrough (logged in, real data) still worth a quick eyeball after deploy — the unchanged data layer makes regressions unlikely, but it was not possible to test with an admin session here
