# Task ADMIN-V3.1 — Program table cap + reorder

**File touched:** `admin.html` only. Targeted edits — no rewrite. Auth, data loading, RLS scoping, Supabase URL/key, and every other section untouched.

## Change 1: Program targeting capped at top 10

`renderTargeting()` keeps its existing grouping/sort logic, but rows beyond the first 10 now get a `.tgt-extra` class and are hidden by default. When there are more than 10 programs, a toggle row appears at the bottom of the card:

- Collapsed: **"Show all N programs ▾"** — click to reveal the hidden rows
- Expanded: **"Show top 10 only ▴"** — click to collapse back

With 10 or fewer programs the toggle stays hidden and the table behaves exactly as before. Re-renders (e.g. changing the cohort filter) always reset to the collapsed top-10 view.

**One deliberate deviation from the task spec:** the spec's toggle code showed hidden rows by setting their inline style to an empty string. Because the spec's own CSS rule (`.tgt-extra { display: none; }`) would immediately re-hide rows with no inline override, expanding would never work. The toggle therefore sets `display: 'table-row'` explicitly — same intended behavior, but functional.

## Change 2: Program targeting moved down

The section (label + card) moved from its slot after Recommended actions to just before the Student detail table. New page order:

1. Header
2. Intro note (with timestamp)
3. Cohort filter
4. KPIs
5. Activation funnel
6. Recommended actions
7. Pipeline chart + stage breakdown
8. Upcoming deadlines
9. Cohort summary
10. Needs attention (stuck students)
11. **Program targeting** (moved here)
12. Student detail table
13. GDPR footer

Only the HTML block moved — the render function targets elements by ID, so no JS changes were needed for the move itself.

## Verification performed

- Inline script syntax-checked with Node: clean
- Stubbed-DOM harness with fake data (12 programs all-cohorts, 1 program in a filtered cohort): all 30 assertions passed, including — 2 rows marked `.tgt-extra` at 12 programs, correct toggle labels both ways, expand shows rows as `table-row`, collapse re-hides, toggle hidden at ≤10 programs, expansion state resets on re-render, and all ADMIN-V3 insight/render assertions still green
- Section order in the markup confirmed against the spec
- Page served locally in a browser: parses with zero console errors; unauthenticated visit still redirects to ldpscout.com (auth gate untouched)
- Not tested: a logged-in admin session with real data — worth a quick eyeball after deploy
