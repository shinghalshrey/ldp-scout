# Task 19.1 — Sidebar reorder + table dividers + page tour fix

Small post-19 polish commit landed between Task 19 and the much larger
Task 19.2 architecture overhaul. Three changes, all driven by Pranav's
first-look feedback on the deployed Task 19 build.

> No DB changes. No new auth or quota implications. Pure frontend polish.
> Documented retroactively — was committed without a per-task explainer
> at the time, gap filled here for continuity.

---

## Files touched

| File | What changed |
|------|--------------|
| `index.html` | Sidebar section order rearranged: Search → **Quick Filters** → Geography → Function → Status → Pro Tip (was Search → Geo → Fn → St → Quick Filters → Tip). |
| `styles.css` | Sidebar got `max-height: calc(100vh - 100px); overflow-y: auto` so its content scrolls internally when it overflows the viewport. `.prog-table-wrap .prow` and `.thead` border colors bumped from `--border` (rgba 0.07) to `--border2` (rgba 0.13) for legibility — scoped so other tables aren't affected. |
| `app.js` | Programs page tour step 2 target updated from `.filter-row` (gone, was the old horizontal pill row) to `.prog-sidebar`. Body rewritten to reflect the new sidebar layout. |

---

## Why each change

### 1. Sidebar reorder + sticky scroll

On Pranav's screen the My Pipeline filter sat below the fold — the sidebar
was taller than the viewport, sticky positioning prevented him from
scrolling within it, and Pipeline is the single most important toggle for
a returning user. Two fixes applied:

- **Reorder.** Quick Filters (Visa + Pipeline pills) moved to position 2,
  immediately under Search. Pipeline is the second thing the eye lands on,
  before any of the categorical filters.
- **Internal scroll.** `.prog-sidebar { max-height: calc(100vh - 100px);
  overflow-y: auto; }` makes the sticky sidebar internally scrollable when
  its content exceeds viewport height. Belt-and-suspenders — even if
  future filter additions overflow again, every filter stays reachable.

### 2. Table row dividers

Pranav said the table felt confusing to read. The existing `.prow` row
divider was `border-bottom: 1px solid var(--border)` where `--border` =
`rgba(0,0,0,0.07)` — extremely faint. Bumped to `--border2` (rgba 0.13,
roughly 2× more visible) on Programs table only. Other tables (Deadlines,
Applications Kanban) keep their existing aesthetic.

Scoped via `.prog-table-wrap .prow` (and `.thead`) instead of editing
`.prow` directly — avoided collateral damage to the other pages.

### 3. Page tour step 2 target fix

Task 19 replaced the horizontal `.filter-row` element with a sticky
`.prog-sidebar`. The page tour was unchanged from before and still
pointed at the dead `.filter-row` selector. The coachmark engine
silently skipped (querySelector returned null) instead of crashing, so
the tour just lost step 2.

Fix: retarget to `.prog-sidebar` and rewrite the body to match the new
layout. The other three steps still point at valid elements (`#prog-stats`,
`.thead`, `.prow:first-child`).

---

## Lessons

- After any layout change that touches selectors, audit `tourSteps`. The
  coachmark engine fails silently — you only notice if you actually click
  the tour.
- Pinned files (`PROJECT_OVERVIEW.md`, `DB_SCHEMA.md`) and CHANGES files
  are the only durable record of what's been built. Skipping a CHANGES
  file (as happened here originally) leaves a gap that's annoying to
  reconstruct later. Going forward: every commit gets a CHANGES file,
  even tiny ones.
