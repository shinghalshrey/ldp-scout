# Task 19.2 — Programs page architecture overhaul

Six interlinked changes triggered by a deep product review of the Programs
page. Sequencing matters: the catalog read-only architecture decision
(Path A) cascades into UI cleanup; the new Stage column replaces what the
old Pipeline button column did; the sidebar accordion is the new home
for the Sector filter you wanted (and prepares the UI infrastructure for
the geography drill-down landing in Task 19.3).

> **No DB migration in this task.** The Path A architecture finding
> (Programs is read-only from the client; users can't INSERT/UPDATE/DELETE
> rows in the `programs` table per the existing RLS) was already the live
> reality — we just stopped pretending otherwise in the UI. All writes
> continue to flow through `user_applications` (per-user, RLS-scoped).

---

## What this task did

### 1. Programs catalog read-only (Path A)

The `+ Add Program`, `Edit`, and `Del` buttons on the Programs page were
vestigial from a pre-Supabase architecture where `progs[]` lived in
localStorage. They wrote to in-memory `progs[]` + localStorage. On the
next sign-in, `fetchProgramsFromSupabase()` overwrote `progs[]` with the
canonical Supabase rows and the user's edits silently vanished.

The fix: **acknowledge the architecture**. Programs is a curated, verified
catalog. Users can't mutate it. If a user wants to track a program not in
the catalog, they either:
- email `hello@ldpscout.com` to request it be added (new mailto link
  in the meta row), or
- log it manually on the Applications page (still works — that table IS
  per-user writable).

Code changes:
- Removed the `+ Add Program` button → replaced with a subtle dashed-link
  "Don't see a program? Request it →" that mailtos `hello@ldpscout.com`.
- Removed the `Edit` and `Del` buttons from each row (the entire Actions
  column dies).
- Removed the program modal (`<div id="ov-prog">…</div>`) block from
  `index.html`.
- Stubbed `saveProg()`, `editP()`, `delP()` with `console.warn` + a
  toast explaining the new architecture. This catches any lingering
  handler refs (cached HTML, browser extensions) and avoids crashing.
- The original `saveProg` implementation was removed entirely (was
  duplicated by the stub, JS used the later declaration — confusing).

Why not Path B (add a `user_programs` table)? Path B is a real feature
with real DB work — separate RLS policies, fetch path, UI badges for
"your custom" vs "verified". No evidence yet that users actually want to
add custom programs at scale. Email request → manual addition by us
covers the demand at current scale. Revisit if request volume gets high.

### 2. Pipeline semantic fix

The `_pipelineCount()` and `_deadlinesThisMonth()` helpers added in
Task 19 used `!['offer','rejected'].includes(status)` — excluding both
offer and rejected from pipeline counts. The product definition:

- Pipeline = shortlisted + networking + drafting + applied + interview + offer
- NOT pipeline = rejected (exited)

Offer is the **goal-state** of being in pipeline, not an exit. Fixed
both helpers to use `status !== 'rejected'`.

### 3. Sidebar — collapsible accordion sections

The sidebar got dense (Search + Quick Filters + Geography + Function +
Status + new Sector + Pro Tip = ~25 controls). All filter sections now
collapse by default. State persists per-section in `localStorage`
(`ldps_prog_sidebar_v1`).

Each section header shows an active-filter count badge — e.g.
`SECTOR (3)` — when collapsed, so users see at-a-glance state without
expanding. Refreshed on every filter change via `_refreshSidebarBadges()`
hooked into `renderPrograms()`.

Search input stays always-visible at the top (no collapse) — it's the
primary action, doesn't deserve to be hidden.

This UI pattern is reused in Task 19.3 for the geography drill-down
(continent → country → city), which is why it's worth building it
properly now even with only 6 filter sections.

### 4. Sector filter added

Reuses the canonical `ALUMNI_SECTORS` taxonomy (9 sectors: tech, finance,
consulting, consumer, healthcare, industrial, logistics, energy,
sovereign) already defined for the Alumni Finder. Pills in a vertical
stack matching the other filter sections.

`F.sector = new Set()` added to filter state. Persistence extended
(`ldps_prog_filters`). Filter check added in `renderPrograms()`:
`if(F.sector.size && !F.sector.has(p.sector)) return false`.

Use case (your request): "leadership programs for finance in pharma" →
Function=finance + Sector=healthcare. Now possible.

### 5. Stat row redesign

Old: TOTAL · OPEN · ROLLING · WATCH/PREP · ★★★★+ FIT
New: TOTAL · ★★★★+ AI FIT · OPEN · ROLLING · ★ MY PIPELINE

Changes:
- **Watch/Prep card removed** — it was a duplicate of the App Cycle
  sidebar pill, and "Watch" doesn't earn a top-level stat slot in the
  way Open / Rolling / Pipeline do.
- **AI Fit moved to position 2** (was last) — high-fit programs are the
  primary value the AI Scan delivers, deserves more prominence.
- **My Pipeline added as 5th card, in amber.** Distinct color (warm gold,
  `#c89738`, distinct from the forest `--accent`) telegraphs "this is
  YOUR data, not catalog data." Click toggles the pipeline filter
  (same state as `togglePipelineFilter()` — shared with Deadlines page).

### 6. Stage column replaces Pipeline column + custom dropdown

Old table columns (9): Program · Function·Sector · Location · Deadline ·
Status · Fit · 📅 Remind · Pipeline (button) · Actions (Edit/Del)

New table columns (9): Program · **Function** · **Sector** · Location ·
Deadline · **App Cycle** · **✦ AI Fit** · **Stage (dropdown)** ·
**📅 Reminder**

Net: same column count, way more semantically useful.

The new **Stage column** is the single most impactful change. It replaces:
- The old "Pipeline" column (which had a `+ Shortlist` button or a "✓ Saved"
  read-only badge), and
- The old "Actions" column (which had Edit/Del, now killed).

Behavior:
- If a program is NOT in your pipeline → dropdown shows `+ Add to pipeline`
  in a dashed-border empty state.
- If it IS in pipeline → shows the current stage with a colored dot.
- Click the trigger → custom panel opens with 7 stage options
  (Shortlisted / Networking / Drafting / Applied / Interview / Offer /
  Rejected), each with a colored dot matching the Kanban color.
- For programs already in pipeline, the panel also includes a separator
  and a "Remove from pipeline" option (deletes the user_applications row
  after confirm).
- Current stage shows a green checkmark + accent background.

Implementation notes (`renderStageDropdown`, `toggleStageDropdown`,
`setProgramStage`, `_closeAllStageDropdowns`):
- Custom dropdown panel rendered at document.body level with
  `position: fixed`. This bypasses `.table-wrap`'s `overflow: hidden`
  which would otherwise clip the panel.
- Positioning calculated from the trigger button's `getBoundingClientRect()`.
  Auto-adjusts to open upward if the panel would overflow the viewport bottom.
- Only one panel open at a time across the entire table — clicking another
  trigger or anywhere outside closes the current panel.
- Closes on: click outside, Escape, window scroll (any axis, captured at
  document level), window resize.
- Selecting a stage:
  - Branches on whether the program is already in pipeline (calls
    `addProgramToApplications` for inserts, `saveApplicationToDB` for
    updates, `deleteApplicationFromDB` for removes).
  - Re-renders Applications + Programs + ProgressStrip to keep state
    consistent across pages.

### Other small things swept

- Vertical column borders (`border-left: 1px solid var(--border)`) inside
  `.prog-table-wrap` for the readability you flagged. Scoped to this table.
- Sort key wiring: `data-sort-key="sector"` added; corresponding case in
  the `cmp` function inside `renderPrograms()`. The old `case 'fn'` that
  combined `${a.fn} ${a.sector}` is now Function-only (since they're
  separate columns).
- `clearAll()` extended to clear `F.sector` and re-sync pills.
- `_restoreFilterState` and `_persistFilterState` extended with sector.
- `_syncFilterPills('sector')` wired through the existing generic helper.
- The Pro Tip card body updated to reflect the new Stage dropdown UX.
- Page tour step 2 body rewritten — now mentions Quick Filters (Visa),
  Geography, Function, Sector, App Cycle. Step 4 rewritten to call out
  the Stage dropdown.

---

## Files touched

| File | What changed |
|------|--------------|
| `index.html` | Sidebar restructured into accordion sections (Search always-visible; Quick Filters, Geography, Function, Sector, App Cycle collapsible). Sector pills added. Pipeline pill removed from Quick Filters. Table thead rebuilt for 9 columns (separate Function + Sector; App Cycle label; Stage label; Reminder label). Meta row's `+ Add Program` button replaced with mailto request link. Dead `<div id="ov-prog">` modal block removed. |
| `styles.css` | Accordion section styles (`.prog-side-acc`, `.prog-side-head`, `.prog-side-body`, `.prog-side-badge`, `.prog-side-chev`). 9-column grid template overrides for `.prog-table-wrap .thead` and `.prog-table-wrap .prow`. Vertical column borders via `> * + *` sibling selectors. Amber variant for `.stat-card.sc-pipeline`. Full custom dropdown styling (`.stage-dd`, `.stage-dd-panel`, `.stage-dd-opt`, etc.). Mailto request link styling (`.prog-request-link`). |
| `app.js` | `F.sector = new Set()` + persistence + filter check + clearAll. New `STAGES` constant + `STAGE_BY_KEY` map. New `renderStageDropdown`, `toggleStageDropdown`, `setProgramStage`, `_closeAllStageDropdowns` (with global click/scroll/resize/Escape handlers). New `toggleFilterSection`, `_restoreSidebarSections`, `_refreshSidebarBadges`. Row HTML in `renderPrograms` restructured for 9 columns (split Function/Sector, replace Pipeline button with stage dropdown, drop Actions). Stat row rebuilt — Watch/Prep removed, AI Fit moved to position 2, My Pipeline added in amber. `saveProg/editP/delP` stubbed with console.warn + toast. Original `saveProg` implementation removed. `_pipelineCount` and `_deadlinesThisMonth` fixed to use `status !== 'rejected'` (was `!['offer','rejected'].includes`). Programs tour steps 2 and 4 rewritten for new sidebar + Stage dropdown. `_restoreSidebarSections()` hooked into `showPage('programs')`. |

---

## Manual test plan

### A. Path A button removal
1. Sign in. Land on Programs page.
2. Confirm `+ Add Program` button is gone — replaced with a small dashed link "Don't see a program? Request it →" at the right side of the meta row.
3. Click the link → confirms the OS mail composer opens with `hello@ldpscout.com` pre-filled, subject "Program request — LDP Scout".
4. Confirm no row has an Actions column with Edit / Del buttons.
5. Console: type `saveProg()` — should log a warn and show a toast about read-only catalog. Same for `editP(1)` and `delP(1)`.

### B. Stat row redesign
1. Programs page stat row has exactly 5 cards: TOTAL · ★★★★+ AI FIT · OPEN NOW · ROLLING · ★ MY PIPELINE.
2. NO "Watch / Prep" card.
3. MY PIPELINE card uses an amber number (warm gold), distinct from other cards.
4. Click MY PIPELINE → activates pipeline filter, card gets `sc-active` (amber border + light amber background). Table filters to just pipeline programs.
5. Click MY PIPELINE again → deactivates, table shows all.
6. Navigate to Deadlines → My Pipeline toggle there is in lockstep (shared state).
7. Pipeline count shown on the card matches `_pipelineCount()` — should INCLUDE programs in offer stage, EXCLUDE rejected.

### C. Sidebar accordions
1. Fresh browser (or clear `ldps_prog_sidebar_v1` from localStorage).
2. Reload Programs page. All accordion sections (Quick Filters, Geography, Function, Sector, App Cycle) are COLLAPSED. Search input is always visible at top.
3. Click "Geography" header → expands. Chevron rotates 180°. Pills appear.
4. Click "Europe" pill → activates. Chevron stays unchanged.
5. Click "Geography" again → collapses. The header now shows `(1)` badge next to "Geography" indicating one active filter.
6. Reload the page → Geography section is collapsed (because we collapsed it before unloading) but the "(1)" badge persists (because the filter is still active in localStorage).
7. Expand Geography again → "Europe" pill is highlighted (on state restored from localStorage).
8. Click "All" pill → clears geo filter. Badge disappears (filter count is 0).
9. Click "Clear filters" (the TOTAL PROGRAMS stat card when any filter is active) → all sections' badges clear.

### D. Sector filter
1. Expand the Sector section. Confirm 10 pills: All · Tech & Innovation · Finance · Consulting · Consumer & Retail · Healthcare · Industrial · Logistics · Energy · Sovereign / Public.
2. Click "Healthcare". Table filters to healthcare programs only.
3. Expand Function. Click "Finance". Table now shows Finance × Healthcare = "Finance leadership programs in pharma/healthcare" (your use case).
4. Collapse both — badges read "Function (1)" and "Sector (1)".

### E. Stage dropdown — empty state (program not in pipeline)
1. Pick any program row whose Stage column shows "+ Add to pipeline" (dashed border).
2. Click the dropdown trigger → panel opens below the button.
3. Panel shows 7 stage options (Shortlisted → Rejected) with colored dots.
4. Panel does NOT show "Remove from pipeline" (program isn't in pipeline yet).
5. Click "Networking" → panel closes, toast appears, row's Stage column updates to show "Networking" with the blue dot.

### F. Stage dropdown — existing pipeline entry
1. Pick a program now in your pipeline.
2. Click its Stage dropdown trigger.
3. Panel opens. Current stage has accent background + green checkmark.
4. Panel includes a separator and a "Remove from pipeline" red-hover option.
5. Change stage to "Applied" → toast, row updates, Applications Kanban also reflects the change (navigate there to confirm).
6. Click the trigger again → "Applied" is now marked as current.
7. Click "Remove from pipeline" → confirm dialog → confirm → row's Stage flips back to "+ Add to pipeline" empty state. Applications page no longer shows that card.

### G. Stage dropdown — open/close behavior
1. Open a Stage dropdown on row A. Now click another Stage dropdown on row B → A closes, B opens.
2. Open one. Click anywhere outside (table header, sidebar, white space) → closes.
3. Open one. Press Escape → closes.
4. Open one. Scroll the page → closes.
5. Open one. Resize the window → closes.
6. Open one near the bottom of the visible viewport → panel auto-positions ABOVE the trigger so it doesn't get clipped.

### H. Table columns + readability
1. Confirm 9 columns: Program / Organisation · Function · Sector · Location · Deadline · App Cycle · ✦ AI Fit · Stage · 📅 Reminder.
2. NO "Actions" column.
3. Vertical thin dividers visible between every column.
4. Click "Function" header → sorts by function. Click again → reverses direction. Same for "Sector" (new), "Location", "Deadline", "App Cycle", "✦ AI Fit", and program name.
5. Stage column is NOT sortable (no arrow). Same for Reminder.

### I. Pipeline semantic fix
1. Sign in. Note the Programs welcome strip count: "N programs in your pipeline".
2. Open Applications. Move a card to "Offer" → count should NOT decrease.
3. Move it to "Rejected" → count DECREASES by 1.
4. Move it back to any other stage → count INCREASES.

### J. Page tour
1. Open Programs page tour ("?" → "Tour this page →").
2. Step 1 highlights the stat row.
3. Step 2 highlights the sidebar; body mentions Quick Filters (Visa), Geography, Function, Sector, App Cycle, Search.
4. Step 3 highlights the column headers.
5. Step 4 highlights the first row; body mentions the Stage dropdown.

---

## Known follow-ups

### Task 19.3 — Geography continents with multi-continent support
Confirmed: continents stored as TEXT[] array on `programs` table.
Filter logic OR-matches against the user's selected set. No "Global"
bucket — programs that span multiple regions get tagged with all
relevant continents. Requires DB migration + manual data curation
across all 393 rows. Done as a separate task with its own Claude Code
SQL session + content review pass.

### Mobile card view dead code
`app.js:2730-ish` references `#prog-cards` and `#prog-table` IDs for a
mobile card view. Neither ID exists in `index.html` (never has).
Pre-existing dead code, not a Task 19.2 regression. Either implement
properly or remove — separate task.

### "+ Shortlist" buttons in Alumni and AI Fit pages
Those buttons in `renderAlumniSearch` and `renderAIResults` still use
the old `addProgramToApplications(progId, 'shortlisted')` path. They
still work correctly. Optional polish: those could also become the
Stage dropdown for cross-page consistency, but that's a UX choice not
a correctness issue. Defer.

### Path B (user_programs table)
Not in this task. If demand for user-added custom programs grows, the
clean implementation is: new `user_programs` table with RLS scoped to
`auth.uid()`, fetch path that unions global + user-added, "your custom"
badge on user-added rows. Email-based requests via `hello@ldpscout.com`
covers current demand.
