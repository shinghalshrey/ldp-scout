# Task TC — Tab consolidation: 8 tabs → 5

## Goal
Collapse the 8-tab navigation into 5 by merging four destinations into existing
pages. **UI reorganization only** — no business logic, data loading, or Supabase
queries changed. Render targets moved; data flows untouched.

| Before (8) | After (5) |
|---|---|
| Command Center | **Command Center** |
| Programs | **Programs** (+ AI Fit Scan + Deadlines) |
| AI Fit Scan | → merged into Programs |
| Alumni Finder | → merged into Networking |
| My Applications | **My Applications** |
| Networking | **Networking** (+ Find Alumni sub-view) |
| Deadlines | → merged into Programs |
| Market Intel | removed (placeholder) |
| | **Profile** (new tab → opens the existing profile modal) |

New nav order: **Command Center · Programs · My Applications · Networking · Profile**

Diagnostic confirms the result:
```
[TaskTC] nav tabs: 5
```

---

## 1. AI Fit Scan → Programs
- Removed the AI Fit Scan nav tab.
- Moved the entire `#page-aifit` markup (`#aifit-view-pre` upload UI + `#aifit-view-post`
  results) into a new collapsible **`#programs-scan-panel`** at the top of `#page-programs`
  (above the table, by `#fit-banner-mount`). **Every inner ID is preserved**
  (`aifit-view-pre/post`, `aifit-results-container`, `analyze-btn`, `resume-file-input`,
  `aifit-upload-box`, …) so the scan logic — `runAIAnalysis`, `loadAndRenderLastScan`,
  `renderAIResults`, `renderQuotaExhausted`, quota checks, drag-and-drop — works **unchanged**.
  Only the render target moved.
- Added a **"✦ Scan résumé"** button to the Programs action bar (top-right, next to
  "+ Add new program"). It calls `openProgramsScan()` → shows the panel + scrolls to it
  (keeps prior results if present, else shows the upload UI).
- After a scan, `renderAIResults()` reveals the panel and renders the **tier summary bar**
  (existing `.aifit-summary-strip`) as the banner. The tier lists + gap analysis + coaching
  are wrapped in a new **`#aifit-full-results`** block, collapsed behind a
  **"View full results ▾"** toggle (`toggleAIFitFullResults()`) that expands inline.
- The last saved scan hydrates into the panel **once per session** via
  `_hydrateLastScanOnce()` (Programs is now the default landing tab — we don't re-query
  Supabase on every visit).
- Re-pointed every `showPage('aifit')` caller to `openProgramsScan()`:
  the fit-prompt banner (3 states), the per-row "Scan résumé" cell, the mobile-card CTA,
  the Command Center first-run card + quick action, and the onboarding step-3 completion
  (now lands on Programs and calls `revealScanResults()`).
- The fit-attention coral dot moved from the old nav tab to the **Scan button**
  (`updateFitTabIndicator()` targets `#prog-scan-btn`).

## 2. Deadlines → Programs
- Removed the Deadlines nav tab and `#page-deadlines`.
- Added a **"📅 Deadlines view"** toggle (`toggleDeadlinesView()`, state `_deadlinesView`)
  to the Programs action bar. When on, `renderPrograms()`:
  - filters to programs whose deadline cell resolves to a real date **or** "Rolling"
    (i.e. `deadlineLabel(p, resolveProgramView(p).deadline) !== '—'`), applied to both
    catalog and user-added rows, and
  - sorts ascending by the resolved deadline (real dates first, "Rolling"/undated last),
    overriding any column sort while active.
- Moved the **ICS export** button (**"⬇ Export calendar"** → `exportMyPipelineDeadlines()`)
  into the same action bar.
- Command Center "Upcoming deadlines · See all →" now calls `openProgramsDeadlines()`
  (lands on Programs with the Deadlines view enabled).

Verified against the 48-program seed set:
```
All view:       48 rows, 4 with "—"
Deadlines view: 44 rows, 0 with "—", sorted 30 Jun → 15 Jul → 1 Aug → … → Rolling (last)
```

## 3. Alumni Finder → Networking
- Removed the Alumni Finder nav tab and `#page-alumni`.
- The Networking page gained **sub-view pills** (`#net-subnav`): **"My Contacts"** (the
  original tracker) and **"Find Alumni"** (the relocated finder). Toggled by
  `setNetworkingSubview('contacts'|'alumni')` → `_applyNetworkingSubview()`.
- The original networking content is wrapped in `#net-subview-contacts`; the Alumni Finder
  markup moved verbatim into `#net-subview-alumni` (all IDs preserved:
  `alumni-school-wrap`, `al-sector-list`, `alumni-prog-search`, `alumni-search-rows`, …).
  Switching to "Find Alumni" lazily runs the same init the old page did
  (`initAlumniSchoolDrop` / `renderAlumniSectorList` / `renderAlumniSearch`).
- `togglePipelineFilter()` updated: it re-renders Programs, or the alumni sub-view when
  the Networking page is active and that sub-view is open (the old `page-deadlines` /
  `page-alumni` active checks are gone).

## 4. Market Intel — removed
- Removed the nav tab and `#page-market`, and dropped it from the `showPage` dispatch.
  `renderMarketIntel()` is left defined (null-guarded, never called) for easy revival.

## 5. Navigation / routing
- `PAGE_ORDER` is now `['command','programs','applications','networking']`. The first four
  map positionally to the nav buttons (`showPage` activates `tabs[PAGE_ORDER.indexOf(id)]`).
  **Profile** is the 5th tab but opens a modal (`openProfileModal()`), so it is intentionally
  not in `PAGE_ORDER`.
- Any saved `ldps_last_page` pointing at a removed page (`aifit`/`alumni`/`deadlines`/`market`)
  now fails the `PAGE_ORDER.includes()` check and falls back to `command` — no broken landing.
- The redundant topbar Profile button (`#acct-profile-btn`) is kept hidden (element +
  handler intact) now that the nav tab is the canonical entry point.
- Mobile uses the same `.nav-tabs` horizontal-scroll strip — 5 tabs fit comfortably; the
  stale "7/8 nav tabs" CSS comment was updated.
- The AI Fit dwell-tour (tied to the old aifit page) was removed from `showPage`; all nav
  pages now fire the standard `maybeAutoTour`.
- Per-session UI state (`_scanLoadedOnce`, `_deadlinesView`, `_netSubview`) resets on sign-out.

## 6. Onboarding & tours
- Onboarding step 3 copy: "…later from the AI Fit Scan tab" → "…later with the **Scan résumé**
  button on the Programs tab".
- Tours updated for the new structure:
  - **Programs** tour gains a `.prog-actions` step (Scan / Deadlines view / Export).
  - **Networking** tour gains a `#net-subnav` step explaining the two sub-views.
  - Both reference the Scan button instead of the old AI Fit tab.

---

## Files changed
- **index.html** — nav (8→5 tabs incl. Profile); Programs action bar + `#programs-scan-panel`;
  Networking sub-view pills + relocated Alumni Finder; removed `#page-aifit`,
  `#page-alumni`, `#page-deadlines`, `#page-market`; onboarding copy.
- **app.js** — `PAGE_ORDER` + `showPage` dispatch; new helpers (`openProgramsScan`,
  `closeProgramsScan`, `revealScanResults`, `toggleDeadlinesView`, `openProgramsDeadlines`,
  `setNetworkingSubview`, `_applyNetworkingSubview`, `_hydrateLastScanOnce`,
  `toggleAIFitFullResults`); deadlines filter+sort in `renderPrograms`; panel reveal +
  full-results toggle in `renderAIResults`/`renderQuotaExhausted`; re-pointed CTAs;
  `togglePipelineFilter` page checks; sign-out state reset; `[TaskTC]` diagnostic.
- **styles.css** — `.prog-actions` / `.prog-action-btn`; `.prog-scan-panel*`;
  `.aifit-fullresults-toggle` / `.aifit-full-results`; `.net-subnav` / `.net-subpill` /
  `.net-subview*`; mobile rules; updated nav-tab count comment.

---

## Task TC.2 — Programs page declutter (follow-up)
The first cut placed the AI Fit scan as an always-present panel inside the
Programs table view, which felt cluttered. Reworked to the same **sub-view pill**
pattern used on Networking:

- Added **`#prog-subnav`** pills at the top of `#page-programs`:
  **"Browse Programs"** (the catalog table, default) and **"✦ AI Fit Scan"** (the
  scanner). The browse content is wrapped in `#prog-subview-browse`; the scan panel
  moved into `#prog-subview-scan`. Switched by `setProgramsSubview('browse'|'scan')`
  → `_applyProgramsSubview()` (state `_progSubview`, reset to `browse` on each
  Programs entry and on sign-out).
- Removed the "Scan résumé" button from the action bar (the pill replaces it). The
  panel's header button is now **"← Back to programs"**.
- `openProgramsScan()` / `revealScanResults()` now just flip to the scan sub-view;
  `renderAIResults()` no longer force-reveals a panel (so silent hydration on page
  load fills results without yanking the user off the table). The fit-attention
  coral dot moved to the `#prog-subpill-scan` pill.
- Shared the pill CSS across both pages (`.net-subnav, .prog-subnav` /
  `.net-subpill, .prog-subpill`). Programs tour + fit-banner copy updated to point
  at the "AI Fit Scan" view instead of the old tab/button.

## Diagnostics
```
[TaskTC] nav tabs: 5
[TaskTC] deadlines view: true|false   (logged on each toggle)
```

## Verification
- `node --check app.js` → OK. No duplicate IDs in `index.html`. No console errors on load.
- Browser preview (seed data): nav renders 5 tabs; scan panel hidden by default, reveals
  on result render with the tier-summary banner + collapsed "View full results" toggle that
  expands inline; Deadlines view filters 48→44 rows (0 "—") and sorts ascending with Rolling
  last; Networking "Find Alumni" sub-view toggles cleanly with "My Contacts".
- Signed-in-only data flows (live Supabase scan, alumni feed, contacts) are unchanged —
  only their render hosts moved — so they behave exactly as before.
