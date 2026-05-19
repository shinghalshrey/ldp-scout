# Task 19.2.2 — Cross-page editorial header + table polish + AI Fit hydration bug

Eight changes in one commit, triggered by Pranav's second-look review of
Task 19.2.1 in production. Most are visual polish, but one is a real bug
fix (AI Fit hydration on page refresh) and one is genuinely new feature
work (clickable program names in AI Fit results).

> No DB changes. No schema migrations. Pure frontend.

---

## What this task did

### 1. Removed "+ Details" disclosure

The Task 19/19.2 row HTML kept a `<details>` block with description,
eligibility, work_experience, target_degree, and source URL — collapsible
behind "+ Details". Pranav: "this is not good UI. The link of the
program should work and take the user to the program page."

Replaced with: program name IS the link (when `p.url` exists). For rows
where `p.url` is missing, the name renders as plain text — no broken
click target, no UX noise. The `saveProg` admin path (future) can still
populate URLs as data improves.

The full description and eligibility fields are still in the database;
they're just no longer surfaced in the table. Could be re-introduced
later via a clicked-row modal if needed.

### 2. Fixed vertical column dividers — root cause finally identified

Task 19.2.1 attempted to fix ragged column dividers with `display: flex`
+ `min-height: 100%` on each cell. It didn't fully work.

**Root cause:** the base `.prow` rule at `styles.css:83` has
`align-items: center`. CSS Grid's default cell behavior IS `stretch`
(which would have made `border-left` render full-height), but the
explicit `align-items: center` on the row overrode that — every cell
sat at its content height regardless of row height. The previous
`display: flex; min-height: 100%` attempt fought the alignment but
couldn't fully win.

**Fix:** scoped override of `align-items: stretch` on `.prog-table-wrap .prow`
and `.thead`. Now grid cells natively stretch to row height; the existing
`border-left` (unchanged from Task 19.2) renders edge-to-edge.

Cell CONTENT still vertically centers (each cell is a flex column with
`justify-content: center`). First column gets `flex-start` so the program
name sits at the visual top with tags/badges below.

### 3. Center-aligned columns 2-9

Pranav: "keep the text in columns to the right of program/organisation
centrally aligned." Done via `text-align: center` on `.prow > *:not(:first-child)`
and `.thead > *:not(:first-child)`. Combined with the flex cell pattern,
content is both vertically AND horizontally centered. First column stays
left-aligned (program name + org + tags).

### 4. BUG FIX: AI Fit hydration on page refresh

**Bug Pranav noticed:** "the AI Fit column loses its history when I
refresh the page. But if I then go to AI Fit Scan page and come back
to Programs page, the column is populated with the assessment."

**Root cause:** `progs[].aiTier` is populated by `syncAIResultsToPrograms()`,
called from `renderAIResults()`, called from `loadAndRenderLastScan()`.
`loadAndRenderLastScan` only runs on `showPage('aifit')`. On a fresh page
load, the user lands on Programs (or wherever they were); `renderPrograms()`
runs against a `progs[]` that has no `aiTier` yet. AI Fit column shows
"Scan résumé" placeholders. Only after visiting the AI Fit page does the
data sync back.

**Fix:** new helper `hydrateAITierFromHistory()` — silent variant of
`loadAndRenderLastScan` that fetches the most recent scan row from
`user_scan_history` and applies it to `progs[]` via the existing
`syncAIResultsToPrograms()` (which already handles the tier→fit mapping
and localStorage persistence). No view switching, no toast. Called once
in `onSignIn()` right after `fetchProgramsFromSupabase()` and before
the first `renderPrograms()`.

The toast inside `syncAIResultsToPrograms` is suppressed when called
silently via a `window._suppressSyncToast` flag — set true around the
call inside `hydrateAITierFromHistory`, restored after.

### 5. Clickable program names in AI Fit results

Pranav: "can we add links to the programs on the AI Fit scan page when
we get the results?"

The tier-card template at `app.js:4567` rendered program names as plain
text `${p.name}`. Replaced with: `<a href="${p.url}" target="_blank">`
when `p.url` exists, else plain text. New CSS class `.aifit-program-name-link`
gives the same hover treatment (border-bottom shifts to accent green)
as the Programs table row links — visual consistency across the two
surfaces where users click program names.

### 6. Cross-page editorial header pattern

Pranav: "I like the font used in programs page. Let's keep it consistent
across the tool... Tour this page link... move this to the right in the
same row (like the alignment of 'Don't see a program? Request it'). Make
this change for all the tabs — alumni finder, my applications, and
deadlines tab."

Built a unified header pattern shared across Alumni / Applications /
Deadlines:
- `.page-editorial-header` container with consistent padding/margin
- `.page-editorial-eyebrow-row` two-column flex (eyebrow left, tour
  link right) — matches the Programs page meta-row alignment
- `.page-editorial-eyebrow` (mono uppercase tracked)
- `.page-editorial-h1` (Fraunces serif, 32px, weight 500)
- `.page-editorial-subline` (Outfit sans, 14px, --text2)
- `.page-tour-link` (mono uppercase tracked, dashed underline,
  accent-green hover) — propagated to all four pages

Old `.sech > h2 + p` headers + blue `.info-card` blocks removed from
Alumni / Applications / Deadlines. Programs page also updated to use
the unified `.page-editorial-eyebrow-row` for its tour link (was a
custom `.prog-eyebrow-sep + .prog-tour-link` from Task 19.2.1 — now
deprecated).

Per-page personalization updated in `applyPagePersonalization()` to
target the new element IDs (`alumni-h1`, `apps-h1`, `deadlines-h1`,
`alumni-subline`, `deadlines-subline`).

### 7. Stat row visual refresh — uniform cards 1-4, amber pipeline 5

Pranav: "the my pipeline is the special one. Let us keep the color
here different from others. Let's use the same color for the others.
Let's also increase the size of the border this cell when it is
unselected."

Changes:
- All 4 non-pipeline stat numbers now use a unified neutral color via
  new `.cn` class (instead of the previous mix of `cg` green, `cb`
  blue, `cgo` gold). Cards 1-4 read as a coordinated set.
- My Pipeline (`.c-pipe` amber) remains the only colored card — visual
  destination signal.
- All `.stat-card` borders bumped from 1px / `--border` to 1.5px /
  `--border2`. More "card-like" presence when unselected.

### 8. Side-effect cleanup

- `info-card-reopen` "?" badges on each page header — gone (no longer
  in DOM). `reopenInfoCard()` function still defined; becomes a
  harmless no-op since no matching elements exist. Could be deleted
  in a future sweep.
- Programs page tour link is now in the eyebrow row (top of header,
  right side) — moved from the previous Task 19.2.1 inline-after-eyebrow
  position.

---

## Files touched

| File | What changed |
|------|--------------|
| `app.js` | Row HTML in `renderPrograms()` drops the `meta`/`desc`/`detailsBlock` variables and the `<details>` element. Stat row rebuilt: all 4 non-pipeline numbers use `.cn` class. New `hydrateAITierFromHistory()` helper added near `loadAndRenderLastScan()`. `onSignIn` calls it after `fetchProgramsFromSupabase()` and before first `renderPrograms()`. `syncAIResultsToPrograms()` toast suppressed via `window._suppressSyncToast` when called silently. AI Fit tier card template (`renderAIResults()`) wraps program name in an `<a>` when `p.url` exists. `applyPagePersonalization()` retargeted for new editorial header IDs on Alumni / Applications / Deadlines. |
| `index.html` | Alumni Finder, My Applications, Upcoming Deadlines header blocks rewritten with `.page-editorial-header` + `.page-editorial-eyebrow-row` + `.page-tour-link`. All three pages' blue `.info-card` blocks removed. Programs page eyebrow row converted from custom inline tour-link to the unified `.page-editorial-eyebrow-row`. |
| `styles.css` | Old `.prog-eyebrow-sep` and `.prog-tour-link` rules deleted (superseded). New `.page-editorial-header` + `.page-editorial-eyebrow-row` + `.page-editorial-eyebrow` + `.page-editorial-h1` + `.page-editorial-subline` + `.page-tour-link` rules added. Fixed `.prog-table-wrap .prow / .thead { align-items: stretch }` — the actual root-cause fix for ragged borders. Center-alignment rules added for columns 2-9. Stat card border/color updates: `.stat-card { border-width: 1.5px; border-color: var(--border2); }` and `.stat-card .cn { color: var(--text); font-weight: 700; }`. New `.aifit-program-name-link` styles. |

---

## Manual test plan

### A. Row cleanup
1. Open Programs page. No "+ Details" disclosure on any row.
2. Programs with a URL: clicking the program name opens the careers page in a new tab.
3. Programs without a URL: name is plain text (no click target, no broken link).

### B. Vertical column dividers
1. Programs page. Vertical dividers between every column run edge-to-edge of each row — same height as the tallest cell content.
2. Check rows with many tags (Microsoft Aspire — 3 tags + verified badge) vs few tags. Borders should look identical between them.

### C. Center alignment
1. All columns from "Function" onwards have horizontally-centered content.
2. Program / Organisation column stays left-aligned (name + org + tags read left-to-right).
3. Header labels also center-aligned (except "Program / Organisation").

### D. AI Fit refresh bug (the headline fix)
1. Run a scan. Confirm Programs page shows tier badges (Best, Strong, etc.) in the AI Fit column.
2. Hard-refresh the page (Ctrl+F5).
3. **Immediately** check Programs page — AI Fit column should show tier badges, NOT "Scan résumé" placeholders.
4. Open browser console. Should see no errors mentioning `hydrateAITierFromHistory`. Should NOT see the "✦ AI results synced to Programs tab" toast (it's suppressed for silent hydration).

### E. AI Fit clickable program names
1. Visit AI Fit Scan page (use a saved scan or run a new one).
2. Each tier card's program name should be a link (underlined with --border2).
3. Hover over a name — underline shifts to accent green.
4. Click — opens the program's careers page in a new tab.
5. For programs without a URL: name renders as plain text, no underline, no click target.

### F. Cross-page editorial headers
1. Visit Alumni Finder. Header reads: small mono eyebrow "ALUMNI FINDER · LINKEDIN DISCOVERY" on the left, "TOUR THIS PAGE →" on the right. Below: serif h1 + sans subline.
2. Visit My Applications. Eyebrow "YOUR APPLICATION PIPELINE" / Tour link right. Below: serif h1"Pranav's pipeline" (personalized) + sub line with live counts.
3. Visit Upcoming Deadlines. Eyebrow "90-DAY HORIZON · URGENCY BUCKETS" / Tour link right. Below: serif h1 + sub line.
4. Visit Programs. Eyebrow "YOUR LDP COMMAND CENTRE" / Tour link right (NOT inline next to eyebrow text). Below: serif h1 + sub line.
5. Click any "TOUR THIS PAGE →" — page tour starts as before.
6. NO blue info-card on any page below the header.

### G. Stat row
1. Programs page stat row: 5 cards in this order: TOTAL · ★★★★+ AI FIT · OPEN NOW · ROLLING · ★ MY PIPELINE.
2. Cards 1-4 numbers all in the same color (--text, darker neutral).
3. Card 5 (MY PIPELINE) number in amber/warm-gold.
4. All cards have a slightly heavier border (1.5px, --border2) than they did in Task 19.2.
5. Click MY PIPELINE — amber border activates with light amber background.

### H. Programs tour link position
1. Programs page. Top-right of the welcome strip area: "TOUR THIS PAGE →".
2. Top-left of the same row: "YOUR LDP COMMAND CENTRE".
3. They are on the same line, with empty space between them.

---

## Known follow-ups

1. **`reopenInfoCard()` is now dead code** — no DOM elements with class
   `info-card-reopen` exist. The function still loads but never gets
   meaningful calls. Sweep at convenience.

2. **Task 19.3 — Geography continents migration** still queued. CSV
   provided by Pranav has the data needed:
   `id, program_name, company, geo, location` for all 393 rows.
   Confirmed taxonomy: UAE → Asia, Russia → Europe, Turkey → Europe,
   Egypt → Africa, continents stored as TEXT[] (multi-value, e.g.
   Amazon Pathways `{europe, asia}`). Separate Claude Code session
   needed for the DB migration + manual data curation.

3. **AI Fit clickable name CSS** — current `--border2` underline is
   slightly heavier than the table-row name treatment. Could be unified.
   Defer until next visual pass.

4. **Mobile responsive treatment of the editorial header** — current
   media query stacks the eyebrow row at 900px breakpoint. The
   tour link will sit on its own line below the eyebrow text. Verify
   in Vercel preview on a phone.
