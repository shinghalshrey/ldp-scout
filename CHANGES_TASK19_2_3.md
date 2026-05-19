# Task 19.2.3 — Column alignment, edge-to-edge dividers, Pipeline border, last-page persistence

Four targeted fixes after Pranav's third look at Task 19.2.2 in production.
Three are visual; one (last-page persistence) is a small but meaningful UX
upgrade.

> No DB changes. Pure frontend.

---

## What this task did

### 1. Column alignment — top-align cells 2-9

**Pranav:** "see the columns. due to + add to my pipeline the columns on
the left are not aligned"

**Root cause:** Task 19.2.2 set `justify-content: center` on cells 2-9.
With rows of varying height (Amazon row has 3 tags + Verified badge = ~75px
tall; some other rows are ~50px tall), center-vertical alignment placed
text at different Y-offsets per row. Function "Operations" on a tall row
sat lower in the row than Function "Strategy" on a slightly shorter one.
Visually read as misalignment even though the columns themselves were
correctly positioned.

**Fix:** changed `justify-content` from `center` to `flex-start` on all
cells, with a unified `padding-top: 14px` (matches what the row used to
have via `.prow { padding: 13px 16px }`). Now every cell's content starts
at the same Y-offset from row top, regardless of row height. The first
column (Program/Org) also uses `flex-start` so its program name aligns
horizontally with the Function/Sector/etc. text in the same row.

Side effect: tags and verified badges in column 1 now sit just below
the program name (still inside the row, just stacked vertically). No
content lost.

### 2. Vertical dividers — actually edge-to-edge this time

**Pranav:** "vertical dividers are not what they should be. it should be
edge to edge."

**Root cause (revealed):** the base `.prow` rule has `padding: 13px 16px`.
CSS Grid cells fit inside parent padding — so vertical dividers started
13px below the row's top edge and ended 13px above the bottom edge.
That left a visible gap at the row's vertical extremes where the divider
didn't paint. Task 19.2.1's flex/min-height fix and Task 19.2.2's
align-items:stretch fix BOTH worked on cell-stretch but neither addressed
the row's outer padding.

**Fix:** removed vertical padding from `.prow` and `.thead` (set
`padding-top: 0; padding-bottom: 0`), moved that padding INTO each cell
(`padding-top: 14px; padding-bottom: 14px`). The cells now span 100% of
row height (between row-separating `border-bottom`s); border-left renders
truly edge-to-edge. Header cells use slightly tighter padding (11px) to
keep the header band visually compact.

### 3. My Pipeline border — thicker + more visible

**Pranav:** "make the border of my pipeline thicker. the border color is
getting lost in the page background."

**Root cause:** Task 19.2 set border at 1.5px (later 1.5px universal in
Task 19.2.2). My Pipeline used `rgba(200, 151, 56, 0.20)` — 20% opacity
amber against the cream `--bg`. Very faint.

**Fix:**
- Border-width bumped from 1.5px → 2px (scoped to `.stat-card.sc-pipeline`)
- Unselected opacity bumped from 0.20 → 0.55 (much more visible)
- Hover opacity bumped from 0.40 → 0.80
- Active state background tint 0.08 → 0.10 (slightly stronger when selected)

The My Pipeline card now reads as a clearly bordered destination card
even on first glance, distinct from cards 1-4 which have lighter borders.

### 4. Last-page persistence on refresh

**Pranav:** "when I refresh on any page, why do i land back in the
programs page?"

**Root cause:** `index.html` hardcodes `class="page active"` on
`#page-programs`. There's no JS that overrides this on load. So every
refresh defaulted to Programs, regardless of which tab the user was
viewing before.

**Fix:**
- Every `showPage(id)` call now writes `id` to `localStorage` under key
  `ldps_last_page`.
- `onSignIn()` reads that key after all the standard sign-in steps,
  and if it's a valid non-default page, calls `showPage(lastPage)` to
  switch the active page.
- `onSignOut()` clears the key so the next user (or same user on
  re-login) starts fresh on Programs.

Conditional: if `lastPage` equals `'programs'` or is missing/invalid,
no action taken — Programs is the natural default and the DOM already
has it active.

### 5. AI Fit hydration on refresh — already working

**Pranav confirmed:** "the programs page loads the results from the AI
fit scan fine now." Task 19.2.2's `hydrateAITierFromHistory()` is doing
its job. No further changes needed.

### 6. Clickable program names on AI Fit results — already working

**Pranav confirmed:** "the programs are clickable in ai fit scan result"
Task 19.2.2 fix verified in production.

---

## Files touched

| File | What changed |
|------|--------------|
| `app.js` | `showPage()` writes `id` to `localStorage.ldps_last_page` on every call. `onSignIn()` reads it after `updateFitTabIndicator()` and calls `showPage(lastPage)` if it's a non-default valid page. `onSignOut()` removes the key. |
| `styles.css` | `.prog-table-wrap .prow / .thead` get `padding-top: 0; padding-bottom: 0` (vertical padding moved to cells). Cells get `padding-top: 14px; padding-bottom: 14px` (or 11px for thead). Cells use `justify-content: flex-start` instead of `center` for consistent vertical alignment across rows of varying heights. `.stat-card.sc-pipeline` border-width bumped to 2px; unselected/hover/active opacities increased to 0.55 / 0.80 / 0.10. |
| `index.html` | No changes. |

---

## Manual test plan

### A. Column alignment
1. Programs page. Scroll through several rows.
2. The Function column text ("Operations", "Strategy", "Finance"...) should sit at the same Y-offset from row top on every row.
3. Same for Sector, Location, Deadline columns.
4. The Stage column buttons (whether they say "+ Add to pipeline" or "● Interview") should also align consistently.
5. Compare a row with 3 tags + verified badge vs a row with 2 tags: the function column text should be at the SAME Y-position from the top of each row.

### B. Vertical dividers — edge-to-edge
1. Programs page. Look at any row.
2. The vertical divider between Function and Sector (and every other column pair) should run from the row's top border to its bottom border — no gap at top or bottom.
3. Same for the header row's dividers.
4. This is the key visual fix — confirm it looks RIGHT now, not just "better."

### C. My Pipeline border visibility
1. Programs page stat row. The MY PIPELINE card (5th, rightmost) should have a clearly visible amber border at rest.
2. Compare to cards 1-4 (TOTAL / AI FIT / OPEN NOW / ROLLING) — their borders should be lighter, signaling "neutral; standard filter card." MY PIPELINE should clearly read as different and inviting.
3. Hover over MY PIPELINE — border deepens to a darker amber.
4. Click — full amber border + amber-tinted background.

### D. Last-page persistence
1. Sign in. Navigate to Alumni Finder.
2. Hard-refresh (Ctrl+F5). Should land on Alumni Finder, NOT Programs.
3. Click My Applications. Refresh. Should land on My Applications.
4. Click Programs. Refresh. Should land on Programs.
5. Sign out. Sign back in. Should land on Programs (last-page cleared on sign-out).

### E. AI Fit confirmations (already working, sanity-check)
1. Run a fresh scan, then refresh the page — AI Fit column on Programs shows tier badges immediately.
2. AI Fit results page — program names are clickable links (when `p.url` exists).
