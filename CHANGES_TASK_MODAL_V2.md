# CHANGES — Task MODAL_V2: Program snapshot modal redesign

**Files changed:** `app.js` (+94 / −74), `styles.css` (+50 / −22)
**Untouched (as required):** `index.html`, `scan.js`, `data.js`
**Verification:** `node --check app.js` passes; full behaviour confirmed live in the browser preview (desktop + mobile).

## What this was

A **visual redesign only** of the program snapshot modal (`openProgramSnapshot`)
and its signed-out twin (`openProgramSnapshotPublic`). No functionality, data
sources, triggers, save logic, or close behaviour changed — the modal now reads
like a proper program detail page instead of a small tooltip-sized card.

## What changed (plain English)

### Layout
- **Bigger, centered card.** Max-width grew 480px → **680px**; the overlay now
  uses flexbox to center the card **horizontally and vertically**. Radius 16px,
  softer shadow, `max-height: 85vh`.
- **Pinned header + scrolling body.** The card is a flex column: the header
  (company · program · status badge · share · close) stays put while a new
  `.ps-card-body` scrolls everything below it.
- **8-cell key-details grid** replaces the old 3-fact strip — Location, Industry,
  Function, Duration, Visa Sponsorship (Yes ✓ green / No red / Unknown gray),
  Language (falls back to "English (assumed)"), Deadline, Status. 2 columns on
  desktop, 1 column on mobile. Hairline grid lines via the gap + container-bg trick.
- **About section** ("About this program") only renders when a description exists;
  long copy scrolls within a 200px box.
- **Two-sided action bar.** Left: *Visit program page →* (green, only if a URL
  exists) + *Find Alumni →* (outlined, **new** — jumps to the in-app Alumni Finder
  pre-filtered to the company). Right: *Add to Pipeline +* when untracked, or a
  *✓ In pipeline · [stage]* label when tracked.
- **User fields** (your deadline + notes, auto-save on blur) show only for tracked
  programs, on a subtly-shaded row below the action bar.

### Mobile (≤768px)
- Full-screen takeover: `100vw × 100dvh`, no radius, no backdrop blur.
- Single-column grid; action bar and user fields stack vertically with full-width
  buttons; close button gets a 44×44 tap target.

### Public (signed-out `?p=` link) modal
- Uses the **same** grid, layout, and sizing.
- Differences: no share button, no Find Alumni, no pipeline controls, no user
  fields — the right side of the action bar is a *Sign up to save this program →*
  CTA (same `closeProgramSnapshot();showAuthModal()` behaviour as before).

## Code structure

- **New shared helpers** so the two modals stay identical:
  - `_psGridHtml(p, badgeHtml)` — builds the 8-cell grid (with the same status
    badge the header shows; `★ Added by you` for user-added rows).
  - `_psAboutHtml(desc)` — the optional About block.
  - `_psFindAlumni(progId)` — closes the modal, switches to Networking → Alumni,
    drops the company name into the finder's search box, re-renders. Signed-in
    only (the public modal never shows the button).
- Both `openProgramSnapshot` and `openProgramSnapshotPublic` were rewritten to
  emit the new structure via these helpers.

## CSS class changes (`styles.css`)

- **Removed:** `.ps-facts`, `.ps-company`, `.ps-progname`, `.ps-desc`
  (the header company/program text is now styled inline at 18px/14px).
- **Added / replaced:** `.ps-overlay`, `.ps-card`, `.ps-card-body`, `.ps-header`,
  `.ps-grid`, `.ps-grid-cell`, `.ps-grid-label`, `.ps-grid-value`, `.ps-about`,
  `.ps-about-head`, `.ps-about-text`, `.ps-actions`, `.ps-actions-side`,
  `.ps-btn`, `.ps-btn-primary`, `.ps-btn-outline`, `.ps-tracked-label`,
  `.ps-user-fields`, plus a `@media (max-width: 768px)` full-screen block.

## Behaviour preserved (unchanged)

- Triggers (row click + AI-scan click), data fields, `_psSaveField` auto-save,
  `_psAddToPipeline`, `_psShareProgram`, `closeProgramSnapshot` / Escape /
  backdrop close, and the public sign-up CTA all work exactly as before.
- No new Supabase queries; the LinkedIn/alumni and share logic were only moved
  visually.

## Verified in-browser

| Check | Result |
|---|---|
| `node --check app.js` | ✅ pass |
| Desktop: 680px card, centered H+V | ✅ |
| Desktop: 2-column, 8-cell grid | ✅ |
| Desktop: header pinned while body scrolls | ✅ |
| About: `max-height:200px; overflow-y:auto` | ✅ |
| Mobile (375px): full-screen, single column, stacked full-width buttons, 44px close | ✅ |
| Tracked (catalog): real status badge + "✓ In pipeline · Applied" + populated date/notes + save wired | ✅ |
| Tracked (user-added): "★ Added by you" + user fields | ✅ |
| Untracked: "Add to Pipeline +" | ✅ |
| Close via X / Escape / backdrop; inside-click keeps open | ✅ |
| Share → copies `/?p=<id>` + toast, modal stays open | ✅ |
| Find Alumni → Networking → Alumni filtered to the company | ✅ |
| Public modal: same layout, sign-up CTA, no pipeline/share/user-fields | ✅ |
