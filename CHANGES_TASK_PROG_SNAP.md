# Task PROG_SNAP — Program snapshot modal

A lightweight, scannable modal that opens when a user clicks a program row in the
Programs table or an AI Fit Scan result card. It gives a quick read on a program
— company, status, location, visa, deadline, a 3-line description, a link to the
program page, and pipeline controls — without leaving the page.

## Files changed

| File | Lines |
|------|-------|
| `app.js` | +179 / −28 |
| `styles.css` | +28 / −0 |

(Includes the follow-up changes documented at the bottom.)

No other files were touched. `index.html`, `scan.js`, and `data.js` were left
alone, per the task constraints. No new Supabase queries were added — the modal
reads the in-memory `progs[]` and `apps[]` and persists edits through the
existing `saveApplicationToDB()`.

## What it does

**Triggers**
- Every catalog row in the Programs table (`.prow`) now opens the snapshot on
  click (`onclick="openProgramSnapshot(id)"`, cursor turns to a pointer).
- Every AI Fit Scan result card (`.aifit-program-card`) opens the same modal.
- Interactive children keep their own behavior and do **not** open the modal:
  the program-name link, the ✏️ edit button, the "Scan résumé" CTA, the 📅
  reminder button, the stage dropdown, and the AI-card shortlist button each
  call `event.stopPropagation()`. (The stage dropdown already stopped
  propagation inside `toggleStageDropdown()` — verified, not duplicated.)
- User-added rows (synthetic `ua-…` ids) are intentionally **not** wired up,
  because `openProgramSnapshot` looks programs up in `progs[]`.

**The modal (`openProgramSnapshot`)**
1. Header — **Company** (bold) + program name (regular) on one line; status badge
   on the right reusing the Programs table's exact badge classes
   (`b-open` green / `b-rolling` blue / `b-watch` amber / `b-closed` gray); plus
   an ✕ close button.
2. Three key facts on one row with emoji anchors, separated by `·` dots:
   `📍 Location` · `🛂 Visa: Yes ✓` (green) / `Visa: No` (gray) / `Visa: Unknown`
   · `📅 deadline`. Deadline shows a formatted date, else the program's `dlnote`,
   else "Check program page".
3. Description — clamped to 3 lines. Skipped entirely (no placeholder) when the
   program has no description.
4. Actions — "Visit program page →" (hidden when the program has no URL) and,
   depending on pipeline state, either "Add to Pipeline +" (untracked) or a
   non-clickable "✓ Tracked · <Stage>" label (tracked).
5. User deadline + notes — only when the program is tracked. Inline date and
   text inputs prefilled from the user's application, auto-saved on blur with a
   "✓ Saved" toast.

Closes on ✕, backdrop click, or Escape. The Escape listener is added on open and
removed on close so nothing lingers. A diagnostic line is logged on every open:
`[ProgSnap] <org> | <name> | tracked: <bool> | has desc: <bool>`.

## Decisions / deviations from the brief (and why)

- **`p.description`, not `p.desc`.** The brief referred to `p.desc`, but the
  in-memory program object has no such field — the description is mapped to
  `p.description` (from `row.description` at `app.js:509`). Using `p.desc`
  verbatim would have meant the description **never** rendered and the "program
  with description → 3 lines visible" check would silently fail. The code reads
  `p.description` (with `p.desc` kept as a harmless fallback) so the feature
  actually works. The diagnostic logs the resolved value.
- **`addProgramToApplications(p.id)`, not `(p)`.** The brief wrote
  `addProgramToApplications(p)`, but that function's real signature is
  `(progId, stage)` and it does `progs.find(x => x.id === progId)`. Passing the
  object would never match. The add button passes `p.id`; the program is added
  at the default `networking` stage, then the modal re-renders into its tracked
  state.
- **`·` dot separators between the three facts.** The brief's prose said
  "separated by · dots" while its CSS used only a flex `gap`. Dots were added via
  a `::before` pseudo-element (matching the existing `.al-card-meta` convention)
  and are hidden when the facts stack on mobile.
- **`.ps-desc` bottom spacing is `margin`, not `padding`.** The brief specified
  `padding: 0 20px 14px` on the clamped element, but a 14px **padding-bottom sits
  inside `overflow:hidden`** and let a sliver of the clamped 4th line peek
  through — contradicting "max 3 lines visible." Moving the 14px to
  `margin-bottom` keeps the identical spacing while clipping cleanly at 3 lines.
- **Two supporting CSS classes** beyond the brief's list: `.ps-close` (the ✕
  button, required by the close behavior) and `.ps-header-right` (groups the
  badge + ✕ so the header's `space-between` still works). A few properties were
  also added to `.ps-btn` (`text-decoration:none`, `font-family`) because the
  primary action is an `<a>` styled as a button, and to inputs (`font-family`,
  `min-width:0`).

## Verification

`node --check app.js` passes. The modal was exercised against the **live catalog**
(433 real programs) in the local preview:

- ✅ Row click and AI-card click both open the modal; clicking the stage dropdown
  opens its panel and does **not** open the modal.
- ✅ Program with a long description → clamped to exactly 3 lines (measured
  62px / 2.98 lines, content overflow confirmed); no 4th-line sliver after the
  padding→margin fix.
- ✅ Program with no description → no description section.
- ✅ Hard deadline → formatted date ("1 Oct 2026"); only a `dlnote` → note shown;
  neither → "Check program page".
- ✅ Visa Yes → green; Visa No → gray.
- ✅ No URL → "Visit program page" button hidden.
- ✅ Untracked → "Add to Pipeline +"; tracked → "✓ Tracked · Shortlisted" with
  prefilled, editable deadline/notes.
- ✅ Auto-save updates the in-memory application for both fields and skips no-op
  blurs. (The Supabase write and "✓ Saved" toast run through the existing
  `saveApplicationToDB()`, which requires a signed-in session — not reproducible
  in the signed-out preview, where it early-returns.)
- ✅ Closes on ✕, Escape, and backdrop click; clicking inside the card does not
  close; the Escape listener does not leak after close.
- ✅ Header at `max-width: 480px` on desktop; at 375px the card is 92vw (345px)
  and the facts stack vertically with separators hidden.
- ✅ No console errors throughout.

## Follow-up changes (same session)

After testing while signed in, two more things were addressed:

### 1. The *whole* row is clickable — including manually-added programs

The first build only wired up catalog rows. When signed in, a user's own
manually-added programs render at the **top** of the table via a separate
function (`_userAddedRowHTML`), so clicking them did nothing. Fixed by:

- A new `_psResolve(progId)` helper that resolves **both** id types — numeric
  catalog ids (looked up in `progs[]`) and synthetic `'ua-<appId>'` ids
  (rebuilt from `apps[]`). `openProgramSnapshot` and `_psSaveField` now route
  through it, so the snapshot opens — and saves — for user-added rows too.
- User-added rows show a **"★ Added by you"** marker in the badge slot (their
  `status` is a pipeline stage, not open/rolling/watch), no description section,
  and the tracked label + editable deadline/notes (they're always in the
  pipeline).
- The trigger + `stopPropagation` guards were also added to the **mobile card
  view** (`_mobileCardHTML` and `_userAddedCardHTML`), so every catalog and
  user-added card is clickable on mobile as well.

Verified live (signed in): catalog rows still open (no regression); a user-added
row (Houlihan Lokey) opens with "★ Added by you" + "✓ Tracked · Applied" +
editable fields; mobile catalog and user-added cards both open the snapshot; no
console errors.

### 2. Command Center stat-card navigation

In `_renderCCStats()`, the **"Networking Stage"** card pointed at the Networking
tab. A networking *stage* is a pipeline stage, so it now opens **My
Applications** (`showPage('applications')`). The **"Contacts · People tracked"**
card already correctly opened the **Networking** tab (`showPage('networking')`)
and was left as-is.

Verified live: clicking "Networking Stage" activates `page-applications`;
clicking "Contacts" activates `page-networking`.

### 3. Command Center "Offers" card → "Interview" card

Candidates stop tracking once they have an offer, so the **Offers** stat card was
replaced with an **Interview** card that counts programs at the interview stage
(`status === 'interview'`). To avoid double-counting, the **Applied** card was
also narrowed from `applied || interview` to just `applied` — so the two cards
now partition cleanly. (Offers are still shown in the Pipeline Funnel below.)

Verified live: with one app flipped to interview (in memory), Applied went 2→1
and Interview went 0→1 — no double count; the Interview card opens My
Applications.
