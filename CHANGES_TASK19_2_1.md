# Task 19.2.1 — Programs page visual polish

Four targeted fixes after Pranav's first visual review of Task 19.2 in
production. All cosmetic — no behavioral or architectural changes.

> No DB changes. No new state. All four fixes are pure HTML/CSS, with
> one tiny piece of HTML restructuring (eyebrow line gets the tour link
> inline) and one piece of JS-side row-HTML pruning (remove the meta
> + description lines from each row).

---

## What this task did

### 1. Program meta + description removed from each row

The "FULL TIME · 2 YEARS" meta line and the truncated description
("Microsoft Aspire MBA is a 24-month experience focused on...") inside
the first column made rows visually uneven — some rows were 3x taller
than others, breaking the table's rhythm and pushing related rows below
the fold. Both blocks deleted from the row HTML template.

The same data is still accessible via the existing "+ Details"
disclosure on each row, so no info is lost — just hidden by default.

Kept in column 1: program name link · org + ✓ Visa badge · tags ·
✓ Verified May 2026 badge · + Details disclosure.

### 2. Full-height vertical column dividers

The Task 19.2 attempt used `border-left` on each grid cell directly.
Problem: cells with tall content (Program/Org with tags + Details
disclosure) made rows tall, but shorter cells (Function, Sector, Stage)
didn't stretch — so their `border-left` only drew to cell-content
height. Borders looked ragged.

Fix: every grid cell becomes a flex container via
`display: flex; flex-direction: column; min-height: 100%`. Combined
with grid's default `align-items: stretch`, every cell now spans full
row height regardless of its own content. The `border-left` (unchanged
from Task 19.2) now renders edge-to-edge.

First column (Program/Org) gets `justify-content: flex-start` so the
program name sits at the visual top of the row rather than vertically
centered between tags below it.

Pranav's preference (kept): light `--border` color, not the heavier
`--border2`. Just full-height.

### 3. Page tour link — moved to top, editorial styling

Old: bottom-of-page blue info-card (`var(--blue-bg)`, 3px left border,
mono font). Aesthetically out of place against the page's editorial
serif/mono palette — Pranav: "blue background seems odd."

Also old: a small "?" circle in the eyebrow that reopened the same
info-card when dismissed. Different visual language than everything
else on the page.

New: single inline "Tour this page →" link in the eyebrow line, right
after "Your LDP command centre". Same mono / uppercase / tracked-letter
treatment as the eyebrow text itself, so it reads as one cohesive line.
Hover state: color shifts to accent green, dashed underline picks up
accent color too.

Bottom info-card removed entirely from `index.html`. No more blue card.
The "?" reopen control gone too.

### 4. Accordion expanded-state — accent treatment

Old: when a sidebar filter section was open, the header looked the
same as closed (other than the chevron rotation). Pranav couldn't
quickly scan and tell which section was currently open.

New: open sections get a subtle `var(--accent-bg)` background tint
on the header, `var(--accent)` color on the label, and a green
chevron. Mirrors the visual language of the Stage dropdown's
`.stage-dd-opt.is-current` state for consistency.

Closed = neutral. Open = "you are here" in accent green.

---

## Files touched

| File | What changed |
|------|--------------|
| `app.js` | `meta` and `desc` `<div>` blocks removed from each row's HTML in `renderPrograms()`. The variable assignments above also dropped — they computed text that was never used after the removal. The "+ Details" disclosure is unchanged. |
| `index.html` | Welcome strip eyebrow line now contains: `Your LDP command centre · Tour this page →` instead of the previous "?" reopen control. Bottom blue info-card block (the one with `data-hint-key="programs_v1"` after the table) removed entirely. |
| `styles.css` | Three new rule groups appended. (a) `.prog-table-wrap .prow > *` / `.thead > *` set to flex column with `min-height: 100%` so border-left renders full-height. First column gets top-align. (b) New `.prog-eyebrow-sep`, `.prog-tour-link` rules for the new inline tour-link styling. (c) `.prog-side-acc.open .prog-side-head` rules for the accent-color expanded state. The Task 19.2 `border-left` rule at ~line 1270 is unchanged — the new flex-stretch rules just make the borders actually span full height now. |

---

## Manual test plan

### A. Row rhythm (program meta + description removed)
1. Programs page. Visually scan the list — all rows should look roughly the same height now (some variation from the tag count, but no wild outliers).
2. Microsoft Aspire row: should NOT show "FULL TIME · 2 YEARS" or the description text. Should still show the org name, ✓ Visa, tags (MBA, Product, Strategy), Verified May 2026 badge, and "+ Details" disclosure.
3. Click "+ Details" on Microsoft Aspire → the full description, eligibility, etc. is still accessible there.

### B. Column borders
1. Confirm vertical dividers run edge-to-edge of every row regardless of how tall that row's content is.
2. Specifically check rows with lots of tags (tall) vs rows with few tags (short) — the divider lines should look unbroken on both.
3. Color is light (--border, rgba 0.07) — subtle, not heavy. Matches Pranav's "keep the current light color" requirement.

### C. Page tour link
1. NO blue info-card at the bottom of the Programs page.
2. Eyebrow at top reads: "YOUR LDP COMMAND CENTRE · TOUR THIS PAGE →" all in mono / uppercase / tracked-letter.
3. Hover "TOUR THIS PAGE →" — color shifts to forest green, dashed underline picks up the accent color.
4. Click it → page tour starts (same as before, just the trigger location is different).

### D. Accordion accent
1. Programs page, sidebar. Click "Sector" header → section expands.
2. The header background shifts to a subtle pale green (`--accent-bg`).
3. "SECTOR" text is now forest green and bolder.
4. Chevron is forest green too.
5. Click any other section header — that one accents, Sector goes back to neutral.
6. Quickly scan the sidebar with several sections open — visually obvious which ones are open.
