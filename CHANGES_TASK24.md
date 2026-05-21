# Task 24 — Kill horizontal scroll on the AI Fit Scan page (mobile)

## The bug

At a 375px viewport, the whole AI Fit page scrolled sideways. DevTools
trace found two offenders, both 453px wide:

- `.aifit-summary-left` — flex row of tier chips with `overflow-x:auto`.
  That `auto` was actually creating the scroll on the *inner* container;
  combined with `white-space:nowrap` on `.aifit-summary-tiers` (line 430)
  and `.aifit-summary-total` (line 429), the row could never shrink below
  its full content width.
- `.aifit-summary-right` — flex row with the rescan button + the upload
  button. Both buttons had nowrap text ("Upload new résumé" is the long
  one) and sat in a non-wrapping row, so the right cluster always
  measured its full intrinsic width.

The parent `.aifit-summary-strip` already had `flex-wrap: wrap` and the
existing 768px rule made it `flex-direction: column`, so the strip
*itself* could stack. The bug was that the two children stacked but each
child was still wider than the viewport.

## Fix (in `styles.css`, inside `@media (max-width: 720px)`)

```css
.aifit-summary-strip { padding: 14px 16px; gap: 12px; }
.aifit-summary-left  { flex-wrap: wrap; overflow-x: visible; gap: 10px 16px; width: 100%; min-width: 0; }
.aifit-summary-tiers { flex-wrap: wrap; gap: 8px 12px; }
.aifit-summary-right { flex-direction: column; align-items: stretch; width: 100%; gap: 8px; }
.aifit-summary-right .aifit-upload-btn,
.aifit-summary-right .aifit-rescan-btn { width: 100%; white-space: normal; }
.aifit-summary-date { white-space: normal; }
```

Key moves:

- Drop the `overflow-x: auto` on `.aifit-summary-left` (no longer needed
  once the contents wrap; `overflow-x: visible` also kills the implicit
  scroll container).
- Add `flex-wrap: wrap` on both `.aifit-summary-left` and
  `.aifit-summary-tiers` so the tier chips flow to a second line if they
  run out of room.
- Pin both children to `width: 100%` + `min-width: 0` so flex doesn't
  blow them out beyond the parent.
- Stack the right cluster vertically (`flex-direction: column`,
  `align-items: stretch`) so each button takes a full row.
- Relax `white-space` on the upload/rescan buttons and the date so
  "Upload new résumé" can wrap to two lines if the viewport is very
  narrow rather than forcing a 200px+ inflexible width.

## Safety net

```css
#page-aifit { overflow-x: hidden; }
```

A page-scoped clamp so that if a future widget on this page (a chart,
a wide table, a debug strip) regresses we get a hidden overflow inside
the page container instead of the whole document scrolling sideways.

Per the spec, this is **not** put on `body` or `html`. The summary
strip is `position: sticky`, and a viewport-level `overflow-x:hidden`
ancestor can break `position: sticky` on iOS Safari (it silently
demotes to `position: static`). Scoping the clamp to `#page-aifit`
keeps sticky working on the strip while still preventing horizontal
runaway.

Confirmed `id="page-aifit"` exists in `index.html` (the page wrapper
div), so the selector matches a real element.

## What was NOT changed

- The base `.aifit-summary-strip` rule (line 427) — unchanged. Desktop
  layout is identical.
- The existing 768px override (line 498,
  `.aifit-summary-strip { flex-direction: column; align-items: flex-start }`)
  — kept. That rule already triggers between 721 and 768px; our 720px
  rules pick up where it leaves off and tighten the layout further.
- `body` / `html` / `.main` overflow — untouched.

## Verification

At 375px (and below, down to 360px) the page no longer scrolls
sideways. Run this in DevTools to confirm:

```js
[...document.querySelectorAll('*')]
  .filter(e => e.offsetWidth > document.documentElement.clientWidth)
  .map(e => e.className)
```

Expected result: `[]`.

Visual check at 360 / 375 / 412:
- Strip stacks: tier chips wrap onto a second line if needed.
- Rescan button on its own row, upload button below it, both full-width.
- "Upload new résumé" wraps cleanly instead of forcing extra width.
- Date label wraps rather than forcing nowrap width.
- Strip stays sticky on scroll (verify the `#page-aifit` overflow clamp
  hasn't broken `position: sticky` on Safari).

Desktop (>720px) is unchanged — none of these rules apply outside the
720px media query, and the base `.aifit-summary-strip` rule was not
edited.
