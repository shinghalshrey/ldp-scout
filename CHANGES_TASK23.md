# Task 23 — Static two-row mobile nav (no horizontal scroll)

## What changed

### `index.html`
The five `.nav-tab` buttons now carry a `data-short` attribute alongside
their full text. The full text stays in the DOM (assistive tech still sees
"My Applications", not "Apps"); CSS swaps the visual label on mobile.

| Full label       | data-short  |
| ---------------- | ----------- |
| Programs         | Programs    |
| ✦ AI Fit Scan    | AI Fit      |
| Alumni Finder    | Alumni      |
| My Applications  | Apps        |
| Deadlines        | Deadlines   |

### `styles.css` — removed
The Task 21.3/21.4 scrollable-rail block inside `@media (max-width: 720px)`
(former lines ~1364–1375): `.nav-tabs { overflow-x:auto; mask-image:… }`,
`.nav-tabs::-webkit-scrollbar { display:none }`, `.nav-tab { flex-shrink:0 }`.

### `styles.css` — added (same `@media (max-width: 720px)` block)
- `.topbar { flex-wrap: wrap; height: auto; row-gap: 6px; padding: 8px 12px; }` —
  lets the bar grow into two rows.
- `.brand { order: 1 }`, `.topbar-right { order: 2; margin-left: auto }`,
  `.nav-tabs { order: 3; flex-basis: 100%; width: 100% }` — row 1 holds
  brand + sign-out/freshness, row 2 is the tabs alone.
- `.nav-tabs { overflow: visible; mask-image: none; -webkit-mask-image: none;
  justify-content: space-between; gap: 4px }` — undo the scroll rail and
  let tabs share the row evenly.
- `.nav-tab { flex: 1 1 0; min-width: 0; padding: 6px 4px; font-size: 0;
  text-align: center; white-space: nowrap }` — equal-width chips; `font-size:0`
  hides the original long label.
- `.nav-tab::before { content: attr(data-short); font-size: 11px }` — paints
  the short label.

## Spec deviation: `::before` instead of `::after`

The spec said `.nav-tab::after { content: attr(data-short) }`. I used
`::before` instead. Reason: `styles.css:668` already defines

```css
.nav-tab.needs-attention::after { content:''; position:absolute; ... }
```

for the coral pulse dot. An element has exactly one `::after`; if both
rules apply, `.nav-tab.needs-attention::after` has higher specificity
(0,0,2,1 vs 0,0,1,1), so its `content: ''` would win — blanking out the
label on every tab that has an alert. Using `::before` for the label
gives each pseudo-element its own job and keeps both working at once.
The visible result matches the spec; only the pseudo-element name
changed.

## Cascade audit (the Task 21.1 lesson)

Greps:

- `grep -n '\.nav-tabs' styles.css` — three hits: base rule (32), the
  removed Task 21 block (1364), the new Task 23 block.
- `grep -n '\.nav-tab' styles.css` — base (33), `.active` (34),
  `position:relative` (667), `.needs-attention::after` (668), the
  `@media (max-width:768px)` rule at 956
  (`.nav-tab { font-size: 12px; padding: 6px 10px; }`), and the new
  Task 23 rules.
- `grep -n '\.topbar' styles.css` — base (27), `.topbar-right` (35), the
  `@media (max-width:768px)` rule at 950
  (`.topbar { padding: 0 12px; gap: 8px; }`), and the new Task 23
  `.topbar` override.

The 768px rules at 950/956 have the same specificity as the new 720px
rules but appear earlier in source order, so the 720px rules win at
widths ≤720 — no `!important` needed.

`.nav-tab.needs-attention::after` (line 668) is non-media; it stays
because the dot must show at every viewport. Specificity-wise it's
higher than the new `.nav-tab::before`, but they target different
pseudo-elements so they don't conflict. Coral dot still renders on top
of the short label.

The only `!important` retained is `.brand-name { display: none !important }`
from Task 21.4 — kept because that's how the brand text was being hidden
at ≤720; nothing in this task changes that.

## Verification

Mental layout at the two target widths (5 tabs, gap 4px, row padding 12px
each side, so usable row width minus gaps):

- 360px: `(360 − 24 − 4·4) / 5 = 64px` per tab. Longest short label is
  "Deadlines" at ~9 chars × ~6.3px @ font-size:11 ≈ 57px + padding. Fits.
- 412px: `(412 − 24 − 16) / 5 = ~74px` per tab. Comfortable.

No tab wraps because `white-space: nowrap`. No row scrolls because
`overflow: visible` and the row is exactly `100%` of the topbar via
`flex-basis: 100%`. The five tabs total < row width.

Desktop (>720px): media query doesn't apply, so the original `.nav-tabs`
(flex, gap 2px) and `.nav-tab` (padding 6px 16px, font-size 12px) rule
sets are unchanged. `data-short` attributes are inert because no
`::before` rule exists outside the 720px block, and `font-size:0` is not
applied. Full labels render exactly as before.

Coral `.needs-attention` dot: unaffected — it's painted by `::after`,
positioned absolutely top-right with a 7×7 footprint. The `::before`
short label is rendered as normal inline content inside the button, so
they don't share screen real estate.
