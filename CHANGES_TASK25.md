# Task 25 — Deadlines rows: stacked cards on mobile

## The bug

At 360–375px the `.dlitem` row is a horizontal flex container with
`.dldate` (min-width 115px) on the left and `.dldays` (min-width 80px)
on the right, leaving the middle name/org block ~140px. The name then
wraps one-word-per-line and the days pill collides with the wrapped
title. Visually unreadable.

## Fix (CSS-only, no `_renderRow` changes)

All rules added inside the existing `@media (max-width: 720px)` block.
The middle name/org div is targeted via `[style*="flex:1"]` because
`_renderRow` writes it as an inline style (`<div style="flex:1;min-width:0">`).
That's brittle if the markup changes, but keeps app.js untouched as
required.

```css
.dl-bucket-rows .dlitem,
.dlitem {
  flex-direction: column;
  align-items: stretch;
  gap: 6px;
  padding: 14px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
.dl-bucket-rows .dlitem { border-bottom: 1px solid var(--border); }
.dlitem > div { min-width: 0; }
.dldate { order: 1; min-width: 0; font-size: 11px; }
.dlitem > div[style*="flex:1"] { order: 2; }
.dlname { font-size: 15px; }
.dldays { order: 3; min-width: 0; text-align: left; }
.dlitem-actions { order: 4; width: 100%; margin-left: 0; }
.dlitem-actions .ics-btn { width: 100%; justify-content: center; }
```

Stack order top → bottom:

1. **Date eyebrow** (`.dldate`) — small monospace date or "Rolling".
2. **Name + org** block — `.dlname` bumped to 15px so it reads as the
   card title; `.dlorg` keeps its 11px subtitle styling.
3. **Days pill** (`.dldays`) — left-aligned so it flows with the rest
   of the card content instead of orphaning on the right.
4. **CTA** (`.dlitem-actions`) — full-width row pinned at the bottom.
   For dated items this is the "📅 Set reminder" button (full-width via
   `.ics-btn { width: 100%; justify-content: center }`). For rolling
   items it's the existing "No fixed date / dlnote" span, also full-
   width.

### Why I restored card chrome on `.dl-bucket-rows .dlitem`

Line 622 strips background, border, border-radius, and shadow from any
`.dlitem` inside `.dl-bucket-rows` (the urgency-bucket accordions),
because the desktop view wants a dense flat list inside each bucket.
On mobile those buckets are still the primary view, but the dense list
look defeats "stacked card." I selectively put the card chrome back on
mobile only (`background`, `border`, `border-radius`, `box-shadow`),
while keeping the `border-bottom` divider so the row still reads as
"part of this bucket" rather than floating in space.

Specificity note: `.dl-bucket-rows .dlitem` (0,0,2,0) > `.dlitem`
(0,0,1,0), so I included it in the selector group rather than relying
on source order alone.

## `.dl-nudge` — keep or hide?

The spec said "your call." I kept it visible. Rationale:

- **Keep visible (chosen)**: `.dl-nudge` is a short coloured chip
  conveying genuine application-status context (e.g., "Applications
  not yet open" or "Closes soon"). In a stacked layout it sits on its
  own line under `.dlorg` and doesn't fight for horizontal space the
  way it did in the cramped flex row. The information density is low
  enough that hiding it would *remove signal* the user came to this
  page for.
- **Alternative (rejected)**: add `.dl-nudge { display: none }` inside
  the 720px block. Cleaner-looking cards, but at the cost of dropping
  status context that's specifically actionable on the Deadlines page.
  If user testing shows the chip causes visual fatigue, flipping this
  is one line and can ship later.

If you want me to hide it after seeing it on a real device, say the
word and I'll add the one-liner.

## Verification

At 360px each row is now a stacked card:

```
┌────────────────────────────────┐
│ Mar 15, 2026                   │  ← .dldate (order 1, eyebrow)
│ Program Name Here              │  ← .dlname  (order 2, 15px title)
│ Org Name                       │  ← .dlorg
│ [chip] (optional nudge)        │  ← .dl-nudge
│ in 23 days                     │  ← .dldays  (order 3)
│ ┌────────────────────────────┐ │
│ │      📅 Set reminder       │ │  ← .dlitem-actions (order 4)
│ └────────────────────────────┘ │
└────────────────────────────────┘
```

- No horizontal scroll on the page.
- Name and days pill never collide — they're in separate flex items
  on separate lines.
- One full-width CTA per card.
- Urgency-bucket accordions (This week / This month / Next 60 /
  Rolling / Later) are unchanged in structure and open/close behavior.

Desktop (>720px): media query doesn't apply. Base `.dlitem` row
(line 326), `.dl-bucket-rows .dlitem` flat-list override (line 622),
and the original horizontal layout all render unchanged.

## What was NOT changed

- `app.js _renderRow` markup (per spec).
- Base `.dlitem`, `.dldate`, `.dlname`, `.dlorg`, `.dldays`,
  `.dlitem-actions`, `.ics-btn`, `.dl-nudge` rules at lines 326–331,
  593–595, 622–628.
- Accordion bucket logic.
