# Task PERF3 — Funnel bar chart + frozen kanban headers

Two follow-ups on the Command Center funnel and the My Applications board. All in
`app.js` + `styles.css` (no `index.html`, no DB change).

## 1. Pipeline funnel → horizontal bar chart with a fixed axis
The PERF2 funnel scaled each bar to the busiest stage, so a tiny pipeline still looked
"full" and there was no sense of magnitude. **Fix:** `_renderCCFunnel()` now draws a
proper horizontal bar chart against a shared x-axis:
- **Axis starts at 5** and only grows — in whole steps — once a stage count exceeds it
  (`scaleMax = max(5, ceil(maxCount/step)*step)`, `step` chosen for ~5 gridlines). So 1
  app shows as a short bar on a 0–5 axis; 7 apps grows the axis to 8 (ticks 0/2/4/6/8).
- Each stage bar is sized as `count / scaleMax`, with light **vertical gridlines** on
  the track (spacing set inline via `--grid` to match the ticks) and a numeric
  **x-axis** (`.cc-funnel-axis` / `.cc-funnel-tick`) aligned under the bars.
- Stage colour dot + label on the left, count on the right (unchanged).

Verified numerically in-browser: small pipeline → scale 5, bars at 20% for count 1;
larger pipeline (max 7) → scale 8, bars at 87.5 % / 50 % / … , gridlines and ticks
aligned.

## 2. My Applications — frozen stage headers (Excel-style)
With many cards in one column, scrolling down lost track of which stage you were in.
**Fix:** each column header (`.khd`) is now `position: sticky; top: 56px` (just below
the 56 px sticky topbar) with a solid background, a bottom border, and negative margins
that span the column's padding so cards never show through as they scroll underneath.
Each column's header stays frozen until that column ends — exactly like freezing a
header row in Excel. On mobile (columns stack vertically) the header is reset to
`position: static`, keeping the current behavior.

## Verification
- `node --check app.js` → **PASS**.
- Loaded via the `ldp-static` preview: no console errors.
- Bar-chart geometry confirmed by reading computed widths/tick positions for both a
  small (max 1) and a larger (max 7) pipeline.
- Kanban header confirmed to compute to `position: sticky; top: 56px; z-index: 5` with
  a solid background (so it won't override on the page and cards stay hidden behind it).

### Not exercised (auth-gated)
Sign-in needs an emailed OTP, so the live signed-in screens weren't driven end-to-end.
After pulling, worth a quick check:
1. Command Center → funnel reads as a bar chart with a 0–5 axis that grows as stages
   fill up.
2. My Applications → pile 10–15 cards into one stage, scroll down: the stage headers
   stay pinned at the top while cards scroll under them.
