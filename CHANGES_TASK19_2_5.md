# Task 19.2.5 — Programs table: CSS Grid → CSS Table for true column alignment

One fix. The Programs table now uses `display: table` instead of `display: grid`,
which makes column widths shared across all rows. Vertical dividers form
truly continuous lines.

> No DB changes. CSS only.

---

## What this task did

### The real bug Pranav was seeing all along

**Pranav (sharper observation than I'd been understanding):** "bro can
you see the vertical borders between two columns? do those look aligned
to you?? why are you focusing on the rows. look at the columns and see
the borders. they aren't in one line"

**I was diagnosing the wrong problem.** I'd been focused on vertical
alignment of TEXT within cells. The actual issue was that the column
BOUNDARIES themselves zig-zagged from row to row. The vertical divider
between Function and Sector wasn't a straight line down the table —
it shifted left/right by a pixel or two depending on each row's content
widths.

**Root cause:** `.prow` and `.thead` both use `display: grid` with
`grid-template-columns: 2.0fr 0.7fr 0.8fr 1.0fr 0.7fr 0.6fr 0.7fr 1.0fr 0.7fr`.
**Each row independently computes its own column widths.** CSS Grid's
fractional units take into account intrinsic content min-widths — so a
row with a long program name ("Maersk Commercial Graduate Programme")
gets slightly different absolute column widths than a row with a short
program name ("DHL Consulting LDP"). Three rounds of cell-alignment
fixes were band-aids on this fundamental issue.

**Fix:** switched the Programs table to `display: table` with
`table-layout: fixed`. Tables share ONE column-width calculation
across all rows by design. That's literally what HTML tables exist
for. Column widths declared as percentages on the thead cells; all
data rows inherit identical widths.

Result: vertical dividers between columns form perfectly continuous
vertical lines down the entire table. No more zig-zag.

### What stayed

- Column 1 (Program/Org): top-aligned (`vertical-align: top`)
- Columns 2-9: vertically centered (`vertical-align: middle`)
- Cell padding, border colors, hover backgrounds, font choices: identical
- Vertical borders between cells via `border-left` on each non-first cell
- Horizontal row separators via `border-bottom` on cells (last row has none)

### What changed in implementation

- `.prog-table-wrap { display: table; width: 100%; table-layout: fixed; border-collapse: collapse }`
- `.prog-table-wrap #prog-list { display: table-row-group }`
- `.prog-table-wrap .thead { display: table-row }`
- `.prog-table-wrap .prow { display: table-row }`
- `.prog-table-wrap .thead .th { display: table-cell; ... }`
- `.prog-table-wrap .prow > * { display: table-cell; ... }`
- Column widths declared as percentages on thead's `nth-child` cells.
  Total = 100%.
- All flex-cell stuff from 19.2.3/19.2.4 removed (no longer needed).

### What broke / what to verify

The HTML structure inside cells didn't change — `.pname`, `.porg`,
`.tags`, `.cell`, `.badge`, `.fit-tier`, `.stage-dd`, `.ics-btn` all
render unchanged. The new wrapper just delivers them inside `table-cell`
elements instead of `grid-item` div children.

Two minor concerns to verify in production:
- Stage column's "+ Add to pipeline" dropdown button is the widest cell content (~130px). Column 8 set to 12% ≈ 156px on a 1300px viewport. Should fit with cell padding; if it gets clipped, bump column 8 width slightly.
- Sortable th's previously used `display: flex` for the arrow alignment. With `display: table-cell`, the arrow now renders inline (text + arrow span). Visually the same; the gap is just an inline space instead of a 5px flex gap. Acceptable.

---

## Files touched

| File | What changed |
|------|--------------|
| `styles.css` | The big Task 19.2.3/.4 cell-flex block (~50 lines) replaced with the CSS-table block (~70 lines). Net change: simpler, fewer rules, behavior matches expectation. |
| `app.js` | No changes. |
| `index.html` | No changes. |

---

## Manual test plan

### A. Column boundaries
1. Programs page. Look at the vertical divider between Function and Sector columns.
2. Trace your eye down the divider from header to last visible row.
3. **The divider should be a perfectly straight vertical line, no jogs left or right between rows.**
4. Repeat for every other column boundary (Sector/Location, Location/Deadline, Deadline/App Cycle, App Cycle/AI Fit, AI Fit/Stage, Stage/Reminder).
5. If any divider jogs, take a screenshot and flag — there's a deeper issue.

### B. Column widths sensible
1. Program names should all fit comfortably (Microsoft Aspire Experience, IFC / World Bank Young Professionals — these are some of the longer ones).
2. Stage column's "+ Add to pipeline" button shouldn't get clipped on the right.
3. Reminder column's "Set" button or "—" placeholder should fit.

### C. Existing behavior still works
1. Click column headers — sort still works.
2. Stage dropdown opens, click outside closes, all the existing dropdown behavior intact.
3. Set Reminder modal opens on click.
4. + Visa badge shows on programs that have it.
5. AI Fit column shows tier badges (after a scan) or "Scan résumé" placeholder.

### D. No flicker, last-page persistence (Task 19.2.4 still working)
1. Refresh on Alumni Finder → stays on Alumni Finder, no Programs flash.
2. Refresh on Deadlines → stays on Deadlines.

### E. Other tables unaffected
1. My Applications page (Kanban) — unchanged.
2. Deadlines page — unchanged.
3. AI Fit Scan results — unchanged.

---

## Honest debrief

This was my FOURTH attempt at column alignment over Tasks 19.2 → 19.2.4.
Each previous attempt addressed a real problem but didn't see the bigger
issue: CSS Grid computes column widths per-row, which is fundamentally
incompatible with "vertical dividers should form continuous lines."

What I should have done earlier: when Pranav said "vertical dividers"
in Task 19.2.1, I assumed they meant "borders between cells within a
row." They actually meant "the imaginary vertical lines formed by stacking
those borders across rows." Two different things. The first is per-row;
the second requires shared column widths across rows. Once I understood
that distinction, the CSS-table solution was obvious.

Lesson: when a CSS fix takes more than two iterations to get right,
the layout technology choice itself is probably wrong. CSS Grid is great
for many things; perfect-column-alignment-across-rows is not one of
them (without explicit pixel widths). For that specific need, CSS Table
is the correct primitive.
