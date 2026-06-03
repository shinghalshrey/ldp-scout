# Task PERF4 — Font, shortlist toggle, targeting bar charts, Command Center layout

Four changes across `index.html`, `styles.css`, `app.js`. No DB change, no build step.

## 1. New product font — Source Sans 3 (body)
The body font was **Outfit**, which read as generic. Swapped the whole product's body
typeface to **Source Sans 3** (a calm, professional UI sans): updated the Google Fonts
`<link>` and the `--sans` CSS variable. Everything inherits `var(--sans)`, so the change
is global. Display headings stay on the **Fraunces** serif and code/numerals on **DM
Mono** (unchanged).

## 2. AI Fit Scan "Shortlist" button — always visible + toggle
Previously the button only appeared on row hover and could only *add*. Now:
- It's **always visible** (removed the `opacity:0` / hover-reveal).
- It reflects state via `_findAppForProgram`:
  - not in pipeline → **"+ Shortlist"** (adds at the Shortlisted stage)
  - already shortlisted → **"✓ Shortlisted"**, which turns red and reads **"✕ Remove"**
    on hover → clicking **un-shortlists** (removes from pipeline)
  - already in pipeline at another stage → **"✓ <Stage>"** (hover "✕ Remove"; asks for
    confirmation before removing, so you don't lose a later-stage card by accident)
- New `toggleShortlist()` handles add/remove and re-renders the results in place
  (`_rerenderAIResults()` replays the last scan from memory — no re-scan, no quota use).

## 3. "Where you're aiming" → bar charts with a fixed axis
The three targeting lists (Geographies / Sectors / Functions) were scaled to each list's
own max (so a single entry always looked full). They're now **bar charts on a fixed
x-axis**, matching the pipeline funnel: the axis **starts at 5 and grows in increments of
5** (`scaleMax = max(5, ceil(max/5)*5)`), with light vertical gridlines and numeric ticks
(0 … 5 / 10 / 15 …) aligned under the bars. So 1 app shows as a short bar on a 0–5 axis,
and the scale only grows once a city/sector/function passes 5/10/…

## 4. Command Center layout — two-column, "Next steps" removed
**On "Next steps · action items":** it listed each application's free-text `next` field as
a to-do. In practice it's mostly empty and overlaps with **Upcoming deadlines**, so it
added clutter more than signal. **Removed it.** (The data isn't lost — the `next` field
still lives on each application and shows in My Applications; `_renderCCNextSteps()` is
just no longer called and can be re-enabled if you ever want it back.)

New layout, top to bottom:
1. Pipeline stat cards
2. **Pipeline funnel (left) + Upcoming deadlines (right)** — equal halves via the existing
   `.cc-two-col` grid, so the funnel is narrower and the deadlines sit beside it
3. **Where you're aiming** (moved up — now directly under the main row)
4. Networking snapshot

If the deadlines list grows (many dated programs), that column gets taller and the
sections below simply shift down — the layout stays clean. On mobile the two columns
stack.

## Verification
- `node --check app.js` → **PASS**.
- Loaded via the `ldp-static` preview: **zero console errors**; `document.fonts` confirms
  Source Sans 3 is loaded and `body` computes to it.
- Targeting scale verified: max 3 → axis 5; max 7 → axis 10; max 12 → axis 15.
- Measured the targeting axis vs bar track in-browser — **pixel-aligned** (both 167→665px).
- Shortlist button verified: `opacity:1` (always shown), `is-saved` = accent green, label
  spans swap to "✕ Remove" on hover.

### Not exercised (auth-gated)
Sign-in needs an emailed OTP, so the live signed-in Command Center / AI Fit results
weren't driven end-to-end. After pulling, worth a 1-minute look:
1. Whole app reads in Source Sans 3.
2. AI Fit Scan: every row shows a Shortlist button; shortlisting flips it to "✓ Shortlisted"
   and hovering shows "✕ Remove" which un-shortlists.
3. Command Center: funnel + deadlines sit side by side; "Where you're aiming" shows bar
   charts on a 0–5 (growing) axis; no "Next steps" section.
