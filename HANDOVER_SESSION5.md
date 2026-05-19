# LDP Scout — Handover, Session 5 (May 19, 2026)

## How to read this

This handover assumes the new chat has **PROJECT_OVERVIEW.md** and **DB_SCHEMA.md** pinned (they're the canonical reference for stack, auth flow, schema, and deploy commands — don't restate that here). This doc covers only what's specific to this session and what the next session needs to execute.

---

## What this session was

A planning + triage chat. No code shipped. Output was:
- Stale-doc cleanup across `PROJECT_OVERVIEW.md`, `DB_SCHEMA.md`, `SMOKE_TESTS.md` (now uploaded as updated versions).
- A scoped Lovable prompt for redesigning the Programs page.
- A killed feature idea (Happenstance-style LinkedIn 2nd-degree mapping — not viable, see "Dropped" below).
- A reshaped Task 19 that now bundles: page redesign + mandatory full-name onboarding + personalization across all five pages.

---

## Working approach (unchanged, locked in)

- **This chat (Claude.ai)** — planning, triage, debugging, drafting Claude Code prompts.
- **Claude Code (CLI)** — actual code changes. One task per session. Always paste back the diff for review.
- **Triage before building.** New issue mid-session → 2-min diagnostic first.
- **Test BOTH write AND read paths** before declaring task done (Task 1 lesson).
- **One Claude Code session per task.** Don't parallelize tasks touching the same file.
- **After every task:** smoke test on production after Vercel deploys.
- **Deploy gotcha:** frontend = `git push`. Proxy = `cd ldp-proxy && npx vercel --prod` from fresh PowerShell, NOT inside a Claude Code session.
- **Every Claude Code prompt includes:** diagnostic `console.log`s, and a request for a `CHANGES_TASKX.md` plain-English explainer.

## Tone preferences (the user is direct, time-constrained)

- Brief. No filler. No "great question."
- Assume the handover has been read. Don't restate it back.
- Flag stale comments, contradictions, or things that look wrong in pinned files even when not asked.
- When the user is wrong, say so. When uncertain, say so.

---

## Current state of pinned/uploaded files

**Updated this session (re-upload these, they replace the old versions):**
- `PROJECT_OVERVIEW.md` — proxy now correctly described as private GitHub repo with intentionally-manual deploys (was "not a git repo"). Auth flow rewritten for Task 9 reality. Duplicate "Known UI bugs" section deleted (all resolved). Stale-things list now only flags the scan.js Opus comment.
- `DB_SCHEMA.md` — duplicate `Anyone can read programs` policy noted as dropped. `email_account_status` RPC documented. Hardcoded password-user list replaced with a live query. `full_name` mandatory note added.
- `SMOKE_TESTS.md` — "6-digit" corrected to "8-digit". Test 3 tab list fixed (was referencing non-existent "Network"/"Bookings" tabs — actual tabs are Programs, AI Fit Scan, Alumni Finder, My Applications, Deadlines). Test 1 rewritten for the two-button Sign Up/Sign In split. New Test 5 covers mandatory full-name validation.

**Unchanged since Session 4 (re-upload current state):**
- `app.js`, `index.html`, `styles.css`, `scan.js`, `CHANGES_TASK9.md`, `CHANGES_TASK20.md`.

---

## Task 19 — fully scoped, ready to execute

### What it is
1. **Programs page redesign** — move the cluttered horizontal filter row into a 240px sticky LEFT sidebar matching the existing Alumni Finder layout. Lovable does the HTML+CSS; we paste into existing files. **No JS rewrite** — DOM contract preserves all existing IDs, classes, and onclick handlers.
2. **Mandatory `full_name` capture in onboarding** — Next button disabled until non-empty, trim whitespace, no skip path.
3. **Personalization across all five pages** — first name in welcome lines, scan counts, pipeline counts, etc. Reads `userProfile.full_name.split(' ')[0]`.

### Execution order (do not parallelize)
1. User pastes the Lovable prompt below into Lovable.app, gets HTML+CSS back, brings it to the new chat.
2. New chat reviews the Lovable output for contract violations (preserved IDs, no Tailwind, no React, etc.), flags anything that needs revision.
3. New chat drafts the Claude Code prompt covering: (a) Lovable HTML/CSS integration, (b) mandatory full-name validation in onboarding, (c) personalization JS for all five pages, (d) `CHANGES_TASK19.md`.
4. User runs Claude Code, pastes diff back to the chat for review.
5. Git push → Vercel deploys → smoke test (Test 5 in `SMOKE_TESTS.md` is the canonical check, plus production click-through of each personalized page).

### The Lovable prompt (ready to paste)

```
Redesign the "Programs" page of a web app called LDP Scout — a résumé-to-MBA-leadership-program matcher. Output HTML + CSS only (no React, no JS framework). The HTML will be pasted into an existing index.html, the CSS into an existing styles.css. JavaScript already exists and must remain untouched.

DESIGN GOAL
The current page has a cluttered horizontal filter bar with ~15 pills in a single row above the results table. I want to move all filters into a 240px sticky LEFT sidebar (matching the existing Alumni Finder page layout) and use the main column for: a personalized welcome header, key stats, and the program results table.

EXISTING DESIGN TOKENS (do not invent new ones, use these CSS variables)
--bg, --bg2, --bg3        (page bg, card bg, input bg — light cream/off-white feel)
--text, --text2, --text3  (primary, secondary, tertiary text)
--border, --border2       (subtle borders)
--accent                  (forest green ~ #1d6a45 — primary CTA)
--shadow, --shadow-md
--radius                  (~10–12px)
--serif                   (Fraunces — for h1/h2 display)
--sans                    (Outfit — for UI and body)
--mono                    (DM Mono — for stats, counts, code-style labels)

LAYOUT
Two-column grid, like the existing Alumni Finder:
- Left: 240px sticky sidebar (top: 80px), light card with --bg2, --border, --radius, 18px padding
- Right: flexible main column (min-width: 0 to allow overflow handling)
- Gap: 22px
- On viewports < 900px: stack to single column, sidebar becomes non-sticky

SIDEBAR CONTENTS (top to bottom, each section labeled with a small uppercase label `.al-sidebar-label` style: 10px, 600 weight, --text3, letter-spacing .08em, uppercase, 10px margin-bottom)
1. "SEARCH" — single text input, full width
2. "GEOGRAPHY" — vertical stack of pill buttons: All / Europe / UAE/Gulf / Global
3. "FUNCTION" — vertical stack: All / Operations / Finance / Strategy / Consulting / Investments
4. "STATUS" — vertical stack: All / Open / Rolling / Watch
5. "QUICK FILTERS" — two toggle pills stacked: "✓ Visa-sponsoring only" and "★ My Pipeline only"
6. Small "Pro Tip" card at the bottom (same visual treatment as the alumni page's `.al-pro-tip`) explaining: "Click any row to open program details. Save to pipeline with the + icon."

Pill buttons should look like the existing `.fpill` style — pill-shaped, border, 8–10px vertical padding, small font (~12px), with an active state that fills with --accent and uses white text. The active pill in each group is shown with class "on".

MAIN COLUMN (top to bottom)
1. PERSONALIZED HEADER STRIP — this is critical, supports two states:

   STATE A (default, shown by JS when userProfile.full_name is populated):
   - Eyebrow text: "Your LDP command centre" (small caps, --mono, --text3, 11px)
   - h1: "Welcome back, <span id='prog-welcome-name'>there</span>." in --serif, 28–32px, --text. The span gets filled by JS with the user's first name post-onboarding.
   - Sub-stat line in --text2, 14px, reading: "<span id='prog-welcome-pipeline'></span> · <span id='prog-welcome-deadlines'></span>" — these two spans are filled with strings like "8 programs in your pipeline" and "3 deadlines this month" by JS. If the counts are 0, JS replaces them with fallback copy ("Start building your pipeline below").

   STATE B (fallback, shown by JS pre-onboarding or when full_name is empty):
   - Eyebrow: "All programs"
   - h1: "393 verified MBA LDP programs."
   - Subline: "Filter, search, and save to your pipeline."
   - Same DOM structure — JS swaps text content but does not rebuild the elements.

   Both states use the SAME element IDs. The JS toggles innerText on each. Make sure the h1 wraps the name in a span as shown so JS can target it.

2. STAT STRIP (id="prog-stats") — keep this div, my JS already injects 3–4 stat tiles here. Do not generate stat content, just leave an empty div with that ID and good spacing around it.

3. FIT BANNER MOUNT (id="fit-banner-mount") — also keep as empty div, my JS injects an AI-fit summary card here when the user has scanned a resume.

4. RESULTS META ROW (id="prog-meta") — empty div for "Showing X of 393" text my JS injects. Right-align an "+ Add Program" ghost button next to it.

5. PROGRAM TABLE (id="prog-list" wrapped in a .table-wrap card with a .thead row)
   - Keep the existing 9-column thead structure exactly:
     Program / Organisation · Function · Sector · Location · Deadline · Status · Fit ✦ · 📅 Remind · Pipeline · Actions
   - Columns 1–6 are sortable (clicking calls sortBy(key)) — render a ▼ arrow next to each label
   - Use a clean card-style table — light row dividers, hover state with --bg3 background, no zebra striping
   - The body (#prog-list) is filled by my JS — leave it empty in your output

CRITICAL DOM CONTRACT (must preserve, do not rename or remove)
IDs: prog-search, prog-stats, fit-banner-mount, prog-meta, prog-list, visa-pill, page-programs, prog-welcome-name, prog-welcome-pipeline, prog-welcome-deadlines
Classes: page (on root), active (when shown), fpill, fpill.on, pipeline-toggle, table-wrap, thead, th, sortable, th-arrow
onclick handlers (preserve verbatim):
  - oninput="renderPrograms()" on the search input
  - onclick="setF('geo',this)" with data-geo="all|europe|uae|global" on geo pills
  - onclick="setF('fn',this)"  with data-fn="all|operations|finance|strategy|consulting|investing" on function pills
  - onclick="setF('st',this)"  with data-st="all|open|rolling|watch" on status pills
  - onclick="toggleVisaFilter(this)" on visa pill (id="visa-pill")
  - onclick="togglePipelineFilter()" on pipeline pill (class includes "pipeline-toggle")
  - onclick="openM('prog')" on the Add Program button
  - onclick="sortBy('name|fn|loc|deadline|status|fit')" on each sortable th

OUTPUT FORMAT
Return TWO code blocks:
1. The HTML block — the entire contents of `<div class="page active" id="page-programs">…</div>` (replace the existing one)
2. The CSS block — additions and overrides to be appended to styles.css. Use a `.prog-` prefix for any new classes to avoid collisions. Do not rewrite existing `.al-*` or `.fpill` rules — extend them via new selectors if needed.

DO NOT
- Do not output JavaScript, React, Tailwind classes, or shadcn imports.
- Do not change tag names of elements with the listed IDs.
- Do not invent new color values — use only the listed CSS variables.
- Do not remove or rename any of the onclick handlers or data attributes.
- Do not add any external image, icon library, or font — use Unicode characters (✓, ★, ✦, ▼, 📅) for icons, same as the existing app.

VISUAL REFERENCE
Editorial, restrained, MBA-recruiting-tool feel. Think Stripe Press meets a clean alumni directory. NOT a SaaS dashboard. No gradients, no glassmorphism, no emoji-heavy decoration. Generous whitespace. Serif headlines (Fraunces), sans body (Outfit), mono for stats (DM Mono).
```

### Full personalization spec (for the Claude Code prompt)

All keys off `userProfile.full_name` being a non-empty string. JS helper: `getFirstName() => (userProfile?.full_name || '').trim().split(/\s+/)[0] || null`. If null, fall back to STATE B copy on each page.

| Page | Element | Personalized copy |
|---|---|---|
| Programs | h1 | "Welcome back, {firstName}." |
| Programs | sub-stat | "{N} programs in your pipeline · {M} deadlines this month" (fallback: "Start building your pipeline below" when both 0) |
| AI Fit Scan (pre-scan) | header | "Ready when you are, {firstName}." + "{scansLeft} of 3 scans remaining." |
| AI Fit Scan (post-scan) | results header | "{firstName}, here are your top {N} matches across 393 programs." |
| Alumni Finder | h2/sub | "Find alumni at your target programs, {firstName}." + "{schoolName} alumni searches are starred." |
| My Applications | h2/sub | "{firstName}'s pipeline · {N} programs across {stages}" |
| Deadlines | h2/sub | "{firstName}, {N} of your pipeline programs have deadlines in the next 30 days." |
| Topbar | user-info span | First name + school chip (currently shows email) |
| Profile modal | title | "{firstName}, edit your details" |
| Onboarding step 1 | heading | "Welcome to LDP Scout. What should we call you?" |

**Stat-substitution rule:** any `{N}` token is only shown when the count is reliably non-zero. JS checks the value before substituting; HTML provides empty `<span>` placeholders.

### Mandatory full-name validation (onboarding)

- Onboarding Step 1 currently has a name input. Add: Next button stays `disabled` unless `input.value.trim().length >= 1`.
- On submit: `.trim()` the value before writing to `user_profiles.full_name`. Block whitespace-only.
- No skip path. Remove or hide the "Skip for now" button on Step 1 only (other onboarding steps can keep skip).
- Existing users with NULL `full_name` (10 rows pre-Task 19, see DB_SCHEMA query) → on next sign-in, the Profile modal opens automatically with the name field focused. They can't dismiss until name is filled.

---

## Task list

| # | Task | Status | Est. | Notes |
|---|---|---|---|---|
| 19 | Programs redesign + mandatory full_name + personalization on 5 pages | ⏳ NEXT | 3 hr | Lovable → review → Claude Code |
| 22 | Pipeline filter on Alumni Finder | ⏳ | 30 min | After 19. User wants pipeline tab inside alumni-connect to scope alumni search to pipeline programs |
| 23 | "Reached out to alumni" checkbox per program | ⏳ low | 1 hr | After 22. Boolean per (user, program) — no third-party CRM data |
| 21 | OG meta tags (og:image, longer og:description) | ⏳ low | 30 min | LinkedIn Post Inspector flagged this |
| 5 | Cost optimization | ⏳ | 2 hr | Audit Phase 16 P3 first: `git show 1903137 --stat` then `git show 1903137 -- app.js` |
| 7 | Mobile responsiveness | ⏳ weekend | 4-6 hr | Task 19 banks the Programs-page mobile work via <900px stacking in the Lovable spec |

## Dropped this session

- **Happenstance-style LinkedIn 2nd/3rd-degree mapping at a target company.** Not viable: LinkedIn API doesn't expose network graph data; the only ways to get it are (a) browser-extension scraping (TOS violation, LinkedIn actively kills these), (b) Connections.csv upload (1st-degree only, stale immediately), or (c) buying PDL/Apollo data which doesn't include the user's network so adds no value over LinkedIn's own search. Happenstance itself pivoted off this. **The legitimate version** of what the user wanted is Task 22 (pipeline filter on Alumni Finder) + Task 23 ("reached out" tracking), which is what we're building instead.

---

## Known stale things in pinned files (Session 5 status)

- **`scan.js` line ~25 comment** mentions "Opus 4.7" but `ALLOWED_MODELS` whitelists `claude-opus-4-6`. Decide before Task 5 cost work.
- **`DB_SCHEMA.md`** lists only Session 3's password-user count. Re-query before referencing — count grows with every Task 9 password-setup.

Everything else flagged in Session 4 is now clean.

---

## Honest meta for next session

- Lovable output needs to be sanity-checked before the Claude Code paste. Specifically: did Lovable preserve every ID and onclick handler verbatim? Did it use the existing CSS variables instead of inventing hex codes? If it returns Tailwind classes or React anywhere, reject and re-prompt.
- Task 19 is bigger than it looks because it's three tasks bundled. If the user is short on time, split it: 19a (Lovable integration), 19b (mandatory name), 19c (personalization sweep). Three Claude Code sessions instead of one.
- The personalization spec assumes all five pages currently have static `<h2>` and `<p>` elements that JS can target. Verify in `app.js` — there may be pages that re-render their header on every state change, in which case the personalization logic needs to live inside those render functions, not in a one-shot init.

---

## Files to upload at start of next session

**Re-upload (these have changed this session):**
- `PROJECT_OVERVIEW.md`
- `DB_SCHEMA.md`
- `SMOKE_TESTS.md`
- This handover (`HANDOVER_SESSION5.md`)

**Re-upload (current local state, unchanged this session):**
- `app.js`
- `index.html`
- `styles.css`
- `scan.js`
- `CHANGES_TASK9.md`
- `CHANGES_TASK20.md`

**Don't bother:**
- `HANDOVER_SESSION4.md` (superseded)
- `CHANGES_TASK1.md` / `1B` / `2` / `2B` / `3` (too old; covered in PROJECT_OVERVIEW)
- `data.js` (393 program records; only upload if a task touches program data shape)
- `LDP_audit_scoresheet.xlsx` (irrelevant to code work)

**Pin (one-time, stays across chats):**
- `PROJECT_OVERVIEW.md`
- `DB_SCHEMA.md`
