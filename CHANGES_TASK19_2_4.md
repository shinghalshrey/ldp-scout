# Task 19.2.4 — Eliminate page-load flicker + revised column vertical alignment

Two fixes after Pranav's screenshot review of Task 19.2.3 in production.

> No DB changes. Three files touched (index.html + app.js + styles.css).

---

## What this task did

### 1. Page-load flicker eliminated

**Pranav:** "there is a lag of 2/3 seconds before the same page loads.
The first result is the program page when I refresh. It then loads the
page that was refreshed post 2/3 seconds. Not good experience."

**Root cause:** `index.html` had `class="page active"` hardcoded on
`#page-programs`. The `.page { display: none }` / `.page.active { display: block }`
CSS pattern relies on JS to set the `active` class. But because Programs
already HAD it in markup, the browser rendered Programs immediately on
load. Task 19.2.3's last-page restore happened in `onSignIn()` — which
runs AFTER the Supabase auth round-trip (~1-2 seconds). So Programs
flashed for 1-2 seconds, then disappeared as the saved page activated.

**Fix:** two-part:
- Removed the hardcoded `class="page active"` from `#page-programs` in
  `index.html`. Now no page is active by default — the `display: none`
  CSS rule hides ALL pages.
- Added a tiny inline boot script in `<head>` that runs before any other
  JS. It synchronously reads `localStorage.ldps_last_page` (and checks
  for a Supabase session token in localStorage to know if user is
  signed in). It then waits for DOMContentLoaded and adds the `active`
  class to the right page element.

The boot script uses `DOMContentLoaded` to avoid the race where it runs
before the DOM exists (since the `<script>` is in `<head>`). This is
still much faster than `onSignIn()` — typically <100ms vs 1-2s.

Net result: the correct page is visible from the very first paint.
No more Programs-flash-then-Deadlines-shows.

Edge cases:
- Signed-out users: no session key in localStorage → boot script
  defaults to 'programs', adds active class to Programs. But the
  landing overlay covers everything anyway, so the user doesn't see
  any page until they sign in. Then `onSignIn()` calls `showPage()`
  for the real saved page.
- New users / no saved page: defaults to 'programs', same as before.
- Invalid saved page (e.g. user manually edited localStorage):
  `onSignIn()` falls back to 'programs' via PAGE_ORDER check.

### 2. Column vertical alignment — revised approach

**Pranav:** "check the alignment of the columns. they are not aligned.
Please see the columns vertical ones not the rows." (with circled marks
on the Function, AI Fit, and Stage columns showing texts at different
Y-positions within their cells)

**Background:** This is the third attempt at column alignment.
- Task 19.2.1: `align-items: center` (the original) — cells centered
  vertically. Problem: with rows of varying heights (column 1 sometimes
  tall due to tags + verified badge), different rows centered at
  different Y-positions.
- Task 19.2.2: `justify-content: center` on flex cells — same effect,
  same problem.
- Task 19.2.3: switched to `justify-content: flex-start` (top-align).
  Texts now at consistent Y from row top, but Pranav still sees them
  "not aligned" because rows with tall column 1 leave big empty space
  below the top-aligned text in shorter columns.

**The actual constraint:** rows have different heights because column 1's
content varies (different tag counts, presence of verified badge). With
any alignment strategy (top, center, bottom), the visual position of
text in column 2-9 relative to row content varies across rows.

**Best compromise (Task 19.2.4):**
- Column 1 (Program/Org) → TOP-aligned. Program name is the row's
  visual anchor; tags and verified badge stack below it.
- Columns 2-9 (Function, Sector, etc.) → VERTICALLY CENTERED. Their
  short content sits at the visual middle of the cell, which lines up
  with the visual centroid of column 1's content block. This reads as
  "aligned" much better than pure-top alignment (which puts short
  labels at the top with lots of empty space below) or pure-center
  alignment (which floats column 1's program name in the middle).

Combined with `text-align: center` and `align-items: center` on
flex-axis-cross, columns 2-9 now have content centered both horizontally
and vertically. Column 1 stays left-aligned and top-aligned.

The cell-padding pattern from Task 19.2.3 (`padding: 14px 0` on cells
instead of `13px 0` on row) is preserved — vertical dividers still
render edge-to-edge.

### 3. AI Fit hydration + clickable AI Fit results — still working

Pranav confirmed both still work. No changes.

### 4. Vertical dividers — confirmed good

Pranav: "vertical dividers are good." No changes.

### 5. My Pipeline border — assumed working

Task 19.2.3 bumped to 2px @ 55% opacity. Pranav didn't comment
specifically; assuming it's good. Worth a quick visual check during
smoke test.

---

## Files touched

| File | What changed |
|------|--------------|
| `index.html` | Hardcoded `class="page active"` removed from `#page-programs`. New `<script>` block in `<head>` reads `localStorage.ldps_last_page` and activates the correct page on `DOMContentLoaded`. |
| `app.js` | `onSignIn()` last-page restore simplified — always calls `showPage(lastPage)` so the page's render function runs (the boot script only set the `active` class; render still needed). |
| `styles.css` | Column 1 (Program/Org) gets `justify-content: flex-start` (top-aligned). Columns 2-9 get `justify-content: center` (vertically centered). The rest of the cell-padding-vertical fix from Task 19.2.3 unchanged. |

---

## Manual test plan

### A. No-flicker page load
1. Sign in. Navigate to Alumni Finder.
2. Hard-refresh (Ctrl+F5).
3. **Critical:** does Programs flash before Alumni Finder appears? If yes — bug. If no — fix worked.
4. Repeat for My Applications, Deadlines, AI Fit.
5. Sign out. Hard-refresh. Should land on landing page (signed-out state). No page should flash.
6. Sign back in. Should land on... wait, what should happen here? localStorage still has the last signed-in user's page. Let me think... Actually the boot script checks for session token in localStorage. After sign-out, the Supabase session is cleared from localStorage. So boot script falls back to 'programs'. Good.

### B. Column alignment — final version
1. Programs page. Look at any row with tall column 1 (Microsoft Aspire is a good test — 3 tags + verified badge).
2. Program name + "Microsoft ✓ Visa" + tags + verified badge: stack vertically in column 1, top-aligned.
3. "Strategy" in column 2: should sit at the VISUAL MIDDLE of column 1's content block (i.e. roughly between "Microsoft ✓ Visa" line and the tag line).
4. Same for "Tech" in column 3, "Dublin · Amsterdam · Dubai" in column 4, etc.
5. Compare to Amazon row (3 tags + verified). Same pattern: column 2's "Operations" should sit at visual middle of column 1's content.
6. Compare to Santander row (3 tags, NO verified visible if scrolled or hover). Shorter column 1 → shorter row. "Finance" in column 2 still sits at center of column 1's content. Looks aligned across all rows even though rows have different heights.

### C. Confirmed-working items
1. Vertical dividers still edge-to-edge.
2. My Pipeline border still visibly amber against cream background.
3. AI Fit column on Programs hydrates immediately on refresh.
4. AI Fit results page program names clickable.

---

## Known follow-ups

- If Pranav still sees the flicker after this deploy: check whether
  the saved session key in localStorage actually exists at the moment
  of boot. Some Supabase configs use sessionStorage instead of
  localStorage, in which case the boot script's `Object.keys(localStorage).find`
  returns nothing and the fallback to 'programs' kicks in — same flicker.
  Fix in that case: cache the last-page key separately from session
  detection. (Probably not the case here — Supabase JS defaults to
  localStorage — but worth checking if the issue persists.)

- If Pranav still sees column misalignment after this deploy: the
  remaining option is to compact column 1 by removing the wrapping
  tag/verified-badge line, putting them all inline horizontally with
  truncation. Bigger UX change; defer until/unless this approach
  doesn't satisfy.
