# LDP Scout — Handover (Chat: 2026-05-20, mobile-cards deploy fix + UI sweep)

This document is self-contained context to bootstrap a fresh chat. It includes
project overview, current state, technical gotchas, and the chronological log of
this session's work.

---

## 1. Project context

**LDP Scout** (https://ldpscout.com) — résumé-to-MBA-LDP matcher with 422-row
catalog, Supabase backend, Anthropic-powered AI Fit Scan, alumni discovery,
deadline tracking.

- **Owner:** Shrey Singhal (ESADE MBA 2024–2026)
- **Helper:** Pranav (Shrey's brother) — that's the user of this chat
- **Target:** Monday May 25, 2026 demo to ESADE careers office
- **Repo:** `C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout`
- **Stack:** vanilla JS + Supabase (free tier, **NO BACKUPS**) + Vercel +
  Anthropic API for résumé scanning
- **Environment:** Shrey uses Windows / PowerShell, deploys via `git push` → Vercel
  auto-builds (~30s)

---

## 2. Current state (after this chat — all committed to main)

### Pages
- **Programs** — 422-row catalog with filters, AI Fit tier per program,
  per-row verification dates, stage dropdowns, mobile card view
- **AI Fit Scan** — Anthropic-powered résumé→program matching with 5 tiers
  (Best Fit / Strong / Achievable / Long Shot / Not a Fit)
- **Alumni Finder** — school-based alumni connection messages, 3 variants per
  program, "📋 Copy to clipboard" only (LinkedIn search button removed)
- **My Applications** — pipeline with 7 stages; horizontal kanban on desktop,
  vertical stacked sections on mobile
- **Deadlines** — aggregated deadlines table with multi-reminder ICS export
- **Profile** — name, school, password

### Mobile layout (≤720px viewport)
- Programs: stacked cards (not table); welcome banner + 5 stat cards appear
  ABOVE filter sidebar; AI Fit tier badge or "Scan résumé" CTA per card
- Applications: 7 vertical sections (one per stage), full-width cards inside;
  tap to edit, no drag
- Topbar: brand "LDP Scout" hidden (just L logo); nav-tabs horizontally
  scrollable with fade gradient on right edge as scroll hint; Sign Out
  single-line
- Form controls all render in Outfit (global font-family inherit reset)

### Recent commits in chronological order
1. `task 21.1 fix: !important on mobile breakpoint so cards actually win the cascade`
2. `task 21.3: AI Fit fallback on cards + scrollable nav tabs + brand-name hide on phone`
3. `task 21.4: fix AI Fit tier label keys + 5 mobile UI fixes (sign out, nav fade, programs order, applications layout)`
4. `fix: remove LinkedIn search button from draft modal + global font-family inherit for form controls`

---

## 3. Critical technical gotchas (read this before any change)

### 3.1 `progs[].aiTier` uses UPPERCASE enum values

The field stores: `BEST_FIT`, `STRONG_FIT`, `ACHIEVABLE`, `LONG_SHOT`, `NOT_FIT`.

Set by `syncAIResultsToPrograms()` at **app.js:~4640** which receives Anthropic's
response and writes `prog.aiTier = tier` (where tier is the uppercase key).

When rendering tier badges:
- **Desktop**: `fitTier(score, p)` at app.js:~2914 — uses the uppercase keys
- **Mobile**: `_aiTierMobile(p)` at app.js:~3070 — uses the uppercase keys

**This bit me in this chat.** I'd written `_aiTierMobile` with lowercase keys
(`best`, `strong`, etc.). Every lookup missed, every card fell through to the
"Scan résumé" CTA even when the user clearly had scan results. Always cross-check
data conventions against the existing writer when reading from a field.

### 3.2 CSS cascade in styles.css (~1900 lines, substantial layering)

Rules outside `@media` and inside `@media` have **equal specificity**. When both
apply (viewport matches the media query), the LATER rule wins.

This bit me at line 1680 — `.prog-table-wrap { display: table; }` (no media
query, declared late) was overriding `.prog-table-wrap { display: none; }`
inside `@media (max-width: 720px)` declared earlier at line 1212. Mobile cards
never showed despite multiple deploys.

**Rule of thumb**: before claiming any CSS layout fix works, `grep -n '\.target-selector' styles.css`
to see ALL rules on that selector across the whole file. Eyeballing your own
additions isn't enough.

### 3.3 Form controls don't inherit font-family

Browsers do NOT make `<input>`, `<textarea>`, `<select>`, `<button>` inherit
font-family from body. They fall back to a built-in system UI font.

The codebase has a global reset near the top of styles.css:
```css
input, textarea, select, button { font-family: inherit; }
```

This is the ONLY thing keeping every form control in Outfit. Don't remove it.
Explicit `font-family: var(--mono)` etc. on individual elements still wins
via normal specificity.

### 3.4 Sequence collision on `programs.id`

When INSERTing into the programs table, the sequence may need resetting if
prior rows were inserted with explicit ids:

```sql
SELECT setval(pg_get_serial_sequence('programs', 'id'),
              (SELECT MAX(id) FROM programs));
```

Done in prior session — sequence is now correctly past 422.

### 3.5 iOS Calendar 2-alarm limit

The ICS file generated by `downloadICS(item, 'multi')` correctly contains 3
VALARM blocks (`-P30D`, `-P7D`, `-P1D`). However, iOS Calendar's native
add-event preview UI only displays the 2 closest alarms. The 30-day alarm
may or may not survive import to the calendar database.

**Unresolved**: Shrey needs to verify by adding event, then opening Calendar
app and inspecting event details. If 30-day is genuinely dropped by iOS, the
fix is to generate 3 separate events instead of 1 event with 3 alarms.

### 3.6 Mobile breakpoint is 720px (not 768)

iPad portrait (768px) stays on desktop layout. Phones (≤720px) get mobile
cards, vertical kanban, scrollable nav, etc.

Note: existing `@media (max-width: 768px)` and `@media (max-width: 900px)`
blocks also exist — they handle softer responsive tweaks (smaller fonts, etc).
The 720px block is the hard layout switch.

### 3.7 Vercel + private browsing for testing

Vercel deploys take ~30s after `git push`. Best test path on Shrey's iPhone:
open Safari in private/incognito mode → ldpscout.com (no service worker, no
cache). If a deploy isn't taking effect there, the deploy genuinely failed —
don't blame caching.

---

## 4. What was done in this chat

### 4.1 Task 21.1 deploy-but-not-showing bug

**Symptom**: Mobile cards code (renderProgramsMobile + CSS) was committed and
pushed via Vercel, but the table still rendered at phone width. Tested in
private browsing — still broken.

**Investigation path that failed**: assumed deploy/cache issue, asked Pranav
to verify commits. He showed commits 59efe26 + 4038c19 both pushed successfully
with the expected file count and line changes.

**Root cause**: CSS cascade bug. `.prog-table-wrap { display: table; }` at
styles.css:1680 (outside any media query, declared LATE) was overriding
`.prog-table-wrap { display: none; }` inside `@media (max-width: 720px)` at
line 1212. Equal specificity → later rule wins.

**Fix** (committed): `!important` on both display switches inside the 720px
media block. Verified via CSS cascade simulation in Python:
```
At 400px:  table=none, cards=block  ✓
At 1024px: table=table, cards=none  ✓
```

**My accountability for this**: I should have grep'd for ALL `.prog-table-wrap`
rules in the file before claiming the fix would work. I only checked my own
additions. The file has 1900+ lines with substantial layering.

### 4.2 Task 21.3 — AI Fit on cards + scrollable nav + brand hide

**Changes**:
- New `_aiTierMobile(p)` function — renders the AI tier badge if `p.aiTier`
  exists, otherwise renders a dashed "✦ Scan résumé to see your fit" CTA chip
  that taps through to AI Fit page. Mirrors desktop fitTier behavior.
- `@media (max-width: 720px) .nav-tabs { overflow-x: auto; ... }` — horizontally
  scrollable tabs
- `@media (max-width: 720px) .brand-name { display: none !important; }` — just
  L logo on phones; the prior rule targeted `.topbar-brand` which is a class
  that doesn't exist in the HTML (pre-existing bug)
- `.nav-tab { flex-shrink: 0; }` — tabs don't squeeze, they overflow and scroll

### 4.3 Task 21.4 — AI Fit tier bug + 5 mobile UI fixes

**Bug fix (CRITICAL)**:
- `_aiTierMobile()` was using lowercase tier keys (`best`, `strong`, etc.).
  `progs[].aiTier` stores UPPERCASE (`BEST_FIT`, `STRONG_FIT`, etc.). Every
  lookup missed → every card showed CTA even when user had scanned. Fixed by
  using uppercase keys.

**Five mobile UI fixes inside `@media (max-width: 720px)`**:
1. `mask-image: linear-gradient(to right, black 0, black calc(100% - 18px), transparent 100%)`
   on `.nav-tabs` — right-edge fade as scroll hint
2. `#auth-btn { white-space: nowrap; }` — Sign Out on one line
3. `.prog-main { order: 1; } .prog-sidebar { order: 2; }` — welcome + stats
   above filters on mobile Programs page (works because `.prog-layout` is
   `display: grid`, which respects `order` on children)
4. `.kanban { display: block !important; }` + `.kcol` becomes full-width
   vertical section with rounded card styling and count pill. Linear / Notion /
   Asana mobile pattern. Tap to edit (no drag — touch drag is fiddly).
5. `.kanban .kcol .kcol-drop-hint { display: none !important; }` — hide drop
   hint since drag is disabled on touch

### 4.4 Draft Message modal + font consistency sweep

**Modal**:
- Removed "Open LinkedIn search ↗" button from `openConnectMessage()` at
  app.js:3719. Only "📋 Copy to clipboard" button remains under each variant.
- `openLinkedInSchoolSearch()` function still defined at app.js:~3747 —
  unreferenced but harmless dead code. Clean up post-Monday if desired.

**Font sweep — what I checked**:
- `grep -n font-family app.js index.html styles.css` — every explicit
  declaration uses `var(--sans)`, `var(--serif)`, or `var(--mono)`. No
  hardcoded fonts anywhere.
- Searched for `<input>`, `<textarea>`, `<button>` elements without explicit
  font-family. Found 4-5 (Clear all filters button, Try Again button, Sign
  In/Out button #auth-btn, Delete button, etc.)

**Root cause**: Form controls don't inherit font-family from body in any
browser. They fall back to system UI font. That's why the user was seeing
font inconsistency on some buttons/textareas vs. surrounding text.

**Fix** (committed): One global rule near top of styles.css:
```css
input, textarea, select, button { font-family: inherit; }
```

This makes every form control inherit from its parent (body → Outfit) unless
explicitly overridden. Surgical and zero side effects.

---

## 5. Database state (no schema changes this chat)

- `programs` table: **422 rows**
- 50 verified rows (Phase 3 reconciliation, prior session)
- 7 inactive_cycle rows: Nike EHQ, Admiral, Estée Lauder ×2, Scopely, AbbVie FDP, Zuellig
- Zero duplicate (program_name, company) pairs
- Schema includes: `last_verified_at`, `is_active_cycle`, `locations`,
  `language_required`, `program_type`, plus the standard fields used by the
  Programs page rendering

For the full schema, the latest export is in the Supabase Snippet CSV that
Shrey can re-export anytime. No schema migrations were performed in this chat.

---

## 6. Outstanding items

### From prior session (carried forward)
1. **iOS 3-reminder verification** — Shrey to test: download multi-reminder
   ICS on iPhone, tap "Añadir al calendario", open Calendar app, find event,
   check Alerts section. If 30-day alarm missing → switch multi-mode to
   generate 3 separate events instead of 1 event with 3 alarms.
2. **28-item smoke test walkthrough** — covers auth/onboarding, Programs
   badges, AI Fit, cross-page consistency, mobile, email/mailto, edge cases.
3. **Sort UX for mobile cards** — desktop inherits sort from localStorage,
   mobile currently has no explicit sort dropdown. Options: inherit desktop
   sort silently, add explicit dropdown (Deadline / Best fit / Recently
   verified / A-Z), or auto-default by scan state.
4. **Scrape 36 working URLs** for description/eligibility/min_yoe/duration_months
   fields. Improves AI Fit Scan quality on those rows.
5. **Quarterly verification refresh** — green badge auto-degrades to grey
   "Last checked" after 90 days (correct default already).
6. **Dead CSS cleanup post-Monday** — remove `.prog-cards`, `.prog-card-title`,
   `.prog-card-org`, etc. in the `@media (max-width: 768px)` block at
   styles.css:953-961. Referenced DOM IDs don't exist (replaced by Task 21.1).
7. **Defunct `openLinkedInSchoolSearch()`** function at app.js:~3747 — no
   callers after this chat's removal. Safe to delete post-Monday.

### Verification tasks (test after Monday deploy)
8. **AI Fit tier badges on mobile** — verify scanned programs show colored
   tier (Best Fit / Strong / Achievable / Long Shot / Not a Fit), unscanned
   show dashed "Scan résumé" CTA.
9. **Font consistency** — load ldpscout.com, check all form controls (Sign
   In/Out, Try Again, Clear all filters, Draft Message textareas, profile
   inputs) render in Outfit, not system font.
10. **Mobile Applications kanban** — open My Applications on phone, confirm 7
    vertical sections with rounded card backgrounds and count pills, not a
    cramped 7-column horizontal layout.

---

## 7. Files to attach to next chat

Required:
1. **`index.html`** — current HEAD on main (Pranav has been pushing each
   commit; current is `4038c19` + the last two commits above)
2. **`app.js`** — current HEAD
3. **`styles.css`** — current HEAD
4. **This document** — `LDP_SCOUT_HANDOVER_2026-05-20.md`

Highly recommended:
5. **Database snapshot CSV** — latest Supabase export of the `programs` table.
   Used as safety reference if SQL operations go wrong. Filename pattern:
   `Supabase_Snippet_Export_Programs_Sorted_by_ID.csv`

Optional context (if available):
6. Any prior handover docs (e.g. the May 19 session handover, OI_FUTURES doc
   for Pranav's parallel trading work — only attach if relevant to the new
   chat's topic)

---

## 8. Memory edits worth keeping

Already saved in memory from prior sessions:
1. Pranav uses Windows / PowerShell — always give PowerShell commands, not
   bash/zsh
2. Prefer subscription tools (Claude Code, claude.ai chat) over paid API for
   batch tasks
3. Don't skip steps in setup instructions — be explicit and numbered
4. Project context: LDP Scout, ldpscout.com, vanilla JS + Supabase + Vercel,
   May 25 2026 Monday ESADE rollout target

No new memory edits needed from this chat.

---

## 9. Quick-reference: key function locations in app.js

(Line numbers approximate after this chat's edits)

| Function | Location | Purpose |
|---|---|---|
| `fetchProgramsFromSupabase` | ~480 | Pulls 422 rows, populates progs[] |
| `hydrateAITierFromHistory` | ~1779 | Restores p.aiTier from saved scan on sign-in |
| `loadAndRenderLastScan` | ~1809 | Loads last scan into AI Fit page UI |
| `fitTier(score, p)` | ~2914 | Desktop tier badge renderer (uppercase enum keys) |
| `renderPrograms` | ~2900 | Programs page table render |
| `renderProgramsMobile(list)` | ~3147 | Mobile card render (≤720px viewport) |
| `_aiTierMobile(p)` | ~3070 | Mobile card AI Fit chip (uppercase enum keys) |
| `_mobileCardHTML(p)` | ~3200 | Individual mobile card template |
| `renderApplications` | ~3822 | Pipeline kanban render |
| `openConnectMessage(ctx)` | ~3688 | Draft Message modal |
| `copyConnectMsg(idx)` | ~3737 | Copy variant to clipboard |
| `downloadICS(item, mode)` | ~4215 | Single-event ICS export |
| `syncAIResultsToPrograms(result)` | ~4639 | **Sets prog.aiTier to UPPERCASE enum** |
| `renderAIResults(result, meta)` | ~4670 | AI Fit page result render |

---

*End of handover. Generated 2026-05-20.*
