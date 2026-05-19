# Task 19 — Programs page redesign + mandatory full_name + personalization

Three-in-one task per the Session 5 handover: (a) Lovable-generated
Programs-page layout replacing the cluttered horizontal filter row with a
240px sticky sidebar matching Alumni Finder; (b) mandatory `full_name`
capture on onboarding step 1 (no skip path); (c) personalization across the
five pages plus topbar, profile modal, and AI-Fit-Scan post-scan view.

The Lovable HTML+CSS was reviewed before integration. Two real bugs were
caught and fixed during integration (described under "Lovable bugs fixed"
below); the rest of Lovable's output was accepted with minor CSS trimming.

> No DB migration this task. The mandatory-`full_name` work is enforced
> entirely in the front-end onboarding flow. Existing `user_profiles` rows
> with NULL `full_name` will be caught by the Profile-modal auto-open path
> on next sign-in (existing behavior — `onbShouldShow()` triggers when
> neither `onboarding_completed_at` nor `onboarding_skipped_at` is set).

---

## Files touched

| File | What changed |
|------|--------------|
| `index.html` | Programs page block fully replaced with Lovable two-column layout (left sidebar + main column with welcome strip). `data-sort-key` attributes restored on the 6 sortable th's (Lovable dropped them). Profile-modal `<h3>` got `id="profile-modal-title"`. Programs info-card moved below the table so the welcome strip stays clean. |
| `styles.css` | Appended ~130 lines of slimmed Lovable CSS for the new layout. Stripped 4 problematic Lovable rules (see "Lovable bugs fixed" below). |
| `app.js` | New personalization helper block (~180 lines) near the top — `getFirstName()`, `_esc()`, `_pipelineCount()`, `_deadlinesThisMonth()`, `_refreshProgramsCounts()`, `applyPagePersonalization(pageId)`, `_refreshActivePagePersonalization()`. Hooked into `showPage()`, `renderPrograms()`, `renderApplications()`, `renderAIResults()`, `updateAuthUI()`, `openProfileModal()`, `saveUserProfile()`, `onSignIn()`. New `_onbValidateName()` helper + extended `onbGoto()` to handle step-1-specific mandatory-name behavior. Swept three remaining "48" survivors from user-facing strings (one empty-state CTA, one info banner, one tour body). |

---

## Lovable bugs fixed during integration

**1. `data-sort-key` attributes dropped from sortable th's.**

`app.js:2708` reads `th.getAttribute('data-sort-key')` to (a) add the `.sorted`
class to the currently-sorted column and (b) flip its arrow from ▼ to ▲ on
ascending sort. Lovable's output omitted these attributes. Clicking a column
still sorted (the `onclick="sortBy('name')"` etc. were preserved) but the
visual feedback was silently broken. Restored on all six sortable th's:
`data-sort-key="name|fn|loc|deadline|status|fit"`.

**2. `.prog-thead` redefined the column grid template.**

Existing `styles.css:74` (`.thead`) and `styles.css:83` (`.prow` — the data
row class) share a 9-column template: `2.2fr 1fr 0.9fr 0.8fr .6fr .7fr .5fr
110px 70px`. They were tuned to align. Lovable's new `.prog-thead` rule
overrode with a different 9-col template (`2.2fr 1.1fr 1fr 1fr .7fr .8fr
.7fr .9fr .8fr`), plus a 12px gap and 14px/18px padding. With `.prog-thead`
applied to the header but `.prow` still ruling the data rows below, columns
would have visibly misaligned.

Fix: in the CSS we kept the `.prog-thead` class on the div (no DOM change)
but dropped every rule on `.prog-thead { ... }` except for adding mono
typography to its children: `.prog-thead .th { font-family: var(--mono); }`.
Everything else cascades from the existing `.thead` and `.th` rules. Headers
now align with data rows pixel-for-pixel.

**3. `.prog-table-wrap` block was entirely redundant.**

Existing `.table-wrap` already sets bg, border, border-radius, box-shadow,
and overflow. Dropped Lovable's `.prog-table-wrap { ... }` block (the class
stays in the HTML but has no rules attached — harmless and useful if we
ever want a Programs-specific override later).

**4. `.prog-thead .th-arrow { opacity: .5 }` undid the restraint.**

Existing `styles.css:79-82` keeps sort arrows at `opacity:0` and fades them
in on hover or full opacity when sorted. Lovable's `opacity:.5` made all
arrows always half-visible — denser, less editorial. Dropped this override.

---

## Lovable accepted-as-is decisions

- `.prog-h1 #prog-welcome-name { color: var(--accent); font-style: italic; }`
  — italic forest-green for the first name in the welcome h1. Fraunces
  italic + the only color pop on the page = editorial. Kept; revisit if
  it reads as too much in production.
- Persistent half-opacity sort arrows on the eyebrow — n/a, that was the
  thead arrows; eyebrow has no arrows. Kept the eyebrow as-is (mono,
  letter-spaced, --text3).

---

## Personalization implementation

### `getFirstName()`
Reads `userProfile.full_name`, trims, splits on whitespace, returns the
first token. Returns `null` for empty/null. All downstream personalization
keys off this single helper.

### Per-page behavior

| Page | Mode | Personalized via | STATE B fallback (no name) |
|---|---|---|---|
| Programs | one-shot (eyebrow/h1/subline) + live (count spans) | `applyPagePersonalization('programs')` writes eyebrow/h1/subline; `_refreshProgramsCounts()` rewrites the count spans on every `renderPrograms()` so pipeline state stays in sync | eyebrow: "All programs" · h1: "Verified MBA LDP programs." · subline: "Filter, search, and save to your pipeline." (count-agnostic per Task 20 — no hardcoded N in static fallback) |
| Alumni Finder | one-shot | `applyPagePersonalization('alumni')` rewrites h2 + subtitle inside `#page-alumni .sech` | unchanged copy |
| My Applications | mixed | h2 set in `applyPagePersonalization('applications')`; `#app-sub` written inside `renderApplications()` (it carries live counts that change per render — a one-shot would get overwritten) | h2: "My Applications"; sub: "{N} active · {M} total tracked" (unchanged) |
| Deadlines | one-shot | `applyPagePersonalization('deadlines')` rewrites h2 + subtitle | unchanged copy |
| AI Fit pre-scan | one-shot | `applyPagePersonalization('aifit')` targets `#aifit-view-pre .aifit-title` / `.aifit-subtitle` | unchanged copy |
| AI Fit post-scan | template-rendered | personalized intro inserted **above** the existing summary strip inside `renderAIResults()`; the line is "`{firstName}, here are your top N matches across M programs.`" with grammatical guards for N=1 ("is" vs "are") and N=0 ("results" vs "matches") | line omitted entirely |
| Topbar | dynamic | `updateAuthUI()` writes "`{firstName} · {school_label}`" instead of `email`; falls back to email if `full_name` is empty | email (unchanged) |
| Profile modal | one-shot per open | `openProfileModal()` writes "`{firstName}, edit your details`" into `#profile-modal-title` | "Your profile" |

### Counts (Programs page welcome strip)

- **Pipeline count** = `apps.filter(a => !['offer','rejected'].includes(a.status)).length`.
- **Deadlines this month** = pipeline apps whose `a.deadline` is within today + 30 days (inclusive of today, exclusive past, exclusive offer/rejected).
- **Both zero** → single fallback line: "Start building your pipeline below" (deadline span empty; CSS `:empty` rule hides the dot).
- **Pipeline 0, deadlines 0 normal pluralization:** "1 program in your pipeline", "2+ programs in your pipeline", "No deadlines this month", "1 deadline this month", "2+ deadlines this month".

### Re-rendering on profile change

`saveUserProfile()` now calls `updateAuthUI()` + `_refreshActivePagePersonalization()`
after the in-memory `userProfile` reload. This means:
- Onboarding step 1 save → topbar + Programs welcome strip update without nav.
- Profile modal save → same.
- Any other profile field update → topbar consistency maintained.

`onSignIn()` also calls these two after `loadUserProfile()` because the
sign-in flow doesn't go through `showPage()` (the user stays on whatever
page was last active, usually Programs).

---

## Mandatory full_name on onboarding step 1

Implemented entirely in `onbGoto()` + the new `_onbValidateName()` helper:

1. On entry to step 1: `#onb-skip-btn` is hidden via `style.display='none'`.
2. `#onb-name` element gets `oninput = _onbValidateName` (property assignment
   so repeated step-1 visits don't double-bind).
3. `_onbValidateName()` reads `nameEl.value.trim().length >= 1` and toggles
   `nextBtn.disabled` + `style.opacity` accordingly.
4. On entry: `_onbValidateName()` is called once to sync button state to
   whatever's currently in the input (handles pre-fills from partial saves).
5. On exit to step 2/3: skip button is restored to `style.display=''` (CSS
   default visible). Next button state is handled by existing step-2/3 logic.

`onbNext()` step-1 path already had a toast-based "please enter your name"
check — kept it as defense-in-depth. With the disabled-button approach the
toast should never fire in practice, but it's a cheap belt-and-suspenders.

---

## "48" survivors swept

Task 20 missed three user-facing references to the no-longer-accurate
hardcoded "48" program count. Fixed:

- `app.js:1303` — fit-banner text "across all 48 programs" → "across all tracked programs"
- `app.js:1367` — tour body "Snapshot of all 48 LDPs by status" → "Snapshot of all tracked LDPs by status"
- `app.js:3184` (in `renderApplications` empty state) — CTA "Browse the 48 programs first →" → "Browse all programs first →"

Two count mentions remain in non-user-facing comments (`app.js:428` and
`app.js:3755`). Leaving them — they're documentation context that's still
historically meaningful, and they don't leak into OG previews or any UI.

---

## Diagnostic logs

None added in this task. The personalization helpers are no-ops when their
target elements aren't present (so they're safe to call from anywhere), and
their behavior is directly observable in the UI. No debugging hooks were
useful enough to add as console.log noise.

---

## Manual test plan

### Personalization paths

**P1. New user signup → onboarding → see personalized welcome**
1. Fresh browser. Sign up with a whitelisted email. Verify OTP, set password.
2. Onboarding modal appears on step 1. Note **Skip button is hidden** and
   **Next button is disabled**.
3. Type any single character into the name field. Next button enables.
4. Erase the name. Next button disables again. Confirm.
5. Enter "Test User", click Next. Pick a school (step 2). Click Next.
6. Skip step 3 (resume) or upload one.
7. Land on Programs page. Welcome strip reads:
   - Eyebrow: "Your LDP command centre"
   - H1: "Welcome back, *Test*." (italic accent green on "Test")
   - Subline: "Start building your pipeline below" (no dot or trailing span)
8. Topbar shows "Test · [School Label]" instead of email.
9. Click Profile button. Modal title reads "Test, edit your details".

**P2. Persistent welcome — sign out, sign back in**
1. After P1, sign out. Sign in with the same email.
2. Land on whatever page (usually Programs). Topbar + welcome strip
   still show "Test" — no flicker of email.

**P3. Existing user with NULL full_name**
1. Sign in as a user whose `user_profiles.full_name` is NULL.
2. Topbar shows email (fallback).
3. Programs welcome reads STATE B: "All programs" / "Verified MBA LDP
   programs." / "Filter, search, and save to your pipeline."
4. Onboarding modal appears (because `onbShouldShow()` triggers when
   onboarding isn't complete and isn't skipped). Step 1 enforces name.
5. After saving name in onboarding, topbar and welcome strip both
   refresh immediately without a page nav.

**P4. Profile modal name edit**
1. Sign in as a user with `full_name = "Test User"`.
2. Click Profile. Edit name field to "Updated Name". Click Save.
3. Modal closes. Topbar updates to "Updated · …".
4. Programs welcome strip updates to "Welcome back, *Updated*."
5. Confirm no nav happened — same page.

**P5. Live pipeline counts on Programs page**
1. Sign in as a user with name set.
2. Go to Programs. Note current "{N} programs in your pipeline" count.
3. Open a program details modal, click the pipeline-add toggle for a
   new program.
4. Close the modal. Welcome strip count increments by 1.
5. Same for deadline count — set a deadline within 30 days on a
   shortlisted program, then return to Programs page. Count updates.

**P6. AI Fit personalization**
1. Sign in as a user with name set. Go to AI Fit Scan.
2. Pre-scan title reads "Ready when you are, *FirstName*." Subline
   shows scans-remaining count.
3. Upload a résumé, run scan. Post-scan view shows the personalized
   intro line above the summary strip: "*FirstName*, here are your top
   N matches across M programs."
4. Re-load the page. Cached scan re-renders with the personalized intro
   intact (it lives inside `renderAIResults`, called by `loadAndRenderLastScan`).

**P7. Other personalized pages**
1. Alumni Finder h2 reads "Alumni Finder, *FirstName*" (with the
   "?" info-card-reopen still inline at the end if it was dismissed).
2. My Applications h2 reads "*FirstName*'s pipeline"; sub reads
   "*FirstName* · N active · M total tracked".
3. Deadlines h2 reads "*FirstName*, your upcoming deadlines"; sub reads
   "K of your pipeline programs have deadlines in the next 30 days.
   Plan the sprint." (or fallback copy if K=0).

### Programs-page redesign sanity

**L1. Layout — desktop (>900px)**
1. Sidebar is 240px sticky on the left. Search input, four pill groups
   (Geo / Function / Status / Quick Filters), Pro Tip card.
2. Main column shows welcome strip → stat row → fit banner mount →
   meta row + Add Program button → table → info card below table.
3. All sidebar pills work: clicking "Europe" filters Geo. Clicking
   "All" resets. Visa and Pipeline toggles work.

**L2. Layout — mobile (≤900px)**
1. Sidebar stacks above main column; no longer sticky.
2. H1 shrinks to 26px.
3. Page padding shrinks to 20px/16px.

**L3. Sort indicators**
1. Click "Name" column header. Arrow flips to ▲ and column header
   colors accent green (`.sorted` class). Click again — arrow flips to ▼.
2. Click "Deadline". Name column de-styles, Deadline column gets
   the active arrow + green color.
3. Hover any sortable column with no active sort — arrow briefly
   fades to 40% opacity.

**L4. Table alignment**
1. Compare a row's columns against the thead labels — every column
   left-edge lines up. (Specifically verify the "110px" Pipeline
   column and "70px" Actions column at the right edge.)

### Programs onboarding sweeps

**O1. Hidden 48 in Applications empty state**
1. As a fresh user with no apps, navigate to My Applications.
2. Empty-state CTA reads "Browse all programs first →" (not "Browse
   the 48 programs first →").

**O2. Hidden 48 in fit banner**
1. As a user with a résumé but no scan, go to Programs.
2. Fit banner reads "Run an AI fit scan to populate tier rankings
   across all tracked programs." (not "across all 48 programs").

**O3. Hidden 48 in tour**
1. Click the "?" reopen control on Programs page.
2. Click "Tour this page →".
3. The tour step about Pipeline at a glance reads "Snapshot of all
   tracked LDPs by status..." (not "all 48 LDPs").

---

## Known follow-ups (not in this task)

- `prog-cards` / `prog-table` IDs referenced in `app.js:2720-2744` (the
  mobile card-view switcher) don't exist in `index.html`. Pre-existing
  dead code (was already broken before Task 19). Either implement the
  mobile card view properly or remove the dead block — separate task.
- Two `48`-mention comments remain in source — non-blocking documentation
  context, not in any user-visible string. Leave or sweep at convenience.
- The italic-accent-green name treatment is a taste call — verify in the
  Vercel preview. If it reads as too loud, drop the `font-style: italic`
  on `.prog-h1 #prog-welcome-name` and keep just the color, or vice versa.
