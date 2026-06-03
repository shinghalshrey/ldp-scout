# Task PERF — Page-speed optimization + AI Fit Scan results fix

Two user-facing problems, four code changes. All in `app.js` and `styles.css`;
no build step, no framework, no Supabase query changes, no markup in `index.html`.

## The problems
1. **4–5s blank white screen after sign-in.** `onSignIn()` ran six `await` calls
   one after another before rendering anything, so the user stared at nothing
   while each network round-trip finished in series.
2. **"View full results ▾" toggle hid the scan output.** The AI Fit Scan results
   (tier lists, gap analysis, coaching) were collapsed behind a click by default,
   which was confusing — those results should just be visible.

## What changed

### Part 1 — `onSignIn()` now loads data in parallel
Previously: `loadUserProfile → loadUserApplications → loadUserContacts →
loadUserResume → fetchProgramsFromSupabase`, all sequential.

Now:
1. `loadUserProfile()` still runs **first** and completes before anything else —
   `updateAuthUI()`, personalization, and onboarding all depend on `userProfile`.
2. `updateAuthUI()` + `_refreshActivePagePersonalization()` fire immediately after
   the profile loads (don't wait for the rest of the data).
3. The remaining four fetches — `loadUserApplications`, `loadUserContacts`,
   `loadUserResume`, `fetchProgramsFromSupabase` — run **in parallel** via
   `Promise.allSettled`. They're independent (each sets its own module var and has
   its own try/catch), and `allSettled` (not `all`) means one failure can't block
   the others.
4. The post-load steps that need all the data (`hydrateAITierFromHistory`,
   `renderPrograms`, `renderApplications`, onboarding, `renderProgressStrip`,
   `updateFitTabIndicator`, `renderFitBanner`) run after the batch resolves.
5. `showPage()` for the landing page still happens last, after the batch.

**Effect:** wall-clock wait drops from "sum of 6 requests" to "profile + the
slowest of the remaining 4."

### Part 2 — stale-while-revalidate for the programs catalog
The `programs` table (~433 rows) is the heaviest fetch and changes rarely (only
when enrichment SQL is run). Now, right after the profile loads and **before** the
parallel batch, `onSignIn()` reads `localStorage['ldps_progs']`; if present, it
sets `progs` and calls `updateProgramCountInUI()` + `_initProgSuggestionsDatalist()`
immediately, so the program count and the name-autocomplete are populated from
cache before the network call returns. Logs:
`[TaskPERF] stale-while-revalidate: served N cached programs`.

The fresh `fetchProgramsFromSupabase()` still runs in the parallel batch and
overwrites `progs` + re-caches localStorage on success. Because that fetch
completes (inside the awaited `allSettled`) **before** the post-load
`renderPrograms()`, that render is the "revalidate" pass — the Programs table
always reflects the latest catalog without a second redundant render. The
`_progsRefreshed` flag (true when Supabase returned fresh rows) is surfaced in the
`first render` timing log.

**Unchanged:** the three-layer fallback (Supabase → localStorage → hardcoded
`DP[]`) is untouched. SWR only front-loads the localStorage layer so the UI is
populated sooner.

### Part 3 — removed the "View full results" toggle (AI Fit Scan)
In `renderAIResults()`:
- Removed the `aifit-fullresults-toggle` button and the `<div id="aifit-full-results"
  style="display:none">` wrapper (open + close). The tier sections, gap analysis,
  and coaching now render directly below the summary strip.
- Removed the `toggleAIFitFullResults()` function and the `_aifitFullResultsOpen`
  state variable entirely (no remaining references).
- In `styles.css`, removed the `.aifit-fullresults-toggle` and `.aifit-full-results`
  rules.
- **Kept** the per-tier collapse/expand (`toggleAIFitTier`) — that's still useful.

### Part 4 — performance timing diagnostics
Added four `[TaskPERF]` console logs to measure the improvement, all relative to a
`performance.now()` mark at the top of `onSignIn()`:
- `onSignIn started`
- `profile loaded: <ms>`
- `all data loaded: <ms>` (after the parallel batch)
- `first render: <ms>` (after the first full render; notes whether programs came
  from Supabase or cache/fallback)

## What was deliberately NOT changed
- No file restructure / refactor of unrelated code.
- Auth, onboarding, and sign-out logic untouched.
- No build step, bundler, or framework.
- Supabase queries unchanged.
- `scan.js`, `data.js`, `index.html` untouched (the toggle was JS-generated — no
  markup existed in `index.html`).
- Per-tier collapse/expand (`toggleAIFitTier`) behavior unchanged.

## Verification done
- `node --check app.js` → **PASS**.
- Loaded the app via the `ldp-static` preview (port 4173): landing page renders,
  **zero console errors**, signed-out programs fallback (`DP[]`) renders correctly.
- Confirmed no orphaned references to `toggleAIFitFullResults`,
  `_aifitFullResultsOpen`, `aifit-full-results`, or `aifit-fullresults-toggle` in
  `app.js`, `styles.css`, or `index.html`.
- Verified the `renderAIResults()` HTML string stays balanced after removing the
  wrapper div (tiers/gap/coaching each self-close).

### Not exercised (auth-gated)
Sign-in requires an emailed OTP, so the signed-in flow (timing numbers in console,
cached-then-fresh Programs render, full scan-results render, Command Center) was
**not** driven end-to-end here. Recommended manual pass after pulling:
1. Sign in → watch the `[TaskPERF]` logs; first render should be well under 2s.
2. Programs page populates from cache immediately, then refreshes when Supabase
   returns.
3. Programs → AI Fit Scan: summary strip + tiers + gap + coaching all visible with
   no toggle; per-tier collapse still works.
4. Run a fresh scan (if quota); sign out and back in; check Command Center.
