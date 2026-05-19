# LDP Scout — Production Smoke Tests

Run all of these in a **fresh incognito window** against production (`ldpscout.com`).
Open DevTools → Console before starting; the tests rely on a few `window.*` peeks.

---

## P1 — Vercel proxy JWT check (run FIRST, before any UI tests)

This validates the security fix in `ldp-proxy/api/scan.js`. Run from any terminal:

```bash
# Should return HTTP 401 with body: {"error":{"message":"Missing bearer token"}}
curl -i -X POST https://ldp-proxy.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -H "Origin: https://ldpscout.com" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":10,"system":"x","messages":[{"role":"user","content":"x"}]}'

# Should return HTTP 401 with body: {"error":{"message":"Invalid token"}}
curl -i -X POST https://ldp-proxy.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -H "Origin: https://ldpscout.com" \
  -H "Authorization: Bearer not.a.jwt" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":10,"system":"x","messages":[{"role":"user","content":"x"}]}'

# Should return HTTP 403 (CORS rejection): {"error":{"message":"Origin not allowed"}}
curl -i -X POST https://ldp-proxy.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -H "Origin: https://evil.example.com" \
  -d '{}'
```

**Reminder:** the proxy needs `SUPABASE_JWT_SECRET` set in Vercel env vars and a redeploy.
Find the JWT secret in Supabase: Settings → API → JWT Settings → JWT Secret.

| Step | Expected | Result |
|------|----------|--------|
| Anonymous curl | 401 "Missing bearer token" | ☐ |
| Bad token curl | 401 "Invalid token" | ☐ |
| Bad origin curl | 403 "Origin not allowed" | ☐ |
| Signed-in AI Fit scan in browser | 200 with results | ☐ |

---

## Test 1 — Strict email validation + Sign Up / Sign In routing

The whitelist lives in `app.js` line 32 (`EDU_DOMAIN_WHITELIST`). Only exact-domain matches pass.
The Sign Up / Sign In split uses the `email_account_status` RPC to route by account existence.

**Steps:**
1. Open ldpscout.com in incognito → land on hero with email field + Sign Up / Sign In buttons.
2. Enter `random@madeup.edu`, click **Sign Up**.
3. **Expected:** red error including "Please use your school email" — no email sent, no Supabase call.
4. Clear the field, enter `student@esade.edu` (fresh email, never used), click **Sign Up**.
5. **Expected:** "We sent an 8-digit code to..." success state, OTP step shown.
6. Hit Back / refresh. Re-enter the same `student@esade.edu`, click **Sign Up** again.
7. **Expected:** error indicating an account already exists — should use Sign In instead.
8. Enter the same email, click **Sign In**.
9. **Expected:** account routes to OTP flow (no password yet) OR password field (if password was set in a prior session).

**Console peeks:**
```js
isValidEduEmail('random@madeup.edu')   // → false
isValidEduEmail('student@esade.edu')   // → true
isValidEduEmail('foo@RANDOM.EDU')      // → false (case-insensitive but still not in list)
```

| Case | Expected | Result |
|------|----------|--------|
| `random@madeup.edu` Sign Up | Rejected with error | ☐ |
| `student@esade.edu` Sign Up (fresh) | 8-digit OTP sent | ☐ |
| Same email Sign Up again | "Account already exists" | ☐ |
| Same email Sign In | OTP or password step | ☐ |
| `isValidEduEmail('random@madeup.edu')` | `false` | ☐ |
| `isValidEduEmail('student@esade.edu')` | `true` | ☐ |

---

## Test 2 — Pipeline column "+ Shortlist" → Kanban round-trip

Phase 14 added the pipeline button to the Programs table. Both the table column and the Kanban must stay in sync via `program_id`.

**Steps:**
1. Sign in. Navigate to **Programs**.
2. Pick any row that shows the green **`+ Shortlist`** button (not already saved).
3. Click it. **Expected:** button flips immediately to `✓ Shortlisted` (read-only chip).
4. Navigate to **My Applications**. **Expected:** a new card for that program appears in the "Shortlisted" column.
5. Drag the card from "Shortlisted" to "Networking".
6. Hard refresh (Cmd/Ctrl-Shift-R).
7. Navigate to **Programs**. **Expected:** that same row now shows `✓ Networking` (label reflects new stage).
8. Navigate back to **My Applications**. **Expected:** card is still in the Networking column.

**Console peek:**
```js
// After step 3, the in-memory apps[] should contain a row with program_id matching the row's p.id
apps.find(a => a.program_id && a.status === 'shortlisted')   // should return the new app
```

| Step | Expected | Result |
|------|----------|--------|
| 3: button flips to `✓ Shortlisted` | Yes | ☐ |
| 4: kanban card appears in Shortlisted | Yes | ☐ |
| 6→7: row shows `✓ Networking` after refresh | Yes | ☐ |
| 8: kanban card still in Networking | Yes | ☐ |

---

## Test 3 — Auto-tour stack lock (≥30s gap)

Phase 14 added a 30 s minimum gap between auto-tours so rapid page-switching doesn't pile up overlays. The gate is `Date.now() - _lastTourTime < 30000` in `maybeAutoTour()`.

**Pre-req:** fresh user (incognito) with no `ldps_tours_seen_v1` localStorage. Verify in console:
```js
localStorage.getItem('ldps_tours_seen_v1')   // should be null or '{}' before starting
```

**Steps:**
1. Sign in for the first time as a fresh user (or run `localStorage.removeItem('ldps_tours_seen_v1')` then reload).
2. Start a stopwatch. Click through 5 different page tabs in 10 seconds:
   Programs → AI Fit Scan → Alumni Finder → My Applications → Deadlines.
3. Watch how many tour overlays appear and when.

**Expected:** the first tour fires shortly after landing on a page. The next tour does **not** fire until ≥30 s after the first one began, regardless of how many tabs you've switched through.

**Console peek to verify the gate:**
```js
_lastTourTime    // updates only when an auto-tour actually starts
// Right after a tour begins, this should be ~Date.now(); for ~30s after, no new auto-tour fires.
```

| Check | Expected | Result |
|-------|----------|--------|
| First tour fires on initial page | Yes | ☐ |
| Switching pages within 30 s does NOT stack tours | Yes | ☐ |
| After 30 s on a new untoured page, next tour fires | Yes | ☐ |

---

## Test 4 — AI Fit dwell timer (10 s)

AI Fit is special: instead of auto-firing on page entry, the tour arms a 10 s timer that fires only if the user hasn't uploaded a resume.

State machine in `startAifitDwell()` (app.js line 1132):
- enters `aifit` page → arm 10 s timer
- successful upload → cancel timer
- timer expires AND not scanning AND not seen yet → fire tour

**Steps:**
1. Fresh user (or `localStorage.removeItem('ldps_tours_seen_v1')` then reload).
2. Navigate to **AI Fit Scan**. Start a stopwatch.
3. Do nothing. Don't move the mouse over the upload zone.
4. **Expected:** at ~10 s the aifit tour fires.

**Repeat with cancel path:**
5. Refresh, reset `ldps_tours_seen_v1`, go to AI Fit Scan, **upload a résumé within 5 s**.
6. **Expected:** the tour does NOT fire (timer was cancelled by `clearAifitDwell()` in handleFileUpload).

**Console peek:**
```js
_aifitDwellTimer   // a number while armed, null after fire/cancel
_aifitScanning     // true only during runAIAnalysis
```

| Case | Expected | Result |
|------|----------|--------|
| Wait 10s without upload → tour fires | Yes | ☐ |
| Upload resume before 10s → tour does NOT fire | Yes | ☐ |
| Already seen aifit tour → timer never arms | Yes | ☐ |

---

## Test 5 — Mandatory full-name capture (Task 19)

After Task 19 ships, onboarding cannot be completed without a non-empty `full_name`. Personalization (welcome line on Programs page, etc.) reads `full_name.split(' ')[0]`.

**Steps:**
1. Sign up with a fresh email (Sign Up → OTP → 8-digit code → password set).
2. **Expected:** onboarding flow lands on Step 1 with a Full Name input. Submit / Next button is disabled until name is non-empty.
3. Try to submit with empty name. **Expected:** button stays disabled, no submission.
4. Try to submit with whitespace-only ("   "). **Expected:** button stays disabled.
5. Enter "Test User", proceed through rest of onboarding.
6. After onboarding completes, land on Programs page. **Expected:** welcome strip reads "Welcome back, Test." (first name from `full_name.split(' ')[0]`).
7. Refresh. **Expected:** welcome strip still personalized — `full_name` is persisted in `user_profiles`.

**Console peek:**
```js
userProfile.full_name       // "Test User"
userProfile.full_name.split(' ')[0]   // "Test"
```

| Case | Expected | Result |
|------|----------|--------|
| Empty name → Next disabled | Yes | ☐ |
| Whitespace-only name → Next disabled | Yes | ☐ |
| Valid name → onboarding proceeds | Yes | ☐ |
| Programs page welcome uses first name | Yes | ☐ |
| Refresh: name persists | Yes | ☐ |

---

## Troubleshooting cheat sheet

- **Tour never fires:** check `_isTourSeen('<page>')` — if it returns `true` the tour was already shown. Reset with `localStorage.removeItem('ldps_tours_seen_v1')` then reload.
- **Email gate passing things it shouldn't:** confirm the deployed `app.js` actually contains the Phase 15 whitelist (no `EDU_DOMAIN_PATTERNS` regex). Search the deployed source for "EDU_DOMAIN_PATTERNS" — must be absent.
- **+ Shortlist fails silently:** open Network tab, check the Supabase insert call returns 201. If RLS blocks it, that's a P5 issue (next session).
- **Proxy curl returns 200 unauthenticated:** the env var `SUPABASE_JWT_SECRET` isn't set in Vercel, or the new code didn't deploy. Force-redeploy in the Vercel dashboard.
- **Welcome line shows email instead of first name:** `user_profiles.full_name` is NULL for that user. Check the onboarding flow ran end-to-end, or backfill via the Profile modal.
