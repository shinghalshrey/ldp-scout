# CHANGES — Task EMAIL-GATE: signup gate by email domain + school auto-set + year range

**Date:** 2026-06-07
**Author:** Claude (Opus 4.8)
**Files:** Modified `app.js`. New `CHANGES_TASK_EMAIL_GATE.md`.

LDP Scout is institutional: only students at partner business schools may **sign
up**. School identity now comes from the email domain — the onboarding
school-selection step is gone — and unrecognised domains are blocked at signup.

All changes are in `app.js`. `index.html` is frozen, so the onboarding and
profile-modal changes are applied at runtime (hiding/disabling elements), the
same pattern already used for the JS-injected year dropdowns.

---

## What changed

### 1. Domain → school mapping (top of `app.js`)
Added `EMAIL_DOMAIN_TO_SCHOOL` (ESADE, HEC, Bocconi, LBS, EDHEC) and
`deriveSchoolFromEmail(email)` exactly as specified, near the existing email
helpers.

### 2. Hard gate at signup (`lpSignUp`)
Before any OTP is sent, `lpSignUp` now calls `deriveSchoolFromEmail(email)`. If it
returns `null`:
- shows: *"LDP Scout is currently available to students at partner business schools (ESADE, HEC, Bocconi, LBS, EDHEC). If your school should be on this list, email hello@ldpscout.com."*
- returns immediately — **no `emailAccountStatus` call, no OTP, no `auth.users` row**.

This replaces the older broad `.edu` whitelist (`isValidEduEmail`) on the signup
path. The new gate is intentionally stricter: e.g. `insead.edu` was in the old
whitelist but is **not** a partner, so it is now blocked from signup.

Diagnostics:
- `console.log('[EMAIL-GATE] signup attempt:', email, '→', derived)`
- `console.log('[EMAIL-GATE] blocked: unrecognized domain', domain)`

### 3. Auto-set school on profile creation (`loadUserProfile`)
When the first-time **stub** profile row is created (the `data === null` branch),
`school_key`/`school_label` are populated from `deriveSchoolFromEmail(currentUser.email)`
(both in the DB upsert and the in-memory `userProfile`). Existing users hit the
other branch and are untouched.

### 4. Onboarding reduced to 2 steps (`onbOpen`/`onbGoto`/`onbNext`)
- Old: Step 1 (name + year) → Step 2 (school) → Step 3 (résumé).
- New: **Step 1 (name + year) → Step 2 (résumé).**
- The school panel (`#onb-panel-2`), the auto-detect banner, the 3rd step
  indicator (`#onb-step-ind-3`) and the 2nd connector bar (`#onb-bar-2`) are
  hidden at runtime. Logical step 2 now drives the résumé panel (`#onb-panel-3`).
- `onbOpen` no longer detects/pre-selects a school; `onbNext` no longer has a
  school step. (The now-unused school-picker helpers remain defined but are never
  invoked.)

### 5. School read-only in the profile modal (`openProfileModal`, `saveProfileChanges`)
- `#profile-school-input` is shown with the saved `school_label` but **disabled**,
  with a one-time helper note: *"School is set from your email and cannot be
  changed. Contact hello@ldpscout.com if this is incorrect."*
- `saveProfileChanges` no longer reads, validates, or writes school — only name,
  MBA year, and password. (This also removes a latent trap where a disabled field
  whose label didn't exactly match `ALL_MBA_SCHOOLS` would have failed the save.)

### 6. MBA start-year range widened to 2020–2030 (`_mbaYearOptionsHtml`)
Both the onboarding and profile dropdowns call this one helper, so the single
change updates both. (Was 2024–2028.)

---

## Sign-IN is intentionally NOT gated (existing users keep access)

The brief's verification step 6 — *"Existing gmail users can still sign IN (only
signup is gated)"* — required a behavior change: the old code gated **both**
`lpSignUp` and `lpSignIn` with `isValidEduEmail`, so legacy gmail/hotmail accounts
could not even sign in. The domain check was therefore **removed from `lpSignIn`**.
Account existence is the real guard there: unknown emails get *"No account found.
Use Sign Up,"* and the signup path enforces the partner-school gate. No existing
user data is modified.

Side effect: `isValidEduEmail` + `EDU_DOMAIN_WHITELIST` and `detectSchoolFromEmail`
are no longer called. They are left defined (not deleted) to keep the diff small
and avoid touching unrelated code; they no longer gate anything.

---

## Verification (in the browser preview, against the live app)

No JS errors; all touched functions parse and run. Verified via DOM assertions:

| # | Check | Result |
|---|-------|--------|
| 1 | `lpSignUp` with `test@gmail.com` | Blocked — partner message shown, **no** account-status call, **no** OTP ✅ |
| 2 | `lpSignUp` with `a@alumni.esade.edu` | Passes gate → continues to status + OTP ✅ |
| 3 | `deriveSchoolFromEmail` | esade/hec/bocconi/lbs/edhec → correct; gmail & insead → `null`; case-insensitive ✅ |
| 4 | Onboarding | Step 1 = name+year, Step 2 = résumé; school panel + 3rd dot + 2nd bar hidden; CTA "✦ Scan my résumé" ✅ |
| 5 | Profile modal | School shows label, `disabled`, helper note present ✅ |
| 6 | Year dropdowns | 2020–2030 (12 options incl. placeholder) in both onboarding and profile ✅ |
| 7 | `lpSignIn` with `legacy@gmail.com` | Not blocked by domain — proceeds to account-status ✅ |

Auto-set school (#3) is exercised by `deriveSchoolFromEmail` correctness plus the
stub-creation code path; the live end-to-end (real OTP + new row) needs a real
partner-domain inbox and is left for a manual smoke test.

---

## Not touched
`scan.js`, `index.html`, `ldp-proxy/*`, `generate-dashboard.js`, `admin.html`,
`styles.css`, and all DB columns. Existing user rows are not modified.
