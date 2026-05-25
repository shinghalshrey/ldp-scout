# CHANGES — Alumni school-identity fix (root cause)

**File changed:** `app.js` only (one block removed in `pickAlumniSchool`).

## The real bug

My earlier fix made the LinkedIn draft read the user's *profile* school instead of the
dropdown. Correct — but it didn't work, because the **Alumni school dropdown was overwriting
the profile school**. `pickAlumniSchool` called `saveUserProfile({school_key: <selected>})`,
so browsing HEC's alumni literally changed your identity to HEC (visible in the topbar too).
The message then faithfully read "HEC".

## Fix

Removed the profile-overwrite from `pickAlumniSchool`. The dropdown now only sets
`activeAlumniSchool` (a session-local search target). Your home school — set at onboarding,
editable only in Profile — stays put. Result:
- Draft message always says you're an MBA at **your** school, whatever you browse.
- Variant ② is "Shared-school angle" only when the alumni is actually from your school,
  else "Cross-school angle" — exactly what your two screenshots should now show, but with the
  identity locked to ESADE.
- The topbar school stops changing when you browse other schools' alumni.

Trade-off: the dropdown no longer *remembers* a non-home school across sessions (it defaults to
your home school each load). That persistence was the buggy behaviour; if you want it back later
it should live in localStorage, not your profile. Flag if you want that.

## Test
Alumni Finder → switch the dropdown to HEC Paris → Draft Message → variant ① says "an MBA at
ESADE Business School" (not HEC), variant ② reads "Cross-school angle". Switch back to ESADE →
variant ② becomes "Shared-school angle". Topbar stays "Shrey · ESADE Business School" throughout.

## Deploy
```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add app.js CHANGES_ALUMNI_SCHOOL_FIX.md
git commit -m "Fix: Alumni school picker no longer overwrites user's profile/home school"
git push
```
