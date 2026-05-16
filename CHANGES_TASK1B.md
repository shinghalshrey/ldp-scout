# Task 1B — Fix: AI Fit scan not loading on first navigation

## What the race was

`initAuth()` calls `sb.auth.getSession()` (async), stores the resolved user in
the module-level `currentUser`, and then calls `onSignIn()`. This is all async
and not awaited by the script's top-level boot sequence.

On first navigation to the AI Fit tab, `showPage('aifit')` calls
`loadAndRenderLastScan()` immediately. The original guard was:

```js
if(!currentUser) return;   // bail early if no user
```

But `currentUser` can be set in memory while the Supabase JS client's internal
session state hasn't yet propagated — specifically, the bearer token that the
client attaches to outbound fetch requests. The Supabase client only fully
commits the session token after the `INITIAL_SESSION` / `SIGNED_IN`
`onAuthStateChange` event has been processed internally. If
`loadAndRenderLastScan()` fires before that internal propagation finishes, the
two `from('user_scan_history')` queries go out without the auth header, RLS
silently returns zero rows, `!row` is true, and the function returns early —
leaving the upload zone visible.

After a hard refresh (`Ctrl+Shift+R`), the browser re-runs the full init
sequence. The `INITIAL_SESSION` event fires and is fully processed before the
user can click any tab, so the session token is attached and queries succeed.

## Which fix was chosen and why

**Option (a): replace the in-memory guard with `await sb.auth.getUser()`.**

```js
// before
if(!currentUser) return;
// ... queries used currentUser.id

// after
const { data: { user } } = await sb.auth.getUser();
if(!user) return;
// ... queries use user.id
```

`sb.auth.getUser()` is a Supabase JS v2 method that resolves the session
fully — including flushing any pending internal token propagation — before
returning. Awaiting it at the top of `loadAndRenderLastScan()` guarantees that
subsequent queries go out with a valid bearer token, regardless of when in the
init lifecycle the function is called.

This approach was chosen over option (b) (re-triggering from `onAuthStateChange`)
because:

- **Self-contained.** The fix lives entirely inside `loadAndRenderLastScan()`.
  No need to add a "which page is currently visible?" check to the auth listener.
- **Minimal diff.** Two lines changed, one line added (console.log).
- **Correct by construction.** The function no longer has any dependency on the
  order of external initialization; it resolves its own user identity before
  touching the DB.
- **No redundant calls.** `getUser()` is fast (hits the local session storage
  then validates with Supabase; no extra round-trip if the session is healthy).

A `console.log` was also added at the very top of the function so you can
confirm the race in DevTools: it prints `currentUser` **before** the `getUser()`
await, showing whether it was null at call time.

## Files changed

- `app.js` — `loadAndRenderLastScan()` (lines ~1443–1470)

## How to test

1. Log out completely (Supabase session cleared).
2. Log in via OTP. You should land on the Programs tab.
3. **Without refreshing**, click the AI Fit tab.
4. **Expected (after fix):** Previous scan results load immediately.
   **Before fix:** Upload zone appeared; hard refresh was required.
5. Open DevTools → Console. Confirm the log line:
   `[loadAndRenderLastScan] currentUser at call time: null`
   (or a UUID if the race was already gone by the time you clicked).
   Either way, the scan should now load because `getUser()` resolves the
   session authoritatively before querying.
6. Verify hard refresh still works (regression check).
7. Verify a brand-new user (no scan history) still sees the upload zone.
