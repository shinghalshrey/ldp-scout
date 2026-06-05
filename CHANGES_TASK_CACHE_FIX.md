# Task: Clear program cache on sign-out

## What was wrong

The list of programs is cached in the browser's localStorage under the key
`ldps_progs`. That cache is **per-browser (per-domain)**, not per-user. It does
not get wiped when someone signs out.

Because the app uses a "stale-while-revalidate" pattern — it shows the cached
programs immediately and *then* refreshes them from Supabase — the following
leak was possible:

1. An ESADE user signs in. The cache fills with 428 programs, including 18
   that are ESADE-exclusive.
2. That user signs out, but the cache stays on disk.
3. A different school's user (e.g. HEC) signs in on the **same browser**.
4. For a brief moment the app shows the 428 stale ESADE programs — including
   the 18 ESADE-only ones — before the fresh Supabase query (410 programs for
   HEC) replaces them.

That brief window is a data leak: one school's user can momentarily see another
school's exclusive programs.

## What changed

One file changed: **`app.js`** — inside the `onSignOut()` function.

Added two lines, right next to the existing localStorage cleanup that already
clears the saved last-page:

```js
// Task TC — clear the per-domain program cache so a different school's user
// can't briefly see the previous user's school-exclusive programs via the
// stale-while-revalidate path before the fresh Supabase query lands.
try { localStorage.removeItem('ldps_progs'); } catch {}
console.log('[Auth] program cache cleared on sign-out');
```

- `localStorage.removeItem('ldps_progs')` deletes the cached program list on
  sign-out, so the next user starts from an empty cache and only ever sees data
  freshly fetched for *their own* account. The `try/catch` matches the style of
  the adjacent cleanup line and guards against localStorage being unavailable.
- The `console.log` is a diagnostic marker so the cache-clear can be confirmed
  in the browser console during testing.

No other files were touched. `index.html`, `styles.css`, `scan.js`, and
`data.js` were left as-is.

## Verification

- **`node --check app.js`** — passes (syntax OK).
- **Manual sign-in/sign-out cycle** — requires real ESADE and HEC Supabase
  credentials, so it must be run by someone who has them. Expected behaviour:
  1. Sign in as ESADE → programs load (428), cache populated.
  2. Sign out → browser console shows `[Auth] program cache cleared on sign-out`.
  3. Sign in as HEC → programs load fresh from Supabase (410), with **no** stale
     ESADE-only programs visible even briefly.
