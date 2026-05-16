# Task 1: Fix AI Fit Scan Persistence

## Root Cause (plain English)

**Two bugs, one broken SQL config.**

### Bug 1 — INSERT silently discards errors (app.js)

Supabase JS v2's `.insert()` / `.select()` calls **never throw**. They always
resolve to `{ data, error }`. The original `saveScanToHistory` did:

```js
await sb.from('user_scan_history').insert({ ... });
```

…and never checked `error`. So when the server rejected the insert (403 RLS or
GRANT block), the `await` resolved normally, the catch block was never hit, and
the code happily bumped `_scanCount` as if the row had been saved. Nothing was
actually persisted to the database, but nothing was logged either. The user saw
correct results on the screen but got a blank page after logout/login.

### Bug 2 — Count query also didn't check errors (app.js)

In `loadAndRenderLastScan`, the count query:

```js
const countResp = await sb.from('user_scan_history')
  .select('id', { count: 'exact', head: true })
  .eq('user_id', currentUser.id);
_scanCount = countResp.count || 0;
```

`countResp.error` was never inspected. A 403 response leaves `countResp.count`
as `null`, so `_scanCount` silently became `0`. No error was logged, so there
was no visible indication of the failure.

### Root cause of the 403 — Missing GRANT

The `user_scan_history` table was created via raw SQL (not through the Supabase
dashboard). The Supabase dashboard normally auto-adds:

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON table TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON table TO anon;
```

Raw `CREATE TABLE` does not do this. Without the GRANT, even a perfectly correct
RLS policy is irrelevant — PostgREST returns HTTP 403 before RLS is even
evaluated, because the `authenticated` role has no permission to touch the table
at all.

---

## What was changed in app.js

### `saveScanToHistory` (≈ line 1399)

- Destructures `{ error: insertErr }` from the INSERT call.
- If `insertErr` is set, logs it with `console.error` including the Supabase
  error `code`, `message`, `hint`, and `details` — every field PostgREST
  returns — then re-throws so the outer catch fires.
- Changed outer catch from `console.warn` to `console.error` so failures are
  visually distinct in the console.

### `loadAndRenderLastScan` — count query (≈ line 1439)

- Checks `countResp.error` immediately after the count query.
- If set, logs it with `console.error` (same structured fields) so a 403 is
  immediately obvious.

### `loadAndRenderLastScan` — latest-row query (≈ line 1456)

- Upgraded the existing `console.warn` to `console.error` and added the
  structured `code` / `hint` fields to match the new logging convention.

---

## SQL to run in Supabase SQL Editor

Open the Supabase dashboard → SQL Editor and run this once. It is fully
idempotent (safe to re-run).

```sql
-- 1. Grant table-level access to the authenticated role.
--    Without this, PostgREST returns 403 before RLS is even checked.
GRANT SELECT, INSERT ON public.user_scan_history TO authenticated;

-- 2. Enable RLS (idempotent if already on).
ALTER TABLE public.user_scan_history ENABLE ROW LEVEL SECURITY;

-- 3. Drop + recreate policies so they explicitly target the authenticated role.
--    The original policies had no TO clause, which is technically correct but
--    makes them hard to inspect. Explicit is better.
DROP POLICY IF EXISTS "users read own scans"   ON public.user_scan_history;
DROP POLICY IF EXISTS "users insert own scans" ON public.user_scan_history;

CREATE POLICY "users read own scans"
  ON public.user_scan_history
  FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "users insert own scans"
  ON public.user_scan_history
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);
```

---

## How to test

1. **Run the SQL above** in the Supabase dashboard first.

2. Sign in, upload a résumé, and run an AI Fit scan. Open the browser DevTools
   console. You should see **no** `[saveScanToHistory]` errors. The row should
   now appear in Supabase → Table Editor → `user_scan_history`.

3. Sign out, then sign back in. Navigate to AI Fit. The previous scan results
   should render automatically (no re-upload needed).

4. If you still see a 403, check the console — the new logging will print the
   exact Supabase error code and hint, pointing directly at the remaining issue.

5. To confirm the "scan used" counter is correct: the chip in the results view
   should show the real count (e.g. "1 of 5 scans used") and not reset to 0
   after a page reload.

---

## On the 422 at /auth/v1/user

This comes from `sb.auth.updateUser({ password, data: { has_password: true } })`
in the post-OTP password-set flow. Supabase returns 422 when the session's
access token is too old to perform a sensitive mutation (it requires a "fresh"
session). This is not related to scan persistence and does not block the normal
sign-in/scan flow. It only affects users who click the "set a password" prompt
immediately after a magic-link sign-in but whose token has already been
refreshed once. It is safe to leave alone for now; fixing it would require
reauthenticating the user (e.g. resending the magic link with `shouldCreateUser:
false`) before calling `updateUser`.
