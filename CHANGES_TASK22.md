# Task 22 — Drop free scan quota from 3 to 1

## What changed

Two constants flipped from `3` to `1`:

1. **`ldp-proxy/api/scan.js`** — `const SCAN_QUOTA = 1;` (line 48)
2. **`ldp-scout/app.js`** — `const SCAN_QUOTA_CLIENT = 1;` (line 1760)

Also added a quota observability line in `scan.js` right after the count
resolves:

```js
console.log('[quota] user', claims.sub, 'completed', scanCount, 'limit', SCAN_QUOTA);
```

(`claims.sub` is the verified Supabase user id — this is what `userId` refers
to in the spec.)

Two stale comments that mentioned "3 scans" were softened to "quota" /
"X of N scans" so they don't lie when the constant moves again.

## Security boundary vs display

- `SCAN_QUOTA` in `ldp-proxy/api/scan.js` is the **real enforcement**. The
  proxy is the only thing standing between an authenticated user and the
  Anthropic API key. It runs server-side on Vercel, counts completed scans
  via PostgREST against `user_scan_history`, and returns HTTP 429 with
  `code: 'quota_exceeded'` once `scanCount >= SCAN_QUOTA`. Bypassing this
  means bypassing the budget cap.
- `SCAN_QUOTA_CLIENT` in `ldp-scout/app.js` is **display + UX gating only**.
  It powers the "X of N scans remaining" copy, the pre-scan chip, and the
  client-side short-circuit (`renderQuotaExhausted`) that avoids a wasted
  proxy round-trip when the user is already over. Anyone can edit it in
  DevTools; it does not protect anything.

## Why both must match

If client says "3 remaining" but server enforces 1, the user clicks Scan,
gets a 429 from the proxy, and sees the hard-block error UI — confusing
and looks like a bug. If client says "1 remaining" but server enforces 3,
we leave free scans on the table and the help-desk request is "why
won't it let me scan, I thought I had more left?" Same incoherence in
reverse. The constants are intentionally duplicated (client can't import
from a Node-only file) so they have to be edited together.

## Grandfathering

The check is `scanCount >= SCAN_QUOTA`, evaluated at request time against
the current row count in `user_scan_history`. It is **not** a flag that
gets stamped on the user record. Implications:

- A user who already completed 1, 2, or 3 scans under the old limit has
  rows in `user_scan_history` that are unaffected by this change.
- Under the new `SCAN_QUOTA = 1`, anyone with `count >= 1` is at or over
  quota, so the *next* attempted scan is blocked. Their *existing* tier
  results render normally (those are loaded from `user_scan_history`, not
  re-generated), so they don't lose visible value.
- Functionally: users who already scanned **see no change** to what's
  rendered. Users with 0 prior scans get exactly one scan instead of
  three. Only brand-new signups feel the tighter cap.

If we ever want to actually retire old free scans we'd need to either
delete rows or add a separate `scans_granted` field on the user; neither
is in this change.

## Deploy

- **Frontend** (`ldp-scout/`): deploys via the usual `git push` to main.
- **Proxy** (`ldp-proxy/`): deploys manually by Shrey from a fresh
  PowerShell — not from this Claude Code session:

  ```powershell
  cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-proxy
  npx vercel --prod
  ```

Until the proxy is redeployed, enforcement is still at the old limit (3)
even after the frontend is live — that's safe (server permissive, client
strict means users just see "0 of 1 remaining" but the proxy still lets
the call through). The reverse order (proxy first, frontend later) would
be safer if we cared about a tight UX, but for this change it doesn't
matter much.
