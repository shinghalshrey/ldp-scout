# LDP Scout — Security Audit (2026-06-03)

Read-only review of `index.html`, `app.js`, `vercel.json`, `data.js`, `DB_SCHEMA.md`,
plus a live export of the Supabase RLS policies. Backend is **Supabase (Postgres +
Auth)**; the AI scan calls a **separate** Vercel proxy (`ldp-proxy.vercel.app/api/scan`,
not in this repo). The **🟢 Fixed** items were addressed in commit *Task SEC* (same day);
see `CHANGES_TASK_SEC.md`.

## The model in one line
The Supabase **anon key is public by design** (it ships in `app.js` — expected). So
**Row-Level Security is the only thing isolating one user's data from another's.**

---

## Verified live — RLS is correctly configured ✅
From the live `pg_policies` export (2026-06-03):

| Table | Policy (cmd) | Rule |
|-------|--------------|------|
| `user_profiles` | select / update / insert | `auth.uid() = user_id` |
| `user_applications` | ALL | `auth.uid() = user_id` (qual + check) |
| `user_resumes` | ALL | `auth.uid() = user_id` (qual + check) |
| `user_contacts` | ALL | `auth.uid() = user_id` (qual + check) |
| `user_scan_history` | select / insert | `auth.uid() = user_id` |
| `community_intel` | read (authenticated) / write own | `auth.uid() = user_id` |
| `program_job_descriptions` | read (authenticated) | — |
| `programs` | select | `true` (public catalog) |

Every user-data table is scoped to the owning user. `programs` is **read-only public**
(no INSERT/UPDATE/DELETE policy ⇒ clients cannot tamper with the catalog; edits happen
via the service role in the SQL editor). **Conclusion: no user-to-user data leakage
through the database.**

> Residual check (do once): confirm RLS is *enabled* per table, since policies are
> ignored if the table's RLS flag is off:
> `select relname, relrowsecurity from pg_class where relname like 'user\_%';`
> — each must be `true`.

---

## Findings

### 🟢 Fixed in Task SEC
- **XSS — AI-model output rendered as raw HTML.** `renderAIResults()` interpolated the
  model's `reason`, `rating`, `tip`, `title`, `body` without escaping. Today this is
  self-XSS (a scan only renders in the author's own browser, seeded by their own résumé
  + the admin catalog), but a successful XSS could read the Supabase session JWT from
  `localStorage`. **Fix:** all five now go through `esc()`. (`profile_summary` is not
  rendered to the DOM, so no change needed there.)
- **`javascript:` / `data:` URLs in links.** Program and contact links rendered
  `href="${esc(url)}"`; `esc()` escapes quotes but not the URL scheme, so a stored
  `javascript:…` URL was a clickable self-XSS. **Fix:** new `safeUrl()` allows only
  `http(s):`/`mailto:` (else `#`), applied to all program/LinkedIn link hrefs.
- **PII (emails) in auth console logs → Sentry breadcrumbs.** Eight `[auth]` logs
  printed the user's email; Sentry captures console logs as breadcrumbs, so emails left
  the browser on any error. **Fix:** emails redacted from those logs (debug signal kept).
- **Dead "bring-your-own-key" path.** `showApiKeyPrompt()`/`setApiKey()` were unreachable
  (the scan always uses the JWT proxy) yet persisted a user's Anthropic key in
  `sessionStorage`. **Fix:** removed.
- **Missing security headers.** **Fix:** `vercel.json` now sets `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: SAMEORIGIN` (anti-clickjacking), `Referrer-Policy:
  strict-origin-when-cross-origin`, and a restrictive `Permissions-Policy`.

### 🟡 Open / accepted (lower priority)
- **Session-replay & analytics egress.** `index.html` loads Microsoft **Clarity**
  (session replay), **Sentry**, and **GA**. None leak to *other users*, but they send
  data off-platform:
  - Clarity is loaded with **no explicit masking config**. It masks password fields and
    (by default) input text, but records on-screen DOM — i.e. résumé-derived content and
    program lists. **Recommend:** set Clarity masking to strict and confirm in the Clarity
    dashboard; consider not loading it on the résumé/scan views.
  - GA `application_logged` sends `program_name` + `org` to Google (`app.js`). Minor.
  - **Recommend** documenting these in a privacy notice.
- **Account enumeration.** The anon-callable `email_account_status` RPC returns
  `{account_exists, has_password}` for any email. Common pattern; accept, or add
  rate-limiting/captcha if you want to close it.
- **Content-Security-Policy not set.** A strict `script-src` CSP would be the strongest
  defense against the XSS class above, but the app uses inline `onclick`/`onmouseover`
  handlers and inline styles throughout, so a meaningful CSP requires refactoring those
  to delegated listeners first, then full signed-in testing. **Deferred** — tracked as a
  follow-up; not shipped in Task SEC to avoid breaking the app.

---

## Direct answers
- **Can passwords leak?** **Low.** Passwords go only to Supabase Auth over HTTPS, are
  bcrypt-hashed server-side, and are never in the `public` tables, `localStorage`, or
  console logs. Inputs are `type="password"` (Clarity does not record their values). No
  service-role key is in the client — only the public anon key.
- **User-to-user data leakage?** **No** — confirmed by the live RLS policies above.
- **Are these protected?** Yes: HTTPS, Supabase Auth for credentials, RLS for data,
  server-side AI key behind a JWT-authenticated proxy with server-enforced scan quota.
- **Are user-added programs safe?** **Yes.** They live in `user_applications` (RLS
  own-row, private), and all fields are escaped on render. The former `javascript:`-URL
  self-XSS in the `url` field is now closed by `safeUrl()`.

## Already done well
HTTPS throughout · public anon key only (no service key in client) · correct per-user
RLS · passwords delegated to Supabase Auth · AI key server-side behind a JWT proxy with
quota enforcement · user input escaped via `esc()` · `rel="noopener"` on external links.
