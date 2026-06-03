# Task SEC — Security quick-wins

Hardening pass from the 2026-06-03 audit (`SECURITY_AUDIT_2026-06-03.md`). Live Supabase
RLS was verified correct (per-user policies on every user table) — no DB changes needed.
These are the client/app-layer fixes. **No user-facing behaviour changes** (see below).

## Changes (`app.js`, `vercel.json`)
1. **Escape AI-model output (XSS).** `renderAIResults()` now wraps the model's `reason`,
   `rating`, `tip`, `title`, and `body` in `esc()` before inserting them as HTML.
2. **Block dangerous URL schemes.** New `safeUrl()` permits only `http(s):`/`mailto:`
   (otherwise `#`); applied to every program and LinkedIn link `href`. Stops a stored
   `javascript:`/`data:` URL from executing on click.
3. **Redact PII from auth logs.** Removed the user's email from 8 `[auth]` `console.*`
   calls (they were captured into Sentry breadcrumbs). Debug signal (context, flags) kept.
4. **Removed dead "bring-your-own-key" path.** `showApiKeyPrompt()`/`setApiKey()` were
   unreachable and persisted an Anthropic key in `sessionStorage`; deleted.
5. **Security headers** (`vercel.json`): `X-Content-Type-Options: nosniff`,
   `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`,
   `Permissions-Policy: camera=(), microphone=(), geolocation=()`.

## Does this change the user experience?
**No visible change.**
- AI advice text is plain text, so `esc()` is invisible for normal content; it only
  matters if the model ever emits literal `< > & " '`, which now display correctly
  instead of being parsed as HTML.
- `safeUrl()` leaves all normal `http(s)`/`mailto` links working exactly as before; it
  only neutralises malicious schemes.
- Console-log and header changes are invisible to users.
- The removed key-prompt was unreachable, so nothing is lost.

## Deferred (needs a refactor, not shipped here)
A strict `Content-Security-Policy` would be the strongest XSS defence, but the app uses
inline `onclick`/`onmouseover` handlers and inline styles everywhere; a meaningful CSP
requires converting those to delegated listeners first + full signed-in testing.

## Verification
- `node --check app.js` → PASS; `vercel.json` parses as valid JSON.
- Loaded via the `ldp-static` preview: zero console errors; `safeUrl()` unit-checked
  (`javascript:alert(1)` → `#`, `https://x.com` → unchanged).
