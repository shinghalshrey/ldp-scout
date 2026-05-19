# LDP Scout — Project Overview

**One-line:** Résumé-to-MBA-Leadership-Development-Program matcher. Upload a résumé, get AI-scored fit for ~393 LDP programs across Europe and beyond, with alumni discovery, deadline tracking, and a shortlist Kanban.

**Live:** https://ldpscout.com (also https://www.ldpscout.com)

**Audience:** Current MBA students and alumni at whitelisted schools (INSEAD, IESE, IE, Bocconi, IMD, LBS, Oxford Saïd, Cambridge Judge, ESADE, HEC, ESCP, EDHEC, RSM, etc. — full list in `app.js` `EDU_DOMAIN_WHITELIST`).

---

## Tech stack

| Layer | Tech | Notes |
|---|---|---|
| Frontend | Vanilla JS, single-page (no framework) | `app.js` ~4,500 lines, `index.html`, `styles.css`, `data.js` (programs DB seed) |
| Auth | Supabase Auth — email OTP (8-digit) + optional password | Anon key inline in `app.js:14`; real security from RLS |
| Database | Supabase Postgres | 7 tables in `public` schema, all RLS-enabled. Full schema: `DB_SCHEMA.md` |
| AI proxy | Vercel serverless function (`ldp-proxy/api/scan.js`) | Verifies Supabase JWT (ES256 via JWKS, HS256 legacy), enforces quota, forwards to Anthropic |
| AI models | Anthropic Claude — Opus 4.6 (tier classification), Sonnet 4.5 (gap analysis), Haiku 4.5 (reserve) | Whitelisted in `scan.js` `ALLOWED_MODELS` |
| Email | Supabase built-in (sender: `noreply@ldpscout.com`) | No Resend integration currently. If/when added, document here. |
| Domain | Cloudflare (purchase + DNS) | Vercel hosts the actual sites |
| Frontend hosting | Vercel (auto-deploy on git push to main) | Repo: `ldp-scout` |
| Proxy hosting | Vercel (manual deploy) | Private GitHub repo: `shinghalshrey/ldp-proxy`. **Auto-deploy is intentionally NOT connected** — manual deploy only. |

**Frontend libs (loaded from CDN in `index.html`):**
- `@supabase/supabase-js@2`
- `pdf.js@2.16.105` — résumé PDF parsing
- `mammoth@1.6.0` — résumé .docx parsing
- Google Fonts: Fraunces (editorial serif), DM Mono, Outfit

---

## Folder structure (local)

```
C:\Users\shrey\Desktop\LDP-Scout-Master\
├── ldp-scout\               # frontend — git repo, deploys via push
│   ├── app.js
│   ├── index.html
│   ├── styles.css
│   ├── data.js
│   ├── CHANGES_TASK*.md     # per-task plain-English explainers
│   ├── SMOKE_TESTS.md
│   ├── PROJECT_OVERVIEW.md
│   ├── DB_SCHEMA.md
│   └── LDP_audit_scoresheet.xlsx
└── ldp-proxy\               # proxy — private GitHub repo, manual Vercel deploy
    └── api\scan.js
```

Folder was renamed from "LDP Scout Master" → "LDP-Scout-Master" to avoid spaces in paths.

---

## Deploy commands

**Frontend:**
```bash
git add -A && git commit -m "..." && git push
# Vercel auto-builds on push to main
```

**Proxy (the one that bites you):**
```powershell
# Fresh PowerShell window — NOT inside a Claude Code session.
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-proxy
npx vercel --prod
```

**Why this matters:** `npx vercel` deploys interactively. Running it inside a Claude Code session swallows the prompts and the deploy hangs or fails silently. Always use a fresh terminal.

---

## Auth flow (canonical, post-Session 4)

**Two-button landing UI.** Email field with both **Sign Up** and **Sign In** buttons side by side.

**Sign Up path (new users):** Email → domain whitelist check → `email_account_status` RPC confirms no existing account → OTP sent → 8-digit code → **mandatory** password setup (no skip) → mandatory full-name capture during onboarding → into app.

**Sign In path, existing user with password:** Password field shown by default. "Login using code instead?" and "Forgot password?" available as text links beneath.

**Sign In path, existing user without password:** OTP flow (no password setup at end — they already exist).

**Forgot password:** Uses `force:true` to mandate password setup post-OTP regardless of `has_password` flag.

**Race condition fix (Task 9):** "Login using code instead?" path awaits fresh `sb.auth.getUser()` before deciding whether to show password setup step. Without this, stale auth state caused the setup step to render for users who already had passwords.

**Password-signup (entering a new email on the password form):** Not reachable from the UI. Sign Up button only accepts emails with no existing account; Sign In button only accepts emails that already have one.

**Supabase setting:** "Confirm email" toggle is **ON** (verified May 18, 2026). With OTP flow this is fine — the OTP code IS the confirmation, no clickable link involved, so email-safety scanners don't preconsume it.

**Session persistence:** Supabase sessions live in localStorage for ~30 days. In incognito, sessions are wiped when ALL incognito windows are closed, not when individual windows close.

---

## Quota & cost model

- **Free quota:** 3 completed scans per user, lifetime. Enforced server-side in `scan.js` by counting rows in `user_scan_history` for that user via PostgREST `count=exact`. Fail-closed (503) if the quota query errors.
- **Quota row written by frontend** *after* both tier + gap calls succeed. So the check on call N+1 blocks the next scan, not the current one.
- **Cost target:** $0.10/scan (Task 5). Current is higher. Biggest lever is model choice; secondary is prompt size and `max_tokens`.
- `MAX_TOKENS_CAP = 32000` in proxy (bumped from 6000 so tier classification can return all 393 programs in one pass).

---

## Working approach

- **This chat (Claude.ai)** — planning, triage, debugging, schema work, prompt drafting.
- **Claude Code (CLI)** — actual code changes. One task per session. Always paste back the diff and a `CHANGES_TASKX.md` explainer.
- **Triage before building.** New issue mid-session → 2-min diagnostic first.
- **Test write AND read paths** before declaring done (Task 1 lesson).
- **Deploy gotcha:** proxy from PowerShell, not from inside Claude Code.

---

## Known stale things in pinned files (clean these up when convenient)

These don't break anything but will confuse future-you or future-Claude:

1. **`scan.js` line ~25 comment** mentions "Opus 4.7" but `ALLOWED_MODELS` whitelists `claude-opus-4-6`. Either bump the whitelist or fix the comment. (Worth deciding before Task 5 cost work — Opus 4.7 vs 4.6 is a real cost/quality tradeoff.)

2. **`DB_SCHEMA.md`** lists only two users with `has_password = true` (Session 3 snapshot). Re-query before referencing this number — it grows with every Task 9 password-setup completion.
