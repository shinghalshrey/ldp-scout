# LDP Scout — Project Overview

**One-line:** Résumé-to-MBA-Leadership-Development-Program matcher. Upload a résumé, get AI-scored fit for ~393 LDP programs across Europe and beyond, with alumni discovery, deadline tracking, and a shortlist Kanban.

**Live:** https://ldpscout.com (also https://www.ldpscout.com)

**Audience:** Current MBA students and alumni at whitelisted schools (INSEAD, IESE, IE, Bocconi, IMD, LBS, Oxford Saïd, Cambridge Judge, ESADE, HEC, ESCP, EDHEC, RSM, etc. — full list in `app.js` `EDU_DOMAIN_WHITELIST`).

---

## Tech stack

| Layer | Tech | Notes |
|---|---|---|
| Frontend | Vanilla JS, single-page (no framework) | `app.js` ~4,400 lines, `index.html`, `styles.css`, `data.js` (programs DB seed) |
| Auth | Supabase Auth — email OTP (8-digit) + optional password | Anon key inline in `app.js:14`; real security from RLS |
| Database | Supabase Postgres | Tables: `user_profiles`, `user_scan_history`. Schema: `DB_SCHEMA.md` |
| AI proxy | Vercel serverless function (`ldp-proxy/api/scan.js`) | Verifies Supabase JWT (ES256 via JWKS, HS256 legacy), enforces quota, forwards to Anthropic |
| AI models | Anthropic Claude — Opus 4.6 (tier classification), Sonnet 4.5 (gap analysis), Haiku 4.5 (reserve) | Whitelisted in `scan.js` `ALLOWED_MODELS` |
| Email | Supabase built-in (sender: `noreply@ldpscout.com`) | No Resend integration currently. If/when added, document here. |
| Domain | Cloudflare (purchase + DNS) | Vercel hosts the actual sites |
| Frontend hosting | Vercel (auto-deploy on git push to main) | Repo: `ldp-scout` |
| Proxy hosting | Vercel (manual deploy) | Folder: `ldp-proxy` — **not a git repo** |

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
│   └── LDP_audit_scoresheet.xlsx
└── ldp-proxy\               # proxy — NOT a git repo, deploys manually
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

## Auth flow (current state, post-Session 3)

1. User enters school email → frontend checks against `EDU_DOMAIN_WHITELIST` (exact-domain match, case-insensitive). No `.edu`/`.ac.uk` regex fallback (removed in Phase 15).
2. Send 8-digit OTP via Supabase email.
3. User enters code → Supabase verifies → session issued.
4. If `user_metadata.has_password === true` → skip password setup, go to app.
5. If no `has_password` flag → offer optional "Set a password" step. **Currently optional. Open question whether to make this mandatory (Option C from Session 3).**

A "Use a password instead" link sits below Send Code for returning users. Currently a small green underlined link — Issue Y is making it more visible.

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

1. **`SMOKE_TESTS.md` Test 1** says "6-digit code" — actual flow uses **8-digit** (see `app.js:422`, `:454`, `:475`).
2. **`scan.js` line ~25 comment** mentions "Opus 4.7" but `ALLOWED_MODELS` whitelists `claude-opus-4-6`. Either bump the whitelist or fix the comment. (Worth deciding before Task 5 cost work — Opus 4.7 vs 4.6 is a real cost/quality tradeoff.)
3. **Handover framing of Issue X** says "Whitelist accepts any address at a valid domain." That's not a bug — that's how email whitelists work. The real Issue X question is whether Supabase delivered an OTP to a typo address and someone actually received it. The 2-min incognito test is to verify this, not to test the whitelist.
