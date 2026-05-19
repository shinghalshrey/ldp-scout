# LDP Scout — Project Overview

**One-line:** Résumé-to-MBA-Leadership-Development-Program matcher. Upload a résumé, get AI-scored fit for ~393 LDP programs across Europe and beyond, with alumni discovery, deadline tracking, and a shortlist Kanban.

**Live:** https://ldpscout.com (also https://www.ldpscout.com)

**Audience:** Current MBA students and alumni at whitelisted schools (INSEAD, IESE, IE, Bocconi, IMD, LBS, Oxford Saïd, Cambridge Judge, ESADE, HEC, ESCP, EDHEC, RSM, etc. — full list in `app.js` `EDU_DOMAIN_WHITELIST`).

---

## Tech stack

| Layer | Tech | Notes |
|---|---|---|
| Frontend | Vanilla JS, single-page (no framework) | `app.js` ~4,900 lines, `index.html`, `styles.css`, `data.js` (programs DB seed) |
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

**Mandatory full_name (Task 19):** Onboarding step 1 disables the Next button until `value.trim().length >= 1` and hides the Skip button. Existing rows with NULL `full_name` are caught by `onbShouldShow()` triggering the onboarding modal on next sign-in.

**Supabase setting:** "Confirm email" toggle is **ON** (verified May 18, 2026). With OTP flow this is fine — the OTP code IS the confirmation, no clickable link involved, so email-safety scanners don't preconsume it.

**Session persistence:** Supabase sessions live in localStorage for ~30 days. In incognito, sessions are wiped when ALL incognito windows are closed, not when individual windows close.

---

## Personalization (Task 19, applied across product)

Single helper: `getFirstName()` reads `userProfile.full_name`, trims, splits, returns the first token. All personalization downstream keys off this.

Where it shows:
- **Topbar:** firstName · school_label (fallback to email if `full_name` is NULL)
- **Programs page:** "Welcome back, *FirstName*." h1 + live "{N} programs in your pipeline · {M} deadlines this month" subline. STATE B fallback: "Verified MBA LDP programs." with count-agnostic copy (per Task 20 — no static numbers that would leak into OG previews / pre-JS crawlers).
- **Alumni Finder, Applications, Deadlines, AI Fit (pre + post-scan):** h2/h1 + subtitle personalized
- **Profile modal:** "*FirstName*, edit your details" title

Refresh paths: `showPage()` calls `applyPagePersonalization(id)`. `saveUserProfile()` calls `_refreshActivePagePersonalization() + updateAuthUI()` so name changes propagate without a page nav.

---

## Programs catalog architecture (Path A, Task 19.2)

**The `programs` table is read-only from the client.** No INSERT/UPDATE/DELETE RLS policies. Users cannot mutate the catalog.

The old `+ Add Program / Edit / Delete` buttons were vestigial from a pre-Supabase architecture. They wrote to in-memory `progs[]` + localStorage and got silently wiped on next sign-in by `fetchProgramsFromSupabase()`. As of Task 19.2 they're gone from the UI. `saveProg()`, `editP()`, `delP()` are stubs with `console.warn` to catch lingering refs.

Users wanting to track a program not in the catalog:
- Email `hello@ldpscout.com` to request addition (mailto link in the Programs meta row), OR
- Log it manually on the Applications page (per-user table, IS writable)

**Future option (Path B, not implemented):** A `user_programs` table with RLS scoped to `auth.uid()` that unions with the global catalog for display. Email-based requests cover current demand at scale.

---

## Pipeline semantic

Pipeline = shortlisted + networking + drafting + applied + interview + offer.
NOT pipeline = rejected (exited).

Offer is the **goal-state** of being in pipeline, not an exit. `_pipelineCount()` and `_deadlinesThisMonth()` use `status !== 'rejected'`.

---

## Quota & cost model

- **Free quota:** 3 completed scans per user, lifetime. Enforced server-side in `scan.js` by counting rows in `user_scan_history` for that user via PostgREST `count=exact`. Fail-closed (503) if the quota query errors.
- **Quota row written by frontend** *after* both tier + gap calls succeed. So the check on call N+1 blocks the next scan, not the current one.
- **Cost target:** $0.10/scan (Task 5). Current is higher. Biggest lever is model choice; secondary is prompt size and `max_tokens`.
- `MAX_TOKENS_CAP = 32000` in proxy (bumped from 6000 so tier classification can return all 393 programs in one pass).

---

## Programs page UI (post-Task 19.2)

**Layout:** Two-column. 240px sticky left sidebar (accordion sections) + main column.

**Sidebar sections** (collapsible accordions, state persists in `ldps_prog_sidebar_v1`):
1. Search (always visible)
2. Quick Filters — Visa-sponsoring only (Pipeline pill moved to stat card)
3. Geography — Europe / UAE / Global (Task 19.3 will replace with continent drill-down)
4. Function — Operations / Finance / Strategy / Consulting / Investments
5. Sector (new, Task 19.2) — 9 sectors from `ALUMNI_SECTORS` taxonomy
6. App Cycle (renamed from Status) — Open / Rolling / Watch
7. Pro Tip card

Each section header shows `(N)` badge when filters are active. `_refreshSidebarBadges()` runs on every `renderPrograms()`.

**Stat row** (5 cards): TOTAL · ✦ AI FIT · OPEN NOW · ROLLING · ★ MY PIPELINE (amber). Watch/Prep stat card removed in 19.2 (was a duplicate of the sidebar pill).

**Table** (9 columns): Program/Org · Function · Sector · Location · Deadline · App Cycle · ✦ AI Fit · **Stage (dropdown)** · 📅 Reminder. Vertical column borders for legibility.

**Stage dropdown** is the headline UX win of Task 19.2. Per row: shows current pipeline stage OR "+ Add to pipeline" empty state. Click opens a custom panel with 7 stage options (Shortlisted → Rejected) + "Remove from pipeline" if applicable. Writes through `saveApplicationToDB` / `deleteApplicationFromDB` so the Applications Kanban stays consistent.

**Removed:** Pipeline button column, Actions (Edit/Del) column, +Add Program button. Replaced by Stage dropdown + mailto link in the meta row.

---

## Working approach

- **This chat (Claude.ai)** — planning, triage, debugging, schema work, prompt drafting, **and direct code edits** (now that Pranav doesn't run Claude Code for these tasks).
- **Claude Code (CLI)** — reserved for the heavy DB work (e.g. Task 19.3 SQL migration). One task per session.
- **Pranav executes the git push from PowerShell.**
- **Triage before building.** New issue mid-session → 2-min diagnostic first.
- **Test write AND read paths** before declaring done.
- **Every commit gets a CHANGES_TASKn.md** explainer — gap in 19.1 happened once, won't again.
- **Deploy gotcha:** proxy from PowerShell, not from inside Claude Code.

---

## Recent task log (most recent first)

| Task | One-line | Files | Date |
|---|---|---|---|
| 19.2 | Programs page architecture overhaul: Path A read-only catalog, Stage dropdown, accordion sidebar, Sector filter, amber Pipeline stat card, pipeline semantic fix | app.js, index.html, styles.css | May 19, 2026 |
| 19.1 | Sidebar reorder (Quick Filters to top), table row dividers, tour step 2 target fix | app.js, index.html, styles.css | May 19, 2026 |
| 19 | Programs page redesign (Lovable two-column layout), personalization across 5 pages + topbar + profile modal, mandatory full_name on onboarding step 1, "48" sweep | app.js, index.html, styles.css | May 19, 2026 |
| 20 | Remove hardcoded program count from static HTML (OG preview was scraping stale "48") | index.html | May 18, 2026 |
| 9 | Landing page two-button auth (Sign Up / Sign In) + mandatory post-OTP password setup + race-condition fix | app.js, index.html, styles.css | May 18, 2026 |

---

## Queued (next up)

### Task 19.3 — Geography continents with multi-continent support

Replace the 3-bucket geo filter (Europe / UAE / Global) with continent-based filtering supporting programs that span multiple continents.

**Approach:**
- Add `continents` TEXT[] array column to `programs` table
- Manual curation across all 393 rows: tag each with relevant continents (a program in "EU · UAE · India" gets `{europe, asia}`, no "Global" catch-all)
- Filter logic: OR-match (`p.continents.some(c => F.geo.has(c))`)
- Frontend: 6 continent pills (Europe / Asia / North America / South America / Africa / Australia). No "Global" pill — span-multiple-continents handled by the array.

**Requires:** DB migration session in Claude Code, plus several hours of content curation (LLM first-pass tagging from `loc` strings, human review of edge cases). Open questions to resolve before starting: UAE → Asia or MENA? Russia → Europe or Asia? Antarctic research programs (probably none, but worth confirming the taxonomy).

**Future extensibility:** The same TEXT[] approach can layer Country and City filters on top — continent click reveals countries (filtered to programs in that continent), country click reveals cities. Already designed; not blocked on Task 19.3.

---

## Known stale/cleanup items (low priority)

1. **Mobile card view dead code** — `app.js:2730-ish` references `#prog-cards` and `#prog-table` IDs that don't exist in `index.html` (never have). Pre-existing dead code, not a regression. Either implement properly or remove.

2. **`scan.js` line ~25 comment** mentions "Opus 4.7" but `ALLOWED_MODELS` whitelists `claude-opus-4-6`. Decide before Task 5 cost work — Opus 4.7 vs 4.6 is a real cost/quality tradeoff.

3. **`DB_SCHEMA.md`** row counts are snapshots and grow over time. Re-query before referencing absolute numbers.

4. **Two "48"-mention comments** remain in source (non-user-facing). Sweep at convenience.

5. **"+ Shortlist" buttons in Alumni Finder and AI Fit pages** still use the old single-stage path. They work correctly, but Stage dropdown would be more consistent cross-page. Defer.
