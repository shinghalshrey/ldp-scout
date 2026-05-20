# LDP Scout — Project Overview

**One-line:** Résumé-to-MBA-Leadership-Development-Program matcher. Upload a résumé, get AI-scored fit for ~393 LDP programs across Europe and beyond, with alumni discovery, deadline tracking, and a shortlist Kanban.

**Live:** https://ldpscout.com (also https://www.ldpscout.com)

**Audience:** Current MBA students and alumni at whitelisted schools (INSEAD, IESE, IE, Bocconi, IMD, LBS, Oxford Saïd, Cambridge Judge, ESADE, HEC, ESCP, EDHEC, RSM, etc. — full list in `app.js` `EDU_DOMAIN_WHITELIST`).

**Status (May 20, 2026):** ESADE careers launch prep in progress. Public rollout targeted for Monday.

---

## Tech stack

| Layer | Tech | Notes |
|---|---|---|
| Frontend | Vanilla JS, single-page (no framework) | `app.js` ~4,960 lines, `index.html`, `styles.css`, `data.js` (programs DB seed) |
| Auth | Supabase Auth — email OTP (8-digit) + optional password | Anon key inline in `app.js:14`; real security from RLS |
| Database | Supabase Postgres | 7 tables in `public` schema, all RLS-enabled. Full schema: `DB_SCHEMA.md` |
| AI proxy | Vercel serverless function (`ldp-proxy/api/scan.js`) | Verifies Supabase JWT (ES256 via JWKS, HS256 legacy), enforces quota, forwards to Anthropic |
| AI models | Anthropic Claude — Opus 4.6 (tier classification), Sonnet 4.5 (gap analysis), Haiku 4.5 (reserve) | Whitelisted in `scan.js` `ALLOWED_MODELS` |
| Email | Supabase built-in (sender: `noreply@ldpscout.com`) | mailto: `hello@ldpscout.com` for program requests — verify MX routing before launch |
| Domain | Cloudflare (purchase + DNS) | Vercel hosts the actual sites |
| Frontend hosting | Vercel (auto-deploy on git push to main) | Repo: `ldp-scout` |
| Proxy hosting | Vercel (manual deploy) | Private GitHub repo: `shinghalshrey/ldp-proxy`. Auto-deploy intentionally NOT connected — manual deploy only. |

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

---

## Deploy commands

**Frontend:**
```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add -A && git commit -m "..." && git push
# Vercel auto-builds on push to main
```

**Proxy (the one that bites you):**
```powershell
# Fresh PowerShell window — NOT inside a Claude Code session.
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-proxy
npx vercel --prod
```

Why this matters: `npx vercel` deploys interactively. Running it inside a Claude Code session swallows the prompts and the deploy hangs or fails silently. Always use a fresh terminal.

---

## Auth flow (canonical)

Two-button landing UI. Email field with both Sign Up and Sign In buttons side by side.

**Sign Up path (new users):** Email → domain whitelist check → `email_account_status` RPC confirms no existing account → OTP sent → 8-digit code → mandatory password setup (no skip) → mandatory full-name capture during onboarding → into app.

**Sign In path, existing user with password:** Password field shown by default. "Login using code instead?" and "Forgot password?" available as text links beneath.

**Sign In path, existing user without password:** OTP flow (no password setup at end).

**Forgot password:** Uses `force:true` to mandate password setup post-OTP regardless of `has_password` flag.

**Mandatory full_name (Task 19):** Onboarding step 1 disables the Next button until `value.trim().length >= 1` and hides the Skip button.

**Supabase setting:** "Confirm email" toggle is ON. With OTP flow this is fine — the OTP code IS the confirmation.

**Session persistence:** Supabase sessions live in localStorage for ~30 days. In incognito, sessions wipe when ALL incognito windows close.

---

## Personalization (Task 19, applied across product)

Single helper: `getFirstName()` reads `userProfile.full_name`, trims, splits, returns the first token. All personalization downstream keys off this.

Where it shows:
- **Topbar:** firstName · school_label (fallback to email if `full_name` is NULL)
- **Programs page:** "Welcome back, *FirstName*." h1 + live "{N} programs in your pipeline · {M} deadlines this month" subline. STATE B fallback: count-agnostic copy (per Task 20 — no static numbers that leak into OG previews).
- **Alumni Finder, Applications, Deadlines, AI Fit (pre + post-scan):** h1/subtitle personalized
- **Profile modal:** "*FirstName*, edit your details" title

Refresh paths: `showPage()` calls `applyPagePersonalization(id)`. `saveUserProfile()` calls `_refreshActivePagePersonalization() + updateAuthUI()` so name changes propagate without a page nav.

---

## Programs catalog architecture (Path A, Task 19.2)

**The `programs` table is read-only from the client.** No INSERT/UPDATE/DELETE RLS policies. Users cannot mutate the catalog.

The old `+ Add Program / Edit / Delete` buttons were vestigial from a pre-Supabase architecture. As of Task 19.2 they're gone from the UI. `saveProg()`, `editP()`, `delP()` are stubs with `console.warn`.

Users wanting to track a program not in the catalog:
- Email `hello@ldpscout.com` to request addition (mailto link in the Programs meta row), OR
- Log it manually on the Applications page (per-user table, IS writable)

Future option (Path B, not implemented): A `user_programs` table with RLS scoped to `auth.uid()` that unions with the global catalog for display.

---

## Pipeline semantic

Pipeline = shortlisted + networking + drafting + applied + interview + offer.
NOT pipeline = rejected (exited).

Offer is the goal-state of being in pipeline, not an exit. `_pipelineCount()` and `_deadlinesThisMonth()` use `status !== 'rejected'`.

---

## Quota & cost model

- **Free quota:** 3 completed scans per user, lifetime. Enforced server-side in `scan.js` by counting rows in `user_scan_history` for that user via PostgREST `count=exact`. Fail-closed (503) if the quota query errors.
- **Quota row written by frontend** after both tier + gap calls succeed. So the check on call N+1 blocks the next scan, not the current one.
- **Cost target:** $0.10/scan (Task 5). Current is higher.
- `MAX_TOKENS_CAP = 32000` in proxy.

**Launch consideration:** 3 scans/user is generous for individual use. If ESADE careers shares the link with a class of 90 students who all run a scan, that's $20-30 in one day. Decide before launch whether to drop to 1-2 scans for public launch and bump for known users.

---

## Programs page UI (post-Task 19.2.5)

**Layout:** Two-column. 240px sticky left sidebar (accordion sections) + main column.

**Sidebar sections** (collapsible accordions, state persists in `ldps_prog_sidebar_v1`):
1. Search (always visible)
2. Quick Filters — Visa-sponsoring only
3. Geography — Europe / UAE / Global (Task 19.3 will replace with continent drill-down)
4. Function — Operations / Finance / Strategy / Consulting / Investments
5. Sector (Task 19.2) — 9 sectors from `ALUMNI_SECTORS` taxonomy
6. App Cycle (renamed from Status) — Open / Rolling / Watch
7. Pro Tip card

Each section header shows `(N)` badge when filters are active. Expanded section gets accent-bg highlight.

**Stat row** (5 cards): TOTAL · ✦ AI FIT · OPEN NOW · ROLLING · ★ MY PIPELINE.
- Cards 1-4: uniform neutral number color (`--text`), 1.5px border at `--border2`
- Card 5: amber number (`#c89738`), 2px border at higher opacity — visually the "destination" card

**Table** (9 columns, CSS Table layout for shared column widths across rows): Program/Org · Function · Sector · Location · Deadline · App Cycle · ✦ AI Fit · Stage (dropdown) · Reminder. Column widths: 22 / 8 / 9 / 11 / 8 / 7 / 8 / 16 / 11 %. Vertical column borders form continuous lines down the table.

**Stage dropdown** (Task 19.2): per row, shows current pipeline stage OR "+ Add to pipeline" empty state. Click opens custom panel with 7 stage options (Shortlisted → Rejected) + "Remove from pipeline" if applicable. Writes through `saveApplicationToDB` / `deleteApplicationFromDB`.

**Tour link** sits right-aligned in editorial eyebrow row: "TOUR THIS PAGE →" (mono, uppercase, dashed underline). Same pattern across Alumni / Applications / Deadlines pages.

Removed (post-Task 19.2): Pipeline button column, Actions (Edit/Del) column, +Add Program button, "+ Details" disclosure on each row. Replaced by Stage dropdown + mailto link in the meta row + name-as-link in row.

---

## Page-load behavior (Task 19.2.4)

`<head>` boot script synchronously reads `localStorage.ldps_last_page` on every load. If a Supabase session is present in localStorage, the saved page (or 'programs' as default) is marked `active` before first paint. No more flicker where Programs flashes before the user's last-viewed page loads.

`showPage()` writes the current page to localStorage on every call. `onSignOut()` clears it so the next user starts fresh on Programs.

---

## Working approach

- **This chat (Claude.ai)** — planning, triage, debugging, schema work, prompt drafting, **and direct code edits** (Pranav doesn't run Claude Code for these tasks).
- **Claude Code (CLI)** — reserved for heavy DB work (e.g. Task 19.3 SQL migration).
- **Pranav executes the git push from PowerShell.**
- **Triage before building.** New issue mid-session → 2-min diagnostic first.
- **Test write AND read paths** before declaring done.
- **Every commit gets a CHANGES_TASKn.md** explainer.
- **Long chats degrade.** When chat hits ~25-30 turns, open a fresh one with canonical files pinned.
- **Deploy gotcha:** proxy from PowerShell, not from inside Claude Code.

---

## Recent task log (most recent first)

| Task | One-line | Files | Date |
|---|---|---|---|
| 19.2.5 (nudge) | Stage column 12% → 16%, Reminder 15% → 11% so "+ Add to pipeline" renders fully | styles.css | May 19 |
| 19.2.5 | Programs table: CSS Grid → CSS Table for truly continuous vertical column dividers | styles.css | May 19 |
| 19.2.4 | No-flicker boot (read last-page from localStorage before paint) + column alignment v3 | app.js, index.html, styles.css | May 19 |
| 19.2.3 | Column alignment (top-align col 1) + edge-to-edge dividers (move padding to cells) + Pipeline border 2px @ 55% + last-page persistence | app.js, styles.css | May 19 |
| 19.2.2 | Cross-page editorial header + table polish + AI Fit hydration bug fix + clickable AI Fit results | app.js, index.html, styles.css | May 19 |
| 19.2.1 | Row meta/desc cleanup, full-height column borders (failed), editorial tour link, accordion accent state | app.js, index.html, styles.css | May 19 |
| 19.2 | Programs page architecture overhaul: Path A read-only catalog, Stage dropdown, accordion sidebar, Sector filter, amber Pipeline stat card, pipeline semantic fix | app.js, index.html, styles.css | May 19 |
| 19.1 | Sidebar reorder (Quick Filters to top), table row dividers, tour step 2 target fix | app.js, index.html, styles.css | May 19 |
| 19 | Programs page redesign (Lovable two-column layout), personalization across 5 pages + topbar + profile modal, mandatory full_name on onboarding step 1, "48" sweep | app.js, index.html, styles.css | May 19 |
| 20 | Remove hardcoded program count from static HTML (OG preview was scraping stale "48") | index.html | May 18 |
| 9 | Landing page two-button auth (Sign Up / Sign In) + mandatory post-OTP password setup + race-condition fix | app.js, index.html, styles.css | May 18 |

---

## Queued

### Task 19.3 — Geography continents with multi-continent support
- Add `continents` TEXT[] array column to `programs` table
- Manual curation across all 393 rows (CSV exported, sitting in chat history): tag each with relevant continents
- Filter logic: OR-match (`p.continents.some(c => F.geo.has(c))`)
- Frontend: 6 continent pills (Europe / Asia / North America / South America / Africa / Australia). No "Global" pill — span-multiple-continents handled by the array.
- Taxonomy locked: UAE → Asia, Russia → Europe, Turkey → Europe, Egypt → Africa.
- **Not launch-blocking. Defer.**

### Mobile experience (LIKELY NEEDED BEFORE LAUNCH)
The Programs table now uses `display: table` with `table-layout: fixed` and 9 columns. At 380px viewport (typical phone), the table will horizontal-scroll or crush cells. The dead mobile-card-view code at `app.js:2730` was supposed to handle this but was never wired up. Verify on a phone before Monday rollout.

---

## Launch-readiness checklist (Monday rollout)

1. **Mobile experience** — verify on a phone, especially the Programs table. May need card-view fallback at <900px.
2. **First-time user flow** — cold sign-up with a fresh email on a whitelisted domain. Walk the whole flow.
3. **mailto:hello@ldpscout.com** routing — verify the email actually arrives somewhere you read. Cloudflare MX records.
4. **AI scan quota policy** — current 3 lifetime/user. If ESADE shares with a cohort of 90, cost on day 1 ≈ $25. Decide before launch.
5. **Domain whitelist** — confirm `@esade.edu`, `@alumni.esade.edu`, `@student.esade.edu`, etc. Check `EDU_DOMAIN_WHITELIST` in app.js.
6. **Page tour copy** — walk through each page's tour to make sure copy reflects current state.
7. **Supabase Confirm Email setting** — verify still ON.

---

## Known stale/cleanup items (low priority)

1. **Mobile card view dead code** — `app.js:2730-ish` references `#prog-cards` and `#prog-table` IDs that don't exist in `index.html`. Pre-existing dead code. Will need real implementation for mobile rollout.

2. scan.js line ~25 comment mentions "Opus 4.7" but ALLOWED_MODELS whitelists claude-opus-4-6. Fix on next scan.js touch — change the comment, not the whitelist (Opus 4.6 is the intended model per Task 5 cost-model decisions)

3. **`reopenInfoCard()` is dead code** as of Task 19.2.2 — no DOM elements with class `info-card-reopen` exist anywhere anymore.

4. **Two "48"-mention comments** remain in source (non-user-facing).

5. **"+ Shortlist" buttons in Alumni Finder and AI Fit pages** still use the old single-stage path. Stage dropdown would be more consistent cross-page. Defer.

6. 6. **Catalog calibration gaps (discovered May 20 2026).** The 393-row scraped catalog has both duplicate variants (Amazon ×11 rows, J&J ×15, BASF ×6) and gaps relative to the ESADE-careers + founder-curated lists in `List_of_LDPs.xlsx`. Tier 1 curation task is in progress: ~40 catalog rows being verified via Anthropic API + web_search, ~20 missing programs to be added by SQL INSERT after URL discovery. Until `last_verified_at` is populated, the "✓ Verified May 2026" badge in the frontend should be considered marketing copy, not a per-row truth claim.