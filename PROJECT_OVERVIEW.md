# LDP Scout — Project Overview

**One-line:** Résumé-to-MBA-Leadership-Development-Program matcher. Upload a résumé, get AI-scored fit across the LDP catalog, with alumni discovery, deadline tracking, and a shortlist/pipeline Kanban.

**Live:** https://ldpscout.com (also https://www.ldpscout.com)

**Audience:** Current MBA students and alumni at whitelisted schools (INSEAD, IESE, IE, Bocconi, IMD, LBS, Oxford Saïd, Cambridge Judge, ESADE, HEC, ESCP, EDHEC, RSM, etc. — full list in `app.js` `EDU_DOMAIN_WHITELIST`).

**Status (May 21, 2026):** ESADE careers launch prep. Demo to ESADE careers office targeted Monday May 25. Catalog at 422 rows, all verified. Tasks 22–26 **live** (quota→1, mobile two-row nav, AI Fit overflow fix, deadlines mobile cards, SEO/meta + favicon/OG + lazy résumé parsers). One hotfix on top of Task 26 — `defer` was missing from `data.js` / `app.js` after `supabase-js` was deferred, which broke the live site for a few minutes until the fix shipped as commit `9760b88`. Next build: Applications overlay + user-added programs (Task 27, spec locked, not launch-blocking).

---

## Catalog headline numbers (keep these straight)

- **`programs` table: 422 rows** — 415 `is_active_cycle = true`, 7 `is_active_cycle = false` (Nike EHQ, Admiral, Estée Lauder ×2, Scopely, AbbVie FDP, Zuellig).
- **Every row has `last_verified_at` set.**
- The "**393 programs scanned**" string seen in older screenshots is a *stale scan result* from May 20, when the catalog was 393. The catalog has since grown to 422. A fresh scan will read "across 422 programs." Run one before the demo so the headline isn't stale.

---

## Tech stack

| Layer | Tech | Notes |
|---|---|---|
| Frontend | Vanilla JS, single-page (no framework) | `app.js` (~5,140 lines), `index.html`, `styles.css` (~1,985 lines), `data.js` (seed) |
| Auth | Supabase Auth — email OTP (8-digit) + optional password | Anon key inline in `app.js`; real security from RLS |
| Database | Supabase Postgres | 7 tables in `public`, all RLS-enabled. Full schema: `DB_SCHEMA.md`. **Free tier — NO BACKUPS.** |
| AI proxy | Vercel serverless function (`ldp-proxy/api/scan.js`) | Verifies Supabase JWT (ES256 via JWKS, HS256 legacy), enforces quota, forwards to Anthropic |
| AI models | Anthropic Claude — Opus 4.6 (tier classification), Sonnet 4.5 (gap analysis), Haiku 4.5 (reserve) | Whitelisted in `scan.js` `ALLOWED_MODELS` |
| Email | Supabase built-in (sender `noreply@ldpscout.com`) | `mailto:hello@ldpscout.com` for program requests — verify MX routing before launch |
| Domain | Cloudflare (purchase + DNS only — proxy/CDN currently OFF) | Apex `A` records point to GitHub Pages IPs `185.199.108–111.153`. Proxy is on Vercel. |
| Frontend hosting | **GitHub Pages** (auto-deploy on `git push` to `main`) | Repo: `shinghalshrey/ldp-scout` (public). Workflow `pages build and deployment` runs `build → report-build-status → deploy`, typically 1–2 min total. Live status: `github.com/shinghalshrey/ldp-scout/actions`. |
| Proxy hosting | Vercel (manual deploy via `npx vercel --prod`) | Private GitHub repo `shinghalshrey/ldp-proxy`. Auto-deploy from GitHub intentionally NOT connected. Scope: `shrey's projects` (Hobby tier). |

**Frontend libs (CDN in `index.html`):** `@supabase/supabase-js@2`, `pdf.js@2.16.105` (résumé PDF parse), `mammoth@1.6.0` (résumé .docx parse), Google Fonts (Fraunces, DM Mono, Outfit).

> Perf note (Task 26, done): `pdf.js` and `mammoth` are now lazy-loaded via `ensureResumeParsers()` on first résumé parse, not in `<head>`. `supabase-js` carries `defer`, and `data.js`/`app.js` carry `defer` too (this last bit was the post-26 hotfix — without it, app.js executed before supabase loaded and threw `ReferenceError: supabase is not defined` on line 18, which killed the landing overlay and showed an empty Programs page to every visitor). Net effect: ~2 MB off the landing-page initial load (the mobile LCP fix).

---

## Folder structure (local)

```
C:\Users\shrey\Desktop\LDP-Scout-Master\
├── ldp-scout\               # frontend — public git repo, GitHub Pages auto-deploys on push
│   ├── app.js
│   ├── index.html
│   ├── styles.css
│   ├── data.js
│   ├── vercel.json          # dead code on GitHub Pages — see "vercel.json gotcha" below
│   ├── CHANGES_TASK*.md
│   ├── SMOKE_TESTS.md
│   ├── PROJECT_OVERVIEW.md
│   └── DB_SCHEMA.md
└── ldp-proxy\               # proxy — private git repo, manual Vercel deploy
    └── api\scan.js
```

---

## Deploy commands

**Frontend (`git push` → GitHub Pages auto-build, ~1–2 min):**
```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add -A
git commit -m "..."
git push
```
Watch the deploy at `https://github.com/shinghalshrey/ldp-scout/actions`. The run is named `pages build and deployment`. It goes yellow (running) → green check (`pages-build-deployment` job → `deploy` step shows `https://ldpscout.com/`). If it goes red, click into the failed job for the log.

**Proxy (the one that bites you — fresh PowerShell, NOT inside Claude Code):**
```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-proxy
npx vercel --prod
```
`npx vercel` is interactive; running it inside a Claude Code session swallows the prompts and the deploy hangs or fails silently. Always a fresh terminal. Deploy is ~10s; the alias `https://ldp-proxy.vercel.app` is updated automatically.

### vercel.json gotcha

`ldp-scout/vercel.json` was added in Task 26 to set long-cache headers on favicons/OG image and must-revalidate on `app.js`/`styles.css`/`data.js`. **It does nothing**, because the frontend is on GitHub Pages, not Vercel. GitHub Pages serves all assets with its own default `Cache-Control: max-age=600` (10 min) and does not honour `vercel.json`. Consequences:

- The PageSpeed "use efficient cache lifetimes" warning will NOT clear from Task 26 alone.
- Favicons / `og-image.png` are NOT cached for a year — they're cached for 10 min like everything else.
- `app.js`/`styles.css`/`data.js` get 10-min cache instead of always-revalidate. After a push, users on a 10-min-old page may see stale JS until the cache TTL expires. **Hard refresh (Ctrl+Shift+R) fixes it immediately; this is what to tell anyone reporting "didn't see my fix."**

Paths if we actually want cache control (post-launch):
1. **Cloudflare proxy ON** — flip the apex DNS record from grey-cloud (DNS-only) to orange-cloud (proxied), then add a Page Rule for `*ldpscout.com/*.png` etc. to override `Cache-Control`. Lowest-effort, no DNS change.
2. **Move the frontend to Vercel** — DNS change to point apex at Vercel; `vercel.json` would then take effect as written.
3. **Live with default GHP caching** — fine for launch; revisit if cache lifetimes show up as a real complaint.

Leave `vercel.json` in the repo for now — harmless, and it's correct if we ever take path 2.

---

## Working approach (canonical)

- **This chat (Claude.ai)** — planning, triage, debugging, schema work, and **drafting clean prompts to paste into Claude Code**. This chat does *not* write production code directly.
- **Claude Code (CLI)** — writes the code. One Claude Code session per task. Don't parallelize tasks touching the same file.
- **Triage before building.** New issue mid-session → propose a 2-min diagnostic (incognito test, SQL query, DevTools/network check) before any code.
- **Test write AND read paths** before declaring a task done (the Task 1 lesson).
- **Every commit gets a `CHANGES_TASKn.md`** plain-English explainer.
- **Deploy gotcha:** proxy from a fresh PowerShell, not from inside Claude Code.
- **Long chats degrade.** ~25–30 turns → open a fresh chat with canonical files pinned.

---

## Auth flow (canonical)

Two-button landing UI: email field with Sign Up and Sign In side by side.

- **Sign Up (new):** Email → domain whitelist → `email_account_status` RPC confirms no existing account → 8-digit OTP → mandatory password setup (no skip) → mandatory full-name capture → app.
- **Sign In, existing w/ password:** password field default; "Login using code instead?" + "Forgot password?" links beneath.
- **Sign In, existing w/o password:** OTP flow (no password setup at end).
- **Forgot password:** `force:true` mandates password setup post-OTP regardless of `has_password`.
- **Mandatory full_name (Task 19):** onboarding step 1 disables Next until `value.trim().length >= 1`, hides Skip.
- **Supabase "Confirm email" toggle ON** — fine with OTP (the code IS the confirmation).
- **Session persistence:** ~30 days in localStorage. Incognito wipes when all incognito windows close.

---

## Personalization (Task 19)

Single helper `getFirstName()` reads `userProfile.full_name`, trims/splits, returns first token. Topbar (firstName · school_label, email fallback if full_name NULL), Programs h1 + pipeline subline, Alumni/Applications/Deadlines/AI Fit h1s, Profile modal title. Refresh: `showPage()`→`applyPagePersonalization(id)`; `saveUserProfile()`→`_refreshActivePagePersonalization()` + `updateAuthUI()`.

---

## Programs catalog architecture (Path A)

**`programs` is read-only from the client** — no INSERT/UPDATE/DELETE RLS. The old + Add/Edit/Delete buttons are gone; `saveProg()/editP()/delP()` are `console.warn` stubs. Users track off-catalog programs via `mailto:hello@ldpscout.com` (Programs meta row) or the writable Applications page.

Future option (Path B, not built): a `user_programs` table RLS-scoped to `auth.uid()` unioned with the global catalog.

---

## Pipeline semantic

Pipeline = shortlisted + networking + drafting + applied + interview + offer. NOT pipeline = rejected (exited). Offer is the goal-state, not an exit. `_pipelineCount()` and `_deadlinesThisMonth()` use `status !== 'rejected'`.

---

## Quota & cost model

- **Free quota: 1 completed scan per user, lifetime** (Task 22, **live as of May 21** — proxy deployed via `npx vercel --prod`, frontend on GitHub Pages). Enforced server-side in `scan.js` (`SCAN_QUOTA = 1`) by counting `user_scan_history` rows via PostgREST `count=exact`; fail-closed (503) on query error. Frontend mirror `SCAN_QUOTA_CLIENT = 1` in `app.js` is display-only. **Reminder: a frontend `git push` alone won't change quota enforcement — the proxy must be re-deployed manually any time `SCAN_QUOTA` changes.**
- **Quota row written by the frontend** after both tier + gap calls succeed, so the check on call N+1 blocks the *next* scan.
- **Cost target: $0.10/scan (set in Task 5 — predates the CHANGES_TASKn.md convention, so no CHANGES doc exists for it).** Cost optimization was **not** Task 19 or 20 (Task 19 = Programs redesign + personalization; Task 20 = removing the hardcoded program count from static HTML).
- **Current cost is above target.** Levers, in order of impact: (1) `MAX_TOKENS_CAP = 32000` in proxy — this was bumped up from 6000 and is the most likely driver; (2) quota (now dropping to 1); (3) per-scan payload — system prompt + program list sent to the model; (4) model choice per pass (Opus 4.6 for tier is the premium line item). Actual per-scan cost is only visible in the Anthropic console — confirm there before quoting anyone a number.
- **Cohort math:** at 1 scan/user, 90 ESADE students = up to 90 scans on launch day, not 270.

---

## Mobile layout (≤720px is the hard layout switch)

Breakpoint **720px** (NOT 768). iPad portrait (768px) stays desktop. Softer `@media 768px`/`900px` blocks handle font/spacing tweaks only.

- **Programs:** stacked cards (`renderProgramsMobile` / `_mobileCardHTML`), not the table. Welcome + 5 stat cards appear ABOVE the filter sidebar (`order` on grid children). AI Fit tier badge per card, or dashed "✦ Scan résumé" CTA if unscanned (`_aiTierMobile`, **UPPERCASE tier keys** — see gotchas).
- **Applications:** 7 vertical stacked sections (one per stage), full-width cards, tap to edit (no drag).
- **Topbar (Task 23, committed):** on ≤720px the topbar wraps to **two rows** — row 1 brand + Profile/Sign Out, row 2 the nav tabs full-width, evenly spaced, **not scrollable, no wrap**. Tabs keep full labels for desktop but show shortened ones on mobile via a `data-short` attribute + `::after { content: attr(data-short) }` (real text stays in the DOM for screen readers). The old scrollable-rail + mask-fade rules were removed.
- Form controls inherit Outfit via global `input,textarea,select,button { font-family: inherit; }` near top of `styles.css` — do not remove.

---

## Critical technical gotchas

1. **`progs[].aiTier` is UPPERCASE enum:** `BEST_FIT`, `STRONG_FIT`, `ACHIEVABLE`, `LONG_SHOT`, `NOT_FIT`. Set by `syncAIResultsToPrograms()`. Readers `fitTier()` (desktop) and `_aiTierMobile()` (mobile) must use uppercase keys. Lowercase keys silently miss every lookup.
2. **CSS cascade in `styles.css`:** rules outside `@media` and inside one have equal specificity → later wins. Before claiming a layout fix, `grep -n '\.selector' styles.css` for ALL rules on it across the whole file. (This bit Task 21.1: a late `.prog-table-wrap{display:table}` beat the mobile `display:none` until `!important` was added.)
3. **Horizontal overflow clamp:** there's still no *global* clamp on `html`/`body`. Task 24 fixed the known AI Fit offender (`.aifit-summary-left/right` wrap on mobile; buttons full-width) and added `#page-aifit { overflow-x: hidden }` as a per-page net. If a new page scrolls sideways on mobile, the diagnostic is: `[...document.querySelectorAll('*')].filter(e => e.offsetWidth > document.documentElement.clientWidth)` in DevTools at 375px. Do NOT put `overflow-x:hidden` on body — it breaks the sticky AI Fit summary strip.
4. **Résumé parsers are lazy-loaded (Task 26):** pdf.js + mammoth are no longer in `<head>`. `ensureResumeParsers()` injects them on demand the first time a résumé is parsed (app.js ~4275). They're ~2 MB combined and not needed on the landing page. Don't move them back to `<head>` — that re-breaks mobile LCP.
5. **Form controls don't inherit font-family** — kept in Outfit only by the global reset above.
6. **`programs.id` sequence** — reset with `setval(pg_get_serial_sequence('programs','id'), (SELECT MAX(id) FROM programs))` after explicit-id inserts. Currently past 422.
7. **iOS Calendar 2-alarm limit:** `downloadICS(item,'multi')` writes 3 VALARMs (-P30D/-P7D/-P1D) but iOS preview shows only the 2 closest; 30-day alarm may not survive import. Unverified — if dropped, generate 3 separate events.
8. **Test deploys in private browsing.** Frontend: GitHub Pages build is 1–2 min — confirm green on the Actions tab, then load in incognito (no SW/cache). Proxy: Vercel is ~10s — confirm green on `vercel.com/shrey-s-projects1/ldp-proxy` and either hit `/api/scan` directly or run an in-app scan. If a change isn't live in incognito after a green build, the deploy genuinely failed — not caching. (Edge case for the 10-min GHP cache window on `app.js`/`styles.css`/`data.js`: hard refresh forces revalidation.)

---

## Applications → Deadlines → Calendar data flow

- **"Log Application" modal** (`openM('app',…)` / `editAp` / `saveApp`) writes to **`public.user_applications`** via `saveApplicationToDB()` — INSERT or UPDATE keyed on `(id, user_id)`.
- **Columns:** `user_id, program_id (nullable), name, org, geo, status, applied_on, deadline, next_step, contact, notes`.
- **Privacy:** RLS `own_apps_all` (ALL) — `auth.uid() = user_id`. **Per-user private. Not visible to other users.** (Contrast: `program_intel` is read-public — never store private data there.)
- **Deadlines linkage** (`buildDeadlineItems()`): a logged application is matched to a catalog program by `program_id` OR case-insensitive name match. If matched, the deadline shown/exported comes from the **program** record (`p.deadline`), not the app's own `deadline` field. If unmatched (free-standing), the app's own `deadline` is used as a `type:'application'` item.
- **Known design gaps (now addressed by Task 27, spec locked):** (a) a user's custom deadline typed in the modal is currently **ignored** when the app matches a program — Task 27's `resolveProgramView` makes the user's deadline win everywhere; (b) name-only matches are fragile — Task 27 always sets `program_id` when picking from the catalog search. Free-standing rows (`program_id = null`) become user-added private programs unioned into the Programs page. See the Task 27 spec under Queued.
- **Calendar export:** Deadlines page → "Set reminder" (single) / "Export my pipeline to calendar" (`exportMyPipelineDeadlines`) → ICS. So modal-entered deadlines do reach calendar export, subject to the matching caveat above.

---

## Page-load behavior

`<head>` boot script reads `localStorage.ldps_last_page` before first paint; if a Supabase session exists, the saved page (default 'programs') is marked active pre-paint — no Programs flash. `showPage()` writes current page to localStorage; `onSignOut()` clears it.

---

## SEO / performance baseline (PageSpeed, May 21 2026)

| | Mobile | Desktop |
|---|---|---|
| Performance | 69 | 97 |
| Accessibility | 93 | 93 |
| Best Practices | 100 | 100 |
| SEO | 80 | 80 |

**Status after Task 26 (committed, awaiting push + re-test):**
- **SEO:** added meta description, canonical, Open Graph (with `og-image.png`), Twitter card, favicon links (SVG + ico + png set + apple-touch + webmanifest), `theme-color`, and a WebApplication JSON-LD block. Expect SEO to move from 80 toward ~90+ after deploy. "Links are not crawlable" will likely persist (onclick SPA nav) and is acceptable for an auth-gated app.
- **Perf:** removed the 3 bogus `Cache-Control`/`Pragma`/`Expires` http-equiv metas; lazy-loaded pdf.js + mammoth (`ensureResumeParsers()`), `defer` on supabase-js (and on `data.js`/`app.js` post-hotfix). This targets the ~3.65s mobile render-block and the ~2 MB unused-JS payload. Re-run PageSpeed after push to confirm mobile LCP drops from 5.0s. **Note:** Task 26 also added `vercel.json` cache-header rules — those don't apply because the frontend is on GitHub Pages, not Vercel (see "vercel.json gotcha" in the Deploy section). The "use efficient cache lifetimes" PageSpeed flag will therefore persist until Cloudflare proxy + Page Rules are set up.
- **Still open (post-launch):** Fraunces font request pulls many weights/italics — trim to used weights to shrink the font payload (find exact contributors via Network tab sorted by size). Minify CSS/JS + unused-CSS are small wins that need a build step — skip (breaks the no-build workflow).
- **A11y (post-launch):** insufficient color contrast; headings not in sequential order.

---

## Recent task log (most recent first)

| Task | One-line | Files | Date |
|---|---|---|---|
| 26-hotfix | Add `defer` to `data.js` + `app.js` so they execute after `supabase-js` (which Task 26 had deferred). Without this, app.js ran first and threw `ReferenceError: supabase is not defined` on line 18 — landing overlay never appeared, signed-out visitors saw an empty Programs page. Commit `9760b88`. | index.html | May 21 |
| 26 | SEO head (description, OG+og-image, Twitter, favicon set, canonical, JSON-LD, theme-color), removed bogus cache metas, `vercel.json` cache headers *(dead code on GitHub Pages — see Deploy section)*, lazy résumé parsers + defer supabase | index.html, app.js, vercel.json, assets | May 21 |
| 25 | Deadlines rows → stacked mobile cards, one CTA at bottom | styles.css | May 21 |
| 24 | Kill horizontal scroll on AI Fit Scan page (mobile) — summary strip wraps, buttons full-width, `#page-aifit` overflow clamp | styles.css | May 21 |
| 23 | Static two-row mobile nav (no horizontal scroll), shortened labels via `data-short` | index.html, styles.css | May 21 |
| 22 | Drop free scan quota 3 → 1 (frontend mirror + proxy `SCAN_QUOTA` + quota log line) | app.js, scan.js | May 21 |
| (post-21.4) | Remove LinkedIn search button from draft modal; global font-family inherit for form controls | app.js, styles.css | May 20 |
| 21.4 | Fix AI Fit tier label keys (uppercase) + 5 mobile UI fixes (sign-out nowrap, nav fade, programs order, applications vertical kanban) | app.js, styles.css | May 20 |
| 21.3 | AI Fit fallback chip on mobile cards + scrollable nav tabs + brand-name hide on phone | app.js, styles.css | May 20 |
| 21.1 | Mobile card view for Programs + `!important` cascade fix + verified-only filter + reminder flow | app.js, styles.css | May 19–20 |
| 21 | Truthful per-row Verified badge + mobile fallback for Programs table | app.js, styles.css | May 19 |
| 19.2.x | Programs page architecture overhaul → editorial header, CSS Table dividers, AI Fit hydration fix, no-flicker boot, Stage column widths | app.js, index.html, styles.css | May 19 |
| 19.1 | Sidebar reorder, table dividers, tour fix | app.js, index.html, styles.css | May 19 |
| 19 | Programs redesign + personalization across pages + mandatory full_name | app.js, index.html, styles.css | May 19 |
| 20 | Remove hardcoded program count from static HTML (stale OG previews) | index.html | May 18 |
| 9 | Two-button landing auth + mandatory post-OTP password + race fix | app.js, index.html, styles.css | May 18 |
| 5 | AI scan cost model — $0.10/scan target, model whitelist, quota (no CHANGES doc) | scan.js | earlier |

---

## Queued / in-flight tasks

| # | Task | Notes | Launch-blocking |
|---|---|---|---|
| 27 | **Applications overlay + user-added programs** (spec locked — see below) | app.js + index.html, no DB migration | No — post-launch, high value |
| — | Geography continents `TEXT[]` (Task 19.3) | DB migration + 422-row curation | No — defer |
| — | Scrape ~36 working URLs for description/eligibility/min_yoe/duration | data quality for AI Fit | No |
| — | iOS 3-reminder verification | manual test | No |
| — | A11y: contrast + heading order; trim Fraunces font weights | from PageSpeed | No |

### Task 27 spec — Applications overlay + user-added programs (decisions locked May 21)

**Goal:** make `user_applications` a per-user overlay on the read-only catalog, and let users add their own private programs as the replacement for the `mailto:hello@` request flow.

**Decisions (locked):**
1. **Overlay precedence:** for any tracked program, `deadline = app.deadline ?? program.deadline`; stage/status/applied_on/next_step/contact/notes are user-only; catalog facts (function, sector, geo, location, language_required, is_active_cycle, tier) are NOT user-overridable. A single `resolveProgramView(p)` merges the user's `apps[]` overlay onto each catalog program, called by every render path. Override applies **everywhere**, including the Programs table.
2. **User-added programs** = `user_applications` rows with `program_id = null`. **Union them into the Programs page** (scoped to login), badged "**Added by you**" — badge must be prominent enough to distinguish user adds from catalog rows. Missing catalog fields render as "—".
3. **No dedup/merge:** if an admin later adds the same program to the catalog, BOTH rows stay (user's + catalog's); the badge disambiguates; user can delete their own.
4. **Stage on add:** reuse the existing 7-stage dropdown; default a fresh add to **Shortlisted**, full dropdown available.
5. **AI Fit:** user-added programs are **excluded from the scan and labelled "not scored."** No manual per-program scan at launch (would burn the single quota).
6. **Calendar:** ICS export reads the resolved deadline → the `.ics` carries the user's edited/entered date. A previously-undated program that the user gives a deadline becomes Deadlines-listed and ICS-exportable.
7. **Privacy:** all of the above is the user's private overlay; RLS `own_apps_all` guarantees it never touches the shared catalog or other users.
8. **Modal/UX:** rename the modal field "Program / Role" → "**Program**"; the field becomes a searchable dropdown over the **full catalog** + an "+ Add new program" action; **replace the Programs-page "Don't see a program? Request it" mailto with the same Log Application button.**

**Admin upside:** user adds become a demand backlog — query `user_applications WHERE program_id IS NULL` (Supabase dashboard / service role, not client) to see most-requested programs and promote popular ones into the catalog.

---

## Launch-readiness checklist (Monday)

1. **Tasks 22–26 + hotfix shipped** (May 21). Frontend pushed, GitHub Pages green; proxy deployed via `npx vercel --prod`. No further deploy work for the demo unless Task 27 lands first.
2. **Re-deploy the proxy** only if `SCAN_QUOTA` or any `scan.js` line changes between now and Monday: `cd ldp-proxy; npx vercel --prod` from a fresh PowerShell. A git push does NOT deploy the proxy.
3. **Verify asset files committed** — `git ls-files *.png *.svg *.ico *.webmanifest` includes `og-image.png` and `site.webmanifest`. (Confirmed May 21.)
4. **Run a fresh scan** on a test account so the demo shows "across 422 programs," not 393. Both Pranav's and Shrey's accounts are at quota=1 already; create or use a clean whitelisted test account.
5. **Mobile** — verify Tasks 23/24/25 in incognito on a real phone (two-row nav, no AI Fit sideways scroll, deadlines cards).
6. **Re-run PageSpeed** — confirm mobile LCP dropped (target: 5.0s → ~2s) and SEO moved off 80. "Use efficient cache lifetimes" will remain (vercel.json doesn't apply on GHP — see Deploy section).
7. **Validate share preview** — opengraph.xyz / LinkedIn Post Inspector shows the green OG card; favicon shows in tab.
8. **Domain whitelist** — confirm `@esade.edu`, `@alumni.esade.edu`, `@student.esade.edu` in `EDU_DOMAIN_WHITELIST`.
9. **`mailto:hello@ldpscout.com`** — verify it lands somewhere you read (Cloudflare MX). (Being phased out by Task 27, but still live until then.)
10. **First-time cold sign-up** with a fresh whitelisted email — walk the whole flow.
11. **Confirm `www → apex` is a single 301** (PageSpeed showed www redirecting); canonical/OG point to `https://ldpscout.com/`.
12. **Supabase "Confirm email"** still ON.

---

## Known stale/cleanup items (low priority, post-Monday)

1. `scan.js` ~line 25 comment mentions "Opus 4.7" but `ALLOWED_MODELS` whitelists `claude-opus-4-6`. Fix the comment, not the whitelist (Opus 4.6 is intended per Task 5).
2. `openLinkedInSchoolSearch()` (~app.js:3747) — unreferenced after the draft-modal cleanup. Safe to delete.
3. `reopenInfoCard()` — dead since Task 19.2.2.
4. Dead `.prog-cards`/`.prog-card-*` CSS in the `@media 768px` block (~styles.css:953) references DOM IDs that no longer exist (superseded by Task 21.1 `.pmc-*`).
5. A couple of non-user-facing "48" comments remain in source.
6. "+ Shortlist" buttons in Alumni Finder / AI Fit still use the old single-stage path; Stage dropdown would be more consistent cross-page.

---

## Key function locations in app.js (approximate)

| Function | ~Line | Purpose |
|---|---|---|
| `fetchProgramsFromSupabase` | 480 | Pulls 422 rows into `progs[]` |
| `loadUserApplications` | 1594 | Loads `user_applications` into `apps[]` |
| `saveApplicationToDB` | 1620 | INSERT/UPDATE `user_applications` |
| `deleteApplicationFromDB` | 1660 | DELETE `user_applications` |
| `SCAN_QUOTA_CLIENT` | 1760 | Frontend quota mirror (display only) |
| `hydrateAITierFromHistory` | ~1779 | Restores `p.aiTier` from saved scan |
| `loadAndRenderLastScan` | ~1809 | Loads last scan into AI Fit UI |
| `renderPrograms` | ~2900 | Programs table render (desktop) |
| `fitTier(score,p)` | ~2914 | Desktop tier badge (uppercase keys) |
| `_aiTierMobile(p)` | ~3070 | Mobile AI Fit chip (uppercase keys) |
| `renderProgramsMobile(list)` | ~3147 | Mobile card render (≤720px) |
| `_mobileCardHTML(p)` | ~3200 | Mobile card template |
| `saveApp` | 5006 | Modal save → saveApplicationToDB |
| `editAp(id)` | 5067 | Open Log Application modal |
| `renderApplications` | 3821 | Pipeline kanban render |
| `buildDeadlineItems` | 3936 | Programs+apps → deadline items |
| `renderDeadlines` | 4120 | Deadlines page render |
| `_renderRow(item)` | 4045 | Deadline row template |
| `downloadICS(item,mode)` | ~4215 | ICS export |
| `syncAIResultsToPrograms(result)` | ~4639 | Sets `prog.aiTier` UPPERCASE |
| `renderAIResults(result,meta)` | ~4670 | AI Fit results render (summary banner ~4717) |

---

*Regenerated 2026-05-21 (post tasks 22–26 + post-26 defer hotfix, all live). app.js ~5,140 lines pre-22-26; line numbers approximate and will have shifted slightly after the task edits.*
