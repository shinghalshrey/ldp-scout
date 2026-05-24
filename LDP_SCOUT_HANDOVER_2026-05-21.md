# LDP Scout — Handover (Chat: 2026-05-21, tasks 22–26 + SEO/perf + Applications overlay spec)

Self-contained context to bootstrap a fresh chat. Read this top to bottom; it
supersedes the 2026-05-20 handover.

---

## 1. Project context

**LDP Scout** (https://ldpscout.com) — résumé-to-MBA-LDP matcher. 422-row
catalog, Supabase backend, Anthropic-powered AI Fit Scan, alumni discovery,
deadline tracking, pipeline kanban.

- **Owner:** Shrey Singhal (ESADE MBA 2024–2026). **Helper/user of this chat:** Pranav (Shrey's brother).
- **Target:** Monday May 25, 2026 demo to ESADE careers office.
- **Repos (local root `C:\Users\shrey\Desktop\LDP-Scout-Master\`):**
  - `ldp-scout` — frontend (app.js, index.html, styles.css, data.js). Deploys via `git push` → Vercel auto-build (~30s).
  - `ldp-proxy` — Vercel serverless (`api/scan.js`). Private GitHub. **Auto-deploy intentionally OFF — manual `npx vercel --prod` only.**
- **Stack:** vanilla JS (no framework) + Supabase (free tier, **NO BACKUPS**) + Vercel + Anthropic API. Cloudflare DNS.
- **Env:** Windows / PowerShell. Give PowerShell commands.

---

## 2. Working approach (canonical)

- **This chat (Claude.ai):** planning, triage, debugging, schema work, asset generation, and **drafting paste-ready prompts for Claude Code.** Does not write production code directly.
- **Claude Code (CLI):** writes the code. One session per task; don't parallelize tasks touching the same file.
- **Triage before building:** new issue → 2-min diagnostic (incognito, SQL, DevTools) before code.
- **Test write AND read paths** before "done."
- **Every commit gets `CHANGES_TASKn.md`.**
- **Deploy gotcha:** proxy from a fresh PowerShell, never inside Claude Code (`npx vercel` is interactive and hangs).
- **Long chats degrade** (~25–30 turns) → fresh chat with canonical files pinned.

---

## 3. DEPLOY STATE RIGHT NOW (the most important section)

As of this handover, tasks 22–26 are **committed locally but actions remain:**

1. **Push both repos.** `ldp-scout` (5 commits 2350dd9→d78c871) and `ldp-proxy` (fafc5e5).
2. **Deploy the proxy MANUALLY** — `cd ldp-proxy; npx vercel --prod` from a fresh PowerShell. **The git push does NOT deploy the proxy.** Until this runs, the live scan quota is still 3, not 1. This is the easiest thing to forget.
3. **Verify assets committed** — in `ldp-scout`: `git ls-files *.png *.svg *.ico *.webmanifest` must include `og-image.png` and `site.webmanifest` (the `<head>` OG/favicon links 404 otherwise).
4. **Commit the updated `PROJECT_OVERVIEW.md`** — Claude Code left it modified-but-uncommitted (it was outside task scope). The current version is the regenerated one from this session.

After deploy: re-run PageSpeed, validate the OG preview (opengraph.xyz / LinkedIn Post Inspector), and run one fresh AI Fit scan on a test account so the demo headline reads "across 422 programs" (older screenshots show a stale "393" from a May-20 scan).

---

## 4. What shipped this session (tasks 22–26)

- **22 — Scan quota 3 → 1.** `SCAN_QUOTA = 1` in `scan.js` (the real gate) + `SCAN_QUOTA_CLIENT = 1` in `app.js` (display mirror) + a quota log line. Already-scanned users are grandfathered at their count; 1 only bites new users. **Needs proxy deploy to take effect.**
- **23 — Two-row mobile nav.** ≤720px: topbar wraps to two rows (brand+Profile/SignOut, then full-width tabs), **not scrollable, no wrap.** Tabs keep full desktop labels; mobile shows shortened labels via a `data-short` attribute + `::after { content: attr(data-short) }` (real text stays in DOM for a11y). Removed the old scrollable-rail + mask-fade rules.
- **24 — Kill AI Fit horizontal scroll (mobile).** `.aifit-summary-left/right` now wrap; buttons full-width ("Upload new résumé" wraps); `#page-aifit { overflow-x: hidden }` as a per-page safety net. Diagnostic confirmed the offenders were `.aifit-summary-left` and `.aifit-summary-right` (both ~453px at 375px viewport).
- **25 — Deadlines mobile cards.** ≤720px: `.dlitem` becomes a stacked card with the date eyebrow on top, name on its own line(s), days pill, and one full-width CTA at the bottom (Set reminder, or the rolling note). Desktop unchanged. Fixes the name/days collision seen in screenshots.
- **26 — SEO/meta + perf.** Added meta description, canonical, Open Graph (+`og-image.png` 1200×630 dark green), Twitter card, favicon set (SVG + ico + 16/32/192/512 + apple-touch + webmanifest), `theme-color`, WebApplication JSON-LD. Removed the 3 bogus `Cache-Control`/`Pragma`/`Expires` http-equiv metas. Added `vercel.json` (long-cache static assets, must-revalidate app.js/styles.css/data.js). **Lazy-loaded pdf.js + mammoth via `ensureResumeParsers()`** (injected on first résumé parse, ~2 MB off the landing load) + `defer` on supabase-js.

---

## 5. Critical technical gotchas

1. **`progs[].aiTier` is UPPERCASE enum** (`BEST_FIT`/`STRONG_FIT`/`ACHIEVABLE`/`LONG_SHOT`/`NOT_FIT`). Writer: `syncAIResultsToPrograms()`. Readers `fitTier()` (desktop), `_aiTierMobile()` (mobile) must use uppercase keys.
2. **CSS cascade in `styles.css` (~1,985 lines):** rules in/out of `@media` have equal specificity → later wins. `grep -n '\.selector' styles.css` for ALL rules before claiming a layout fix. (Bit Task 21.1.)
3. **Lazy résumé parsers (Task 26):** pdf.js + mammoth are NOT in `<head>` anymore — `ensureResumeParsers()` injects them on demand (~app.js:4275). Don't move them back to `<head>`; that re-breaks mobile LCP. When testing résumé upload, the first parse triggers the lazy load.
4. **No global `overflow-x` clamp.** Per-page net `#page-aifit{overflow-x:hidden}` exists; don't put it on `body` (breaks the sticky AI Fit summary). New sideways-scroll bug? Diagnostic at 375px: `[...document.querySelectorAll('*')].filter(e=>e.offsetWidth>document.documentElement.clientWidth)`.
5. **Mobile breakpoint is 720px** (NOT 768). iPad portrait stays desktop.
6. **Form controls** kept in Outfit by a global `input,textarea,select,button{font-family:inherit}` near the top of styles.css — don't remove.
7. **`programs.id` sequence:** after explicit-id inserts, `SELECT setval(pg_get_serial_sequence('programs','id'),(SELECT MAX(id) FROM programs));`. Currently past 422.
8. **iOS Calendar 2-alarm limit** (unverified): ICS writes 3 VALARMs but iOS may drop the 30-day. If confirmed dropped, emit 3 separate events.
9. **Proxy deploy is manual** and from a fresh PowerShell. `git push` to `ldp-proxy` does nothing live.

---

## 6. Database / data state

- **`programs`: 422 rows** — 415 `is_active_cycle = true`, 7 false (Nike EHQ, Admiral, Estée Lauder ×2, Scopely, AbbVie FDP, Zuellig). All have `last_verified_at`. Read-only from client (no write RLS).
- **7 tables in `public`, all RLS-on** (anon key is public; RLS is the only protection). Full schema in `DB_SCHEMA.md`. No migration this session, and **Task 27 needs none.**
- **`user_applications`** — RLS `own_apps_all` (ALL) = `auth.uid() = user_id`. Private per user. Columns: `user_id, program_id (nullable), name, org, geo, status, applied_on, deadline, next_step, contact, notes`.
- **`program_intel`** is read-public — never store anything personal there.
- The "393 programs scanned" in old screenshots is a stale May-20 scan; catalog is 422.

---

## 7. Quota & cost model

- **Quota = 1/user lifetime** (Task 22). `scan.js SCAN_QUOTA` is the gate; `app.js SCAN_QUOTA_CLIENT` is display only. Quota row written by the frontend after both tier + gap calls succeed (so the check blocks scan N+1).
- **Cost target $0.10/scan was Task 5** (predates the CHANGES-doc convention — NOT Task 19/20). Current cost is above target. Levers in impact order: `MAX_TOKENS_CAP = 32000` in proxy (bumped up from 6000 — likely the driver), per-scan program payload, model choice (Opus 4.6 for the tier pass). Actual per-scan cost is only visible in the Anthropic console.
- Models whitelisted in `scan.js ALLOWED_MODELS`: `claude-opus-4-6` (tier), `claude-sonnet-4-5` (gap), `claude-haiku-4-5-20251001` (reserve).
- Cohort math at quota 1: 90 ESADE students = up to 90 scans launch day.

---

## 8. NEXT BUILD — Task 27: Applications overlay + user-added programs

**Spec is fully locked (decisions made May 21).** No DB migration. Touches `app.js` + `index.html`. Not launch-blocking, but high value (it replaces the `mailto:hello@` request flow with private user adds + an admin demand backlog).

### Locked decisions
1. **Overlay precedence:** `deadline = app.deadline ?? program.deadline`; stage/status/applied_on/next_step/contact/notes are user-only; catalog facts (function/sector/geo/location/language_required/is_active_cycle/tier) are NOT user-overridable. One `resolveProgramView(p)` merges the user's `apps[]` overlay onto each catalog program; every render path calls it. Override applies everywhere incl. the Programs table.
2. **User-added programs** = `user_applications` rows with `program_id = null`, unioned into the Programs page (per login), badged "**Added by you**" (prominent). Missing catalog fields render "—".
3. **No dedup:** if admin later adds the same program, both rows stay; badge disambiguates; user can delete their own.
4. **Stage on add:** reuse the 7-stage dropdown; default new add to **Shortlisted**.
5. **AI Fit:** user-added programs excluded from scan, labelled "not scored." No manual per-program scan (would burn the single quota).
6. **Calendar:** ICS reads the resolved deadline → carries the user's edited/entered date. A previously-undated program the user gives a deadline becomes Deadlines-listed + ICS-exportable.
7. **Privacy:** entirely the user's private overlay (RLS guarantees it).
8. **Modal/UX:** rename modal field "Program / Role" → "**Program**"; field = searchable dropdown over the FULL catalog + "+ Add new program"; replace the Programs-page "Don't see a program? Request it" mailto with the same Log Application button.

### Paste-ready Claude Code prompt

```
Task 27: Make user_applications a per-user overlay on the read-only programs catalog, and let users add their own private programs. No DB migration. Files: app.js, index.html.

CONTEXT (verify against current code first):
- progs[] = catalog (from Supabase, read-only). apps[] = this user's user_applications rows (loadUserApplications ~1594). Both in memory.
- buildDeadlineItems() (~3936) currently matches an app to a program by program_id OR case-insensitive name, and when matched uses the PROGRAM's deadline (wrong — should prefer the app's).
- saveApplicationToDB() (~1620) already persists program_id, deadline, status, etc. The "Log Application" modal already has a Stage dropdown and a Deadline field.
- Programs page render: renderPrograms (~2900 desktop) / renderProgramsMobile (~3147 mobile) / _mobileCardHTML (~3200). fitTier (~2914) / _aiTierMobile (~3070) render the AI Fit badge.
- ICS: _icsPayload(item) (~4040) + downloadICS (~4215). Deadlines: renderDeadlines (~4120), _renderRow (~4045).

1. RESOLVER. Add resolveProgramView(p) that returns a merged view of a catalog program with this user's overlay:
   - find the user's app for p via program_id === p.id (PREFERRED) or, fallback, exact case-insensitive name match.
   - deadline: app.deadline || p.deadline ; appStatus: app ? app.status : null ; inPipeline: !!app
   - DO NOT let the app override catalog facts (function/sector/geo/location/language_required/is_active_cycle/tier).
   Use this resolver everywhere a program's deadline/pipeline state is shown: Programs table rows, mobile cards, buildDeadlineItems, and the ICS payload. Replace the current "matched → use program deadline" logic in buildDeadlineItems with the resolver so the USER's deadline wins.

2. ICS uses the resolved deadline. Confirm _icsPayload / downloadICS read the resolved deadline so a downloaded .ics carries the user's edited/entered date, not the catalog date. A previously-undated catalog program that the user gives a deadline (via the modal) must now appear on the Deadlines page with a "Set reminder" ICS button.

3. USER-ADDED PROGRAMS (program_id = null) unioned into the Programs page:
   - In the Programs render, after the catalog list, append the user's apps where program_id is null as program-like cards/rows.
   - Badge them prominently: a pill labelled "Added by you" (distinct color from catalog badges — use the amber/accent treatment, not the green verified badge). Must be obvious at a glance vs catalog rows.
   - Missing catalog fields (function/sector/geo/tier/AI fit) render as "—".
   - These rows are NOT scored: show a small "Not scored" chip where the AI Fit badge would be. Exclude program_id=null rows from the AI Fit scan payload entirely.
   - Respect existing filters/sort where the field exists; rows with "—" sort last.

4. MODAL + ENTRY POINTS (index.html + app.js):
   - Rename the modal field label "PROGRAM / ROLE (TYPE TO SEARCH TRACKED PROGRAMS)" to just "PROGRAM".
   - The field is a searchable dropdown over the FULL catalog (progs), not just tracked programs. When the user picks a catalog program, set program_id to that program's id (so matching is by id, never fragile name).
   - Add an "+ Add new program" affordance for free-text entry → saves with program_id = null. Default the Stage dropdown to "shortlisted" for a fresh add (user can change).
   - Replace the Programs-page "Don't see a program? Request it" mailto:hello@ link with a button that opens this same Log Application modal in add-new mode. Remove the mailto.

5. DIAGNOSTICS: add console.log lines:
   console.log('[overlay] resolved', p.id, 'deadline', resolved.deadline, 'fromUser', !!app && !!app.deadline);
   console.log('[user-programs] union count', userOnly.length);
   Leave them in for now; we'll strip post-verification.

TEST (write AND read paths):
- Log an application for a CATALOG program with a custom deadline → that deadline shows on Programs row, Deadlines page, and the downloaded .ics. Refresh/sign out+in → still there (persisted).
- Add a NEW program (program_id null) with a deadline → appears on Programs page badged "Added by you" with "—" for missing fields and "Not scored"; appears on Deadlines with a working Set reminder; private (not visible to a second test account).
- A catalog program with NO deadline, after the user adds one → now appears on Deadlines with ICS.
- Run an AI Fit scan → user-added programs are excluded; catalog scoring unchanged.

Write CHANGES_TASK27.md (plain English: the overlay precedence rule, the program_id-first matching, the union + badge, the not-scored rule, the modal/mailto change, and the admin note that program_id IS NULL rows are a demand backlog queryable via the Supabase dashboard).
```

---

## 9. SEO / performance baseline (PageSpeed, May 21, pre-deploy of Task 26)

| | Mobile | Desktop |
|---|---|---|
| Performance | 69 | 97 |
| Accessibility | 93 | 93 |
| Best Practices | 100 | 100 |
| SEO | 80 | 80 |

- Desktop is fine (FCP 0.9 / LCP 1.0 / CLS 0.027). **Mobile is the story:** FCP 4.5s, LCP 5.0s (both red), but **TBT 0ms** — so it's render-blocking + payload, NOT JS execution. Biggest lever was render-blocking (~3.65s) + the ~7.3 MB payload, dominated by pdf.js + mammoth (~2 MB) which Task 26 lazy-loads.
- SEO 80 = missing meta description (fixed) + "Links are not crawlable" (onclick SPA nav; will persist; acceptable for an auth-gated app).
- **Re-run PageSpeed after deploy** to confirm mobile LCP dropped and SEO moved off 80.
- Post-launch: trim Fraunces font weights (find heavy requests via Network tab sorted by size); a11y contrast + heading order. Skip CSS/JS minify (small wins, needs a build step, breaks the no-build workflow).

---

## 10. Files to attach to a fresh chat

Required (current HEAD after tasks 22–26 — re-export from the repo so they're post-26):
1. `index.html`
2. `app.js`
3. `styles.css`
4. `PROJECT_OVERVIEW.md` (the regenerated one from this session)
5. `DB_SCHEMA.md`
6. This handover (`LDP_SCOUT_HANDOVER_2026-05-21.md`)
7. Latest `programs` CSV export (422 rows, full schema)

Recommended:
8. `ldp-proxy/api/scan.js` (quota/cost context — different repo)
9. The `CHANGES_TASK22.md … 26.md` explainers (and 27 once built)

---

## 11. Memory edits (already saved, keep)

1. Windows / PowerShell — give PowerShell commands.
2. Prefer subscription tools (Claude Code, claude.ai) over paid API for batch work; flag cost if API is the only option.
3. Don't skip steps in setup instructions — explicit and numbered.
4. Project: LDP Scout, ldpscout.com, vanilla JS + Vercel proxy + Supabase, Monday May 25 2026 ESADE launch; catalog curation is the demo-blocker.

No new memory edits required from this session.

---

*End of handover. Generated 2026-05-21.*
