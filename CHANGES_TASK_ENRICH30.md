# Task ENRICH-30 (data) — Catalog enrichment, batch #30 (30 programs)

> **HAND-OFF BRIEF (read first).** Enriched 30 previously-unenriched catalog rows and produced one
> Supabase migration (NOT auto-applied): **`enrich_programs_batch30.sql`** (30 `UPDATE`s, one
> transaction). Highlights:
> - **GROUP A (14)** — the most-incomplete rows — got empty fields filled (`eligibility`,
>   `work_experience`, `duration`, `target_degree`, `locations`/`countries`/`continents`, …) AND
>   **rich, AI-fit-grounded `description`s** (specific functions, rotation structure, selection,
>   eligibility signals, locations). #399's thin one-liner was rewritten; **#12's stale deadline was
>   corrected** (Jan–Feb → the WBG YPP's 1–30 Sept window). The 2 ESADE Perk rows stay minimal stubs.
> - **GROUP B (16)** — scraped from **mba-exchange.com**. Each row gets (a) its mba-exchange `url`
>   **replaced** with the company's own durable official page, and (b) its raw/garbled scraped
>   **`description`/`eligibility`/`work_experience` REWRITTEN** into clean copy distilled from the
>   companies' official job postings (the scrape was the raw material to enrich, per your
>   clarification). `target_degree` normalized (`'Master'` → `'Master''s'`).
> - **`visa` corrected on #39** (Thermo Fisher) `true→false` — official page requires US work auth,
>   no sponsorship. **`visa` set `false→true`** on #18 Samsung GSG (HIGH) and #63/#76 LVMH SPRING +
>   #194 Nomura IB (MEDIUM).
> - **2 ESADE stubs** (#418, #422 Perk Venture): minimal description + **`visible_to = '{"esade"}'`**.
> - **2 ephemeral GROUP A links upgraded** (#399 LinkedIn job post, #415 Hilti job-req → durable hubs).
> - Source: the companies' official job postings + June-2026 careers-page research (reachability noted inline).

Deliverable: **`enrich_programs_batch30.sql`** — 30 `UPDATE`s keyed by `programs.id`, wrapped in one
`BEGIN; … COMMIT;`. **Not auto-applied** — review, take the snapshot at the top of the SQL, run it in
the Supabase SQL editor, eyeball the verification `SELECT`, then `COMMIT` (or `ROLLBACK`).

## Which 30, and why

```
GROUP A — most gaps (14):  3 9 10 12 13 14 18 36 39 43 399 415 418 422
GROUP B — mba-exchange scrape, enrich (16):  61 63 71 76 96 103 107 108 110 113 115 144 152 176 188 194
```

## Sources & method
- **GROUP A** — official careers pages + June-2026 web research. Empty fields were filled, and
  `description`s were (re)written to be **rich and specific** — the goal is better data quality and
  stronger AI résumé-fit grounding (concrete functions, rotation structure, selection process,
  eligibility signals, locations), not minimal stubs. #399's thin description was rewritten and #12's
  stale deadline/dlnote corrected. Two ephemeral links (#399 LinkedIn post, #415 Hilti job-req — both
  expire → 404) were upgraded to durable hubs.
- **GROUP B** — these rows were scraped from **mba-exchange.com**, so their `description`/`eligibility`
  were verbose raw job-posting dumps, in places **garbled (mojibake)**, with **junk `work_experience`**
  values (`'Yes'`, `'Unknown'`). Per your clarification, the task is to **enrich** them: each row's
  `description`/`eligibility`/`work_experience` is **rewritten** into clean copy, distilled from the
  company's own posting text (which carried the real substance) plus official-page research, and the
  mba-exchange `url` is replaced with the company's durable official page. Confidence is noted **inline
  per row** (HIGH / MEDIUM / LOW); nothing is invented.

## ⭐ Link quality — the USP
Every `url` written is a **durable landing page** (program page, or early-careers / students / MBA
hub), **not** an expiring job-requisition URL. Reachability noted in the SQL. Notes:
- **GROUP B** (16/16 replaced): Wells Fargo CIB-MBA program page, TD `graduate-leadership-programs`,
  ByteDance SEA early-careers, Lilly US-cMBA, Sanofi USA early-careers, Vanguard/Edwards/Visa/Marriott
  student hubs, Nomura early-careers, etc. — all **200** on automated check.
- **#188 Philips** reuses the OLDP page 200-verified in the EU batch
  (`/professional/in/en/operational-leadership-development-program`; the `/global/en/` variant 404s).
- **#63 / #76 LVMH** → the **LVMH graduate-programs hub** (200-verified in the EU batch). The deeper
  `/lvmh-spring-future-leaders-singapore` and `/lvmh-spring-general-management` pages were
  **bot-blocked to automated checks** (not 404s); paths noted in the row comments for an optional
  manual upgrade.
- **#14 Noon** (`noon.com/uae-en/careers/`, left as-is) timed out on automated fetch — **verify in
  browser** (LOW).

## ⚠ Data-quality findings & decisions

**`visa` changes (review if you have better data):**
- **#39 Thermo Fisher GM GLDP — CORRECTED `true→false`** (HIGH): page requires US work auth with **no
  current or future sponsorship** (F-1/J-1/H-1/OPT/CPT ineligible).
- **#18 Samsung GSG — `false→true`** (HIGH): recruits international MBAs into Seoul, sponsors Korean visas.
- **#63 / #76 LVMH SPRING — `false→true`** (MEDIUM): international multi-country rotational programme
  (consistent with #55 LVMH HORIZONS, set `true` in the EU batch).
- **#194 Nomura IB Associate — `false→true`** (MEDIUM): full-time IB associate roles routinely sponsor H-1B.
- All other US-based, no-sponsorship rows leave `visa = false`.

**Mojibake / junk fixed in the GROUP B rewrite:** encoding corruption was confirmed **in the data**
(not a read artifact) — e.g. **#61** `Ã¯Â¿Â½` (a lost character), **#96** `Â•`, **#113/#144/#152** `Â'`.
The rewrites remove these, and junk `work_experience` (`'Yes'`/`'Unknown'`) is replaced with real
ranges. `source_url` still points at mba-exchange (original provenance); `url` is now the official page.

**Mislabeled / not-quite-what-the-name-says (described honestly, names NOT auto-changed):**
- **#9 Mubadala** — the named programme (Maseeraty) is an **Emiratisation track, UAE nationals only**;
  MBA hires enter via investment roles.
- **#10 Chalhoub** — no current programme literally called "Management Associate"; closest are a
  ~6-month traineeship / SGII NEWGEN (+ an 18-month Emirati national track).
- **#13 Temasek / GIC** — two separate entities; both intakes are **early-career (<1 yr exp)**, not post-MBA.
- **#14 Noon** — no branded MBA "Strategy & Operations" cohort confirmed (LOW).
- **#399 Zuellig Pharma** — niche; thin public info, no durable program page (used the careers portal).
  Existing (non-mba-exchange) description left as-is.

**ESADE-exclusive stubs:** **#418** (no public info → "contact ESADE careers office" stub) and **#422**
(existing JobTeaser description kept) — both set `visible_to = '{"esade"}'`.

**#415 Hilti Executive Leadership** — confirmed distinct from #21 Outperformer (MBA + engineering;
Account Manager → team lead in 12–18 months → international assignment); enriched accordingly.

**#12 IFC/WB YPP — deadline CORRECTED.** The row had `deadline = 2027-02-01` / dlnote "Typically
Jan–Feb"; the WBG Young Professionals Program window is **1–30 September** (matches sister row #211).
Set `deadline = 2026-09-30` + a Sept-window dlnote. Confirm any IFC-specific cycle before publishing.

## Geo fields — vocabulary note (important)
`countries[]` / `continents[]` use the app's **canonical filter vocabulary** — `'USA'`, `'UK'`,
`'Singapore'`, `'North America'`, `'Middle East'`, `'Global'`, … — because those are the exact keys the
geo filter matches (`COUNTRY_TO_CONTINENT` / `CONTINENT_ORDER` in `app.js`). `locations[]` keeps the
**human-readable full-name** convention (`'United States'`, `'United Kingdom'`), so the two differ in
spelling on purpose. Countries outside the app's map (Philippines, Vietnam, Indonesia for #176/#399)
are listed for accuracy but won't show a country-level pill — the **continent** filter ('Asia') covers them.

## Fields written
- **GROUP A:** `description` (rich rewrite for 11 rows incl. #399; 2 ESADE stubs minimal),
  `eligibility, work_experience, target_degree, duration, language_required[], locations[],
  countries[], continents[]` (gaps filled), plus `geo` (#399/#415/#422), `location` (#415),
  `url` (#399/#415), `visa` (#18/#39), `deadline`+`dlnote` (#12 correction), `visible_to` (#418/#422).
- **GROUP B:** `url` (all 16, replacing mba-exchange), **`description`, `eligibility`,
  `work_experience` (rewritten)**, `target_degree` (normalized where it was `'Master'`), `duration`,
  `language_required[]`, `locations[]`, `countries[]`, `continents[]`, `visa` (#63/#76/#194),
  `last_verified`, `last_verified_at`.
- `last_verified = 'Jun 2026 (est.)'` + `last_verified_at = now()` on **all 30** rows.
- **Not touched:** `company`, `program_name`, `industry`, `function`, `tier`, `status`, `dlnote`,
  `tags`, `notes`, `program_type`, `source_url`, `salary`, `deadline`, `is_active_cycle`.

## Verification performed
- 30 `UPDATE`s; target-ID set matches the task exactly (no missing / extra / duplicate).
- All 16 GROUP B `url`s replaced ("mba-exchange" now appears only in comments). #418/#422 both set `visible_to`.
- `$md$` tags balanced (58 = 29 descriptions × 2); **no mojibake markers remain in any data line**
  (only in the comment documenting what was fixed); every single-quoted field has balanced quotes
  (apostrophes doubled — `Master''s`, `years''`, …); one `BEGIN;`/`COMMIT;`; 5 `visa` + 2 `visible_to`.

## How to apply
Snapshot (`programs_backup_batch30`) → run `enrich_programs_batch30.sql` in the Supabase SQL editor →
eyeball the verification `SELECT` (30 rows + the #418/#422 `visible_to` spot-check) → `COMMIT`
(or `ROLLBACK`).

## Suggested follow-ups
1. **Run the migration** (snapshot → run → verify SELECT → COMMIT).
2. **Optional URL upgrades after a browser check:** swap #63/#76 to the deeper LVMH SPRING pages, and
   optionally #36→`jobs.abbott/early-careers`, #39→`jobs.thermofisher.com/global/en/gm-gldp`,
   #10→`careers.chalhoubgroup.com/pages/graduate-hiring`, #12→the `/ext/en/careers/talent-programs/`
   canonical YPP path (all 200-verified, more specific than the durable links left in place).
3. **Re-confirm the 4 MEDIUM `visa` flips** (#63/#76/#194 and the #39 correction) before publishing.
4. Optionally clear/refresh **`source_url`** on the 16 GROUP B rows (still points at mba-exchange).
5. Consider correcting **#61 Samsung** `industry` (`healthcare` → `tech`) — a pre-existing data error,
   left untouched as out of scope.
