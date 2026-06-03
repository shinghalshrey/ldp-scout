# Task TC (data) — Catalog enrichment, batch #2 (remaining 20 flagship LDPs)

Continuation of `CHANGES_TASKTC_DATA.md` / `enrich_programs_tasktc.sql` (batch #1,
10 programs — **already applied** to Supabase per the user). This batch covers the
**20 remaining candidates** the batch-1 changelog named as "Next".

Source file: `Esade_Interview report answers.xlsx` (ESADE Careers "Interview
Reports" — real student/alumni submissions, 2023–2025 cycles), re-extracted, plus
June-2026 official-careers-page web research.

## Deliverable
**`enrich_programs_tasktc_2.sql`** — 20 `UPDATE`s keyed by `programs.id`, wrapped in
a single transaction, each only setting columns we have good data for (untouched
columns preserved). No schema changes.

| id | Program | URL | Geo | Visa | Source mix |
|----|---------|-----|-----|------|------------|
| 15 | Siemens · XPS Leadership Program | ✅ siemens.com | global | ✅ true (Siemens arranges) | web + Excel |
| 16 | Siemens · Finance Excellence Program | ✅ siemens.com | europe | ✅ true | web + Excel (Bavaria, Apr) |
| 38 | BASF · MBA Leadership Development | ✅ basf.com | *untouched* | *untouched* ⚠ | web + Excel |
| 336 | BASF · Diverse Leaders Program (MBA) | ✅ basf.com | us | ⚠ **false** (US auth req.) | web |
| 348 | BASF · Manufacturing DLP (MBA) | ✅ basf.com | us | ⚠ **false** | web |
| 316 | Henkel · PRISM/HRP (Functions) | ✅ henkel-northamerica.com | us | — | web + Excel |
| 158 | Nike · MVP Rotational Leadership Assoc. | ✅ careers.nike.com | us | — | web |
| 137 | Nike · MVP Graduate Internship | ✅ careers.nike.com | us | — | web |
| 127 | Heineken · Global Graduate Programme | ✅ theheinekencompany.com | global | ⚠ **false** (right-to-work req.) | web + Excel |
| 181 | Nestlé · Marketing Development Program | ✅ nestlejobs.com | us | ⚠ **false** (stated) | web + Excel |
| 291 | Cardinal Health · MBA Strategy Internship | ✅ cardinalhealth.com | us | ⚠ **false** (stated) | web + Excel |
| 350 | Cardinal Health · MBA Marketing Internship | ✅ cardinalhealth.com | us | ⚠ **false** | web |
| 359 | Cardinal Health · MBA Finance Internship | ✅ cardinalhealth.com | us | ⚠ **false** | web |
| 114 | Amex · Campus Graduate Strategy Internship | ✅ americanexpress.com | us | ⚠ **false** (stated) | web + Excel |
| 174 | Amex · HR Leadership Development (HRLDP) | ✅ americanexpress.com | us | ⚠ **false** (stated) | web |
| 142 | Barclays · IB Analyst Graduate | ✅ search.jobs.barclays | global | ✅ **true** (UK/EU) | web + Excel |
| 86 | UBS · Graduate Talent Program (Tech) | ✅ ubs.com | europe | ✅ **true** (sponsors permits) | web + Excel |
| 70 | SAP · Academy Customer Success (Sales/Presales) | ✅ jobs.sap.com | global | — (varies) | web + Excel |
| 146 | SAP · Academy People & Culture (HR rotational) | ✅ jobs.sap.com | global | — (varies) | web |
| 236 | "Oliver Wyman" → Marsh McLennan FLDP, NY | ✅ oliverwyman.com | us | ⚠ **false** (no sponsorship) | web (+ OW note) |

## Sourcing & confidence
- **Geography, hiring window, language, selection-process detail** → ESADE
  spreadsheet's real submissions = **high confidence** (primary data). Each
  enriched `description` embeds the actual interview/case format and "ESADE alumni
  placement: …" so the **AI Fit scan has concrete role grounding**.
- **URL, structure, eligibility, visa, deadline window** → official careers pages,
  June 2026 (cited inline per row). **Unverifiable fields were left untouched, not
  guessed** — e.g. visa is left alone for Henkel/Nike where sponsorship wasn't
  documented.

## Two data corrections worth flagging
1. **#236 is mislabelled in the catalog.** "Summer Associate, FLDP, New York" is the
   **Marsh McLennan group Finance LDP**, *not* an Oliver Wyman *consulting* role. It
   is enriched as the finance program (10-week NY, no U.S. sponsorship). The separate
   ESADE consulting-interview data (Madrid/Dubai/Milan, multi-round case interviews)
   is preserved in its `dlnote` but **not** merged into the finance JD. → Consider
   renaming this row's `company`/`program_name` later.
2. **#38 BASF MBA LDP geo/visa left untouched.** The best-documented flagship runs in
   the **U.S.** (Florham Park, NJ; no sponsorship), but the catalog row is tagged
   Europe/Ludwigshafen, so I did **not** flip `geo`/`visa` — the U.S.-cohort caveat
   is captured in `dlnote` instead. The two explicitly-U.S. BASF MBA rows (#336, #348)
   *do* get `visa = false`.

## Visa corrections set in this batch (`visa = false`, each cited)
Nestlé (#181), Cardinal Health (#291/#350/#359), Amex (#114/#174), Marsh/OW FLDP
(#236), BASF U.S. MBA (#336/#348) — all state no sponsorship / U.S.-only work
authorisation. Heineken (#127) → false because "the right to work in the country of
your program is essential." Set `visa = true`: Siemens (#15/#16, arranges permits),
Barclays (#142, UK/EU sponsorship), UBS (#86, sponsors non-EU/EFTA permits).

## Fields written
`url, geo, location, locations[], visa, status, dlnote, language_required[],
work_experience, target_degree, description, last_verified, last_verified_at`.
No firm dated deadline existed for any of the 20 (all rolling/region-dependent), so
none was set — windows are captured in `dlnote`. No schema changes.

## How to apply
Same as batch #1 — the catalog lives in Supabase and this file is **not** auto-applied.
Review it, take the snapshot at the top (`programs_backup_tasktc2`), run it in the
Supabase SQL editor, eyeball the verification `SELECT`, then `COMMIT`.

## Coverage note
This completes the 30-program enrichment plan from `CHANGES_TASKTC_DATA.md`
(10 in batch #1 + 20 here). No additional J&J tracks were added: the ESADE J&J
reports were all IRDP (already enriched as #19 in batch #1), and no further J&J
MBA rows surfaced in the catalog export.
