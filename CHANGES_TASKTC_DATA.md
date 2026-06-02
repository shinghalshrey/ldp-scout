# Task TC (data) — Catalog enrichment from the ESADE interview reports

Source file: `Esade_Interview report answers.xlsx` (ESADE Careers "Interview Reports"
— real student/alumni submissions about companies, roles, locations, hiring
processes; ~507 unique reports across two form-sheets, 2023–2024 cycles).

## What the Excel turned out to be
A recruitment **interview-experience** dataset, not a program list. Columns:
company, role, sector, role-type, country/city, start/end dates, recruitment
duration, language, last-interview date, process phases, and a free-text
description of the interview/case content. Overwhelmingly internships and
consulting/finance interviews (249 MBA · 151 Bachelor · 75 MSc/CEMS reports;
only ~9 explicitly tagged "Graduate/Rotational Program").

## Decision 1 — catalog additions: skipped (agreed)
The Excel mostly **confirms companies already in the catalog** (Amazon, J&J, BCG,
Kraft Heinz, Mastercard, Roche, Siemens, Nestlé, …). The only genuinely *new*
structured programs in it are MSc/Bachelor-level grad schemes (Amplifon,
Tabacalera, Arma Partners, EY rotation, Simon Kücher, AFME, Hilti-Mexico) — not
MBA LDPs. Per your call, **no rows were added**; all effort went to enrichment.

## Decision 2 — enrichment: verified batch of 10 flagship LDPs
The Excel overlaps **63 catalog programs at ~21 companies** with real data. For
this first batch I enriched **10 flagship LDPs**, combining the spreadsheet's
real student data with June-2026 web research. Deliverable:
**`enrich_programs_tasktc.sql`** — 10 `UPDATE`s keyed by `programs.id`, wrapped
in a transaction, each only setting columns we have good data for (existing
values for untouched columns are preserved).

| id | Program | URL | Geography | Hiring window | Visa | JD/desc |
|----|---------|-----|-----------|---------------|------|---------|
| 1 | Amazon Pathways Operations LDP | ✅ amazon.jobs | ✅ EU/UK/UAE/US/IN (+8 ESADE cities) | ✅ rolling, Aug–Nov | ✅ yes | ✅ |
| 19 | J&J IRDP | ✅ careers.jnj.com | ✅ Global (LatAm placements) | ✅ rolling, Feb intvw | ✅ yes | ✅ |
| 33 | J&J Finance MBA LDP (FLDP) | ✅ careers.jnj.com | ✅ USA | ✅ autumn | ⚠️ **no** (US work auth req) | ✅ |
| 34 | Kraft Heinz MBA Leadership | ✅ careers.kraftheinz.com | ✅ Chicago/Amsterdam | ✅ Oct–Dec (8 Dec 2025) | — varies | ✅ Ketchup Invitational |
| 8 | Mastercard MBA Leadership | ✅ careers.mastercard.com | ✅ Global/EU/UAE/LatAm | ✅ spring/autumn | — varies | ✅ |
| 7 | BCG Associate (MBA) | ✅ careers.bcg.com | ✅ London/AMS/Dubai + 3 | ✅ FT Aug–Sep | ✅ yes | ✅ |
| 21 | Hilti Outperformer | ✅ careers.hilti.group | ✅ Liechtenstein/global | ✅ Sep–Oct (regional) | ✅ yes | ✅ AC in Panama |
| 17 | Roche Business Perspectives | ✅ careers.roche.com | ✅ Basel/global | ✅ annual, Jun start | ✅ yes | ✅ |
| 41 | AB InBev Global MBA | ✅ ab-inbev / anheuser-busch | ✅ Global (LatAm) | ✅ Sep–May | ⚠️ **no** (no sponsorship) | ✅ |
| 211 | World Bank YPP | ✅ worldbank.org | ✅ Washington DC | ✅ **1–30 Sep** (firm) | ✅ yes (G-4) | ✅ |

### Sourcing & confidence
- **Geography, hiring window, language, selection-process detail** → from the
  spreadsheet's real submissions = **high confidence** (primary data). The
  `description` for each program now embeds the actual interview/case format and
  "ESADE alumni placements: …" so the **AI Fit scan has concrete role grounding**.
- **URL, deadline, visa, eligibility, structure** → public web research (June
  2026), official careers pages cited inline in the SQL. Confidence noted per row;
  **unverifiable fields were left untouched, never guessed.**
- **Two visa corrections worth flagging:** J&J **FLDP (#33)** requires permanent
  U.S. work authorisation, and **AB InBev (#41)** states it does not sponsor work
  visas → both set `visa = false`. (J&J **IRDP #19**, by contrast, is an
  international-mobility program → `visa = true`.)
- Firm dated deadline only where one genuinely exists: **World Bank YPP** (30 Sep).
  The rest are rolling/region-dependent windows captured in `dlnote`.

### Fields written
`url, geo, location, locations[], visa, status, deadline, dlnote,
language_required[], work_experience, eligibility, target_degree, description,
last_verified, last_verified_at`. No schema changes — all columns already existed.

## How to apply
The catalog lives in Supabase; this file is **not** auto-applied. Review it, take
the snapshot at the top (`programs_backup_tasktc`), run it in the Supabase SQL
editor, eyeball the verification `SELECT`, then `COMMIT`.

## Next (remaining 20 of 30)
Same method, drawing on the 63 overlap programs — strong candidates with real
Excel data: Siemens (#15/#16), BASF MBA LDP (#38), Henkel PRISM (#316), Nike MVP
(#158), Heineken (#127), Nestlé (#181), Cardinal Health (#291/#350/#359),
American Express (#114/#174), Barclays (#142), UBS (#86), SAP Academy (#70/#146),
Oliver Wyman FLDP (#236), plus more J&J tracks. Say the word and I'll produce
`enrich_programs_tasktc_2.sql`.
