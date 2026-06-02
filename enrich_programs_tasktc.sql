-- ============================================================================
-- Task TC (data) — Catalog enrichment, verified batch #1 (10 flagship LDPs)
-- ============================================================================
-- Source data:
--   • Geography, hiring window (interview months), language, and selection-
--     process detail → ESADE "Interview Reports" spreadsheet (real student
--     submissions, 2023–2024 cycles). HIGH confidence — primary data.
--   • URL, application deadline, visa sponsorship, program structure → public
--     web research, June 2026 (official careers pages cited per row). Confidence
--     noted inline; unverifiable fields are left untouched (not guessed).
--
-- Each UPDATE only SETs columns we have good data for, so existing values for
-- untouched columns are preserved. Keyed by programs.id. Wrapped in a single
-- transaction — review the SELECT below, then run. Roll back if anything looks
-- off.
--
-- ⚠ Review before running. Take a snapshot first:
--     CREATE TABLE programs_backup_tasktc AS SELECT * FROM programs
--       WHERE id IN (1,7,8,17,19,21,33,34,41,211);
-- ============================================================================

BEGIN;

-- Sanity check — see the rows you're about to change:
-- SELECT id, company, program_name, url, deadline, visa FROM programs
--   WHERE id IN (1,7,8,17,19,21,33,34,41,211) ORDER BY id;

-- ── #1 Amazon · Pathways Operations LDP ─────────────────────────────────────
-- URL/structure/visa: amazon.jobs (HIGH). Placements/window/lang: Excel (HIGH).
UPDATE programs SET
  url = 'https://www.amazon.jobs/content/en/career-programs/pathways',
  geo = 'global',
  location = 'EU · UK · UAE · US · India',
  locations = ARRAY['Spain','United Kingdom','Italy','Luxembourg','Germany','UAE','United States','India'],
  visa = true,
  status = 'rolling',
  dlnote = 'Rolling intake; applications typically open Aug–Nov. ESADE interviews observed Jan–Mar.',
  language_required = ARRAY['English'],
  work_experience = '3+ years management/leadership experience preferred',
  target_degree = 'MBA / Master''s',
  description = $md$Three-year Operations Leadership Development Program for MBA/Master's graduates. Trajectory: lead 50–100 associates in a fulfillment/sortation/delivery site → Operations/Area Manager (300–500 team) → Senior Manager. Selection is heavily behavioural, structured on Amazon's Leadership Principles (STAR-format "tell me about a time…" questions across two interviewers) plus CV-deep-dive. ESADE alumni placements: Madrid, Barcelona, Seville, Luxembourg, London, Munich, Milan/Vercelli, Dubai.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 1;

-- ── #19 Johnson & Johnson · International Recruitment & Development (IRDP) ────
-- URL/structure: careers.jnj.com (HIGH). Placements/window/lang/interview: Excel.
UPDATE programs SET
  url = 'https://www.careers.jnj.com/en/student-opportunities/leadership-development-programs/international-recruitment/',
  geo = 'global',
  location = 'Global · EMEA · APAC · Americas',
  locations = ARRAY['Colombia','Brazil','Mexico','Canada','China','Japan','United States'],
  visa = true,
  status = 'rolling',
  dlnote = 'Rolling per region/function; intern interviews observed Feb. Full-time and internship tracks.',
  language_required = ARRAY['English','Spanish'],
  target_degree = 'MBA / Master''s',
  description = $md$International Recruitment & Development Program — a multi-year rotational leadership program for MBA/Master's students across J&J's commercial, marketing, sales and supply-chain functions, built around global mobility. Interviews are competency/credo-based (strengths-weaknesses, "why J&J", fit-to-Credo) and often include a live business challenge posed by the hiring manager to talk through. ESADE alumni placements: Bogotá, Cali, São Paulo.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 19;

-- ── #33 Johnson & Johnson · Finance MBA LDP (FLDP) ──────────────────────────
-- URL/structure/visa/eligibility: careers.jnj.com (HIGH).
-- NOTE: corrects visa → false (US program requires permanent US work authorisation).
UPDATE programs SET
  url = 'https://www.careers.jnj.com/en/student-opportunities/leadership-development-programs/finance-leadership-development-program/',
  geo = 'us',
  location = 'USA (New Brunswick, NJ / Cincinnati, OH)',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'Full-time MBA track recruits in the autumn for the following summer cohort.',
  language_required = ARRAY['English'],
  work_experience = '5+ years full-time professional or military experience',
  eligibility = 'Full-time MBA graduating Aug 2025–Aug 2026; permanent U.S. work authorisation required (no sponsorship); CMA certification obtained during the program.',
  target_degree = 'MBA',
  description = $md$Finance MBA Leadership Development Program — a four-year rotational finance accelerator with targeted training, continual coaching, and assigned peer + leader mentors. Participants complete the CMA certification during the program. Requires 5+ years prior experience and permanent U.S. work authorisation.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 33;

-- ── #34 Kraft Heinz · MBA Leadership Program ────────────────────────────────
-- URL/structure/deadline: careers.kraftheinz.com (HIGH). Selection process: Excel.
-- visa intentionally not set (varies by US vs EU role).
UPDATE programs SET
  url = 'https://careers.kraftheinz.com/',
  geo = 'global',
  location = 'Chicago, USA · Amsterdam, NL',
  locations = ARRAY['United States','Netherlands'],
  status = 'open',
  dlnote = 'MBA internship (pipeline to the Leadership Program) recruits ~Oct–Dec; 2025 cycle closed 8 Dec 2025.',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$MBA Leadership Program, fed by a 10-week MBA summer internship at the Chicago HQ where interns own a growth-plan project end-to-end. Distinctive selection route — the "Ketchup Invitational" MBA case competition: (1) a 4-minute personal video on a prompt, (2) selection onto a cross-school team, (3) 3–4 weeks to solve a case and present to a panel against other top MBA programs. EU roles run out of Amsterdam.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 34;

-- ── #8 Mastercard · MBA Leadership / Management Associate Program ────────────
-- URL/structure: careers.mastercard.com (HIGH). Placements/interview: Excel.
-- visa intentionally not set (Mastercard states sponsorship varies by role).
UPDATE programs SET
  url = 'https://careers.mastercard.com/us/en/student-fulltime-jobs',
  geo = 'global',
  location = 'Global · Europe · UAE · Americas',
  locations = ARRAY['United States','United Kingdom','UAE','Brazil','Colombia'],
  status = 'rolling',
  dlnote = 'Summer interns recruited in the spring; full-time Management Associate roles in the autumn. Visa sponsorship varies by role/location.',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$Management Associate Program — an 18-month rotational leadership program for second-year MBAs, rotating every six months across one of four tracks (Finance; Markets; Operations & Technology; Product). The Advisors / Consulting Services arm also hires MBA summer consultants. Interviews mix background/fit ("why Mastercard", "why consulting/MBA") with a mini business case. ESADE alumni placements: São Paulo, Bogotá.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 8;

-- ── #7 BCG · Associate / Consultant (Full-time MBA) ─────────────────────────
-- Recruiting timeline: careers.bcg.com (HIGH). Interview format/placements: Excel.
UPDATE programs SET
  url = 'https://careers.bcg.com/global/en/on-campus',
  geo = 'global',
  location = 'London · Amsterdam · Dubai · Vienna · Munich · São Paulo',
  locations = ARRAY['United Kingdom','Netherlands','UAE','Austria','Germany','Brazil'],
  visa = true,
  status = 'open',
  dlnote = 'Full-time MBA recruiting Aug–Sep; summer-consultant (MBA1) recruiting Nov–Dec.',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$Post-MBA entry as a Consultant (Associate in some offices) on the generalist consulting track. Interviews are the classic two-part format: a case (market sizing, profitability, etc.) plus fit ("why BCG", strengths/weaknesses, "tell me about yourself"). Strong on-campus presence at ESADE. ESADE alumni placements: Vienna, Munich, São Paulo (in addition to the London/Amsterdam/Dubai hubs).$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 7;

-- ── #21 Hilti · Outperformer (Global Management Development Program) ─────────
-- URL/structure/deadline/visa: careers.hilti.group (HIGH). Process/placement: Excel.
UPDATE programs SET
  url = 'https://careers.hilti.group/en-us/what-we-do/early-careers/recent-graduates/global-management-development-program/',
  geo = 'global',
  location = 'Schaan, Liechtenstein · Global (regional placements)',
  locations = ARRAY['Liechtenstein','Mexico','United Kingdom','Slovakia','Finland'],
  visa = true,
  status = 'rolling',
  dlnote = 'Deadlines vary by region (commonly Sep–Oct). Two tracks: Business and Finance.',
  language_required = ARRAY['English','Spanish'],
  target_degree = 'Master''s / MBA',
  description = $md$Outperformer — Hilti's two-year Global Management Development Program for graduates, with international rotations and an overseas assignment, on a Business or Finance track. Selection: HR STAR-method interview → 45-minute online case → regional-office interview → a full-day assessment centre (e.g. in Panama for the LatAm region) featuring a group business-case discussion and a personal-introduction exercise. ESADE alumni placement: Mexico City.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 21;

-- ── #17 Roche · Business Perspectives ───────────────────────────────────────
-- URL/structure: careers.roche.com (HIGH). Window/interview/placement: Excel.
UPDATE programs SET
  url = 'https://careers.roche.com/global/en/business-perspectives-at-roche',
  geo = 'global',
  location = 'Basel, Switzerland · Global',
  locations = ARRAY['Switzerland'],
  visa = true,
  status = 'rolling',
  dlnote = 'Annual intake; ESADE interviews observed Jun (summer start). Global rotations/assignments.',
  language_required = ARRAY['English'],
  target_degree = 'Master''s / MBA',
  description = $md$Business Perspectives — an 18–24 month rotational graduate program with up to four assignments (6–8 months each) spanning Pharmaceuticals, Diagnostics and Group functions, with international-assignment options and a programme manager + buddy. Interviews are typically run by the direct hiring manager and are CV/experience-led (role-specific rather than purely behavioural). ESADE alumni placement: Basel.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 17;

-- ── #41 AB InBev · Global MBA Program ───────────────────────────────────────
-- URL/visa/window: ab-inbev.com careers (HIGH). Placement: Excel.
-- NOTE: corrects visa → false (AB InBev states it does not sponsor work visas;
-- applicants need the right to work in the country of application).
UPDATE programs SET
  url = 'https://www.anheuser-busch.com/global-mba-program',
  geo = 'global',
  location = 'Global (Belgium · Brazil · USA · LatAm)',
  locations = ARRAY['Belgium','United States','Brazil','Peru'],
  visa = false,
  status = 'rolling',
  dlnote = 'Early-careers applications generally open Sep–May (region-dependent); some close early once filled. AB InBev does not sponsor work visas.',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$Global MBA / management-trainee leadership track at the world's largest brewer, geared to fast progression into general-management and commercial/finance leadership. Selection typically runs over ~3 months: an HR group round, an HR interview, and a final panel with company VPs. AB InBev requires the right to work in the country of application (no visa sponsorship). ESADE alumni placement: Lima (Finance).$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 41;

-- ── #211 World Bank Group · Young Professionals Program (YPP) ────────────────
-- URL/deadline/eligibility/visa: worldbank.org (HIGH). Interview/placement: Excel.
UPDATE programs SET
  url = 'https://www.worldbank.org/ext/en/careers/talent-programs/young-professionals-program',
  geo = 'us',
  location = 'Washington, DC, USA · Global offices',
  locations = ARRAY['United States'],
  visa = true,
  status = 'watch',
  deadline = DATE '2026-09-30',
  dlnote = 'Application window 1–30 September annually (closes 30 Sep, 23:59 UTC); cohort starts 1 Sep the following year. G-4 visa sponsored for international staff.',
  language_required = ARRAY['English'],
  work_experience = '2–6 years relevant professional experience',
  eligibility = 'Master''s (or higher) completed before 1 Sep of start year; nationality of a World Bank Group member country; fluent English. Not open to current WBG staff.',
  target_degree = 'Master''s / MBA / PhD',
  description = $md$Young Professionals Program — the World Bank Group's flagship leadership entry route into operations, strategy and finance, leading to a staff appointment. Interviews and assessments run Dec–Jan; panels (two interviewers) are CV walk-throughs plus situational/strengths questions ("how would others describe you", "how would you solve situation X", "why the World Bank"). ESADE alumni placement: Washington, DC (Business/Strategy & Finance).$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 211;

-- Confirm 10 rows updated, then COMMIT (or ROLLBACK to abort):
-- SELECT id, company, url, geo, visa, deadline, dlnote FROM programs
--   WHERE id IN (1,7,8,17,19,21,33,34,41,211) ORDER BY id;

COMMIT;
