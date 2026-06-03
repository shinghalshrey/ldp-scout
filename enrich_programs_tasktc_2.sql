-- ============================================================================
-- Task TC (data) — Catalog enrichment, verified batch #2 (20 flagship LDPs)
-- ============================================================================
-- Continuation of enrich_programs_tasktc.sql (batch #1, ids 1,7,8,17,19,21,33,
-- 34,41,211 — already applied). This batch covers the remaining 20 candidates
-- named in CHANGES_TASKTC_DATA.md.
--
-- Source data:
--   • Geography, hiring window (interview months), language, and selection-
--     process detail → ESADE "Interview Reports" spreadsheet (real student
--     submissions, 2023–2025 cycles). HIGH confidence — primary data.
--   • URL, program structure, eligibility, visa sponsorship, deadline window →
--     public web research, June 2026 (official careers pages cited per row).
--     Confidence noted inline; unverifiable fields are LEFT UNTOUCHED, not guessed.
--
-- Each UPDATE only SETs columns we have good data for, so existing values for
-- untouched columns are preserved. Keyed by programs.id. Wrapped in a single
-- transaction — review the SELECT below, then COMMIT (or ROLLBACK to abort).
--
-- ⚠ Two data notes worth reading before you run:
--   • #236 "Oliver Wyman FLDP" is in fact the Marsh McLennan (parent group)
--     FINANCE Leadership Development Program in New York — NOT an Oliver Wyman
--     *consulting* role. It is enriched as the finance program. The separate
--     ESADE consulting-interview data (Madrid/Dubai/Milan case interviews) is
--     noted in its dlnote but not grafted onto the JD.
--   • #38 BASF MBA LDP: the well-documented flagship runs in the U.S. (Florham
--     Park, NJ; no visa sponsorship), but this catalog row is tagged Europe/
--     Ludwigshafen, so geo/visa are LEFT UNTOUCHED and the U.S.-cohort caveat is
--     captured in dlnote. The two explicitly U.S. BASF MBA rows (#336, #348) do
--     get visa = false.
--
-- ⚠ Review before running. Take a snapshot first:
--     CREATE TABLE programs_backup_tasktc2 AS SELECT * FROM programs
--       WHERE id IN (15,16,38,70,86,114,127,137,142,146,158,174,181,236,291,316,336,348,350,359);
-- ============================================================================

BEGIN;

-- Sanity check — see the rows you're about to change:
-- SELECT id, company, program_name, url, geo, visa FROM programs
--   WHERE id IN (15,16,38,70,86,114,127,137,142,146,158,174,181,236,291,316,336,348,350,359) ORDER BY id;

-- ── #15 Siemens · XPS Leadership Program ────────────────────────────────────
-- URL/structure/visa: siemens.com (HIGH). Placement/interview: Excel.
UPDATE programs SET
  url = 'https://www.siemens.com/global/en/company/jobs/growth-careers/siemens-xps-leadership-program.html',
  geo = 'global',
  location = 'Munich, Germany · Global',
  locations = ARRAY['Germany'],
  visa = true,
  status = 'rolling',
  dlnote = 'No fixed deadline — CV + cover letter accepted year-round (2025/26 cohort recruiting). Siemens organises the visa/work permit for the country of placement.',
  language_required = ARRAY['English'],
  target_degree = 'Master''s / MBA',
  description = $md$XPS Leadership Program — a two-year global development track that immerses tech-and-business talent in a full-time, non-rotational "direct-entry-plus" transformation role while accelerating leadership through structured training, mentorship and international exposure. Siemens looks for globally minded leaders with strong academic and digital business backgrounds. Interviews are background-led — about yourself, your experience and your knowledge of the company. ESADE alumni report Siemens placements in Bavaria, Germany.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 15;

-- ── #16 Siemens · Finance Excellence Program (FEP) ──────────────────────────
-- URL/structure/visa: siemens.com (HIGH). Placement/window/interview: Excel (HIGH).
UPDATE programs SET
  url = 'https://www.siemens.com/global/en/company/jobs/growth-careers/finance-excellence-program.html',
  geo = 'europe',
  location = 'Munich, Germany · Global',
  locations = ARRAY['Germany'],
  visa = true,
  status = 'rolling',
  dlnote = 'No set deadline — applications accepted throughout the year. ESADE interviews observed Apr. Siemens organises the visa/work permit.',
  language_required = ARRAY['English'],
  target_degree = 'Master''s / MBA',
  description = $md$Finance Excellence Program — Siemens' finance-leadership accelerator built to develop "the CFOs of tomorrow," rotating ambitious finance talent across finance functions and locations with strong mentorship and international exposure. Interviews are background- and experience-led (about yourself and your knowledge of the company). ESADE alumni placement: Bavaria, Germany (Finance Excellence Program).$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 16;

-- ── #38 BASF · MBA Leadership Development Program (LDP) ──────────────────────
-- URL/structure/eligibility: basf.com (HIGH). geo/visa LEFT UNTOUCHED — see header note.
UPDATE programs SET
  url = 'https://www.basf.com/us/en/careers/grow-at-basf/development-programs',
  status = 'rolling',
  dlnote = 'Flagship MBA LDP runs in the U.S. (Florham Park, NJ) as three eight-month rotations over two years and requires permanent U.S. work authorisation (no sponsorship); 2026-cohort graduation window May 2022–Jul 2026. BASF also runs European graduate/trainee tracks.',
  language_required = ARRAY['English'],
  work_experience = '3–10 years professional experience',
  target_degree = 'MBA',
  description = $md$Two-year cross-functional MBA Leadership Development Program embedding participants in dynamic commercial teams through a rotational structure (commonly three eight-month rotations) with hands-on, high-impact projects, on a path into general management. Targets recent or current MBAs with 3–10 years' experience and an undergraduate business/technical background. ESADE alumni report BASF roles in Barcelona (Commercial & Digital Excellence); interviews cover studies, experience, fit and what you would contribute.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 38;

-- ── #336 BASF · Diverse Leaders Program (MBA) ───────────────────────────────
-- URL/eligibility/visa: basf.com (HIGH). U.S. MBA program → visa false.
UPDATE programs SET
  url = 'https://www.basf.com/us/en/careers/grow-at-basf/development-programs',
  geo = 'us',
  location = 'USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'U.S.-based MBA rotational track; requires permanent U.S. work authorisation without sponsorship. Includes commitment to relocate within the U.S.',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$BASF's MBA-level Diverse Leaders Program — a U.S. rotational leadership track that develops MBA talent across commercial functions toward general-management roles, in the same family as BASF's MBA Leadership Development Program (multiple eight-month rotations over ~two years).$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 336;

-- ── #348 BASF · Manufacturing Diverse Leaders Program (DLP) — MBA ────────────
-- URL/eligibility/visa: basf.com (HIGH). U.S. MBA program → visa false.
UPDATE programs SET
  url = 'https://www.basf.com/us/en/careers/grow-at-basf/development-programs',
  geo = 'us',
  location = 'USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'U.S.-based MBA program focused on manufacturing/operations leadership; requires permanent U.S. work authorisation without sponsorship; relocation within the U.S. expected.',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$BASF's Manufacturing Diverse Leaders Program (DLP) — the operations/manufacturing-focused MBA rotational leadership track, developing participants toward plant- and operations-leadership roles across BASF's U.S. production network through multiple rotations over ~two years.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 348;

-- ── #316 Henkel · PRISM / HRP — Leadership Rotational Program (Functions) ────
-- URL/structure/process: henkel-northamerica.com (HIGH). Placement: Excel.
UPDATE programs SET
  url = 'https://www.henkel-northamerica.com/careers/prism',
  geo = 'us',
  location = 'USA',
  locations = ARRAY['United States'],
  status = 'rolling',
  dlnote = 'Henkel has rebranded PRISM as the HRP (Henkel Rotational Program). 24-month North-America rotational program; the Functions track (Finance / Purchasing / IT) recruits on a rolling basis.',
  language_required = ARRAY['English'],
  target_degree = 'MBA / Master''s',
  description = $md$PRISM / Henkel Rotational Program (HRP) — a 24-month rotational leadership program letting early-career talent explore different businesses, divisions and functions with customised learning and a dedicated mentor. The Functions track spans Finance, Purchasing and IT. Selection: recruiter screening interview → competency interview with a Track Manager → panel interview with a presentation → (on-site round for technical tracks) → offer. ESADE alumni report Henkel roles in Barcelona (Laundry & Home Care marketing).$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 316;

-- ── #158 Nike · Marketing Vanguard Program (MVP) — Rotational Leadership Assoc.
-- URL/structure/eligibility: careers.nike.com (HIGH). Adjacent placement: Excel.
UPDATE programs SET
  url = 'https://careers.nike.com/',
  geo = 'us',
  location = 'Beaverton, OR, USA',
  locations = ARRAY['United States'],
  status = 'rolling',
  dlnote = 'Rotational Leadership Associate track for 2nd-year Master''s-in-Marketing / MBA candidates with 3–5 years'' experience. Based at Nike World HQ, Beaverton. Recruits in line with the MBA cycle.',
  language_required = ARRAY['English'],
  work_experience = '3–5 years professional experience',
  target_degree = 'MBA / Master''s in Marketing',
  description = $md$Marketing Vanguard Program (MVP), Rotational Leadership Associate — a two-year program building foundational marketing leadership through four rotations across Brand Marketing, Consumer Direct Marketing, Planning & Operations, and Brand Creative, with an extensive core curriculum, leadership mentorship and broad visibility into Nike's Worldwide Marketing organisation. For the MVP application includes a go-to-market strategy exercise. (Note: ESADE alumni also report adjacent Nike roles in Hilversum, NL — Marketplace Operations.)$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 158;

-- ── #137 Nike · Marketing Vanguard Program (MVP) — Graduate Internship ───────
-- URL/structure: careers.nike.com (HIGH). Feeder to the MVP rotational role.
UPDATE programs SET
  url = 'https://careers.nike.com/',
  geo = 'us',
  location = 'Beaverton, OR, USA',
  locations = ARRAY['United States'],
  status = 'rolling',
  dlnote = '10-week paid summer internship (relocation assistance) for MBA / Master''s-in-Marketing students graduating ~Dec 2027–Spring 2028; the feeder into the MVP Rotational Leadership Associate role.',
  language_required = ARRAY['English'],
  target_degree = 'MBA / Master''s in Marketing',
  description = $md$Marketing Vanguard Program (MVP) Graduate Internship — a 10-week paid summer internship at Nike World HQ that gives MBA/Master's-in-Marketing students on-the-job experience within Worldwide Marketing, leadership mentorship and a core curriculum, serving as the pipeline into the two-year MVP Rotational Leadership Associate program.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 137;

-- ── #127 Heineken · Global Graduate Programme (Global Leadership Development) ─
-- URL/structure/eligibility: theheinekencompany.com (HIGH). Placement/interview: Excel.
-- NOTE: "right to work in the country of your program is essential" → visa false.
UPDATE programs SET
  url = 'https://careers.theheinekencompany.com/content/IGP/',
  geo = 'global',
  location = 'Amsterdam, NL · Global (country of application)',
  locations = ARRAY['Netherlands'],
  visa = false,
  status = 'rolling',
  dlnote = 'Three-year accelerated programme; you apply to and start in the operating company of your country of application, so the right to work there is essential (no global sponsorship). Functions: Commerce, Supply Chain, Finance, Digital & Technology, Procurement, People. Max ~1 year post-graduation.',
  language_required = ARRAY['English'],
  target_degree = 'Bachelor''s / Master''s',
  description = $md$HEINEKEN Global Graduate Programme — a three-year accelerated international leadership track: you start in your home operating company, take a cross-functional assignment, then an international assignment abroad, and finish in a management position back home. Entry functions include Commerce (Sales/Marketing), Supply Chain, Finance, Digital & Technology, Procurement and People. Selection: CV + cover letter → situational online assessments → two interviews. Requires full global mobility and English. ESADE alumni placement: Amsterdam (Market Intelligence); interviews are fit-led (motivations, academic path, past experience, company knowledge).$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 127;

-- ── #181 Nestlé · Marketing Development Program (USA) ───────────────────────
-- URL/structure/visa: nestlejobs.com (HIGH). Selection-process colour: Excel.
-- NOTE: posting states "not eligible for Visa Sponsorship" → visa false.
UPDATE programs SET
  url = 'https://www.nestlejobs.com/early-careers',
  geo = 'us',
  location = 'Arlington, VA, USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'Nestlé USA Marketing Development Program (2026 cohort recruited via the Diversity Leadership Symposium). Not eligible for visa sponsorship. MBA marketing internships feed the program.',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$Marketing Development Program — Nestlé USA's accelerated marketing-leadership track that rotates participants across brand and cross-functional roles (exposure to functions beyond marketing) with structured mentorship, networking and coaching. ESADE alumni report Nestlé selection in Spain running an external screening interview → HR fit interview → a group assessment-centre case → final fit interview with the hiring manager.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 181;

-- ── #291 Cardinal Health · MBA Strategy Internship ──────────────────────────
-- URL/structure/visa: cardinalhealth.com (HIGH). Interview themes: Excel.
-- NOTE: "unlimited U.S. work authorisation without sponsorship" → visa false.
UPDATE programs SET
  url = 'https://www.cardinalhealth.com/en/careers/students-grads/mba-internships.html',
  geo = 'us',
  location = 'Dublin, OH, USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'Summer MBA internship for full-time MBAs between year 1 and year 2; a pipeline to full-time roles. Requires unlimited U.S. work authorisation (no sponsorship now or in future).',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$MBA Strategy Internship — a formalised summer program for full-time MBA students that deepens knowledge of Cardinal Health and the healthcare industry while building leadership skills on business-critical strategy projects, acting as a pipeline into full-time post-MBA roles (including Corporate Development / Strategy). Interview themes reported by ESADE alumni: trends within healthcare, demonstrated leadership, "why this company", and a résumé walk-through.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 291;

-- ── #350 Cardinal Health · MBA Marketing Internship ─────────────────────────
-- URL/structure/visa: cardinalhealth.com (HIGH).
UPDATE programs SET
  url = 'https://www.cardinalhealth.com/en/careers/students-grads/mba-internships.html',
  geo = 'us',
  location = 'Dublin, OH, USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'Summer MBA internship for full-time MBAs between year 1 and year 2; pipeline to full-time roles. Requires unlimited U.S. work authorisation (no sponsorship).',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$MBA Marketing Internship — a structured summer program for full-time MBA students working on meaningful marketing and commercial projects across Cardinal Health's healthcare businesses, with a formal mentoring program, planning-committee leadership exposure and broad networking; a pipeline into full-time post-MBA marketing roles.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 350;

-- ── #359 Cardinal Health · MBA Finance Internship ───────────────────────────
-- URL/structure/visa: cardinalhealth.com (HIGH).
UPDATE programs SET
  url = 'https://www.cardinalhealth.com/en/careers/students-grads/mba-internships.html',
  geo = 'us',
  location = 'Dublin, OH, USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'Summer MBA internship for full-time MBAs between year 1 and year 2; pipeline to full-time roles. Requires unlimited U.S. work authorisation (no sponsorship).',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$MBA Finance Internship — a structured summer program for full-time MBA students on the Strategic Finance team, building financial models and dashboards (Excel, SAP, Tableau) and contributing to business-critical finance projects across Cardinal Health, with formal mentoring and leadership exposure; a pipeline into full-time post-MBA finance roles.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 359;

-- ── #114 American Express · Campus Graduate — Strategy Internship ────────────
-- URL/eligibility/visa: americanexpress.com careers (HIGH). Interview detail: Excel.
-- NOTE: Amex states it will not pursue sponsorship for these roles → visa false.
UPDATE programs SET
  url = 'https://www.americanexpress.com/en-us/careers/student-programs/global-students-page.html',
  geo = 'us',
  location = 'New York / Phoenix / Sunrise, FL, USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'Campus Graduate summer internship for advanced business/management graduate students (e.g. MBA) graduating Dec 2025–Jun 2026 with 5+ years'' experience. Amex states it will not pursue visa sponsorship for these positions (may vary by role).',
  language_required = ARRAY['English'],
  work_experience = '5+ years professional experience',
  target_degree = 'MBA / advanced graduate degree',
  description = $md$Campus Graduate Strategy / Business-Strategy summer internship — high-impact strategic projects within American Express, the pipeline into full-time post-MBA strategy roles. Interviews reported by ESADE alumni (finance/strategy track): "why Amex / why you / why this role", how Amex earns revenue and where its expenses sit, a view on good leadership, 3–4 behavioural questions (Amazon STAR format), and a product-profitability case ("Amex is launching a new product — how would you assess its profitability and the strategic decision to launch?").$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 114;

-- ── #174 American Express · HR Leadership Development Program (HRLDP) ────────
-- URL/structure/visa: americanexpress.com careers (HIGH).
-- NOTE: Amex states it will not pursue sponsorship for these roles → visa false.
UPDATE programs SET
  url = 'https://www.americanexpress.com/en-us/careers/student-programs/global-students-page.html',
  geo = 'us',
  location = 'New York, NY, USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'Summer internship is the pipeline into the two-year full-time HRLDP. For HR-related master''s students. Amex states it will not pursue visa sponsorship for these positions (may vary by role).',
  language_required = ARRAY['English'],
  target_degree = 'HR-related Master''s',
  description = $md$Human Resources Leadership Development Program (HRLDP), within the Colleague Experience Group — a two-year program of three diverse, high-impact, personalised CEG rotations preparing participants for larger, more complex HR roles. The summer internship (for HR-related master's students — HRM, Org Psych, ILR, Human Capital) is the pipeline into the full-time HRLDP, with strong interns offered a return after graduation.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 174;

-- ── #142 Barclays · Investment Banking — Graduate Programme ─────────────────
-- URL/deadline/visa: search.jobs.barclays (HIGH). Adjacent placement: Excel.
UPDATE programs SET
  url = 'https://search.jobs.barclays/graduates-investment-banking',
  visa = true,
  status = 'open',
  dlnote = 'Banking/Markets graduate programmes typically open until late January, but most offers are made by December — apply early. UK/EU roles: Barclays sponsors the Skilled Worker visa and applies for work permits on the candidate''s behalf (subject to local immigration law).',
  language_required = ARRAY['English'],
  target_degree = 'Bachelor''s / Master''s / MBA',
  description = $md$Investment Banking Analyst Graduate Programme — Barclays' structured graduate route into Banking, open to any degree discipline with an interest in business and finance. UK/Europe roles offer full visa sponsorship. ESADE alumni report Barclays placements in Madrid (Global Markets, Equities), with selection conducted partly in Spanish and English.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 142;

-- ── #86 UBS · Graduate Talent Program — Technology (Business Analyst) ────────
-- URL/process/visa: ubs.com careers (HIGH). Placement: Excel.
UPDATE programs SET
  url = 'https://www.ubs.com/global/en/careers/early-careers/graduate-talent-program.html',
  geo = 'europe',
  location = 'Zurich, Switzerland',
  locations = ARRAY['Switzerland'],
  visa = true,
  status = 'rolling',
  dlnote = 'Applications accepted year-round; roles advertised ~4 weeks and may stay open until filled (rolling — apply early). Max 3 applications per academic year across UBS divisions. Online assessments due within 7 days of invitation. UBS readily sponsors work permits for non-EU/EFTA candidates.',
  language_required = ARRAY['English'],
  target_degree = 'Bachelor''s / Master''s',
  description = $md$Graduate Talent Program (Technology, Business Analyst) — UBS's structured graduate program for final-year undergraduates or recent graduates (within ~2 years, 2.1/CGPA equivalent), open to all majors with an interest in finance. Combines on-the-job experience with structured development at a Swiss-headquartered bank that sponsors work permits. ESADE alumni placement: Zurich (Business Management, Wealth Management — LATAM coverage).$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 86;

-- ── #70 SAP · Academy for Customer Success (Sales & Presales) ───────────────
-- URL/structure: jobs.sap.com (HIGH). Placement/interview: Excel.
UPDATE programs SET
  url = 'https://jobs.sap.com/content/SAP-Academy-Customer-Success/',
  geo = 'global',
  location = 'Local SAP office + classroom in Dublin, California',
  status = 'rolling',
  dlnote = 'Early-career program with two tracks: Sales (~8 months) and Presales (~12 months). Both blend classroom learning (incl. a block in Dublin, California) with on-the-job training and field mentoring. SAP generally sponsors work visas, though this varies by location.',
  language_required = ARRAY['English'],
  target_degree = 'Bachelor''s / Master''s / MBA',
  description = $md$SAP Academy for Customer Success — an early-career development program preparing graduates for a Sales or Presales career through experiential classroom learning married with on-the-job training. Sales Academy: ~8 months (orientation in the local office + ~3 months classroom in Dublin, California). Presales Academy: ~12 months, building a foundation via virtual classroom learning with full-time faculty plus field mentoring. ESADE alumni placement: Barcelona (Digital Demand Associate, Demand Generation); selection ran a recorded-video answer → fit interview → a technical interview showcasing Excel/analytical skills.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 70;

-- ── #146 SAP · Academy for People & Culture — HR Rotational Trainee ─────────
-- URL/structure: jobs.sap.com (HIGH).
UPDATE programs SET
  url = 'https://jobs.sap.com/content/SAP-Academy-People-Business-Transformation/',
  geo = 'global',
  status = 'rolling',
  dlnote = '20-month program for recent graduates / early-career professionals (up to ~3 years'' experience). Roles posted across global hubs (e.g. Newtown Square PA, Walldorf, Bangalore, São Leopoldo). SAP generally sponsors work visas, though this varies by location/role.',
  language_required = ARRAY['English'],
  target_degree = 'Bachelor''s / Master''s',
  description = $md$SAP Academy for People & Culture — a 20-month HR rotational trainee program for high-performing graduates with a passion for people and culture, giving hands-on experience across the full HR spectrum through four rotations: People & Culture Services, Employee & Labor Relations, Organizational Growth & Health, and People Growth & Leadership Excellence.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 146;

-- ── #236 (catalog: "Oliver Wyman") · Marsh McLennan FLDP — Summer Associate, NY
-- URL/structure/visa: oliverwyman.com / Marsh McLennan careers (HIGH).
-- NOTE: this is the Marsh McLennan group FINANCE LDP, not an OW consulting role.
-- The separate OW consulting interview data (Madrid/Dubai/Milan case interviews)
-- is captured in dlnote only — not merged into this finance JD.
UPDATE programs SET
  url = 'https://www.oliverwyman.com/careers/entry-level.html',
  geo = 'us',
  location = 'New York, NY, USA',
  locations = ARRAY['United States'],
  visa = false,
  status = 'rolling',
  dlnote = 'This is the Marsh McLennan (parent group) Finance Leadership Development Program, not an Oliver Wyman consulting role. 10-week NY summer program; requires permanent U.S. work authorisation (no sponsorship now or in future). Separately, ESADE alumni report OW *consulting* internships in Madrid, Dubai and Milan recruited via personal-fit + business-case interviews (multi-round: Associate → Manager/Partner → Senior Partner).',
  language_required = ARRAY['English'],
  target_degree = 'MBA',
  description = $md$Finance Leadership Development Program (FLDP), Summer Associate — Marsh McLennan's 10-week NY finance program giving post-MBA summer associates hands-on experience in one of its Finance groups (Controllership; FP&A; Global FP&A Transformation & Innovation; Global Business Services; Internal Audit; Investor Relations; Strategy & Corporate Development; Tax; Treasury). Strong performers may be offered a place on the full-time FLDP. Requires unrestricted U.S. work authorisation.$md$,
  last_verified = 'June 2026',
  last_verified_at = now()
WHERE id = 236;

-- Confirm 20 rows updated, then COMMIT (or ROLLBACK to abort):
-- SELECT id, company, url, geo, visa, status, dlnote FROM programs
--   WHERE id IN (15,16,38,70,86,114,127,137,142,146,158,174,181,236,291,316,336,348,350,359) ORDER BY id;

COMMIT;
