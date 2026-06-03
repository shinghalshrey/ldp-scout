# Task PERF2 — Self-added program fixes + Command Center readability

Six fixes around user-added programs and the Command Center. All in `app.js` and
`styles.css` (no `index.html`, no DB schema change).

## 1. Self-added program name was a blue link
A user-added program with a URL rendered its name as a default browser hyperlink
(blue + underline), unlike catalog rows. **Fix:** `_userAddedRowHTML()` and
`_userAddedCardHTML()` now use the same inline style as catalog rows — dark text with
a subtle bottom border that turns accent-green on hover.

## 2. Stage is now togglable for self-added programs
The self-added row showed a static "Applied" badge; catalog rows have a stage
dropdown. **Fix:** the row/card now render the same `stage-dd` dropdown via a new
`_userAddedStageDropdown()`. `toggleStageDropdown()` and `setProgramStage()` were
generalized to accept the synthetic `ua-<appId>` id and operate directly on the
underlying application (change stage, or "Remove from pipeline"). Catalog behavior is
unchanged (numeric ids still take the original path).

## 3. Geography of self-added programs now reads in the Programs filter
The geo filter matches on structured `continents[]` / `countries[]`, which user-added
rows didn't have — so filtering by Europe/Spain hid them. **Fix:** new `_deriveGeo()`
turns the free-text geography ("Barcelona, Europe") into canonical
`{ continents:['Europe'], countries:['Spain'] }`, reusing the catalog's
`COUNTRY_TO_CONTINENT` map plus a new `CITY_TO_COUNTRY` map of common MBA-hub cities
(Barcelona→Spain, London→UK, etc.). `_userAddedRows()` now attaches those arrays, so
the program appears under both the **Europe** and **Spain** filters.

## 4. Command Center "Where you're aiming" — geography
Previously a single program split into confusing rows ("Barcelona 1", "Europe 1").
**Fix:** geography is now resolved to clean continent + country via the new
`_appGeoLabels()` — catalog-linked apps borrow the program's structured continents
(+ a short country list); user-added apps use `_deriveGeo()`. A Barcelona program now
reads as **Europe + Spain** (never a bare city), and each program counts once per
label.

## 5. Sector / Function were undercounted in "Where you're aiming"
Catalog programs added to the pipeline didn't store `sector`/`fn` on the application
row, so they were invisible to the tally (e.g. two Tech/Strategy programs showed
"Tech 1"). **Fix:** (a) `addProgramToApplications()` now stores `sector`/`fn`; and
(b) `_ccTally()` falls back to the linked catalog program's value when the app row has
none — so existing rows are fixed too, without a re-save. Counts are now grouped
case-insensitively ("Tech"/"tech" merge). The two Tech/Strategy programs now read
**Tech 2 / Strategy 2**.

## 6. Pipeline funnel redesigned
The single stacked segmented bar was hard to read. **Fix:** `_renderCCFunnel()` now
renders one labelled horizontal bar per stage (same visual language as "Where you're
aiming"): colour dot + stage name, a proportional fill scaled to the busiest stage,
and the count on the right. New `.cc-funnel-row*` CSS; the old `.cc-funnel-seg` /
legend markup is retired (legend cleared).

## Verification
- `node --check app.js` → **PASS**.
- Loaded via the `ldp-static` preview: landing renders, **zero console errors**.
- Unit-tested `_deriveGeo` / `_appGeoLabels` / `_ccTally` against the current pipeline
  data: `_deriveGeo("Barcelona, Europe")` → Europe + Spain; geo tally → Europe 1 /
  Spain 1 / North America 1 / USA 1; sector → Tech 2; function → Strategy 2.

### Not exercised (auth-gated)
Sign-in needs an emailed OTP, so the signed-in surfaces weren't driven end-to-end.
Recommended manual pass after pulling:
1. Programs page: the self-added program's name is dark (not blue); its Stage is a
   working dropdown (change stage + Remove).
2. Filter geography by Europe, then Spain — the self-added program appears in both.
3. Command Center: funnel shows readable per-stage bars; "Where you're aiming" shows
   Europe + Spain (no "Barcelona"), and Sector/Function counts include catalog-added
   programs.
