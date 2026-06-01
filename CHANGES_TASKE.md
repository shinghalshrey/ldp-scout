# Task E — Multi-level geography filter (continent → country)

## What changed
The old single-value geography filter (the coarse `geo` column with three hard-coded pills:
All / Europe / UAE / Global) has been **replaced** with a two-level, data-driven picker built
from the programs' new `continents text[]` and `countries text[]` columns.

## Data loading (`app.js`)
- **SELECT** in `fetchProgramsFromSupabase()` now also pulls `continents, countries`.
- The program mapping (~line 484) now carries:
  ```js
  continents: Array.isArray(row.continents) ? row.continents : [],
  countries:  Array.isArray(row.countries)  ? row.countries  : [],
  ```
  The `geo` column is still read for legacy display (table/alumni cells) but is **no longer
  used for filtering**. The fallback `data.js` array has neither array column, so the filter
  simply doesn't appear in offline/fallback mode — by design.

## The filter — two levels
**Continent level** (top pills, always visible):
- One pill per continent that has ≥1 program, in canonical order: Europe, North America,
  Asia, Middle East, Global, South America, Africa, Oceania (unknown continents appended
  alphabetically). Plus an "All" pill.
- **Multi-select.** A program shows if **any** of its `continents[]` overlaps the selection,
  **or** the program is `Global` (global programs surface under *every* continent).

**Country level** (indented sub-row, conditional):
- Appears **only when exactly one continent is selected**. With 0 or 2+ continents selected
  the country row is hidden (too many / ambiguous), and any country selection is cleared.
- One pill per distinct country among the programs in that continent. **Multi-select.**
  A program shows if **any** of its `countries[]` overlaps the selection.

**Combined logic** (`_geoPass(p)`, used by both the catalog list and user-added rows):
1. No continent selected → geography doesn't filter (show all).
2. Continent(s) selected → `p.continents` must overlap the selection **OR** include `Global`.
3. Country(ies) selected → `p.countries` must overlap (**AND** with the continent filter).

## Count badges
Each pill shows a count, e.g. **Europe (89)**. The count is "how many programs you'd see if
this were the only thing selected":
- Continent pill count = programs matching that continent **including** global programs
  (because globals show under it). The **Global** pill counts only true global programs.
- Country pill count = programs in the current continent whose `countries[]` include it.

## UI / styling
- Lives in the existing **Geography** sidebar section (`index.html`), now just two containers:
  `#geo-continent-pills` and `#geo-country-pills`, populated by `renderGeoFilter()`.
- Pills reuse the existing `.fpill` look (consistent with Function/Sector). Added
  `styles.css`: `.fpill-count` (muted count), `.geo-country-row` (indented, left-border
  sub-row), `.geo-country-label`, and a slightly smaller `.fpill-country`.

## Plumbing updated
- New filter state: `F.geo` (Set) → **`F.continents`** + **`F.countries`** (Sets).
- `clearAll()`, `_persistFilterState()` / `_restoreFilterState()` (localStorage), the
  "any filter active" check, and the sidebar active-count badge all updated to the two new
  Sets. Selection now persists across tab switches and reloads like the other filters.
- `renderGeoFilter()` is called from `renderPrograms()` so counts and active states stay live;
  `toggleContinent(btn)` / `toggleCountry(btn)` update state, persist, and re-render.
- Removed the old `geo` pill markup and its `setF('geo', …)` wiring / `'geo'` entries in the
  `_syncFilterPills` loops. The old `({europe,uae,global})` label map used for *display* of
  the legacy `geo` field on cards is left untouched (display only, not the filter).

## Diagnostics
`renderGeoFilter()` logs once per dataset load (guarded by a signature so it doesn't spam on
every re-render):
```js
console.log('[TaskE] geo filter — continents:', <distinct continents>, 'countries:', <distinct countries>);
```

## Verification
- `node --check app.js` passes.
- The geography predicates are pure and were unit-checked offline:
  - Global programs appear under every continent; selecting **Global** shows only globals.
  - Multi-continent selection unions correctly (overlap).
  - Country filter is AND-ed with continent; a global program with no matching country is
    correctly excluded once a country is selected.
  - Counts match the visible result per pill.
- A live browser run can't exercise this until the new `continents`/`countries` columns are
  populated in Supabase (explicitly out of scope here); with empty arrays the filter hides
  itself gracefully.

## Out of scope (untouched)
No Supabase data changes; the `geo` column itself is not modified. This is frontend-only —
reading the new arrays and filtering on them.

---

# Task E2 — Country pills now only show countries in the selected continent

## Bug
Multi-continent programs carry countries from several regions (e.g. a program tagged
`continents: ['Europe','Asia']`, `countries: ['UK','India','Hong Kong']`). The country
drill-down collected countries from *every* program that matched the continent — including
those multi-region programs and Global programs — so selecting **Europe** showed out-of-region
pills like Argentina, Brazil, Canada and Hong Kong.

## Fix (`app.js`)
- Added a `COUNTRY_TO_CONTINENT` constant (next to `CONTINENT_ORDER`) mapping each known
  country to its continent.
- In `renderGeoFilter()`, the country drill-down now:
  1. Collects candidate countries only from programs that **explicitly** list the selected
     continent in `continents[]` (Global programs are excluded from the drill-down).
  2. Keeps only countries where `COUNTRY_TO_CONTINENT[country] === selectedContinent`.
     Countries absent from the map are not shown (they can't be placed in a continent).
- Each country pill's count = programs that have the selected continent in `continents[]`
  **AND** the country in `countries[]`, so every shown pill has ≥1 program.

## Diagnostics
```js
console.log('[TaskE2] country pills for', selectedContinent, ':', visibleCountries.length, 'countries shown');
```

## Verification
`node --check` passes. Offline check with a multi-continent program
(`['Europe','Asia']` → `['UK','India','Hong Kong']`) confirms:
- **Europe** → Germany, Spain, UK only (India/Hong Kong correctly excluded).
- **Asia** → India, Hong Kong.
- **North America** → Canada (a Global-only `USA` is excluded).
- Counts correct in every case.
