# CHANGES — Alumni Finder LinkedIn link QC

**Date:** 2026-06-05
**File touched:** `app.js` only (53 insertions, 7 deletions — net +46 lines)
**Not touched:** `index.html`, `styles.css`, `scan.js`, `data.js`

Audited and fixed every Alumni Finder LinkedIn school link, fixed the known-bad
slugs, and added a mobile-friendly "copy search text" button so the searches still
work when LinkedIn's mobile app strips the `?keywords=` filter from deep links.

---

## Part 1 — Boot-time slug audit (~17 lines)

Added a one-time diagnostic right after the `ALL_MBA_SCHOOLS` array (and its derived
`SCHOOL_LABELS` / `SCHOOL_LI_IDS` maps). On every page load it prints each school's
`/school/{slug}/people/` URL to the console so a bad or missing slug is obvious at a
glance, then a summary line.

Verified live in the browser console:

```
[AlumniQC] School LinkedIn slug audit:
  ✓ ESADE Business School → https://www.linkedin.com/school/esade/people/
  … (one line per school) …
  ✗ Other / Not listed → NO SLUG (alumni search will use broad fallback)
[AlumniQC] 37 schools with slugs, 1 without
```

(38 entries total: 37 with slugs + the "Other / Not listed" catch-all with no slug.)

## Part 2 — Slug fixes (5 corrected)

Every slug was verified against the live LinkedIn school page on 2026-06-05. Five were
wrong; each fixed entry carries an inline `// fixed:` comment explaining why.

| Key | School | Old slug (broken) | New slug (verified) | Reason |
|-----|--------|-------------------|---------------------|--------|
| `oxford` | Oxford Saïd Business School | `said-business-school` | `oxfordsbs` | Old slug was not the Oxford page; the real school page is `/school/oxfordsbs/people` |
| `imperial` | Imperial College Business School | `imperial-college-business-school` | `imperial-business-school` | School rebranded to "Imperial Business School" (effective Apr 2025); the current-brand slug has a live alumni `/people` directory |
| `cranfield` | Cranfield School of Management | `cranfield-school-of-management` | `cranfieldschoolofmanagement` | LinkedIn slug has no hyphens |
| `rsm` | Rotterdam School of Management (RSM) | `rotterdam-school-of-management` | `rotterdam-school-of-management-erasmus-university` | Canonical page includes `-erasmus-university` (~84k followers) |
| `escp` | ESCP Business School | `escp-europe` | `escp-business-school` | Rebranded from "ESCP Europe" (2020); old name slug is outdated |

**Verified correct — no change (12):** ESADE (`esade`), HEC Paris (`hec-paris`),
INSEAD (`insead`), London Business School (`london-business-school`),
IESE (`iese-business-school`), IE (`ie-business-school`),
Cambridge Judge (`cambridge-judge-business-school`),
SDA Bocconi (`sda-bocconi-school-of-management`),
Warwick (`warwick-business-school`),
WHU (`whu-otto-beisheim-school-of-management`),
St. Gallen (`university-of-st-gallen`), IMD (`imd-business-school`).

### Note on Imperial (the "reportedly doesn't work" report)

Both `imperial-college-business-school` (old) and `imperial-business-school` (new)
currently resolve and both have a `/people` alumni directory, so the old slug is not a
hard 404. The school rebranded to **"Imperial Business School"** with changes effective
April 2025, so `imperial-business-school` is the durable, current-brand slug and is the
one this app now uses — consistent with the project's no-404 / prefer-durable-landing-page
principle. The rebrand is also the most likely cause of the "doesn't work" report (an
old-name slug being consolidated mid-transition). The full context is in the inline
comment so it can be revisited if LinkedIn changes again.

## Part 3 — Mobile "copy search" buttons (~20 lines)

On mobile, the LinkedIn app strips `?keywords=` from `/school/` links, so the chip lands
on the school page without the company filter. Fix: a small 📋 button after each of the
two search chips that copies the plain search text to the clipboard, so the user can
paste it straight into LinkedIn's own search box.

- **Search A** (school → company chip): copies `"{schoolLabel} {company} alumni LinkedIn"` — e.g. `ESADE Business School Amazon alumni LinkedIn`.
- **Search B** (company → school chip): copies `"{company} {schoolShort}"` — e.g. `Amazon ESADE`.
- Buttons use `class="al-copy-btn"` + an inline `display:none` so they are **hidden on desktop**.
- A one-time `<style id="al-copy-style">` is injected at the top of `renderAlumniSearch()` with `@media (max-width:768px){ .al-copy-btn{ display:inline-block !important } }`, so they **appear on mobile** (`styles.css` was off-limits, so the rule is injected via `<style>` as instructed).
- **Escaping:** the copy text sits inside a single-quoted JS string inside a double-quoted `onclick`, so a tiny helper escapes both layers (HTML entities for `& " < >`, JS-string escaping for `\` and `'`). It deliberately does **not** use `&#39;` for apostrophes — the HTML parser would decode that back to `'` and break the string for orgs like **Moody's** or **L'Oréal**. (Verified: clicking the L'Oréal button copies the exact text and fires the toast, no syntax error.)
- The broad fallback chip ("Anyone at {org}", shown only when no school is selected) was intentionally left without a copy button — the spec defines copy text only for Search A and Search B, and there's no school-filtered query to copy in that state.

## Part 4 — Render diagnostic (3 lines)

After the cards render, `renderAlumniSearch()` logs:

```
[AlumniQC] rendered 428 cards, school: esade slug: esade
```

(`slug` shows `NONE` when no school is selected.)

---

## Verification (run in the live preview)

- ✅ `node --check app.js` passes.
- ✅ Boot console shows the full slug audit + `37 schools with slugs, 1 without`.
- ✅ In-memory slugs confirmed: imperial→`imperial-business-school`, oxford→`oxfordsbs`, cranfield→`cranfieldschoolofmanagement`, rsm→`rotterdam-school-of-management-erasmus-university`, escp→`escp-business-school`.
- ✅ 856 chips ↔ 856 copy buttons rendered (exactly one button per chip).
- ✅ Desktop (1280px): copy buttons computed `display:none` (hidden).
- ✅ Mobile (375px): copy buttons computed `display:block`, `offsetParent` set, ~31×26px (visible).
- ✅ Click → clipboard receives the exact text (incl. the L'Oréal apostrophe case) and the toast `"✓ Copied — paste into LinkedIn search"` shows.
- ✅ LinkedIn URL pattern unchanged: `/school/{slug}/people/?keywords=…` (e.g. `/school/esade/people/?keywords=Amazon`).
- ✅ No console errors.

## Out of scope (left untouched, as required)

- The `/school/{slug}/people/?keywords=` URL pattern — unchanged.
- Alumni Finder layout / card design — unchanged (buttons sit inline in the existing chip row).
- `styles.css` — not edited; the copy-button styling is inline + an injected `<style>`.
- No existing functionality removed.
