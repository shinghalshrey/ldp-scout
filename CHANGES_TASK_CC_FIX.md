# Task CC-FIX — Command Center stat cards

Make the Command Center stat cards clickable, clarify the "Networking" card, and add a
"Contacts" card so adding a contact has a visible counter.

**Files touched:** `app.js`, `styles.css`
**Not touched:** `index.html`, `scan.js`, `data.js`
**Verification:** `node --check app.js` → passes. Real `_renderCCStats()` source run against
stub inputs → 5 cards, correct labels, correct `showPage()` targets, diagnostic log fires.

---

## app.js — `_renderCCStats()` (lines 6454–6488)

| # | Change | Detail |
|---|--------|--------|
| 1 | Cards clickable | Added `onclick="showPage(...)"` + `cursor:pointer` to all cards: Total Active → `applications`, Networking Stage → `networking`, Applied → `applications`, Offers → `applications`. |
| 2 | Networking card reworded | Label `Networking` → `Networking Stage`; sub `Outreach in progress` → `Apps in pipeline`. |
| 3 | New 5th card | After Offers: `${contacts.length}` · "Contacts" · "People tracked" · `--c:var(--purple)` · `onclick="showPage('networking')"`. |
| 4 | Diagnostic log | First line of the function: `console.log('[CC-STAT] apps:', apps.length, 'contacts:', contacts.length);` |

Function grew from **29 → 35 lines** (+6: 1 log line + 5-line Contacts card). Four card
lines edited in place for onclick/cursor; two lines reworded (label + sub).

## styles.css

| Line | Change | Lines |
|------|--------|-------|
| 2255 | `.cc-stat-row` grid `repeat(4, 1fr)` → `repeat(5, 1fr)` | 1 modified |
| 2265 | `.cc-stat-card` — added `cursor: pointer;` | 1 added |
| 2269 | `.cc-stat-card:hover` — `translateY(-1px)` → `translateY(-2px)` | 1 modified |

Net styles.css: **+1 line** (2 modified in place).

---

## Deviations from the literal task spec (intentional, to avoid regressions)

These three items were already present in the codebase. Re-adding them verbatim would have
created duplicate/conflicting rules or overwritten an established value, so the existing
code was reused/edited in place to honor the *intent* and *exact values* requested:

1. **`--purple` already defined** (`styles.css:10`, `#5a3a9a`, with a matching `--purple-bg`
   in the coordinated muted palette). The task said define `#7C3AED` *"if not present"* — it
   is present, so the variable was left untouched and the card uses `var(--purple)`. Forcing
   the brighter `#7C3AED` would clash with the palette and affect other `--purple` consumers.
2. **`.cc-stat-card` / `.cc-stat-card:hover` already existed** with a richer
   `transition: transform .15s ease, box-shadow .15s ease` and a hover box-shadow. Instead of
   appending duplicate selectors, `cursor: pointer` was added to the existing rule and the
   hover lift was bumped to the requested `-2px` in place (keeping the box-shadow).
3. **Mobile breakpoint already existed** — `styles.css:2413` already has
   `@media (max-width: 900px) { .cc-stat-row { grid-template-columns: repeat(2, 1fr); } }`,
   exactly as requested. No duplicate block was added.

`cursor:pointer` is set both inline (per CHANGE 1) and in the `.cc-stat-card` CSS rule;
this is redundant but harmless and satisfies both literal requirements.

## Verification evidence

```
$ node --check app.js          → SYNTAX_OK

Real _renderCCStats() source vs. stub inputs (apps=5, contacts=3):
  DIAGNOSTIC_LOG = "[CC-STAT] apps: 5 contacts: 3"
  CARD_COUNT     = 5
  CURSOR_POINTER = 5
  LABELS         = ["Total Active","Networking Stage","Applied","Offers","Contacts"]
  ONCLICKS       = [applications, networking, applications, applications, networking]
  CONTACTS_NUM   = shows 3 (contacts.length)
```

`showPage('applications')` and `showPage('networking')` are both valid page IDs
(dispatch table at `app.js:2855–2856`; `#page-applications` / `#page-networking` exist),
so each card navigates to the correct page.

> Note: the Command Center renders only for a signed-in user (`showPage` gates on
> `currentUser`; `renderCommandCenter` has a first-run gate), so a static browser preview
> without Supabase credentials can't reach the cards. Verification therefore runs the real
> function source directly rather than through the auth-gated UI.
