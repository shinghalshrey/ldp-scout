# Task 21.1 — Mobile card view for Programs page

## What changed and why

The Programs page on mobile was broken — column headers crushed together and overlapping rows. The 9-column CSS-table layout was never going to fit on 390px phones; horizontal scroll with sticky-column was a workaround, not a fix.

This rebuilds the mobile experience as a stacked card list. iPad and larger keep the desktop table; phones (<=720px) get cards.

## What you get

**Each mobile card shows:**
- Logo placeholder (initials of company name) + program name + company
- Status pill (Open / Rolling / Watch) when applicable
- Location + deadline line with icons
- AI Fit tier badge (Best/Strong/Achievable/Long Shot/Watch) — only when the user has scanned their résumé
- Function, sector, language (if specified), visa (if sponsored) chips
- Verified badge (same green/amber/grey rules as desktop)
- Two action buttons at the bottom: full-width Stage dropdown (`+ Add to pipeline` or current stage), plus a 📅 calendar reminder icon

**Reminder flow:**
- Tap 📅 → existing ICS modal opens with the same two choices as before:
  - **Multiple Reminders** — 30 days, 7 days, 1 day before deadline
  - **One Reminder** — 7 days before deadline
- Reuses the existing `openICSModal()` and `downloadICS(item, mode)` flow — no new code paths.
- Reminder icon **only renders on programs with a fixed deadline date**. Rolling/no-deadline programs (~40 of 422) hide the icon entirely.

**Pagination:**
- Loads 50 cards at first paint
- "Load more (N remaining)" button at the bottom to expand by 50 more
- Counter line above cards: "422 programs · 50 shown"
- Pagination state resets automatically when filters/sort change

**AI Fit hydration on mobile (the bug you flagged):**
- Same fix as desktop. `hydrateAITierFromHistory()` runs in `onSignIn()` before the first `renderPrograms()`. The mobile render function reads `p.aiTier` from the same `progs[]` array, so AI Fit results show on the Programs page immediately on sign-in — no need to visit AI Fit Scan first.

## Files modified

| File | What changed | Lines added |
|------|--------------|-------------|
| `app.js` | Removed dead `prog-cards` block. Added 8 mobile helper functions and the render call hook at the end of `renderPrograms()`. Reuses existing `openICSModal()`, `renderStageDropdown()`, and `verifiedBadge()`. | ~130 |
| `styles.css` | Removed the horizontal-scroll table fallback. Added `@media (max-width: 720px)` block with full card styling, AI Fit tier colors, status pill variants, and pagination button. iPad (>720px) keeps the desktop table layout. | ~170 |
| `index.html` | Added `<div id="prog-mobile-list">` as a sibling to `.prog-table-wrap`. Hidden by default; CSS swaps visibility at 720px. | 1 |

## Breakpoints

- **>720px** (laptop, iPad): full desktop table layout, mobile card list hidden
- **<=720px** (phone): table hidden, card list shown, 5-column stat row collapses to 2-per-line, sidebar stacks above content
- **<=480px** (small phone): tighter padding, smaller card titles

## Deploy

```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
# Copy app.js, styles.css, index.html from /mnt/user-data/outputs/ over the existing files

git status
git diff --stat
git add app.js styles.css index.html
git commit -m "task 21.1: mobile card view for Programs page + reminder flow"
git push
```

## Smoke test (mobile, ~5 min)

Open ldpscout.com in Chrome DevTools at 390px width (iPhone 13) or a real phone.

1. **Sign in** → Programs page renders as cards, not the broken table.
2. **Counter line** at top reads "422 programs · 50 shown".
3. **Scroll** — should be smooth, no horizontal overflow.
4. **Verified badges** — green "Verified May 2026" on the 50 verified programs, amber "Cycle paused" on Nike EHQ / Admiral / Estée Lauder / etc.
5. **Tap a Verified program** with a URL (e.g., "Microsoft Aspire Experience") — opens careers page in new tab.
6. **Tap an unclickable program** (e.g., "Werfen") — name is plain text, no link.
7. **Tap "+ Add to pipeline"** on any card → existing Stage dropdown panel opens. Pick "Shortlisted" → card shows current stage.
8. **Tap 📅** on a program with a deadline (e.g., "Microsoft Aspire" 1 Oct) → existing two-choice modal opens. Pick "Multiple Reminders" → .ics file downloads.
9. **Verify no 📅 button** on rolling-deadline programs (e.g., Amazon Pathways).
10. **AI Fit hydration**: Run an AI Fit scan from the AI Fit page. Sign out. Sign back in. Land on Programs (or navigate to it). Cards should show tier badges (✦ Best Fit, ✦ Strong, etc.) immediately, no need to visit AI Fit first.
11. **Load more** — scroll to bottom of 50 cards, tap "Load more (372 remaining)". Next 50 cards append.
12. **Filter** — apply any sidebar filter (e.g. "Visa-sponsoring only"). Counter and card list update. Pagination resets to 50.
13. **Sort** — change sort order. Cards re-order. Pagination resets.

## Known follow-ups (post-Monday)

1. iOS Safari ICS handling — downloads to Files app, manual import. Workable but not great. A `webcal://` deep-link option would be cleaner; needs hosting the ICS file at a real URL rather than data URL.
2. Stage dropdown panel on phone — currently anchored absolutely. The CSS rule constrains it to viewport edges, but a true bottom-sheet UI would feel more native.
3. Card logo — currently shows initials. Future: real company logo from a service like clearbit.
