# CHANGES — Session 2026-05-27

All tasks delivered this session. Files changed per task noted below.

---

## Task 27B.2 — Modal fixes: catalog lock + visa field + filter fix + remove button

**Files:** `app.js`, `index.html`  
**DB migration required (already run):**
```sql
ALTER TABLE public.user_applications ADD COLUMN IF NOT EXISTS visa boolean DEFAULT NULL;
```

### What changed
1. **Function/Sector/Link/Visa locked for catalog programs.** When the modal opens for a catalog-linked program, these four fields are visually greyed and non-editable. A visible banner appears: *"🔒 Function, Sector, Link and Visa are set by the catalog and can't be edited here."* For user-added programs, all fields remain freely editable.
2. **Function label fixed.** Removed the "(for programs you add)" parenthetical — now just "Function" for all programs.
3. **Visa Sponsorship field added to modal.** Dropdown: Unknown / Yes / No. Read-only for catalog programs (pre-filled from catalog). Editable for user-added programs, persists to DB. Shows ✓ Visa chip on Programs page rows.
4. **Right-panel Sector/Function filters fixed for user-added programs.** Was case-sensitive exact match; changed to case-insensitive so "Industrial" typed by user matches `data-sector="industrial"` pill. Visa filter also now works for user-added programs (previously hid them all unconditionally).
5. **Delete button is now context-aware.** Shows "Remove from pipeline" for catalog-linked programs, "Delete" for user-added, hidden for new entries.

---

## Task 27B.2 Hotfix 1 — Catalog lock wasn't blocking input; visa chip missing; ✏️ edit button

**Files:** `app.js`, `index.html`

1. **Catalog lock made bulletproof.** Replaced `disabled` attribute (which broke `gv()` reads and didn't reliably block clicks) with `pointer-events:none` + `readonly` + `tabindex=-1` + `onfocus=blur`. Lock code extracted into `_applyModalCatalogLock(bool)` shared helper.
2. **Visa chip was never showing.** Duplicate `visa` key in `_userAddedRows()` object literal — `visa:false` on the inert-fields line was overwriting the correct `visa:a.visa===true` set earlier. Removed the duplicate.
3. **✏️ edit button added to Programs page rows.** Every row now has a faint ✏️ in the tags area. Clicking it opens the Log Application modal pre-filled with your existing pipeline row (if tracked) or catalog data (if not yet tracked). Works on both desktop table and mobile cards. New helper: `openEditModalForProgram(progId)`.
4. **`.row-edit-btn` CSS** added via `<style>` in `<head>`.

---

## Task 27B.2 Hotfix 2 — Stale org/geo on program switch; bulletproof lock; datalist perf; edit btn all rows

**Files:** `app.js`

1. **Stale org/geo when switching programs mid-modal.** `autoFillFromProgram` previously only filled empty fields — switching from Amazon to another program left Amazon's org/geo in place. Now always overwrites all catalog fields (org, geo, deadline, fn, sector, url, visa) when a catalog program is matched.
2. **Lock upgraded to revert-on-keydown pattern.** Even if user somehow gets focus into a locked field, `oninput`/`onchange`/`onkeydown` handlers immediately revert the value to the locked snapshot. `_modalLockedValues` stores the snapshot. `closeM` clears handlers on close.
3. **Datalist performance fix.** `prog-suggestions` datalist was rebuilt (~421 DOM nodes) on every modal open. Now populated once in `_initProgSuggestionsDatalist()` called after `fetchProgramsFromSupabase()` completes. Zero rebuild cost on subsequent opens — removes a noticeable lag on modal open.
4. **✏️ button shown on all rows**, not just pipeline rows. For untracked programs it opens a pre-filled modal to log the application.

---

## Task 27B.2 Hotfix 3 — Legacy null program_id catalog lock (Amazon case)

**Files:** `app.js`

**Root cause:** Amazon's `user_applications` row had `program_id = null` — it was logged before the program_id healing logic existed. `_findAppForProgram` found it via name fallback (so ✏️ worked), but `openM`'s catalog check only looked at `program_id`, saw null, and treated it as user-added → no lock applied.

**Fix:** `_cp` lookup in `openM` now tries `program_id` first, then falls back to name+org match against `progs[]`. Any catalog program — regardless of whether its app row has a `program_id` — is now correctly identified and locked.

---

## Phase 2 — Table polish + Pro-Tip fix + console.log cleanup

**Files:** `app.js`, `index.html`, `styles.css`

1. **Table headers center-aligned.** All columns except Program/Organisation (which stays left-aligned) are now center-aligned. Table cells (`.cell`) and prow non-first children also center-aligned to match. Sortable header flex alignment updated accordingly.
2. **Pro-Tip text fixed.** Was: *"Click any row to open program details"* — row click does nothing. Now: *"Click ✏️ on any row to log or edit your application. Use the Stage dropdown to move a program through your pipeline."*
3. **`[overlay]` console.logs stripped.** Three diagnostic logs removed from `resolveProgramView`, `autoFillFromProgram`, and `saveApp`. These were flagged in the handover as cleanup once Task 27 was signed off.

---

## Phase 3 — Calendar deep-links + Pipeline CSV export

**Files:** `app.js`, `index.html`, `styles.css`

### Calendar deep-links
The 📅 Set reminder button now opens a modal with three options instead of the old "Multiple Reminders / One Reminder" ICS-only choice:

- **Google Calendar** — opens a pre-filled event in Google Calendar in a new tab. One click to save. No file download needed.
- **Outlook / Office 365** — opens Outlook web calendar with the event pre-filled.
- **Download .ics** — for Apple Calendar or desktop Outlook. Includes 30/7/1-day reminders pre-built (unchanged from before).

Deep-links are built in `openICSModal()` using standard Google Calendar render URL and Outlook Office.com compose URL. No OAuth, no backend.

### Pipeline CSV export
New **"⬇ Export CSV"** button on the My Applications page (next to "+ Log Application").

- Downloads the user's full pipeline as a `.csv` file: `ldp-pipeline-YYYY-MM-DD.csv`
- Columns: Program, Organisation, Geography, Function, Sector, Stage, Started/Applied On, Deadline, Next Step, Alumni Contact, Notes
- Client-side only — reads from `apps[]` in memory, no server round-trip
- Handles commas, quotes, and newlines in field values correctly (RFC 4180 escaping)
- Function: `exportPipelineCSV()`

---

## Deploy

```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add app.js index.html styles.css CHANGES_SESSION_2026-05-27.md
git commit -m "Session 2026-05-27: 27B.2 + hotfixes + Phase 2+3"
git push
```

---

## Open items carried forward

| # | Task | Status |
|---|------|--------|
| 1 | GA events + fake-door tabs | Next |
| 2 | Task 28 — Command Center dashboard | Queued |
| 3 | Networking tracker tab | Queued |
| 4 | Cookie consent / GA consent mode | **Pre-wider-launch blocker** |
| 5 | `iima.ac.in` + `edhec.com` in whitelist | Keep (confirmed) |
| 6 | Update `PROJECT_OVERVIEW.md` | Stale docs, low priority |
