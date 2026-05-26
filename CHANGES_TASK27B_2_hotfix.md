# CHANGES — Task 27B.2 (hotfix): catalog lock + visa chip + ✏️ edit button

Fixes all issues found during 27B.2 live test.

## Bugs fixed

### 1. Catalog fields still clickable
**Root cause:** `disabled` attribute was used, which (a) lets users click in some browsers and (b) makes `gv()` return `''`, wiping fn/sector/url on save.
**Fix:** Replaced `disabled` with `pointer-events:none` + `readonly`. Fields are visually greyed and physically unclickable. Values are preserved for display but not written back on save (catalog programs only save deadline/stage/notes/contact).
**Also added:** A visible banner below the Function/Sector row: *"🔒 Function, Sector, Link and Visa are set by the catalog and can't be edited here."* This appears when a catalog program is open; hidden for user-added.

### 2. ✓ Visa chip not showing for user-added programs
**Root cause:** Duplicate key in object literal. `_userAddedRows()` set `visa: a.visa === true` on one line, then overwrote it with `visa: false` in the inert-fields block below it. Last key wins in JS objects.
**Fix:** Removed the duplicate `visa: false` from the inert-fields line.

### 3. ✏️ Edit modal not accessible from Programs page
**This was the Phase 2 ✏️ edit button — built now** since it's clearly needed.
- **Catalog rows in your pipeline:** a subtle ✏️ button appears in the tags row. Clicking it opens the modal pre-filled with your pipeline row.
- **Catalog rows not yet in pipeline:** ✏️ not shown (nothing to edit yet — use the Stage dropdown to add first).
- **User-added rows:** ✏️ always shown (you own these fully).
- Works on both **desktop table** and **mobile cards**.
- The same ✏️ approach is used on the My Applications Kanban cards (those already work via `editAp()`).

## No DB migration needed (this is a JS/HTML-only fix)

## Deploy
```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add app.js index.html CHANGES_TASK27B_2_hotfix.md
git commit -m "Task 27B.2 hotfix: catalog lock fix; visa chip fix; pencil edit btn on Programs rows"
git push
```

## Test
1. Open a catalog program modal → Function/Sector/Link/Visa greyed and unclickable; lock banner visible; Save works and doesn't overwrite catalog values.
2. Open a user-added program modal → all fields editable, no lock banner.
3. Add a new program with Visa = Yes → Programs page shows ✓ Visa chip on the row.
4. Programs page → tracked program row has a faint ✏️ in the tags line → click it → modal opens with your data.
5. Programs page → untracked program → no ✏️ (use Stage dropdown to add first).
6. User-added row → ✏️ always present → opens correctly.
