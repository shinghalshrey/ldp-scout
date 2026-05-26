# CHANGES — Task 27B.1 (Phase 1): user-added programs first-class + visa note + Google Analytics

Files changed: **app.js**, **index.html**. DB migration (`fn`/`sector`/`url` on `user_applications`) already run.

## What this does

### 1. User-added programs now carry Function / Sector / Link
- The **Log Application modal** gains three fields: **Function**, **Sector**, **Link** (program website, optional).
- These are wired end-to-end ("save/load mapping"): captured in `saveApp` → written to the DB in `saveApplicationToDB` → read back in `loadUserApplications`. So they persist across refresh.
- On the Programs page, a user-added row now shows its **Function** and **Sector** in the existing columns (was "—"), and its **name becomes a clickable link** to the URL you entered (catalog rows already did this).

### 2. Catalog programs unchanged (your call)
- We do **NOT** let users overwrite a catalog program's Function/Sector. Only the **deadline** is user-overridable, exactly as before. The modal's Function/Sector/Link fields **pre-fill from the catalog** when you open an existing catalog program (so the URL/values are visible), but saving doesn't change the shared catalog.

### 3. Filters + count include user-added (per-user)
- User-added rows now obey the **Geography, Function, Sector, and search** filters just like catalog rows (previously they were hidden whenever any filter was on).
- They're hidden under **App Cycle / AI Fit / Visa / Verified** filters (they have no catalog equivalent), and always pass the **My Pipeline** filter (they're always in your pipeline).
- **Total Programs** now reads catalog + *your* user-added count. This is per-user: a user who added 2 programs sees 424; a user who added none still sees 422.

### 4. Visa-filter caveat
- When the "✓ Visa-sponsoring only" filter is on, a note appears under the quick filters: programs outside the filter may still sponsor case-by-case, we can't guarantee sponsorship, confirm with the company.

### 5. Google Analytics (GA4)
- Added the gtag snippet (property `G-EYTE9XRJ00`) to `<head>`. Once deployed, the "Test" in your GA setup should detect the tag.
- **Compliance flag:** raw GA sets analytics cookies. You have EU users (ESADE/HEC/etc.), so before any wider launch you should add a cookie-consent banner / GA consent mode — see the note in the chat. Fine for the current invite-only beta, but it's a real to-do.

## Impact check (everything-is-linked)
- `resolveProgramView` untouched (still deadline-only overlay) — no change to Deadlines page, ICS, or the desktop deadline cell.
- Catalog rows render through the unchanged path; only user-added rows use the new renderers.
- `_userAddedRows` now carries inert `fit/visa/last_verified_at/tags/notes/aiTier` fields so the shared filter/sort never throws on a user-added row.
- Notes / Next Step / Alumni Contact were already saved (confirmed) — untouched.

## Test plan (do these live after deploy + hard refresh)
1. **Add** a program via "+ Add new program" with a Function, Sector, and a Link. Save. → row shows fn/sector, name is a clickable link, Total Programs +1.
2. **Refresh** the page. → the fn/sector/link survive (load mapping works).
3. **Filter** by that program's Function (or Sector, or Geography, or search its name). → the user-added row stays visible; toggle a Function it doesn't have → it disappears.
4. Turn on **App Cycle / AI Fit / Visa / Verified** → user-added row hides (expected).
5. Open an **existing catalog** program's edit modal → Function/Sector/Link fields are pre-filled from the catalog; Function/Sector are not saved as overrides (only your deadline is).
6. Turn on **✓ Visa-sponsoring only** → the caveat note appears; turn off → it hides.
7. GA: after deploy, re-run the "Test" in GA setup (or check Realtime while you browse the site).

## Deploy
```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add app.js index.html CHANGES_TASK27B_1.md
git commit -m "Task 27B.1: user-added programs carry fn/sector/url + filter/count integration; visa note; GA4 tag"
git push
```
