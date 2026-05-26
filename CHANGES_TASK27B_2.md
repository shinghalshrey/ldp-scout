# CHANGES — Task 27B.2: Modal fixes + visa field + filter bug fix

Files changed: **app.js**, **index.html**.  
DB migration required: add `visa` column to `user_applications` — see SQL below.

---

## What this does

### 1. Function / Sector / URL locked for catalog programs
When you open the modal for a **catalog-linked program** (one that has a `program_id`), the Function, Sector, Link, and Visa fields are now **read-only and visually greyed out**. They pre-fill from the catalog so you can see the values, but saving doesn't touch them. The tooltip says "Set by the catalog — not user-editable."

For **user-added programs** (no `program_id`), all four fields remain freely editable — same as before.

This removes the confusion of "why don't my Function/Sector edits show up in the filters?"

### 2. Function label fixed
The "(for programs you add)" parenthetical has been removed. All programs now show the label as simply **Function**.

### 3. Visa Sponsorship field in modal
A new **Visa Sponsorship** dropdown has been added to the modal (between Link and Stage):
- Options: Unknown / not confirmed | Yes — sponsors visas | No — does not sponsor
- For **catalog programs**: pre-fills from the catalog and is read-only.
- For **user-added programs**: user-editable, persists to DB (`user_applications.visa`).
- When set to "Yes", the row shows a **✓ Visa** chip on the Programs page (desktop and mobile).
- The **✓ Visa-sponsoring only** filter on the right panel now includes user-added programs that have `visa = Yes`.

### 4. Right-panel Sector / Function filters now work for user-added programs
The filter logic was case-sensitive string matching (`F.fn.has(p.fn)`). If the user typed "Industrial" but the pill value was `industrial`, the match failed silently.

Fixed with case-insensitive comparison: `[...F.fn].some(v => v.toLowerCase() === pfn)` (same for sector). Geo and search were already correct.

**Also fixed**: the `_visaOnly` filter no longer hides all user-added rows unconditionally. User-added programs with `visa = true` now appear under the visa filter.

### 5. Delete / Remove from pipeline button is now context-aware
The modal footer button:
- **Hidden** when opening a new entry (nothing to delete yet).
- Shows **"Remove from pipeline"** when editing a catalog-linked program (makes it clear you're removing your tracking, not the program).
- Shows **"Delete"** when editing a user-added program.

This is the button to use for the Santander orphan row — open it in the modal and hit "Remove from pipeline".

---

## DB migration (run BEFORE deploying)

```sql
-- Add visa column to user_applications
ALTER TABLE public.user_applications
  ADD COLUMN IF NOT EXISTS visa boolean DEFAULT NULL;
```

Run this in Supabase → SQL Editor before pushing the code. The column is nullable (NULL = unknown, true = yes, false = no). Existing rows get NULL (unknown) by default — correct behaviour.

---

## Test plan
1. **Open a catalog program modal** → Function/Sector/Link/Visa are pre-filled and greyed out; can't type in them; save works and doesn't change those catalog values.
2. **Open a user-added program modal** → Function/Sector/Link/Visa are editable; set Visa = Yes; save → row shows ✓ Visa chip.
3. **Visa filter** → Turn on "✓ Visa-sponsoring only"; user-added program with Visa = Yes appears; one with Visa = No/unknown hides.
4. **Function filter** → Add a program with Function = "Operations"; click the Operations pill → user-added row appears. Click Finance → it disappears.
5. **Sector filter** → Same logic as Function.
6. **Delete button** → Open a catalog program modal → button says "Remove from pipeline". Open a user-added modal → button says "Delete". Open "+ Add new program" → button hidden.
7. **Santander orphan** → Open it from My Applications → modal says "Remove from pipeline" → click it → gone.

---

## Deploy
```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add app.js index.html CHANGES_TASK27B_2.md
git commit -m "Task 27B.2: catalog fn/sector/visa locked; visa field; filter case-insensitive fix; remove-from-pipeline btn"
git push
```
