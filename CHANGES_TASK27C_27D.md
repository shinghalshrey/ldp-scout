# CHANGES — Task 27C + 27D (add-program button, field relabel, Alumni pipeline filter)

**Files changed:** `app.js` (+4 lines) and `index.html` (2 changed, 1 added). Both ship
together. No data migration, no DB change.

These two are deliberately bundled because they're small and independent. **27B (user-added
programs surfacing on the Programs page) is NOT in this push** — it rewrites the Programs
render and goes separately, on top of this.

---

## 27C — "+ Add new program" button + field relabel

1. **Programs page header link changed.** The old "Don't see a program? Request it →"
   (which opened an email to hello@ldpscout.com) is now **"+ Add new program"**. It opens
   the Log Application modal. Whatever the user types that doesn't match a catalog program
   is saved as a user-added program (`program_id` stays null). This replaces the mailto
   request flow, per the locked 27C plan.

2. **Modal field relabelled.** "Program / Role" → **"Program"**. Storage is unchanged — it
   was always a single `name` column (confirmed in the field audit), so this is purely the
   visible label.

**Note:** the modal title still reads "Log Application" even when opened via "+ Add new
program". Functionally identical (you're adding a program to your pipeline); only the
heading wording is shared. Flag if you want a distinct title — that's a trivial follow-up.

---

## 27D — Alumni Finder "My Pipeline" filter

A **"My Pipeline"** toggle now sits in the Alumni Finder feed header, next to the count.
When on, the alumni feed shows only programs you've logged in your pipeline.

It reuses the **same shared state** as the Programs and Deadlines toggles (`_pipelineFilter`,
persisted in localStorage). So flipping it on any of the three pages flips it on all three —
which matches the existing "flip once, filter everywhere" design. Turn it off anywhere and
all three go back to showing everything.

Mechanically: `renderAlumniSearch` now (a) syncs the toggle's on/off appearance with the
shared state and (b) drops any program with no logged application when the filter is on —
the exact same predicate the Programs page uses (`_findAppForProgram(p)`).

---

## What I tested at my end (logic harness, mock data)

I can't run the live DOM/Supabase, but I ran the pure logic against mock programs +
applications. All 10 checks passed:
- `_findAppForProgram` matches by `program_id` first, then name+org for legacy rows, and
  returns nothing for a program with no application.
- deadline precedence: user's date wins; a blank user deadline falls back to the catalog
  date (the `||`-not-`??` rule); a program with no application shows the catalog date.
- the resolver stays deterministic when duplicate same-name rows exist (the id-linked row
  wins, never a name collision).
- the 27D pipeline filter returns only pipeline programs when on, everything when off, and
  composes correctly with the sector filter.

## What YOU need to verify on the live site

1. **Programs page** → "+ Add new program" (top-right of the table) opens the Log
   Application modal. Add a program with a made-up name, Save → it saves without error.
   (It won't appear on the Programs *list* yet — that's 27B. Check it shows on My
   Applications.)
2. **Modal** → the first field now reads "Program", not "Program / Role".
3. **Alumni Finder** → a "My Pipeline" pill is in the feed header. Click it → feed narrows
   to only your pipeline programs; the pill reads "✓ My Pipeline". Click again → all
   programs return.
4. **Shared state** → turn it on in Alumni, switch to Programs/Deadlines → it's on there
   too. Turn off → off everywhere.

## Deploy

```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add app.js index.html CHANGES_TASK27C_27D.md
git commit -m "Task 27C+27D: add-program button, Program relabel, Alumni My-Pipeline filter"
git push
```
(Both files this time — `index.html` changed.) Green check → hard-refresh (Ctrl+Shift+R).
