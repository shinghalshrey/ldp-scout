# CHANGES — Task 27A.1 (fix the Log Application flow: stop duplicates)

**File changed:** `app.js` only. (`index.html` is unchanged from 27A — do NOT re-push it.)
**What you'll see:** logging a program you've already tracked now **updates that one
card** (e.g. changes its deadline) instead of creating a second card. After you clean
up the existing duplicate Santander rows (SQL below), Santander shows once everywhere.

## The bug, in one line

The "Log Application" modal always *inserted* a new row when you weren't editing.
So every time you logged Santander to change its deadline, you got another Santander.
Three logs → three cards → three deadline rows → three calendar events. The catalog
was never duplicated (you confirmed — one Santander on the Programs page); only your
*applications* duplicated.

Every other write path (the Programs stage dropdown, the Alumni "+ Add", drag-and-drop
between columns) already de-duplicated. Only the modal didn't. This was true before
27A — 27A just made it visible because the deadline now actually shows.

## What changed

1. **`saveApp` now updates-on-match.** When you log an application and you're not
   editing a specific row, it first checks whether an application for this same program
   already exists (by `program_id` if you picked from the list, otherwise by name+org).
   If one exists, the save is folded **into that row** — it updates the existing card
   instead of making a new one. A legacy row that had no `program_id` gets its link
   "healed" (the `program_id` written) the next time you log it.

2. **`program_id` is now stored as a number, not a string.** The hidden field hands
   back `"4"` (text); the database and the catalog use `4` (number). `"4" === 4` is
   false in JS, so id-matching silently failed until a page reload re-typed it. Now it's
   coerced to a number at capture, so matching works immediately.

3. **`resolveProgramView` is now deterministic.** It picks the `program_id`-linked row
   first and only falls back to a name match if there's no linked row. Previously, with
   duplicate same-name rows, it grabbed an arbitrary one — which is why the deadline it
   displayed/exported could change between page loads.

## What this does NOT change (intended)

- The quick "+ Add" / stage-dropdown paths still show "Already in your pipeline" if the
  program is already tracked — they don't update details. That's correct: those are
  one-tap "add at this stage" actions. The modal is the "edit the details" path. The
  two behaviours are different on purpose.
- Editing a row and renaming it to match a *different* existing program does NOT merge
  them. Pure edit = update that one row. Merging on rename is risky (data loss) and rare;
  left alone deliberately.
- This de-dups your own rows against each other. It does NOT touch the catalog or merge
  user rows with admin-added catalog programs — so the locked "no dedup" decision (which
  was about admin-vs-user rows) is untouched.

## Cleaning up the three existing Santander rows

The code stops *new* duplicates. The three you already have need deleting by hand. Do
this in the Supabase SQL editor.

**Deletes are permanent and there are no backups — run the SELECT first and only delete
by `id`.** Deleting by `id` is safe because each id is unique to one row; it cannot
affect any other program or any other user.

**Step 1 — see your Santander rows and their ids:**

```sql
select id, name, deadline, status, program_id, created_at
from user_applications
where name ilike '%santander%'
order by created_at desc;
```

You'll see three rows with deadlines `2026-07-26`, `2026-07-27`, `2026-08-10`. Decide
which deadline is the correct one to keep. (Recommended: keep the `2026-07-26` row —
it's the one with `program_id = 4` filled in, i.e. properly linked. But keep whichever
date you actually want; the fix will heal the link on your next log either way.)

**Step 2 — delete the two you don't want, by id:**

```sql
delete from user_applications
where id in ('PASTE_FIRST_ID_TO_DELETE', 'PASTE_SECOND_ID_TO_DELETE');
```

Replace the two placeholders with the `id` values of the two rows you're removing.
Double-check you pasted the two you want gone, not the one you're keeping.

(If you'd rather not touch SQL: you can delete the two extra Santander cards directly
in the My Applications tab — same result, zero risk, scoped to your account.)

## Deploy + test sequence

1. Copy the new `app.js` into `ldp-scout`, then:
   ```powershell
   cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
   git add app.js CHANGES_TASK27A_1.md
   git commit -m "Task 27A.1: de-dup Log Application flow + deterministic resolver + numeric program_id"
   git push
   ```
   (Only `app.js` + this doc. `index.html` did not change.)
2. Wait for the green check on the Actions page, hard-refresh `ldpscout.com` (Ctrl+Shift+R).
3. Run the SELECT, then the DELETE, to get down to one Santander.
4. Hard-refresh. Deadlines page → **one** Santander in "Later (60+ days)".
5. **The real test:** open Log Application, type "Santander CIB Graduate Program",
   set a *different* deadline, Save. Console shows `[overlay] log matched existing row …
   updating instead of inserting`. You should still have **one** Santander card, now
   with the new date — not a second one.
6. Refresh the page. Still one Santander, new date persisted (write + read path).
7. Export to calendar → one Santander event with the new date.
