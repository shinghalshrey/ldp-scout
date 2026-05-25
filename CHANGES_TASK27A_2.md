# CHANGES — Task 27A.2 (Programs page: deadline + reminder now use YOUR date)

**File changed:** `app.js` only. (`index.html` unchanged — do NOT re-push it.)

## What was wrong

This is the bug you just hit: one Santander card now (the de-dup worked), but the
**Programs table still showed 1 Aug** and the **"Set reminder" ICS still exported 1 Aug**
— your changed deadline was ignored on that page.

Cause: 27A only wired the resolver into the *Deadlines* page. The *Programs* page has its
own, separate code for the deadline column and the reminder button, and both read the raw
catalog deadline (`p.deadline` = 1 Aug) instead of your overridden one. I deferred wiring
the Programs page in 27A and flagged it as a known limitation — that deferral is what bit
you. Now fixed.

## What changed

All four Programs-page spots now read through `resolveProgramView(p)` (your deadline wins,
catalog date as fallback) — identical to the Deadlines page:

1. Desktop table — the DEADLINE column.
2. Desktop table — the "📅 Set" reminder button.
3. Mobile card — the deadline line.
4. Mobile card — the "📅" reminder button.

The reminder button on both desktop and mobile now goes through one function
(`openICSModalForProgram`), which resolves your deadline before building the ICS. So the
calendar file finally carries the date you set, not the catalog date.

## Note on your Outlook screenshot

Your earlier export showed the Santander event on 1 Aug, and you may have already *added*
that 1 Aug event to your Outlook calendar. This fix corrects future exports — but the old
1 Aug event already sitting on your calendar won't remove itself. Delete that one calendar
entry manually after you re-export with the corrected date, or you'll see both.

## Test

1. Hard-refresh `ldpscout.com` (Ctrl+Shift+R).
2. Programs page → Santander row → the DEADLINE column should now show **your** date, not
   1 Aug.
3. Click "📅 Set" on that row → the ICS preview should show **your** date.
4. Cross-check the Deadlines page shows the same date (it already did — this just makes the
   Programs page agree with it).
