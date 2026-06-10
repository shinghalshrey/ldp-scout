# Task SEC2 — security fixes (2026-06-11 audit follow-up)

Fixes the findings from the 2026-06-11 review of the admin-dashboard surface (the
review that followed `SECURITY_AUDIT_2026-06-03.md`). The earlier audit predated the
`role` column and `admin.html`, so the privilege-escalation path below was never in
scope then.

## ⚠️ Action required — the critical fix is a database change
The headline fix lives in **`security_fixes_2026-06-11.sql`** and must be run in the
Supabase SQL editor. Until it is applied, the escalation below remains open. The
frontend changes (this push) are safe to deploy on their own; §3 of the SQL pairs with
the `admin.html` change (see "Apply order").

---

## What was wrong, and what changed

### 🔴 CRITICAL — any user could self-promote to admin (`security_fixes_2026-06-11.sql` §1)
`user_profiles` had `own_profile_update` = `UPDATE USING (auth.uid() = user_id)`, a
**row**-level policy with no column restriction. `role` lives in that row, and admin
access is decided by `is_admin_for_school()` reading the caller's own `role`. So any
signed-in user could run, from the browser console:
```js
await sb.from('user_profiles').update({ role:'admin', school_key:'esade' }).eq('user_id', myId);
```
and then read every same-school student's profile, applications, scan history, and
**full résumé text** directly via the REST API — across every school by changing
`school_key`. The dashboard's "show Y/N only" rule is UI-side and was trivially bypassed.

**Fix (two independent layers):**
1. **Column-level GRANTs** — `revoke insert, update on user_profiles from authenticated`,
   then grant back only the columns the app actually writes. `role` is omitted from
   both, so Postgres rejects any client write to it (`permission denied for column role`).
   This is the primary control and changes no app behaviour (the app never writes `role`).
2. **Guard trigger** `guard_user_profile_writes()` — for ordinary API users, forces
   `role='student'` on insert and pins `role` / `school_key` / `school_label` / `email`
   to their existing values on update. The SQL editor and the service-role key are
   exempt, so careers admins are still appointed the documented way.

Side benefit: `school_key`, `school_label`, and `email` are now immutable after signup.

### 🟠 MEDIUM — `school_of_user(uuid)` leaked schools to anonymous callers (§2)
The helper was `grant execute ... to anon`, so an unauthenticated caller with the
public anon key could resolve any user's `school_key` by uuid. **Fix:** revoked from
`anon` (kept for `authenticated`, which the admin policies need).

### 🟠 MEDIUM / GDPR — admins could read résumé text + scan results (§3)
`admin_read_resumes` / `admin_read_scans` granted same-school admins the **whole row**
(RLS can't restrict columns), exposing `user_resumes.raw_text` and
`user_scan_history.result` even though the dashboard only needs existence + timestamps.
**Fix:** dropped those two policies and added SECURITY DEFINER RPCs
`admin_student_resumes()` / `admin_student_scans()` that return only the safe columns
(no `raw_text`, no `result`). A non-admin caller gets zero rows. `admin.html` now reads
through these RPCs instead of the base tables. Owner access (`own_*` policies) is untouched.

### 🟡 LOW — CSV formula injection (`app.js`, `exportPipelineCSV()`)
Exported fields starting with `=` `+` `-` `@` (or a control char) could execute as a
formula when the CSV is opened in Excel / Google Sheets. **Fix:** the `escape()` helper
now prefixes a single quote on those values so the cell is treated as text. Normal
values (including those needing comma/quote escaping) are unchanged.

---

## Files changed
- **`security_fixes_2026-06-11.sql`** (new) — the DB migration (§1–§3). Run in Supabase.
- **`admin.html`** — `loadData()` now calls `admin_student_scans` / `admin_student_resumes`
  RPCs instead of selecting from `user_scan_history` / `user_resumes`. Rendering unchanged.
- **`app.js`** — CSV formula-injection guard in `exportPipelineCSV()`.
- **`CHANGES_TASK_SEC2.md`** (this file).

## Apply order
1. Deploy this push (frontend). The careers dashboard's résumé/scan columns will read
   empty until step 2, because the RPCs don't exist yet — this affects only the admin
   user and does not error.
2. Run `security_fixes_2026-06-11.sql` in the Supabase SQL editor.
3. Reload the careers dashboard and confirm résumé (Y/N) + scan counts populate again.
   (Order 2-before-1 also works; the brief gap is unavoidable since DB changes are manual.)

## Not changed / still open (documented, lower priority)
- **Client-side-only signup domain gate.** `isEmailAllowed()` runs before the OTP send
  but isn't enforced server-side, so it's bypassable. After §1 this no longer leads to a
  data breach (an unauthorised signup can't become admin). Closing it fully needs a
  Supabase `before_user_created` auth hook — left as a follow-up to avoid duplicating the
  domain list in SQL.
- **`community_intel` / `program_job_descriptions`** are `read-all` to any authenticated
  user. Both are empty and unrendered today; escape their content on render if wired up.
- Carryovers from the 2026-06-03 audit (Clarity session-replay masking, no CSP, account
  enumeration RPC) are unchanged.

## Verification performed
- `security_fixes_2026-06-11.sql` reviewed for the upsert-privilege pitfall (school/email
  are granted so PostgREST's `ON CONFLICT DO UPDATE` still plans; the trigger enforces
  immutability) and for recursion safety (the trigger reads no tables → no 42P17).
- `node --check app.js` → clean. CSV guard unit-tested (11/11): formula leads neutralised,
  normal values + comma/quote escaping unchanged.
- `admin.html` test harness (stubbed DOM + Supabase): 36/36 — all existing render
  assertions plus new ones proving `loadData()` calls the two RPCs and maps their results
  into `SCANS`/`RESUMES` (no `raw_text`) so `buildIndexes()` still derives résumé/scan rollups.
- Served locally: `admin.html` parses with zero console errors; the no-session redirect
  to ldpscout.com still fires (auth gate intact).
- **Not testable here:** the live DB migration and a logged-in admin session. Run the SQL,
  then smoke-test the dashboard and a normal-user self-promotion attempt (should fail).
