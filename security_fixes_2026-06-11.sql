-- security_fixes_2026-06-11.sql
-- ═══════════════════════════════════════════════════════════════════════════
-- LDP Scout — security hardening (follow-up to SECURITY_AUDIT_2026-06-03.md).
-- Addresses findings from the 2026-06-11 review of the admin dashboard surface.
--
-- ⚠️  Review, then run in the Supabase SQL editor (Dashboard → SQL Editor).
--     The SQL editor runs as the table owner, so the column GRANTs below do NOT
--     restrict you here — careers-team admins are still appointed from this editor
--     (see §1 note). Re-runnable: CREATE OR REPLACE + DROP ... IF EXISTS.
--
-- Apply order matters only for §3 (it changes how admin.html reads résumé/scan
-- data). Run the WHOLE file, then reload the careers dashboard to confirm.
--
-- WHAT THIS FIXES
--   §1  CRITICAL — privilege escalation: any signed-in user could
--       `update user_profiles set role='admin'` on their own row and gain admin
--       read access to every same-school student's data. `role` is now
--       un-writable by the `authenticated` role (column GRANT) and additionally
--       pinned by a trigger. school_key / school_label / email become immutable
--       after signup.
--   §2  MEDIUM — `school_of_user(uuid)` was executable by `anon`, leaking any
--       user's school_key to an unauthenticated caller. Revoked from anon.
--   §3  MEDIUM / GDPR — the admin_read_resumes / admin_read_scans policies
--       exposed the WHOLE row (résumé raw_text, scan result JSON) to same-school
--       admins via direct REST, even though the dashboard only shows Y/N + counts.
--       Replaced with SECURITY DEFINER RPCs that return only the safe columns.
-- ═══════════════════════════════════════════════════════════════════════════


-- ───────────────────────────────────────────────────────────────────────────
-- §1  CRITICAL — lock the `role` column (and freeze school/email post-signup)
-- ───────────────────────────────────────────────────────────────────────────
-- The fix has two independent layers so neither alone is a single point of
-- failure:
--   (a) Column-level GRANTs: the `authenticated` role simply has NO privilege to
--       write `role`. A self-promotion UPDATE is rejected by Postgres with
--       "permission denied for column role". This is the canonical Supabase
--       pattern and is the primary control.
--   (b) A BEFORE INSERT/UPDATE trigger that, for ordinary API users, forces
--       role='student' on insert and pins role / school_key / school_label /
--       email to their existing values on update. Backs (a) up if a future
--       migration accidentally re-GRANTs the column.
--
-- The app only ever writes: email, school_key, school_label (at signup INSERT)
-- and full_name, mba_year, onboarding_*, tours_completed, hints_dismissed,
-- digest_opt_in (via saveUserProfile UPDATE). It NEVER writes `role`, so locking
-- it out changes no app behaviour.

revoke insert, update on public.user_profiles from authenticated;

-- INSERT: everything the signup stub / first-write may legitimately set — minus role.
grant insert (
  user_id, email, full_name, school_key, school_label, mba_year,
  target_geos, target_fns, goals_note, updated_at,
  onboarding_completed_at, onboarding_skipped_at,
  tours_completed, hints_dismissed, digest_opt_in
) on public.user_profiles to authenticated;

-- UPDATE: the columns saveUserProfile touches, plus school/email so PostgREST's
-- upsert (INSERT ... ON CONFLICT DO UPDATE) still plans — the trigger below makes
-- school/email effectively immutable. `role` is omitted: clients cannot write it.
grant update (
  email, full_name, school_key, school_label, mba_year,
  target_geos, target_fns, goals_note, updated_at,
  onboarding_completed_at, onboarding_skipped_at,
  tours_completed, hints_dismissed, digest_opt_in
) on public.user_profiles to authenticated;

-- Defence-in-depth trigger. SECURITY DEFINER so it can read auth.jwt() regardless
-- of the caller, but it only ever pins NEW values — it never reads other tables,
-- so it cannot re-introduce the 42P17 recursion the admin policies had.
create or replace function public.guard_user_profile_writes()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  claims jsonb := auth.jwt();
begin
  -- No request JWT  → running in the SQL editor (this is how admins are appointed).
  -- role=service_role → trusted backend (service key). Both may set anything.
  if claims is null or (claims ->> 'role') = 'service_role' then
    return new;
  end if;

  -- Otherwise: an ordinary signed-in user acting through the API.
  if tg_op = 'INSERT' then
    new.role := 'student';                 -- ignore any client-supplied role
  elsif tg_op = 'UPDATE' then
    new.role         := old.role;          -- role is immutable to the user
    new.school_key   := old.school_key;    -- school is set once (at signup) and
    new.school_label := old.school_label;  --   immutable thereafter
    new.email        := old.email;         -- email cannot be changed here
  end if;
  return new;
end;
$$;

drop trigger if exists trg_guard_user_profile_writes on public.user_profiles;
create trigger trg_guard_user_profile_writes
  before insert or update on public.user_profiles
  for each row execute function public.guard_user_profile_writes();

-- How to appoint a careers-team admin AFTER this migration (run here, in the SQL
-- editor — the trigger's `claims is null` branch allows it):
--   update public.user_profiles
--      set role = 'admin', school_key = 'esade', school_label = 'ESADE'
--    where email = 'careers.person@esade.edu';


-- ───────────────────────────────────────────────────────────────────────────
-- §2  MEDIUM — stop `anon` from resolving arbitrary users' schools
-- ───────────────────────────────────────────────────────────────────────────
-- school_of_user(uuid) is only ever needed by the admin_* paths (authenticated).
-- Granting it to anon let an unauthenticated caller holding the public anon key
-- look up any user's school_key by uuid. Keep it for authenticated; drop anon.
-- (requesting_user_school() / is_admin_for_school() are left as-is because
-- programs_select may evaluate them for anon catalog reads.)
revoke execute on function public.school_of_user(uuid) from anon;


-- ───────────────────────────────────────────────────────────────────────────
-- §3  MEDIUM / GDPR — minimise what admins can read from résumé / scan tables
-- ───────────────────────────────────────────────────────────────────────────
-- RLS is row-level, not column-level, so admin_read_resumes / admin_read_scans
-- handed same-school admins the ENTIRE row — including user_resumes.raw_text and
-- user_scan_history.result — even though the dashboard only needs existence +
-- timestamps. Replace those policies with SECURITY DEFINER RPCs that select only
-- the safe columns. A non-admin caller gets zero rows (is_admin_for_school →
-- false); the résumé text and scan-result JSON are never returned to anyone but
-- the owner (whose own_* policies are untouched).
--
-- admin.html is updated in the same change to call these RPCs instead of reading
-- the base tables. Run this section, then reload the dashboard.

create or replace function public.admin_student_resumes()
returns table (user_id uuid, file_name text, uploaded_at timestamptz)
language sql
stable
security definer
set search_path = public
as $$
  select r.user_id, r.file_name, r.uploaded_at
  from public.user_resumes r
  where public.is_admin_for_school( public.school_of_user(r.user_id) )
$$;

create or replace function public.admin_student_scans()
returns table (user_id uuid, created_at timestamptz)
language sql
stable
security definer
set search_path = public
as $$
  select s.user_id, s.created_at
  from public.user_scan_history s
  where public.is_admin_for_school( public.school_of_user(s.user_id) )
$$;

revoke all on function public.admin_student_resumes() from public, anon;
revoke all on function public.admin_student_scans()   from public, anon;
grant execute on function public.admin_student_resumes() to authenticated;
grant execute on function public.admin_student_scans()   to authenticated;

-- Remove the over-broad base-table admin policies (raw_text / result exposure).
drop policy if exists admin_read_resumes on public.user_resumes;
drop policy if exists admin_read_scans   on public.user_scan_history;


-- ───────────────────────────────────────────────────────────────────────────
-- Verification (optional — run as a normal signed-in NON-admin test user via the
-- REST API / app console, not here in the SQL editor):
--   -- Should now FAIL with: permission denied for column "role"
--   update user_profiles set role='admin' where user_id = auth.uid();
--   -- Should return [] (no rows), not other users' résumé text:
--   select * from user_resumes;
--
-- In the SQL editor (owner) these confirm the grants/policies landed:
--   select privilege_type, column_name from information_schema.role_column_grants
--    where grantee='authenticated' and table_name='user_profiles'
--      and column_name='role';                       -- expect: 0 rows
--   select polname from pg_policies
--    where tablename in ('user_resumes','user_scan_history') and polname like 'admin_%';  -- expect: 0 rows
-- ═══════════════════════════════════════════════════════════════════════════
