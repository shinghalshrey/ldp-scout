-- admin_rls_recursion_fix.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Fix: "infinite recursion detected in policy for relation user_profiles" (42P17)
--
-- ⚠️ Apply this before the Careers Dashboard (admin.html) can load any data.
--    Until it is applied, EVERY authenticated read across the app fails — see below.
--
-- Context
--   The admin_read_* policies added 2026-06-07 (Task ADMIN) decide whether the
--   requesting user is an admin by SELECT-ing user_profiles *inside a policy that
--   is itself ON user_profiles*. Postgres must evaluate the user_profiles
--   policies to satisfy that inner SELECT, which re-enters the same policy →
--   infinite recursion. Because programs_select and the other admin_read_*
--   policies also read user_profiles, this currently breaks every authenticated
--   read: programs, user_applications, user_resumes, user_scan_history, and even
--   a user reading their OWN profile. Confirmed live on 2026-06-07 against the
--   anon REST endpoint — all five tables returned 42P17.
--
-- Strategy
--   Move the "am I an admin for this school?" lookup into SECURITY DEFINER helper
--   functions. A SECURITY DEFINER function runs with the owner's rights and
--   bypasses RLS on the tables it reads, so the user_profiles lookup no longer
--   re-triggers user_profiles policies — which breaks the recursion. This is
--   Supabase's recommended pattern for self-referential / cross-user policies.
--
-- Safety
--   • Admin access stays read-only (SELECT only; no INSERT/UPDATE/DELETE granted).
--   • School scoping is preserved (an admin still only sees their own school).
--   • own_profile_* and the student-facing policies are left untouched.
--   • Re-runnable: CREATE OR REPLACE + DROP POLICY IF EXISTS.
--
-- Review, then run in the Supabase SQL editor (or via your migration tooling).
-- ─────────────────────────────────────────────────────────────────────────────

-- 1) Helper: the requesting user's own school_key (RLS-bypassing).
create or replace function public.requesting_user_school()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select school_key from public.user_profiles where user_id = auth.uid()
$$;

-- 2) Helper: is the requesting user an admin whose school matches target_school?
create or replace function public.is_admin_for_school(target_school text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.user_profiles
    where user_id    = auth.uid()
      and role       = 'admin'
      and school_key is not distinct from target_school
  )
$$;

-- 3) Helper: school_key for an arbitrary student (RLS-bypassing). Lets the
--    child-table policies avoid an in-policy join back to user_profiles.
create or replace function public.school_of_user(p_user uuid)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select school_key from public.user_profiles where user_id = p_user
$$;

grant execute on function public.requesting_user_school()  to anon, authenticated;
grant execute on function public.is_admin_for_school(text) to anon, authenticated;
grant execute on function public.school_of_user(uuid)      to anon, authenticated;

-- 4) Recreate the admin SELECT policies using the helpers. No in-policy
--    user_profiles subquery is evaluated under RLS, so there is no recursion.

drop policy if exists admin_read_profiles on public.user_profiles;
create policy admin_read_profiles on public.user_profiles
  for select to authenticated
  using ( public.is_admin_for_school(school_key) );

drop policy if exists admin_read_apps on public.user_applications;
create policy admin_read_apps on public.user_applications
  for select to authenticated
  using ( public.is_admin_for_school( public.school_of_user(user_id) ) );

drop policy if exists admin_read_scans on public.user_scan_history;
create policy admin_read_scans on public.user_scan_history
  for select to authenticated
  using ( public.is_admin_for_school( public.school_of_user(user_id) ) );

drop policy if exists admin_read_resumes on public.user_resumes;
create policy admin_read_resumes on public.user_resumes
  for select to authenticated
  using ( public.is_admin_for_school( public.school_of_user(user_id) ) );

-- 5) Sanity checks (optional):
--   -- as any signed-in user, these should all succeed again (no 42P17):
--   select count(*) from public.programs;
--   select count(*) from public.user_profiles;     -- admin: same-school students; student: just self
--   -- as an admin:
--   select public.is_admin_for_school(public.requesting_user_school());  -- expect: true
