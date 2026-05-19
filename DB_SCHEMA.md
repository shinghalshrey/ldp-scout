# LDP Scout — Database Schema

Supabase Postgres. All app tables live in `public` schema. RLS is enabled on every user-data table; the anon key is public, so RLS is the only thing protecting user data.

**Project URL:** `https://kqtarrgtxqpamlfrkgiv.supabase.co`

---

## Tables (verified in Supabase Studio, May 18 2026)

7 tables in `public`, all with RLS on (`relrowsecurity = true`).

### `public.user_profiles`

User profile data, one row per user. Driven by Profile modal.

**RLS policies:**
- `own_profile_select` (SELECT) — `auth.uid() = user_id`
- `own_profile_upsert` (INSERT) — `auth.uid() = user_id`
- `own_profile_update` (UPDATE) — `auth.uid() = user_id`

**Columns (per handover):** `user_id` (PK, FK to `auth.users.id`), `email`, `full_name`, `school_key`, `school_label`, `mba_year`, `target_geos` (text[]), `target_fns` (text[]), `goals_note`, `tours_completed` (jsonb), `hints_dismissed` (jsonb).

**`full_name` is mandatory** going forward (Task 19). Onboarding will not allow proceeding without it. Existing rows with NULL `full_name` will be backfilled by prompting on next sign-in.

No DELETE policy — by design (users can't delete their profile from the UI). If account-deletion is ever added, do it via a Supabase Edge Function with service role, not a client-side DELETE.

Row count (May 18): 10.

---

### `public.user_scan_history`

One row per completed scan. Written by frontend AFTER both tier + gap AI calls succeed. The proxy reads this for quota enforcement (3-scan free limit).

**RLS policies (applied Session 3):**
- `users read own scans` (SELECT) — `auth.uid() = user_id`
- `users insert own scans` (INSERT) — `auth.uid() = user_id`

No UPDATE/DELETE policies — completed scans are immutable from the user's side.

Row count (May 18): 3.

**Proxy reads via PostgREST HEAD + count=exact** (see `scan.js` `getCompletedScanCount`). RLS scopes the count; the explicit `user_id=eq.<uid>` filter in the URL is belt-and-suspenders.

---

### `public.user_applications`

Kanban / shortlist data — referenced by SMOKE_TESTS Test 2. Each row = one program a user has shortlisted/tracked.

**RLS policies:**
- `own_apps_all` (ALL) — `auth.uid() = user_id`

Single permissive policy covering SELECT/INSERT/UPDATE/DELETE. Pragmatic for Kanban (users need to add, move, and remove cards).

**Columns (inferred, not directly verified — confirm in Supabase Studio before Task 4/5):** `id`, `user_id`, `program_id` (matches `data.js` IDs), `status` (`shortlisted`/`networking`/`applied`/etc.), `created_at`, `updated_at`.

---

### `public.user_resumes`

Stored résumé content per user. Discovered via policy scan.

**RLS policies:**
- `own_resume_all` (ALL) — `auth.uid() = user_id`

**Investigate before Task 4/5:** when is a résumé persisted, what's in the row, do we re-use stored résumés on subsequent scans? If yes, this is relevant to cost optimization (Task 5) — don't re-parse if we already have the text.

---

### `public.programs`

The 393-program catalog. Public-read.

**RLS policies (SELECT, public):**
- `programs are public`

(Duplicate `Anyone can read programs` policy was dropped in Session 4.)

---

### `public.program_job_descriptions`

JD content keyed to programs. Public-read.

**RLS policies:**
- `jd_read_all` (SELECT) — public

No insert/update policies — implies content is loaded server-side (via SQL editor or service role), not from the app.

---

### `public.community_intel`

Community-contributed program intelligence. Read-public, write-own.

**RLS policies:**
- `intel_read_all` (SELECT) — public
- `intel_write_own` (ALL) — write scoped to `auth.uid() = user_id`

**Caution:** because it's read-public, anything any user writes is visible to all users. Don't store anything sensitive here. If you ever add fields like internal contact info or interview content, gate them behind a separate table with stricter RLS.

---

## auth.users (Supabase-managed)

`user_metadata` flag the app reads:

- `has_password` (bool) — set when user completes password setup post-OTP. Suppresses the password prompt on subsequent logins. (Mandatory for new users as of Task 9.)

**Issue X status (RESOLVED Session 4):** Original concern was email verification bypass via password signup. Root cause: Supabase "Confirm email" setting was OFF, allowing password-signup to auto-confirm without inbox verification. Resolution: enabled "Confirm email" toggle in Supabase dashboard. Bogus accounts deleted from `auth.users`.

**Defense-in-depth (DONE in Task 9):** Password-signup UI path removed. New users only sign up via OTP, then a mandatory password setup at the end of OTP verification.

To get the current list of password-enabled users:
```sql
SELECT email, raw_user_meta_data->>'has_password' AS has_password, created_at
FROM auth.users
WHERE (raw_user_meta_data->>'has_password')::boolean = true
ORDER BY created_at DESC;
```

---

## RPC functions

### `public.email_account_status(p_email text)`

Added Session 4 as prerequisite for Task 9's two-button Sign Up / Sign In landing UI. Returns whether an account exists for the given email, and whether that account has a password set.

```sql
CREATE OR REPLACE FUNCTION public.email_account_status(p_email text)
RETURNS TABLE(account_exists boolean, has_password boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
  RETURN QUERY
  SELECT
    true AS account_exists,
    COALESCE((u.raw_user_meta_data->>'has_password')::boolean, false) AS has_password
  FROM auth.users u
  WHERE lower(u.email) = lower(p_email)
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, false;
  END IF;
END;
$$;
GRANT EXECUTE ON FUNCTION public.email_account_status(text) TO anon, authenticated;
```

**Security note:** This RPC leaks "does this email have an account" to anyone with the anon key. Accepted as low-risk in Session 4 — the email-enumeration vector exists in any OTP flow (sending an OTP also reveals account existence via response timing or message wording).

---

## Quick verification queries (run periodically)

```sql
-- All RLS policies on public schema
SELECT schemaname, tablename, policyname, cmd
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;

-- Verify RLS is on for all user-data tables
SELECT relname, relrowsecurity
FROM pg_class
WHERE relnamespace = 'public'::regnamespace
  AND relkind = 'r';

-- Row counts (sanity check)
SELECT 'user_scan_history' AS table, count(*) FROM public.user_scan_history
UNION ALL
SELECT 'user_profiles', count(*) FROM public.user_profiles
UNION ALL
SELECT 'user_applications', count(*) FROM public.user_applications
UNION ALL
SELECT 'user_resumes', count(*) FROM public.user_resumes;

-- Recent signups (abuse monitoring)
SELECT id, email, created_at, email_confirmed_at
FROM auth.users
ORDER BY created_at DESC
LIMIT 20;

-- Users with no completed scan (signed up but never used)
SELECT u.email, u.created_at
FROM auth.users u
LEFT JOIN public.user_scan_history h ON h.user_id = u.id
WHERE h.id IS NULL
ORDER BY u.created_at DESC;

-- Users with no full_name (need backfill prompt)
SELECT u.email, p.full_name, u.created_at
FROM auth.users u
LEFT JOIN public.user_profiles p ON p.user_id = u.id
WHERE p.full_name IS NULL OR p.full_name = ''
ORDER BY u.created_at DESC;
```

---

## GRANTs applied (Session 3, re-run if you add new tables)

```sql
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.user_scan_history TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated;
```

The schema-wide sequence GRANT covers any sequences in `public`. If you add a new table with a sequence and find inserts failing with "permission denied for sequence", re-run the sequence GRANT.

---

## Maintenance notes

- **Service role key** never appears in any client code, any pinned file, or any chat. If leaked, rotate in Supabase Settings → API immediately.
- **Anon key** in `app.js:14` and `scan.js` is intentionally public.
- **JWT secret** (HS256 legacy fallback) lives in Vercel env var `SUPABASE_JWT_SECRET`. ES256 verification via JWKS is primary; HS256 is fallback only.
- When adding a new table: enable RLS *before* inserting any rows, write policies, test from an anon session that you can't read others' data, then enable client writes.

---

## Known cleanup items (low priority)

1. Document `user_resumes` row shape and write triggers — relevant to Task 5 cost optimization.
2. Backfill `full_name` for the 10 existing `user_profiles` rows (Task 19 onboarding flow will prompt on next sign-in if NULL).
