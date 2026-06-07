# DB_SCHEMA.md — LDP Scout

Generated from live Supabase introspection on **2026-06-07** (updated from Session 3 baseline).
This document describes the actual deployed schema.

Supabase project: `https://kqtarrgtxqpamlfrkgiv.supabase.co`
Schema: `public`

---

## 1. Tables — quick reference

| Table | Purpose | PK | Rows | RLS |
|-------|---------|----|------|-----|
| `user_profiles` | One row per user, profile + onboarding flags + role | `user_id` | 54 | ✓ |
| `user_scan_history` | One row per completed AI scan, quota enforcement | `id` | 15 | ✓ |
| `user_applications` | Kanban pipeline cards — main user-data table | `id` | 106 | ✓ |
| `user_resumes` | One row per user (upserted), résumé content | `user_id` | 34 | ✓ |
| `user_contacts` | Networking Tracker contacts | `id` | 4 | ✓ |
| `programs` | Public LDP catalog | `id` | 428 | ✓ (multi-tenant via `visible_to`) |
| `program_job_descriptions` | JD content per program | `id` | 0 | ✓ |
| `community_intel` | Community-contributed program intel | `id` | 0 | ✓ |

`id` types vary by table — see each section. Notable: `user_applications.id` is **uuid**; `programs.id` is **integer**; `user_contacts.id` is **bigint**. Foreign keys must match the referent's type.

---

## 2. Foreign keys

The only declared foreign key in the public schema is:

| From | To |
|------|-----|
| `user_contacts.related_app_id` (uuid) | `user_applications.id` (uuid) |

`user_id` columns reference `auth.users(id)` (uuid) implicitly via RLS — there is no declared FK to `auth.users` on any table in `public`.

`program_id` columns on `community_intel`, `program_job_descriptions`, and `user_applications` reference `programs.id` (integer) **logically** but no FK is declared.

---

## 3. `user_profiles`

One row per user. PK on `user_id`. RLS enabled.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| `user_id` | uuid | NO | — |
| `email` | text | NO | — |
| `full_name` | text | YES | — |
| `school_key` | text | YES | — |
| `school_label` | text | YES | — |
| `mba_year` | text | YES | — |
| `target_geos` | text[] | YES | — |
| `target_fns` | text[] | YES | — |
| `goals_note` | text | YES | — |
| `created_at` | timestamptz | YES | `now()` |
| `updated_at` | timestamptz | YES | `now()` |
| `onboarding_completed_at` | timestamptz | YES | — |
| `onboarding_skipped_at` | timestamptz | YES | — |
| `tours_completed` | jsonb | YES | `'[]'::jsonb` |
| `hints_dismissed` | jsonb | YES | `'[]'::jsonb` |
| `digest_opt_in` | boolean | YES | `false` |
| `role` | text | YES | `'student'` |

Notes:
- `target_geos`, `target_fns`, `goals_note` exist in schema but are **unused** — no UI collects them (deliberately dropped in Task OB-CLEANUP). Columns retained for backward compatibility.
- `role` added 2026-06-07. Values: `'student'` (default), `'admin'` (careers team). Used by admin RLS policies for school-scoped cross-user read access.
- `mba_year` wired into onboarding step 1 and profile modal as of Task OB-CLEANUP.

**Policies:**
- `own_profile_select` — SELECT where `auth.uid() = user_id`
- `own_profile_update` — UPDATE where `auth.uid() = user_id`
- `own_profile_upsert` — INSERT with check `auth.uid() = user_id`
- `admin_read_profiles` — SELECT where requesting user has `role = 'admin'` AND matching `school_key` (school-scoped admin access)

---

## 4. `user_scan_history`

One row per completed AI résumé scan. PK on `id`. RLS enabled.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| `id` | uuid | NO | `gen_random_uuid()` |
| `user_id` | uuid | NO | — |
| `result` | jsonb | NO | — |
| `resume_chars` | integer | YES | — |
| `program_count` | integer | YES | — |
| `created_at` | timestamptz | YES | `now()` |

Index: `idx_scan_history_user`.

**Policies:**
- `users read own scans` — SELECT where `auth.uid() = user_id`
- `users insert own scans` — INSERT with check `auth.uid() = user_id`
- `admin_read_scans` — SELECT where requesting user has `role = 'admin'` AND matching `school_key` via join to `user_profiles`

---

## 5. `user_applications`

Main user-data table. One row per pipeline card. PK on `id` (uuid). RLS enabled.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| `id` | uuid | NO | `gen_random_uuid()` |
| `user_id` | uuid | NO | — |
| `program_id` | integer | YES | — |
| `name` | text | NO | — |
| `org` | text | YES | — |
| `geo` | text | YES | — |
| `fn` | text | YES | — |
| `sector` | text | YES | — |
| `url` | text | YES | — |
| `visa` | boolean | YES | — |
| `status` | text | NO | `'networking'` |
| `applied_on` | date | YES | — |
| `deadline` | date | YES | — |
| `next_step` | text | YES | — |
| `contact` | text | YES | — |
| `notes` | text | YES | — |
| `created_at` | timestamptz | YES | `now()` |
| `updated_at` | timestamptz | YES | `now()` |

Indexes: `idx_user_apps_status`, `idx_user_apps_user`.

**Pipeline stages (status values):** `shortlisted → networking → drafting → applied → interview → offer → rejected`. Defined in `STAGES` array in `app.js`.

**Policies:**
- `own_apps_all` — ALL where `auth.uid() = user_id`, check `auth.uid() = user_id`
- `admin_read_apps` — SELECT where requesting user has `role = 'admin'` AND matching `school_key` via join to `user_profiles`

---

## 6. `user_resumes`

One row per user (upserted). PK on `user_id`. RLS enabled.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| `user_id` | uuid | NO | — |
| `file_name` | text | YES | — |
| `raw_text` | text | NO | — |
| `char_count` | integer | YES | — |
| `parsed` | jsonb | YES | — |
| `last_scan_at` | timestamptz | YES | — |
| `uploaded_at` | timestamptz | YES | `now()` |

**Policies:**
- `own_resume_all` — ALL where `auth.uid() = user_id`, check `auth.uid() = user_id`
- `admin_read_resumes` — SELECT where requesting user has `role = 'admin'` AND matching `school_key` via join to `user_profiles`. **GDPR note:** admin dashboard should only show `user_id` existence (Y/N), NOT `raw_text` content.

---

## 7. `user_contacts`

Networking Tracker data. PK on `id` (bigint identity). RLS enabled.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| `id` | bigint | NO | identity |
| `user_id` | uuid | NO | — |
| `full_name` | text | NO | — |
| `company` | text | YES | — |
| `role_title` | text | YES | — |
| `linkedin_url` | text | YES | — |
| `email` | text | YES | — |
| `status` | text | NO | `'identified'` |
| `last_contacted` | date | YES | — |
| `follow_up_date` | date | YES | — |
| `notes` | text | YES | — |
| `related_app_id` | uuid | YES | — |
| `created_at` | timestamptz | YES | `now()` |
| `updated_at` | timestamptz | YES | `now()` |

FK: `related_app_id` → `user_applications.id`.

**Contact stages (status values):** `identified → reached_out → responded → call_scheduled → call_done → referral_received`.

**Policies:**
- `own_contacts_all` — ALL where `auth.uid() = user_id`, check `auth.uid() = user_id`

---

## 8. `programs`

Public LDP catalog. PK on `id` (integer, auto-increment). RLS enabled with multi-tenant visibility.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| `id` | integer | NO | `nextval('programs_id_seq')` |
| `company` | text | NO | — |
| `program_name` | text | NO | — |
| `industry` | text | YES | — |
| `function` | text | YES | — |
| `location` | text | YES | — |
| `duration` | text | YES | — |
| `deadline` | date | YES | — |
| `salary` | text | YES | — |
| `visa` | boolean | YES | `false` |
| `url` | text | YES | — |
| `tier` | integer | YES | `2` |
| `school_partners` | text[] | YES | — |
| `last_verified` | text | YES | `'May 2026'` |
| `created_at` | timestamptz | YES | `now()` |
| `geo` | text | YES | — |
| `dlnote` | text | YES | — |
| `status` | text | YES | — |
| `tags` | text[] | YES | — |
| `notes` | text | YES | — |
| `program_type` | text | YES | — |
| `description` | text | YES | — |
| `eligibility` | text | YES | — |
| `target_degree` | text | YES | — |
| `work_experience` | text | YES | — |
| `source_url` | text | YES | — |
| `logo_url` | text | YES | — |
| `last_verified_at` | timestamptz | YES | — |
| `language_required` | text[] | YES | — |
| `is_active_cycle` | boolean | YES | `true` |
| `locations` | text[] | YES | — |
| `countries` | text[] | YES | `'{}'` |
| `continents` | text[] | YES | `'{}'` |
| `visible_to` | text[] | YES | `ARRAY['all']` |

Notes:
- `visible_to` controls multi-tenant visibility. `'all'` = visible to everyone. `'{esade}'` = visible only to users with matching `school_key`. 18 programs are currently ESADE-exclusive.
- `countries` and `continents` are derived from `locations` for geographic filtering.

**Policies:**
- `programs_select` — SELECT where `'all' = ANY(visible_to)` OR (user is authenticated AND user's `school_key` matches any value in `visible_to`)

---

## 9. `program_job_descriptions`

JD content per program. PK on `id` (uuid). RLS enabled. Currently empty (0 rows).

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| `id` | uuid | NO | `gen_random_uuid()` |
| `program_id` | integer | NO | — |
| `program_name` | text | NO | — |
| `source_url` | text | YES | — |
| `jd_text` | text | NO | — |
| `parsed_reqs` | jsonb | YES | — |
| `scraped_at` | timestamptz | YES | `now()` |
| `verified_at` | timestamptz | YES | — |
| `active` | boolean | YES | `true` |

**Policies:**
- `jd_read_all` — SELECT where authenticated

---

## 10. `community_intel`

Community-contributed program intel. PK on `id` (uuid). RLS enabled. Currently empty (0 rows).

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| `id` | uuid | NO | `gen_random_uuid()` |
| `user_id` | uuid | NO | — |
| `program_id` | integer | NO | — |
| `intel_type` | text | NO | — |
| `content` | text | NO | — |
| `is_anonymous` | boolean | YES | `false` |
| `upvotes` | integer | YES | `0` |
| `created_at` | timestamptz | YES | `now()` |

**Policies:**
- `intel_read_all` — SELECT where authenticated
- `intel_write_own` — ALL where `auth.uid() = user_id`

---

## 11. Admin RLS policies (added 2026-06-07)

School-scoped read access for careers team administrators. An admin user (`role = 'admin'` in `user_profiles`) can SELECT rows from student tables where the student's `school_key` matches the admin's `school_key`. No UPDATE/INSERT/DELETE access — admins can observe but not modify student data.

| Policy | Table | Access |
|--------|-------|--------|
| `admin_read_profiles` | `user_profiles` | SELECT same-school profiles |
| `admin_read_apps` | `user_applications` | SELECT same-school applications (via join to `user_profiles`) |
| `admin_read_scans` | `user_scan_history` | SELECT same-school scan rows (via join to `user_profiles`) |
| `admin_read_resumes` | `user_resumes` | SELECT same-school résumé rows (via join to `user_profiles`) |

**GDPR note:** The admin dashboard UI should only surface résumé existence (Y/N) and scan counts — NOT `raw_text` from `user_resumes` or `result` JSON from `user_scan_history`.
