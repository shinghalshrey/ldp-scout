# CHANGES — Alumni message fix + Task 27B (user-added programs on Programs page)

**File changed:** `app.js` only (+114 / −9). No `index.html`, no CSS, no DB change.
Two independent changes bundled (both app.js). If 27B misbehaves, a revert drops the
alumni fix too — but the alumni fix is ~25 trivial lines, easy to re-apply.

---

## Part 1 — Alumni "Draft Message" school identity fix

**Bug:** the draft message used the *dropdown-selected* school as the user's own identity.
Pick HEC and the note claimed you were an HEC MBA. Variant ② was also broken — it printed
a literal unfinished placeholder: `{if alumni, else: an MBA from HEC}`.

**Fix:**
- Your school now comes from your **profile** (`userProfile.schools[0]`, set at signup) and
  never changes with the dropdown. All three variants present you as an MBA at *your* school.
- Variant ② is now context-aware. When the alumni is from **your** school it reads as a
  shared-school note ("fellow {school} alum…", labelled "② Shared-school angle"). When they're
  from a **different** school it drops any shared-school claim and reads as a cross-school
  outreach ("I'm an MBA at {your school} researching…", labelled "② Cross-school angle").
- The broken `{if alumni…}` placeholder is gone.

The dropdown still controls *whose* alumni you're searching (the LinkedIn search links and the
"{school} alumni at {company}" chips are unchanged) — it just no longer rewrites who *you* are.

---

## Part 2 — Task 27B: user-added programs surface on the Programs page

**What:** a program you logged via "+ Add new program" that matches no catalog program now
appears as a row on the Programs page, marked "★ Added by you" and "Not scored".

**Architecture (deliberately low-risk):**
- User-added rows are built **at render time** and are **never added to `progs[]`**. So the
  résumé scan, the stat counts, and every other `progs[]`-based path ignore them completely —
  scan-exclusion is automatic, not a special case.
- "User-added" = an application with no `program_id` AND no catalog program matching its
  name+org. (So a row already linked to the catalog, or one whose name matches a catalog
  program, is shown once as the catalog row — never duplicated here.)
- They render through **separate functions** (`_userAddedRowHTML`, `_userAddedCardHTML`), so
  the existing catalog row/card templates are byte-for-byte untouched — zero regression risk to
  the 422 catalog rows.
- Reminders work: the synthetic `ua-<appId>` id is resolved straight from the application, so
  the 📅 button exports the user's deadline.

**Behaviour:**
- Pinned to the **top** of the Programs list, with an "★ Added by you" badge and a "Not scored"
  chip (no AI fit). Function/sector columns show "—".
- **Stage shows as a static badge**, not the editable dropdown (edit it on the My Applications
  tab). This is intentional for v1 — no synthetic-id plumbing into the stage dropdown.
- Hidden when any catalog filter (geo/function/sector/status/fit/visa/verified) is active — they
  have nothing to match. The search box still finds them by name/org. The My-Pipeline filter
  keeps them (they're always in your pipeline).
- The "X of 422 programs" meta count reflects **catalog** programs only (stays accurate against
  the real catalog size); user-added rows sit above it.

---

## Tested at my end (logic harness, mock data — 16 checks total this round)

- Alumni: covered by manual trace (message text — no pure logic to assert).
- 27B: 6/6 — only true orphans become user-added; catalog-linked and name-matching apps are
  excluded; synthetic ids namespaced; no-filter shows them; search filters them; an active
  catalog filter hides them.
- (Plus the 10 earlier checks for the resolver/dedup/27D filter still pass.)

## Verify on the live site

1. **Alumni** → Draft Message with your own school selected → variant ② says "fellow … alum".
   Switch the dropdown to a different school → the note still says you're at *your* school, and
   variant ② becomes "Cross-school angle" with no false shared-school claim.
2. **Programs** → "+ Add new program", add one with a made-up name + a deadline → Save. It now
   appears at the **top** of the Programs list as "★ Added by you / Not scored", with a working
   📅 reminder carrying your deadline.
3. Type a catalog filter (e.g. a sector) → the user-added row disappears; clear it → it returns.
4. Confirm the 422 catalog rows look and behave exactly as before (stage dropdowns, reminders,
   AI fit all unchanged).

## Deploy

```powershell
cd C:\Users\shrey\Desktop\LDP-Scout-Master\ldp-scout
git add app.js CHANGES_TASK27B.md
git commit -m "Alumni message school-identity fix + Task 27B: user-added programs on Programs page"
git push
```
Green check → hard-refresh (Ctrl+Shift+R). 27B touches the Programs render — **load the Programs
page first and confirm the catalog renders normally** before anything else. Revert if needed:
`git revert HEAD --no-edit && git push`.
