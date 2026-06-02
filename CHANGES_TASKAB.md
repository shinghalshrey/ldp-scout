# Task AB — Application delete FK fix + feature discoverability hints

## Task A — Fix application delete (FK constraint bug)

**Bug:** deleting an application failed silently when a contact in `user_contacts` still
pointed at it via `related_app_id` (FK `user_contacts_related_app_id_fkey`). The DELETE was
rejected by the constraint, but the frontend removed the card optimistically anyway, so it
vanished and then reappeared on the next reload.

**Where:** the single delete path `deleteApplicationFromDB(id)` (`app.js`), called by both the
kanban stage "✕ Remove" (`setProgramStage(..., '__remove')`) and the edit-modal delete
(`delCurrentApp`). It was already keyed on the application **UUID `id`**, not `program_id`, so
that part was fine.

**Fix:** unlink referencing contacts before deleting, return a success boolean, and only
mutate local state on success:
```js
// 1. unlink contacts that reference this application
await sb.from('user_contacts').update({ related_app_id: null })
  .eq('related_app_id', id).eq('user_id', currentUser.id);
// keep in-memory contacts in sync
contacts.forEach(c => { if(c.related_app_id === id) c.related_app_id = null; });
// 2. then delete the application
const { error } = await sb.from('user_applications').delete()
  .eq('id', id).eq('user_id', currentUser.id);
if(error){ console.error('[deleteApp] failed:', error); toast(...); return false; }
return true;
```
- Diagnostic: `console.log('[TaskA] deleting app:', id, '— unlinking contacts first');`
- Both callers now do `const ok = await deleteApplicationFromDB(...); if(!ok) return;` **before**
  removing the card from `apps`/DOM — so a failed delete no longer makes the card flicker out
  and back. They also call `renderContacts()` so any unlinked contact reflects immediately.

## Task B — Feature discoverability hints

A shared, idempotent helper renders three small dismissible callouts. Each is removed and
re-added on every render (stable ids `hint-kanban` / `hint-addprogram` / `hint-pipeline`), so
they never duplicate and always reflect current eligibility/dismissal. Hint text is static —
no user input — so the `innerHTML` build is safe.

### B1 — Kanban drag hint (My Applications)
*"💡 Drag cards between columns to update your application stage"* — inserted **before**
`#app-kanban`. Shown only when the user has **1–3 applications** (new users). Has a ✕ that
persists `ldp_kanban_hint_dismissed`, and is **auto-dismissed on the first successful drag**
(`dropApp` writes the same key). Cleared in the 0-apps empty state too.

### B2 — "Add new program" explainer (Programs)
*"Can't find your program? Add it manually and track it in your pipeline."* — inserted
**after** the `+ Add new program` link (`.prog-request-link`). Shown only when the user has
**0 manually-added programs** (`_userAddedRows().length === 0`). Per the spec this is **static
text with no ✕** — it simply auto-hides once the user adds their first program.

### B3 — Pipeline filter hint (Programs)
*"Filter to see only programs in your pipeline"* — inserted **after** the `#prog-stats` row
(which holds the "★ My Pipeline" filter card; note the Programs-page pipeline filter is that
stat card, not the alumni-page `.pipeline-toggle` button). Shown when the user has **≥1
application**, the filter is **off**, and it hasn't been dismissed. Has a ✕ (persists
`ldp_pipeline_hint_dismissed`) and is **also dismissed the first time the user toggles the
pipeline filter** (`togglePipelineFilter`).

### Style (`styles.css`, `.feat-hint`)
Matches the spec: `font-size:13px; color:var(--text3,#8A9E98); background:var(--bg2,#f5f0e8);
padding:8px 16px; border-radius:8px; margin:8px 0;` as a flex row with the text on the left and
a small `.feat-hint-x` ✕ on the right.

### Diagnostic
`console.log('[TaskB] hints shown:', { kanban, addProgram, pipeline })` — emitted (change-
guarded so it doesn't spam) whenever the applications or programs page re-renders.

## Verification (in-browser)
- **A:** code path exercised via the two callers; `[TaskA]` log fires; in-memory contacts are
  unlinked. (The FK error itself needs a live Supabase row with a linked contact to reproduce
  end-to-end, but the unlink-then-delete ordering and the `if(!ok) return` guards are in place
  and syntax-checked.)
- **B1:** shows with 2 apps (correct text, ✕, positioned before the board); ✕ removes it and
  persists `=1`; hidden with 4 apps.
- **B2:** shows when `_userAddedRows().length === 0` (correct text, **no** ✕, after the link,
  style 13px/8px/radius 8px); hides once a user-added program exists.
- **B3:** shows with ≥1 app + filter off (correct text, ✕, after `#prog-stats`); toggling the
  filter persists dismissal and keeps it hidden; hidden with 0 apps.
- `node --check app.js` passes.

## Notes
- The diagnostic label `[TaskB]` collides with the earlier dlnote task's
  `[TaskB] deadline cells …` log. I kept `[TaskB] hints shown:` because the spec asked for that
  exact string; they're easy to tell apart by the suffix.
- B2 intentionally has no ✕ dismiss (the spec says "always visible until they add one"), which
  is a deliberate deviation from the generic "all hints have a ✕" style note.

## Files
`app.js` (Task A fix + hint helper/B1/B2/B3 + auto-dismiss hooks), `styles.css` (`.feat-hint`),
`CHANGES_TASKAB.md`.
