# Task F — Show the linked program/application name on contact cards

## Bug
Filtering contacts by "Linked to an application" surfaced the right contacts, but the card
gave no hint of *which* application each contact was tied to. Users couldn't tell what a
linked contact was linked to.

## Fix (`app.js`, `renderContacts()`)
A contact's `related_app_id` references `user_applications.id`. Both contacts and
applications are already in memory, so no extra DB query is needed.

- The loaded applications array is **`apps`** (confirmed: `let apps = []`, populated by
  `loadUserApplications()`). Note the application's display name is mapped to **`a.name`**
  (from the `program_name`/`name` DB column), so the badge uses `linkedApp.name` with a
  `program_name` fallback.
- For each contact with a non-empty `related_app_id`:
  ```js
  const linkedApp = c.related_app_id ? apps.find(a => a.id === c.related_app_id) : null;
  const linkedBadge = linkedApp
    ? `<span class="ct-linked-program" title="Linked application">📋 ${_esc(linkedApp.name || linkedApp.program_name || 'Linked application')}</span>`
    : '';
  ```
- The badge is placed in the `.nt-contact-meta` row (alongside the follow-up chip and the
  LinkedIn/email links), so it sits next to the "Last contacted" / follow-up info.
- **Deleted-app safety:** if `related_app_id` is set but no matching application is found,
  `apps.find` returns `undefined` and nothing is rendered — no broken reference.

## Style (`styles.css`)
Added `.ct-linked-program`, matched to the existing design system (the project uses
`--text3` for muted text and `--bg3` for subtle fills, as on `.nt-li-link`):
```css
.ct-linked-program {
  font-size: 11px;
  color: var(--text3);
  background: var(--bg3);
  padding: 2px 8px;
  border-radius: 4px;
  display: inline-block;
  max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  vertical-align: middle;
}
```
(The truncation keeps long program names from blowing out the card.)

## Diagnostics
Near the top of `renderContacts()`, logged only when the count changes (so it doesn't spam
on every search keystroke):
```js
console.log('[TaskF] contacts with linked app:', <count where related_app_id is non-empty>);
```

## Verification
`node --check app.js` passes. Read-only render change — no data, schema, or save-path
changes, and no extra DB queries (reads the already-loaded `apps` array).

## Files
- `app.js` — linked-app lookup + badge in the contact card; diagnostic.
- `styles.css` — `.ct-linked-program` badge style.
