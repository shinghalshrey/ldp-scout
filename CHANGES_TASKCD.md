# Task CD — Two small UX fixes (app.js)

## Fix C — Onboarding "Skip" lands on Command Center
**Was:** skipping the onboarding modal called `showPage('programs')`, dropping a brand-new
user straight into the Programs table.
**Now:** `onbSkip()` calls `showPage('command')`, so a skipping user lands on the Command
Center home dashboard (first-run cards) — consistent with the "complete without scan" path,
which already leaves the user on Command Center.

The other two paths were already correct and are untouched:
- Complete **with** résumé scan → `showPage('aifit')`.
- Complete **without** scan → modal closes, user stays on Command Center.

Diagnostic added in `onbSkip()`:
```js
console.log('[TaskCD] onbSkip landing:', 'command');
```

## Fix D — Show the contact email in the networking card
**Was:** the contact form has an email field (`ct-email`), it's stored in
`user_contacts.email`, the save handler reads it, and `loadUserContacts()` maps it to
`c.email` — but the contact card never displayed it. Users could enter an email but never
see it again.
**Now:** the networking contact card (`renderContacts()`) renders a clickable `mailto:` email
link on the same meta line as the LinkedIn link, with a small gap between them. When a
contact has no email, nothing is shown (no empty placeholder):
```js
const emailLink = c.email
  ? `<a class="nt-email-link" href="mailto:${_esc(c.email)}" title="${_esc(c.email)}" onclick="event.stopPropagation()">✉</a>`
  : '';
```
- Placed right after `${liLink}` in the `.nt-contact-meta` row.
- `onclick="event.stopPropagation()"` so clicking the email doesn't also open the edit modal
  (matches the LinkedIn link behaviour).
- The address is in the `title` so hovering reveals the full email; the badge itself shows ✉.

Styling (`styles.css`): added `.nt-email-link`, mirroring `.nt-li-link` exactly (same 22×22
badge), with an accent-coloured hover instead of LinkedIn blue.

Diagnostic added near the top of `renderContacts()` (logs only when the count changes, so it
doesn't spam on every search keystroke):
```js
console.log('[TaskCD] contacts with email:', <count of contacts with a non-empty email>);
```

## Verification
`node --check app.js` passes. Both changes are render-only/navigation-only — no data,
schema, or save-path changes.

## Files
- `app.js` — `onbSkip()` landing page + diagnostic; contact card email link + diagnostic.
- `styles.css` — `.nt-email-link` badge style.
