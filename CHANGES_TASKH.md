# Task H — Clarity + Sentry instrumentation, plus 4 audit-bug fixes

## Instrumentation

### Microsoft Clarity (`index.html` `<head>`)
The Clarity loader snippet (project **`x0qag8w613`**) is added immediately after
`<meta charset>` — **before any other script**, including GA — so sessions are captured from
the earliest possible point.

### Sentry (`index.html` `<head>`)
The Sentry Loader Script (`js-de.sentry-cdn.com/490b817b08cd87c36085650541a6f13a.min.js`,
`crossorigin="anonymous"`) is added right after Clarity. The loader auto-initializes from the
DSN embedded in the URL — no `Sentry.init()` call is needed.

### Global async-error handler (`app.js`, top, after the auth globals)
```js
window.addEventListener('unhandledrejection', function(event) {
  console.error('[LDPScout] Unhandled promise rejection:', event.reason);
});
```
This surfaces unhandled async errors (e.g. failed Supabase calls) in the console; Sentry's
loader also hooks `unhandledrejection`/`window.onerror`, so the same errors reach Sentry.

### Diagnostics
```js
console.log('[TaskH] Clarity project: x0qag8w613');
console.log('[TaskH] Sentry loader: active');
```

## Audit bug fixes

### B1 — XSS: unescaped fields in the Applications kanban (`app.js`, `renderApplications`)
`a.next` and `a.contact` were interpolated into card `innerHTML` **unescaped**, while the
neighbouring `a.name`/`a.org`/`a.geo` were escaped. Now both are wrapped in `esc()`:
```js
${a.next?`<div class="apnx">→ ${esc(a.next)}</div>`:''}
${a.contact?`<div ...>👤 ${esc(a.contact)}</div>`:''}
```

### B2 — `showPage()` throws on an unknown page id (`app.js`, `showPage`)
Added a null guard **before** any DOM mutation, so a bad id no longer throws and leaves the UI
half-switched:
```js
const el = document.getElementById('page-'+id);
if(!el){ console.warn('[nav] unknown page:', id); return; }
```
(The active-class swap now uses this `el` reference.)

### W1 — modal overlays at z-index 400 could open under higher overlays (`styles.css`)
`#contact-modal-overlay` was already lifted to 900 in Task F2, but its siblings that share the
`.ics-modal-overlay` class (`#setpw-modal-overlay`, `#profile-modal-overlay`,
`#ics-modal-overlay`) were still at **400** — below the landing (700), onboarding (600) and
onboarding-wizard (800) overlays. The **mandatory post-OTP set-password modal** was the real
risk: it can appear while the landing overlay is still mounted, which would render it
unreachable. Fix: lifted the **shared base** `.ics-modal-overlay` z-index from 400 → **900**,
which covers all four modals at once, and **removed the now-redundant** F2-specific
`#contact-modal-overlay{z-index:900}` rule (no duplication).

### W6 — unescaped `href`/text in alumni cards (`app.js`, alumni card render)
The alumni `al-card-title`/`al-card-meta` put `p.url` straight into `href` and interpolated
`p.name`/`p.org`/`p.loc`/`p.geo` unescaped — fine for catalog rows but an injection vector for
user-added programs (incl. attribute breakout / markup). Now escaped to match the rest of the
codebase (the Programs table already used `esc(p.url)`/`esc(p.name)`):
```js
${p.url?`<a href="${esc(p.url)}" ...>${esc(p.name)}</a>`:esc(p.name)}
...
<div class="al-card-meta">${esc(p.org)} · ${esc(p.loc || p.geo || '')}</div>
```

## Verification (in-browser)
- Console shows `[TaskH] Clarity project: x0qag8w613` and `[TaskH] Sentry loader: active`.
- `window.clarity` is a function (inline stub ran); the Clarity and Sentry `<script>` tags are
  both present in the document.
- A deliberately-rejected promise triggered `[LDPScout] Unhandled promise rejection: …` —
  the global handler works.
- All four overlays (`contact`, `setpw`, `profile`, `ics`) compute **z-index 900**.
- `showPage('___nope___')` returns safely (warns, no throw).
- `node --check app.js` passes.

## Files
`index.html` (Clarity + Sentry), `app.js` (error handler, diagnostics, B1, B2, W6),
`styles.css` (W1), `CHANGES_TASKH.md`.
