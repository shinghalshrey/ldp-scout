# LDP Scout — Code Audit Report

Scope: `app.js` (6.6k lines), `styles.css` (2.6k lines), `index.html` (1.0k lines).
Method: targeted static reading + live DOM inspection in a local static-server preview.
**Audit only — nothing here is fixed except the red-hint change** (Task I small fix, see end).
Severity: 🔴 BUG (broken) · 🟡 WARNING (fragile / edge-case / confusing) · 🟢 CLEANUP.

Line numbers are as of this commit; the red-hint edit shifts code in `openContactModal`
by ~+7 lines below `app.js:6456`.

---

## 🔴 BUGS

### B1 — Unescaped user input in the Applications kanban (stored self-XSS)
`app.js:4368` and `app.js:4369`, inside `renderApplications()`:
```js
${a.next?`<div class="apnx">→ ${a.next}</div>`:''}
${a.contact?`<div ...>👤 ${a.contact}</div>`:''}
```
`a.next` (next_step) and `a.contact` are **user-entered** application fields rendered into
`innerHTML` **without escaping**, while the sibling fields right above them *are* escaped
(`esc(a.name)` 4365, `esc(a.org)` / `esc(a.geo)` 4366). A value like
`<img src=x onerror=alert(1)>` in "Next step" executes on render.
Impact: self-XSS (own data, RLS-scoped), but a real injection and an obvious inconsistency.
**Fix:** wrap both in `esc()`: `→ ${esc(a.next)}` and `👤 ${esc(a.contact)}`.

### B2 — `showPage()` throws on an unknown page id
`app.js:2742`:
```js
document.getElementById('page-'+id).classList.add('active');
```
If `id` doesn't correspond to a `#page-<id>` element (typo in an `onclick`, stale deep link,
future tab rename), `getElementById` returns `null` and `.classList` throws, leaving the UI
half-switched (previous page already removed at 2740). No guard.
**Fix:** `const pg = document.getElementById('page-'+id); if(!pg) return; pg.classList.add('active');`

---

## 🟡 WARNINGS

### W1 — Other `.ics-modal-overlay` modals still at z-index 400 (same class of bug as Task F2)
`styles.css:634` sets `.ics-modal-overlay{z-index:400}`. Task F2 lifted only
`#contact-modal-overlay` to 900 (`styles.css:639`). These siblings remain at **400**, below
`.onboard-overlay` (600), `#landing-overlay` (700) and `#ov-onboard` (800):
- `#setpw-modal-overlay` (`index.html:864`) — **mandatory** post-OTP password setup
- `#profile-modal-overlay` (`index.html:881`)
- `#ics-modal-overlay` (`index.html:913`) — ICS deadline export
If any of these opens while a higher overlay is still mounted, it renders **underneath** and
its controls can't be clicked — exactly the F2 failure mode. **`#setpw-modal-overlay` is the
riskiest**: it appears right after OTP verification; if `#landing-overlay` (z-700) isn't
closed first it would be unreachable. Verify the auth ordering (`hideLanding()` at
`app.js:538` vs where setpw is shown around `app.js:2446`).
**Fix:** raise the shared `.ics-modal-overlay` above 800 (e.g. 900), or lift these three ids
individually as F2 did for the contact modal.

### W2 — Mandatory set-password modal is dismissible by clicking outside
`app.js:2542-2544` wires outside-click → `closeSetPasswordModal()` on `#setpw-modal-overlay`.
If this modal is meant to be mandatory (Task CD/auth comments call it "mandatory password
setup"), letting the user click the backdrop to dismiss it contradicts that.
**Fix:** for the mandatory case, don't bind backdrop-close (or have it re-assert the gate).

### W3 — No Escape-to-close on any modal (accessibility + UX)
The only keydown/Escape handler is `app.js:3929-3930`, scoped to stage dropdowns. The
contact, ICS, profile, setpw, onboarding (`#ov-*`), alumni and application edit modals can't
be dismissed with Esc — only via backdrop click or a Cancel button.
**Fix:** add a single document `keydown` handler that closes the top-most open overlay on
`Escape` (excluding the mandatory setpw case).

### W4 — Programs fetch failure is silent
`app.js:550` calls `await fetchProgramsFromSupabase();` and ignores its boolean return.
On failure the function returns `false` (`app.js:460/470/475`) and the app silently keeps
whatever `progs` already held (localStorage cache or the bundled `DP[]` from `data.js`,
`app.js:2194`). Good for resilience, but the user gets **no indication the catalog is stale**
and no retry affordance.
**Fix:** surface a non-blocking banner/toast when the fetch fails and stale data is in use.

### W5 — No hash/history routing; browser Back doesn't switch tabs
`showPage()` (`app.js:2733`) toggles `.page.active` and writes `ldps_last_page` to
localStorage, but never touches `location.hash`/`history`. There is no `hashchange`/
`popstate` listener. Refresh restores the last tab, but the **Back button doesn't move
between tabs** and tabs aren't deep-linkable.
**Fix (if desired):** drive `showPage` from `location.hash` and add a `popstate`/`hashchange`
listener. (Larger change — flagging, not prescribing.)

### W6 — Unescaped program fields + unvalidated `href` in alumni cards
`app.js:4133` / `app.js:4136` (`renderAlumniSearch` card):
```js
<div class="al-card-title">${p.url?`<a href="${p.url}" ...>${p.name}</a>`:p.name}</div>
<div class="al-card-meta">${p.org} · ${p.loc || p.geo || ''}</div>
```
`p.name`, `p.org`, `p.loc`, `p.geo` are interpolated unescaped, and `p.url` is dropped into
`href` without escaping/scheme validation. For the catalog these are trusted, but
**user-added programs** carry user-controlled `name`/`org`/`url`; if they surface in this
list a `javascript:` URL or markup injects. Same pattern at `app.js:4091-4101` (`${p.org}` in
chip text/titles).
**Fix:** `esc()` the text fields; validate `p.url` starts with `http(s)://` before using it
as `href`.

### W7 — Filter mutations write to localStorage on every keystroke
`renderPrograms()` calls `_persistFilterState()` (localStorage write) and rebuilds the entire
list `innerHTML` on every `oninput` (search box `index.html:287` → `renderPrograms`). Same for
`renderContacts()` (`app.js:6288` filter on each keystroke). Fine at current data sizes
(~400 programs) but it's synchronous DOM teardown + storage I/O per character.
**Fix:** debounce search input (~150 ms) before re-render/persist.

---

## 🟢 CLEANUP

### C1 — Debug `console.log`s that leak user PII
Non-diagnostic logs that print emails / user ids to the console:
`app.js:385, 386, 404, 406` (`[auth]` routing + email), `738, 794, 849, 922, 957`
(`[auth]` email/flags), `1854` (`[loadAndRenderLastScan] currentUser ... id`).
These should be removed or gated behind a debug flag (keep the `[TaskB/E/E2/CD/F/F2/J]`
diagnostics as instructed). `app.js:516` (`✓ Loaded N programs`) is harmless info.

### C2 — `--warn` CSS variable is undefined
The Task I red-hint uses `var(--warn, #C0562A)` but `--warn` is not defined anywhere in
`styles.css` (0 matches), so it always falls back to the literal. Either define `--warn` in
`:root` for reuse or accept the literal. Low priority.

### C3 — Two near-identical HTML-escape helpers
`_esc` (`app.js:37`) and `esc` (`app.js:5863`) both exist and are used in different parts of
the file. Consolidate to one to avoid divergence.

### C4 — Legacy stubs kept "so old onclick handlers don't error"
`enterApp()` (`app.js:2778`), `renderSchoolPills()`/`setAlumniSchool()` (`app.js:3694-3695`)
are explicitly legacy shims. If no live markup references them, remove; otherwise update the
callers. Verify with a grep for each name in `index.html`.

### C5 — Stale "will replace" comment
`index.html:307` previously read "Task 19.3 will replace with continent drill-down" — that
replacement shipped in Task E. Confirm the comment now reflects the implemented two-level geo
filter (it was updated during Task E; flagging so it stays accurate).

### C6 — Repeated per-render recomputation in `renderGeoFilter()`
`app.js` `renderGeoFilter()` recomputes `progs.filter(_continentMatch)` once **per continent
pill** plus a country pass, on every `renderPrograms()`. Correct, but it's O(continents × progs)
each render. Could compute counts in a single pass. Micro-optimization only.

---

## Areas checked that came back clean (positive notes)

- **Event handlers / double-binding:** card lists use inline `onclick` (no `addEventListener`
  re-binding on re-render), and the document/overlay/drag listeners
  (`app.js:2185, 3685, 3924, 3932-3933, 4977-4983, 2539-2553`) are attached once at module
  load / DOMContentLoaded. No double-binding found. Task CD's `event.stopPropagation()` on
  `.nt-email-link` and the status `<select>` is correctly scoped to those elements only.
- **Filter composition:** function/sector/continent/country/status compose with AND logic
  (`app.js:3120-3133` and the geo predicate `_geoPass`), and `clearAll()` (`app.js:2850`)
  resets all of them including the new geo Sets. Count badges refresh via
  `_refreshProgramsCounts`/`_refreshSidebarBadges`.
- **Fallback data:** `progs` initializes from localStorage→`DP[]` (`app.js:2194`);
  `loadUserApplications`/`loadUserContacts` set `[]` on error. Empty-states exist for
  programs (`app.js:3158`), contacts (`app.js:6298`), and the networking overview.
- **Supabase keys:** only the anon key is client-side (public by design). No other secrets
  found in `app.js`/`index.html`; the Claude API key lives behind the `ldp-proxy` Vercel
  function (`app.js:5007`), not in the client. (RLS sufficiency for `user_contacts` /
  `user_applications` is server-side and **out of scope for a frontend file audit** — verify
  in Supabase.)
- **Mobile:** breakpoints exist at 900/768/720/520/480 px (`styles.css`), including the
  documented 720 px (`styles.css:1247, 2376, 2648`) and a mobile single-column contact card.
  No obviously-broken element found in static reading; recommend a device-width spot check of
  the tall modals' `overflow-y:auto` (`.ics-modal` `styles.css:637`).

---

## Task I — the one fix applied (red hint)
`app.js` `openContactModal()` (~`6453-6466`): the "Add programs to My Applications first to
link contacts here." hint is now created once (idempotent) and its colour is set on **every**
open based on the dropdown's option count — `var(--warn, #C0562A)` (red) when only the
"— None —" option exists, `var(--text3)` (muted) once real applications are present.
Verified live: 1 option → `rgb(192,86,42)`; 2 options → `rgb(154,154,142)`; single hint node.
