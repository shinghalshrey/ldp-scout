# Task F2 — Fix "Related Application" dropdown not opening in the Edit Contact modal

## Diagnosis (ran through the checklist against the live page)
The select is `<select id="ct-app-id" class="nt-modal-input">`, populated in `openContactModal()`.
I instrumented and inspected it in the running app (browser eval):

1. **Disabled?** No — `ct-app-id.disabled === false`.
2. **`pointer-events:none` / `overflow:hidden` on an ancestor?** No — walked every ancestor up
   to `<body>`; none had `pointer-events:none`.
3. **A stray `stopPropagation()`/`preventDefault()`?** No. Task CD's `event.stopPropagation()`
   is inline on the `.nt-email-link` anchor in the *card* render — it never touches the modal.
4. **z-index / overlay on top?** ✅ **This was it.**
5. **Options not loading?** No — the dropdown populated correctly (`options.length === 3` with
   apps present, always ≥1 for the "— None —" entry).

### Root cause — stacking
`document.elementFromPoint()` at the centre of the `ct-app-id` select returned a **`<video>`**
element, not the select (`topIsSelect === false`). That video lives inside
`#landing-overlay`, which is `position:fixed; z-index:700`.

The contact modal overlay (`#contact-modal-overlay`, class `.ics-modal-overlay`) sits at the
shared base **z-index: 400**. The app has several full-screen overlays stacked *above* it:

| overlay                         | z-index |
|---------------------------------|---------|
| `.ics-modal-overlay` (contact)  | **400** |
| `.onboard-overlay`              | 600     |
| `#landing-overlay`              | 700     |
| `#ov-onboard` (onboarding wiz)  | 800     |

When the contact modal opens while any of those higher overlays is mounted, that overlay's
full-screen element intercepts pointer events over the modal. Because **"Related Application"
is the bottom-most field**, it's the part most reliably covered — which is exactly why *that*
dropdown wouldn't open while the fields higher up (e.g. Status) still worked.

## Fix (`styles.css`)
Lift the contact modal above every other overlay (it's only ever opened from inside the
authed app, so it should always win the stack):
```css
#contact-modal-overlay { z-index: 900; }
```

## Diagnostics (`app.js`, in `openContactModal()`)
```js
console.log('[TaskF2] Related App dropdown — options count:', appSel ? appSel.options.length : 0,
            'disabled:', appSel ? appSel.disabled : null);
```

## Verification (before/after, in-browser)
With `#landing-overlay` deliberately open (the worst case, z-index 700):
- **Before:** `elementFromPoint` over the select → `VIDEO`, `topIsSelect: false` (covered).
- **After:** `#contact-modal-overlay` computes to `z-index: 900`; `elementFromPoint` over the
  select → `ct-app-id`, `topIsSelect: true`. The native dropdown is now reachable and opens.
- Diagnostic logs `options count: 3 disabled: false`. `node --check app.js` passes.

## Files
- `styles.css` — `#contact-modal-overlay { z-index: 900 }`.
- `app.js` — `[TaskF2]` diagnostic in `openContactModal()`.

## Note
The sibling ICS modals share `.ics-modal-overlay` at z-index 400 and have the same latent
fragility, but they aren't part of this report, so the fix is scoped to the contact modal as
requested. If desired, the base `.ics-modal-overlay` could be raised above the landing overlay
in a follow-up.
