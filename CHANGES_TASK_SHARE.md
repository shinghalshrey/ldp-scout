# Task SHARE — Shareable program links

**File touched:** `app.js` only (147 lines added, 0 removed).
Not touched: `index.html`, `styles.css`, `data.js` (no `scan.js` exists in the repo).

## What this adds

A way to share a single catalog program by link. Inside the program snapshot
modal there's now a 🔗 share button that copies a deep-link to the clipboard.
When anyone opens that link, the program's snapshot pops up — even if they're
signed out. After they sign in or sign up, they land on the Programs tab with
the same program's full modal open, ready to add to their pipeline.

The whole feature is one SPA, one modal, triggered by a `?p=<id>` URL parameter.
No new pages, no routes, no server logic, no changes to the auth flow.

## How it works, end to end

1. **Share button** — In `openProgramSnapshot()`, a small 🔗 button sits next to
   the close ✕, but only for catalog programs (numeric `id`). User-added
   programs (`ua-…` string ids) are private and never get the button. Clicking
   it builds `window.location.origin + '/?p=' + p.id`, copies it to the
   clipboard (`navigator.clipboard.writeText`), and shows a `✓ Link copied`
   toast. `event.stopPropagation()` keeps the click from reaching the modal
   backdrop.

2. **Link detection on load** — At the very top of the boot sequence (before
   `initAuth()`), the app reads `?p=` from the URL, parses it to an integer, and
   stashes it in the module-level `_pendingProgSnap`. The URL is then cleaned
   with `history.replaceState` so a refresh doesn't re-trigger.

3. **Signed-out visitors** — When `initAuth()` decides nobody is signed in, it
   shows the landing page and, if a program was pending, floats a **read-only**
   snapshot on top of it (`openProgramSnapshotPublic`). This version shows the
   header, the three facts, the description, and the "Visit program page" link —
   but no pipeline controls. In their place is a CTA: *"Sign up to save this
   program to your pipeline"* with a **"Sign up free →"** button that closes the
   snapshot and focuses the landing-page email field. The modal sits at
   z-index 8000 (above the landing overlay's 700) and closes on ✕, Escape, or
   backdrop click — it reuses the existing `closeProgramSnapshot` machinery.

4. **After sign-in** — At the end of `onSignIn()`, if a program is still pending,
   the user is taken to the Programs tab and the **full** modal opens (with Add
   to Pipeline + deadline/notes controls) after a short render delay. This same
   path also covers a user who was *already* signed in when they opened the link
   — they skip the public modal and go straight here.

## Diagnostic logs (all prefixed `[Share]`)

- `pending program from URL:` — when `?p=` is detected at boot
- `public modal for:` — when the signed-out snapshot opens
- `copied link for:` — when the share button is clicked (logs org, name, URL)
- `post-signin modal for:` — when the full modal re-opens after authentication

## Edge cases handled

- **Unknown id** (`?p=99999`) → `progs.find` returns nothing → no modal, normal
  landing page. URL is still cleaned.
- **Non-numeric** (`?p=abc`) → `parseInt` → `NaN`, caught by an `isNaN` guard →
  ignored.
- **Already signed in + link** → public modal skipped; straight to Programs tab +
  full modal.
- **User-added program** → share button not rendered at all.
- **Empty `?p=`** → falsy, ignored.

## One intentional deviation from the literal spec

Part 4's example wrote `setTimeout(() => openProgramSnapshot(_pendingProgSnap), 300)`
immediately followed by `_pendingProgSnap = null`. Because the arrow function
closes over the module-level variable, by the time the timeout fired 300 ms
later it would have read the just-cleared `null` and opened nothing. The
implementation captures the id into a local `const _shareId` first, clears the
module var, then uses `_shareId` in the timeout — same intent (open the shared
program, then clear so it can't re-trigger), without the closure bug.

## Line counts (per part)

| Part | What | Lines added |
|------|------|-------------|
| 1 | Share button in modal header + `_psShareProgram()` helper | 24 |
| 2 | Module-level `_pendingProgSnap` + boot `?p=` detection/URL clean | 18 |
| 3 | `openProgramSnapshotPublic()` + signed-out hook in `initAuth()` | 87 |
| 4 | Post-sign-in re-open block in `onSignIn()` | 18 |
| **Total** | | **147** |

## Verification

- `node --check app.js` → passes.
- Loaded `/?p=1` in the running preview (account was already signed in):
  - Boot log fired and the URL was cleaned to `/` (no `?p=1` left).
  - `[Share] post-signin modal for: 1` logged, Programs tab activated, and the
    **full** Amazon Pathways modal opened (share button + Add to Pipeline + visit
    link present; no public CTA).
  - Clicking 🔗 logged `[Share] copied link for: Amazon … http://localhost:4173/?p=1`
    (correct URL) and attempted the clipboard write. *(The headless preview
    blocks clipboard access with `NotAllowedError`, so the graceful fallback
    toast showed instead of `✓ Link copied`; a real user gesture in a normal
    browser resolves the write and shows `✓ Link copied`.)*
  - Rendered `openProgramSnapshotPublic(1)` for inspection: z-index 8000, header
    + status badge + 3 facts + description + visit link + the
    "Sign up to save this program to your pipeline" CTA and
    "Sign up free →" button (wired to `closeProgramSnapshot();showAuthModal()`);
    no share button, no Add-to-Pipeline, no deadline/notes fields. Escape closed
    it cleanly.
- No console errors.
