# CHANGES — Task 27A (Applications overlay: foundation)

**Files changed:** `app.js`, `index.html`
**User-visible result:** when you type a deadline into the Log Application form,
*your* date now wins on the Deadlines page and in the downloaded `.ics`. A
program that had no catalog deadline, once you give it one, now shows up on the
Deadlines page with a working "Set reminder" button.
**No visible change to the modal** — the new piece is an invisible field.

This phase is the plumbing. The "Added by you" programs list (27B) and the modal
relabel + mailto replacement (27C) come later. Nothing here unions new rows into
the Programs page or changes how the page looks.

---

## 1. The deadline now prefers YOUR date (the actual bug fix)

**Before:** if you logged an application against a catalog program and typed your
own deadline, that deadline was thrown away. The Deadlines page and calendar
export always used the *catalog's* date instead. Your typed date went nowhere.

**After:** a new function `resolveProgramView(p)` merges your application onto each
catalog program and decides the deadline like this:

> **your deadline if you entered one, otherwise the catalog's deadline.**

That's it. Catalog facts (function, sector, geography, location, language, tier,
active-cycle) are *never* changed by your application — only the deadline is yours
to override.

### Why the code says `||` and not `??` (do not "fix" this later)

These two look interchangeable but are not, and getting it wrong silently breaks
the feature:

- The form can save an **empty deadline** (`""`) — e.g. you logged a program but
  left the date blank.
- `??` only treats `null`/`undefined` as "missing". An empty string `""` is NOT
  null, so with `??` the empty string would count as "your deadline" and **beat**
  the catalog date — meaning a dated catalog program would suddenly show no date.
- `||` treats `""` as "missing" too, so it correctly falls back to the catalog
  date.

So: **`app.deadline || program.deadline`**. If a future edit changes this to `??`,
catalog deadlines will start disappearing for any program you've logged without a
date. The code has a comment saying this; keep it.

---

## 2. The hidden field that remembers WHICH program you picked

**The problem it solves.** The "Program / Role" box is a text box with a
suggestion list. A text box only knows the *words* in it — it has no idea which
catalog program those words belong to. The catalog's real link is a hidden number
(the program's `id`), and the text box never sees that number. Until now, the app
**never recorded that number at all** — every logged application was saved with no
link to its catalog program. The Deadlines page faked the link by matching on the
program *name*, which is fragile (rename, extra space, etc. and the link breaks).

**The fix.** A new invisible field (`<input type="hidden" id="aps-program-id">`)
sits next to the text box. Its only job is to hold that id number.

**The rule — set on match, blank on everything else, on every keystroke:**

Every time you type or change anything in the Program box, the app asks: *does
what's in the box right now EXACTLY match a real catalog program name?*

- **Yes** → it writes that program's id into the hidden field.
- **No** — including an empty box, a half-typed name, a name that doesn't match,
  OR a name you edited *after* picking one so it no longer matches → it **wipes the
  hidden field blank.**

When you press Save:
- hidden field has a number → the application is **linked** to that catalog
  program (deadlines and, later, AI Fit line up correctly).
- hidden field blank → it's a program you typed yourself, saved as a **user-added**
  program (`program_id = null`).

### Why the "blank it" step is load-bearing (the regression trap)

This is the thing a future edit could quietly break. Picture this sequence:

1. You pick **"Amazon Pathways Operations LDP"** → hidden field stores its id, say `42`.
2. You then edit the text to **"Amazon Pathways Ops (London)"** — now it matches
   *nothing* in the catalog.
3. If the code only ever *sets* the id and forgets to *clear* it, the hidden field
   still says `42`. You press Save and the app silently files your made-up program
   **under Amazon Pathways' id.**

No error. No warning. Just wrong data — in a table that has **no backups**. That's
why the code clears the hidden field on *every* input event that isn't an exact
match, not just when the box is empty. In `autoFillFromProgram` this is the
`hid.value = p ? p.id : ''` line — the `: ''` half is the safety. **Do not remove
the blank branch when editing this function.**

### Editing an existing application keeps its link

When you open an already-logged application to edit it, the hidden field is
pre-filled from that application's stored `program_id` (one new line in `openM`).
Without this, editing and re-saving a linked application would blank its link
(because `autoFillFromProgram` only fires when you type, not when the form opens).

---

## 3. What did NOT change in 27A (known, intentional)

- **The Programs table still shows the catalog deadline**, not your overridden
  one. 27A wires the resolver into the **Deadlines page and ICS only** (that's the
  high-value, low-risk surface). The Programs-table deadline cell gets the resolver
  in a later phase. So after 27A it's expected that a program you've given a custom
  deadline shows your date on the *Deadlines* page but the catalog date on the
  *Programs* table. This is a phasing choice, not a bug.
- **No "Added by you" rows** appear on the Programs page yet — that's 27B.
- **The modal label, the "+ Add new program" affordance, and the mailto link** are
  untouched — that's 27C.

## 4. Edge case (documented, deliberately not fixed)

If you type a brand-new custom program (no id), and *later* an admin adds a catalog
program with the **exact same name**, the resolver's name-fallback will match your
old application to that new catalog row, and your free-standing entry visually
"merges" into the catalog row. Because precedence is `||`, **your data still wins**
(your deadline, your stage) — the only effect is the row shows once instead of
twice. We're choosing to live with this; documenting so it isn't mistaken for a bug.

## 5. Diagnostics left in (strip after verification)

Two `console.log` lines, both prefixed `[overlay]`:
- in `resolveProgramView` — fires only when your deadline actually overrides a
  catalog date (so it's quiet, not 422 lines per render).
- in `autoFillFromProgram` — shows the captured id (or "blank → user-added") each
  time you type in the Program box.

Open the browser console (F12) during testing to watch these. We remove them
before the feature is considered done.

---

## Test checklist (write AND read paths)

1. **Override an existing deadline.** Log an application for a catalog program that
   already has a deadline; type a *different* deadline; Save. Go to Deadlines →
   your date shows. Download the `.ics` → it carries your date. Console shows
   `[overlay] user deadline wins…`.
2. **Persist (read path).** Refresh the page (or sign out and back in). The override
   is still there — proves it saved to the database, not just memory.
3. **Give an undated program a date.** Log a catalog program that has *no* catalog
   deadline; type a deadline; Save. It now appears on the Deadlines page with a
   working "Set reminder" button.
4. **Capture check.** Open the Program box, pick a catalog program from the list —
   console shows a number. Edit the text so it no longer matches — console shows
   `(blank → user-added)`. (This proves the clear-on-edit safety works.)
5. **Edit keeps the link.** Open a linked application, change its stage, Save,
   refresh — it's still linked (its deadline still resolves correctly).
