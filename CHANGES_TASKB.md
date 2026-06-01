# Task B — Stop rendering research notes (`dlnote`) in the deadline column

## What was broken
`dlnote` is a free-text **research/notes** field (e.g. "Applications opening soon — track
at…", "Reported discontinued at EHQ per ESADE careers", "No company identifiable as 'The
Perk Venture'…", "Watch careers.bayer.com"). Three places in the UI used it as a *fallback
for a missing deadline*, so whenever a program had no date these internal notes appeared
sitting in the **deadline** column / "Deadline:" line as if they were the deadline. They are
not deadlines.

## The fix — one helper, used in all 3 places
A single small helper now decides what shows in any deadline *position*, so the three call
sites behave identically and `dlnote` text can never leak into a deadline slot:

```js
function deadlineLabel(p, resolvedDate){
  const d = resolvedDate || p.deadline;
  if(d){
    const dt = new Date(d);
    if(!isNaN(dt.getTime())) return dt.toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'});
  }
  if(p.status === 'rolling' || /rolling/i.test(p.dlnote || '')) return 'Rolling';
  return '—';
}
```

Logic:
1. **Real date** (user-resolved deadline or `p.deadline`) → formatted date (unchanged behaviour).
2. **Rolling** — `status === 'rolling'` *or* the word "rolling" appears in `dlnote` → `"Rolling"`.
3. **Otherwise** → `"—"`. Never the raw `dlnote` text.

It lives next to the other program helpers (just above `_deadlineLineMobile`).

## The 3 spots fixed (`app.js`)
1. **Programs table row** (~line 3164) — was
   `const dl = rv.deadline ? <date> : (p.dlnote || '—');`
   now `const dl = deadlineLabel(p, rv.deadline);`
2. **Program meta card** — `_deadlineLineMobile()` (~line 3298) — previously fell back to a
   `⏰ <p.dlnote>` row. Now it calls `deadlineLabel(...)` and renders the `⏰` row **only**
   when the result is a date or "Rolling"; when the helper returns "—" it renders nothing
   (no empty/garbage row).
3. **Alumni card "Deadline:" line** (~line 3944) — previously fell back to
   `Deadline: <p.dlnote>`. Now uses `deadlineLabel(p)`, and if that is "—" the whole
   "Deadline:" span is omitted.

Out of scope (untouched): the deadline data itself, the ICS export, and the `dlnote` field
in the DB. This is a **render-only** change.

## Diagnostics
On every render of the Programs table we log a one-time tally so we can confirm nothing is
leaking:

```js
console.log('[TaskB] deadline cells — dates:', n, 'rolling:', n, 'dash:', n);
```

Run against the **seed dataset** (`data.js`, 48 programs) the logic produces:

```
[TaskB] deadline cells — dates: 12  rolling: 32  dash: 4
```

The 4 "dash" programs (ids 9, 20, 30, 45) are exactly the ones that *used* to leak their
notes — "Watch LinkedIn & careers page", "Watch careers.bayer.com",
"Watch careers.philips.com", "Watch LinkedIn and insudpharma.com/careers" — and now correctly
show "—". The live Supabase set (≈390 programs, including the "discontinued"/"opening soon"
notes) prints its own real counts to the console at render time; this log is the proof that
0 of them reach the deadline column as raw text.

## What a user now sees in the deadline column
- A program with a date → the formatted date (e.g. **1 Oct 2026**) — unchanged.
- A rolling program (by status or because the note says "rolling") → **Rolling**.
- Anything else (notes like "track at…", "Reported discontinued…", "Watch careers page") →
  a clean **—**. The note text no longer appears in the deadline position anywhere.
