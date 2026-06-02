# Task J — Ground the AI gap analysis in real programs; stop fabrication

The AI Fit Scan makes two sequential Claude calls. Call 1 (Opus) classifies every program
into 5 tiers and works well. Call 2 (Sonnet) produces the gap analysis + coaching and was
broken. All fixes are in `app.js`, inside `runAIAnalysis()` (the Call 2 section, ~line 5110).
Call 1, the proxy (`scan.js`), the JSON schema, and the result-rendering code are untouched.

## Fix 1 — Feed Call 2 the actual target programs (not just tier counts)
**Before:** Call 2 only received tier *counts* (`tierContext` = "BEST_FIT: 3 programs · …")
plus the resume and a profile summary. With no program names or requirements, the gap
analysis was generic and effectively hallucinated.

**After:** before building `gapUsr`, we collect the IDs from the top three tiers
(BEST_FIT, STRONG_FIT, ACHIEVABLE — handling both `{id,reason}` objects and bare IDs), look
each up in the already-loaded `progs` array, cap at 15 to control tokens, and format each as:

```
<name> (<org>) — Eligibility: <≤120 chars> | Work exp: <…> | Target degree: <…>
```

These are appended to the Call 2 user message under a `TARGET PROGRAMS (your top matches —
base your analysis on these)` heading, so the model reasons against what the user's real
target programs actually require.

## Fix 2 — Rewrite the Call 2 system prompt (anti-fabrication guardrails)
The new `gapSys`:
- Tells the model it now has the top-fit programs with requirements and must ground the
  analysis in those **specific** programs.
- Keeps the same 6 dimensions (`leadership_evidence`, `international_exposure`,
  `operations_depth`, `quantitative_rigor`, `cross_functional`, `entrepreneurial_impact`)
  and the same Strong/Medium/Weak ratings, but each rating must be justified against the
  target programs' requirements, and evidence may be `"Not found in resume"` when genuinely
  absent.
- Adds **CRITICAL RULES** that directly answer the "asking me to lie" feedback:
  1. Ground every gap rating in the target programs' actual requirements — don't flag gaps
     the targets don't require.
  2. **Never** suggest fabricating/inventing/adding experience the candidate lacks — only
     reframe, reposition, or better highlight *existing* experience; for true gaps say
     "Consider gaining experience in X", not "Add X to your resume."
  3. Tips must be honest — for a Weak dimension, acknowledge it and suggest real steps
     (courses, projects, volunteering), never misrepresentation.
- Suggestions (still exactly 6) must reference 1–3 target programs by name and only suggest
  reframing existing experience or concrete skill-building next steps.

**Schema is unchanged** — same `gap_analysis` dimension objects (`rating`/`evidence`/`tip`)
and same `suggestions` shape (`title`/`body`/`priority`/`helps_programs`) — so the existing
render functions work as-is. Only the `body` guidance widened from <40 to <50 words.

## Fix 3 — Helper text under the "Related Application" dropdown
The contact modal's Related Application `<select>` (`id="ct-app-id"`) now has a small muted
hint beneath it: *"Add programs to My Applications first to link contacts here."*

Because the deliverable is "commit app.js only" and the select's markup lives in
`index.html`, the hint is **injected from `app.js`** in `openContactModal()` — created once
and guarded by a `.ct-app-hint` check so it never duplicates across modal re-opens. Styled
inline with `var(--text3)` to match the design system.

## Diagnostics
```js
console.log('[TaskJ] gap analysis — top programs sent:', topPrograms.split('\n').length,
            'total chars:', gapUsr.length);
```

## Verification
- `node --check app.js` passes.
- Fix 3 verified live in-browser: opening the contact modal twice yields exactly **one**
  `.ct-app-hint`, positioned immediately after the select, with the muted `--text3` color.
- Fix 1/2 are prompt/payload changes on the Call 2 request; they require a live scan (proxy +
  auth) to exercise end-to-end. The payload-construction logic is pure and syntax-checked, and
  the output JSON schema is deliberately unchanged so rendering is unaffected.

## Out of scope (untouched)
Call 1 tier classification, the `scan.js` proxy, the gap-analysis rendering code, and the
JSON schema.
