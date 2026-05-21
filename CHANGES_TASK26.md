# Task 26 — SEO head, cache headers, lazy parsers, OG/favicon wiring

## 1. Removed http-equiv cache meta tags

Deleted the three old `<meta http-equiv>` tags for Cache-Control, Pragma,
and Expires. They were ignored or partially honoured by browsers, never
reached any CDN, and were the reason PageSpeed flagged "use efficient
cache lifetimes" against ~6,286 KiB of static assets. Cache policy now
lives in HTTP headers — see step 4.

## 2. Added SEO + social meta + favicons + JSON-LD

In `<head>` after `<title>`: `description`, `canonical`, six favicon
links, `theme-color`, eight OG tags (incl. explicit `og:image:width`
and `og:image:height` so LinkedIn/Slack render the 1200×630 card
without a second fetch), four Twitter `summary_large_image` tags, and
a single-line JSON-LD `WebApplication` block.

Note: the description carries a hand-maintained "422 verified" program
count. This is not derived from `data.js` — keep it in sync manually or
replace with a number-free phrasing if you don't want to maintain it.

## 3. Lazy-loaded résumé parsers; deferred supabase

### `index.html`
- Removed both `<script>` tags for pdf.js and mammoth from `<head>`.
- Added `defer` to the supabase-js tag.

Why supabase can defer: I checked the inline bootstrap script that runs
right after (the localStorage `sb-*-auth-token` lookup that picks the
initial page). It does NOT reference the Supabase global — it only reads
localStorage keys by name pattern. So Supabase doesn't need to be parsed
before the bootstrap runs. The first actual use of `supabase.createClient`
is in `app.js`, which loads after. `defer` here is safe and removes the
last render-blocker on the landing page.

### `app.js`
Added the helper `ensureResumeParsers()` right above
`extractTextFromFile()`:

```js
let _parsersLoaded = false;
async function ensureResumeParsers(){
  if(_parsersLoaded) return;
  const load = src => new Promise((res, rej) => {
    const s = document.createElement('script');
    s.src = src; s.onload = res; s.onerror = rej;
    document.head.appendChild(s);
  });
  await Promise.all([
    load('https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.16.105/pdf.min.js'),
    load('https://unpkg.com/mammoth@1.6.0/mammoth.browser.min.js')
  ]);
  _parsersLoaded = true;
}
```

Called inside `extractTextFromFile()` AFTER the plain-text early-return
but BEFORE the DOCX/PDF branches. This way a `.txt` upload doesn't
trigger an unnecessary network fetch for the parsers, while every other
path waits for both to load exactly once per session.

Kept the existing `typeof mammoth === 'undefined'` / `typeof pdfjsLib
=== 'undefined'` guards as a fallback — if the CDN load fails mid-flight,
the user gets the existing "Please refresh and try again" error instead
of a TypeError.

### Test plan (do this after deploy)
1. Sign in → AI Fit Scan → upload a `.pdf` → confirm text extracts and
   the scan runs.
2. Same flow with a `.docx`. (Both must work — pdf.js and mammoth are
   loaded together in a single `Promise.all`, so verifying one verifies
   the load path but not necessarily both libraries.)
3. Network tab on the landing page: confirm pdf.min.js and
   mammoth.browser.min.js are NOT requested until you actually pick a
   file. They should appear in the waterfall only on first upload.
4. Second upload in the same session — confirm parsers aren't re-fetched
   (the `_parsersLoaded` flag short-circuits).

## 4. Cache headers via `vercel.json`

New file `ldp-scout/vercel.json`:

```json
{
  "headers": [
    { "source": "/(.*)\\.(png|svg|ico|webmanifest)", "headers": [{ "key": "Cache-Control", "value": "public, max-age=31536000, immutable" }] },
    { "source": "/(app.js|styles.css|data.js)", "headers": [{ "key": "Cache-Control", "value": "public, max-age=0, must-revalidate" }] }
  ]
}
```

- Favicons, og-image, manifest: cached one year, marked `immutable`.
  If you ever update `og-image.png` you'll need to rename it (or add a
  `?v=2` query string) to force a refetch.
- `app.js`, `styles.css`, `data.js`: `max-age=0, must-revalidate` — the
  browser revalidates on every request but Vercel returns a fast 304
  when unchanged. Preserves the "always-fresh app code" behavior the
  original `no-cache` meta was aiming for.
- `index.html` is not listed; Vercel's default serves it with
  revalidation, which is what we want.

## 5. Missing asset

`apple-touch-icon.png` was listed in the spec as already in the repo but
is not actually present in `ldp-scout/` — confirmed via directory listing.
The `<link rel="apple-touch-icon">` tag is in place; the file will 404
silently until committed. iOS falls back to the favicon, so nothing
breaks visibly, but the home-screen icon will look low-res until the
file ships.

## Validation checklist (post-deploy)

- [ ] Favicon shows in browser tab on ldpscout.com.
- [ ] `view-source:` shows all OG, Twitter, canonical, JSON-LD tags.
- [ ] opengraph.xyz preview shows the 1200×630 og-image card.
- [ ] LinkedIn Post Inspector shows the same.
- [ ] Network panel: og-image.png returns `Cache-Control: public, max-age=31536000, immutable`.
- [ ] Network panel: app.js returns `Cache-Control: public, max-age=0, must-revalidate` and 304s on second load.
- [ ] Landing page Network panel does NOT request pdf.min.js or mammoth.browser.min.js until the user picks a file.
- [ ] PageSpeed: SEO moves off 80, "Use efficient cache lifetimes" warning clears, and the "Eliminate render-blocking resources" line drops by roughly the pdf.js + mammoth + supabase weight.
