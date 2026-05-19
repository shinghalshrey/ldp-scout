# Task 20 — Remove hardcoded program count from static HTML

Link-preview crawlers (LinkedIn, WhatsApp, Slack, etc.) don't execute
JavaScript, so the OpenGraph card scraped from `ldpscout.com` was
showing whatever number was hardcoded in the static HTML — at the time
of this commit, "48" — even though the live, signed-in product had
grown well past that count and `app.js` was already swapping the value
in via `updateProgramCountInUI()` for actual users. Six occurrences of
`<span class="ldp-prog-count">48</span>` were rewritten in
`index.html` (the H1 the OG preview reads, the Programs page
subheading, the master-list line, the AI Fit step text, and the
search-bar hint) so the static copy no longer references a count. The
phrasing now reads "top verified MBA-specific LDPs", "All verified
MBA LDP rotational programs", etc. — accurate at any catalogue size.
`updateProgramCountInUI()` and the signed-in dashboard counters
("Showing all N programs", filter-result counts, stats card) are
untouched and keep rendering the live `progs.length` from Supabase.
Note: the document `<head>` has no `og:*` or `twitter:*` meta tags
today, so crawlers were falling back to the `<title>` and body text;
nothing OG-specific needed editing — adding proper OG tags is a
separate follow-up.
