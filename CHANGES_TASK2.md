# Task 2 — Change AI Fit scan quota from 5 → 3

## Every change made and where

### 1. `ldp-proxy/api/scan.js` — line 48

```diff
-const SCAN_QUOTA = 5;
+const SCAN_QUOTA = 3;
```

This is the **server-side source of truth**. All downstream references in the
same file (`scanCount >= SCAN_QUOTA`, the 429 error message
`Free scan limit reached (${SCAN_QUOTA} of ${SCAN_QUOTA})`, and the
`limit: SCAN_QUOTA` field in the JSON response body) use the constant
directly, so they all update automatically.

---

### 2. `ldp-scout/app.js` — line 1433

```diff
-const SCAN_QUOTA_CLIENT = 5;
+const SCAN_QUOTA_CLIENT = 3;
```

This is the **client-side mirror** used only for UI display. Every reference
in app.js (`renderQuotaExhausted`, the `scansUsedTxt` chip in
`renderAIResults`, the hard-block gate in `loadAndRenderLastScan` and
`runAIAnalysis`) reads this constant, so all UI strings update automatically.

---

### 3. Two stale comments in `app.js` updated

| Line (approx) | Before | After |
|---|---|---|
| ~1467 | `// If they've burned through all 5 scans` | `… all 3 scans` |
| ~3805 | `// … "X of 5 scans" chip` | `… "X of 3 scans" chip` |

No logic change — comments only.

---

## How the counter reads from Supabase (live count vs. cached)

The displayed count is **always seeded from a live Supabase query**, not from
a stale in-memory value.

**On AI Fit page entry:** `loadAndRenderLastScan()` runs. It calls
`sb.auth.getUser()` (Task 1B fix — ensures the session token is fully
propagated before querying), then executes:

```js
const countResp = await sb
  .from('user_scan_history')
  .select('id', { count: 'exact', head: true })
  .eq('user_id', user.id);
_scanCount = countResp.count || 0;
```

This sets `_scanCount` from the real row count in `user_scan_history`.

**After a successful scan:** `renderAIResults` is called with
`scans_used: optimisticCount` (i.e., `_scanCount + 1`). This gives instant
feedback without a round-trip. When `saveScanToHistory` completes, it also
bumps `_scanCount` so subsequent references stay consistent.

**Hard-block gate:** Both `loadAndRenderLastScan` (on page entry) and
`runAIAnalysis` (just before firing the API calls) compare `_scanCount`
against `SCAN_QUOTA_CLIENT = 3`. If `_scanCount >= 3`, `renderQuotaExhausted`
is called and the upload zone is hidden. The server also enforces this with a
429, so the gate is defended at both layers.

---

## Full updated scan.js

```js
import crypto from 'crypto';

// ─── Config ───────────────────────────────────────────────────────────
// CORS allowlist: production origin + localhost dev ports.
const ALLOWED_ORIGINS = new Set([
  'https://ldpscout.com',
  'https://www.ldpscout.com',
]);
const LOCALHOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

// Model whitelist — the three models the app actually calls.
// Opus 4.6: tier classification (high-stakes reasoning, expensive).
// Sonnet 4.5: gap analysis (smaller output, cheaper).
// Haiku 4.5: future use / fallback.
const ALLOWED_MODELS = new Set([
  'claude-opus-4-6',
  'claude-sonnet-4-5',
  'claude-haiku-4-5-20251001',
]);

// Absolute ceiling on max_tokens per call. Bumped from 6000 → 32000 to allow
// the tier classification call to return all 393+ programs in a single pass.
// Sonnet 4.5 and Opus 4.7 both support up to 64K output natively.
const MAX_TOKENS_CAP = 32000;

// Soft caps on payload size to limit abuse.
const MAX_SYSTEM_LEN = 8000;
const MAX_USER_LEN   = 300000;

// Supabase URL — used to fetch JWKS for ES256 verification AND to count
// completed scans for quota enforcement. Hardcoded to match frontend SUPA_URL;
// override via env (SUPABASE_URL) if you ever move projects.
const SUPABASE_URL = process.env.SUPABASE_URL
  || 'https://kqtarrgtxqpamlfrkgiv.supabase.co';
const JWKS_URL = `${SUPABASE_URL}/auth/v1/.well-known/jwks.json`;

// Supabase anon key — used to call the REST API for quota counting. The anon
// key is designed to be public (it's already in the frontend at app.js:14);
// security comes from Row Level Security policies on user_scan_history.
// Override via env (SUPABASE_ANON_KEY) for rotation flexibility.
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY
  || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtxdGFycmd0eHFwYW1sZnJrZ2l2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg1MDMxNzksImV4cCI6MjA5NDA3OTE3OX0.D6Foh3F2gS0d1lpWEHuc5incL-9LDW__17qRony9X2U';

// Free-tier scan quota — users get this many completed scans, lifetime.
// A "completed" scan = a row in user_scan_history (frontend writes one after
// both tier + gap calls succeed). Both calls in a single scan happen BEFORE
// the row is written, so checking on every call only blocks the (N+1)th scan.
const SCAN_QUOTA = 3;

// WebCrypto handle (Node 16+ exposes this; Vercel runs Node 20).
const subtle = crypto.webcrypto.subtle;

// ─── JWKS cache (10 min, matches Supabase edge cache) ─────────────────
let _jwksCache = null;
const JWKS_TTL_MS = 10 * 60 * 1000;

async function fetchAndCacheJwks() {
  const res = await fetch(JWKS_URL);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const jwks = await res.json();
  const keysByKid = new Map();
  for (const jwk of (jwks.keys || [])) {
    if (jwk.alg === 'ES256' && jwk.kty === 'EC' && jwk.kid) {
      const key = await subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
      keysByKid.set(jwk.kid, key);
    }
  }
  _jwksCache = { fetchedAt: Date.now(), keysByKid };
  return keysByKid;
}

async function getSigningKey(kid) {
  const now = Date.now();
  const fresh = _jwksCache && (now - _jwksCache.fetchedAt) < JWKS_TTL_MS;
  if (fresh) {
    const cached = _jwksCache.keysByKid.get(kid);
    if (cached) return cached;
  }
  const keysByKid = await fetchAndCacheJwks();
  const found = keysByKid.get(kid);
  if (!found) throw new Error(`unknown kid: ${kid}`);
  return found;
}

// ─── JWT verification (ES256 primary, HS256 legacy fallback) ──────────
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

async function verifySupabaseJWT(token, hs256Secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const [headerB64, payloadB64, sigB64] = parts;

  const header = JSON.parse(b64urlDecode(headerB64).toString('utf8'));
  const sigBytes = b64urlDecode(sigB64);
  const signingInput = `${headerB64}.${payloadB64}`;

  if (header.alg === 'ES256') {
    if (!header.kid) throw new Error('missing kid');
    const key = await getSigningKey(header.kid);
    const ok = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sigBytes,
      new TextEncoder().encode(signingInput),
    );
    if (!ok) throw new Error('bad signature');
  } else if (header.alg === 'HS256') {
    if (!hs256Secret) throw new Error('hs256 secret not configured');
    const expected = crypto
      .createHmac('sha256', hs256Secret)
      .update(signingInput)
      .digest();
    if (expected.length !== sigBytes.length
        || !crypto.timingSafeEqual(expected, sigBytes)) {
      throw new Error('bad signature');
    }
  } else {
    throw new Error(`unsupported alg: ${header.alg}`);
  }

  const payload = JSON.parse(b64urlDecode(payloadB64).toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('token expired');
  if (payload.nbf && payload.nbf > now + 60) throw new Error('token not yet valid');
  if (!payload.sub) throw new Error('missing sub claim');
  return payload;
}

// ─── Quota enforcement ────────────────────────────────────────────────
// Count completed scans for the user via PostgREST count=exact + HEAD.
// Returns the integer count. Throws on network / RLS / API failures so the
// caller can fail-closed (better to inconvenience one scan than burn budget).
async function getCompletedScanCount(userId, userJwt) {
  // user_id filter is belt-and-suspenders alongside RLS — if RLS is ever
  // misconfigured (P5 audit), this still scopes the query to one user.
  const url = `${SUPABASE_URL}/rest/v1/user_scan_history`
            + `?user_id=eq.${encodeURIComponent(userId)}&select=id`;
  const res = await fetch(url, {
    method: 'HEAD',
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': `Bearer ${userJwt}`,
      'Prefer': 'count=exact',
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`quota query failed: ${res.status} ${body.slice(0, 120)}`);
  }
  // Content-Range header looks like "0-0/N" or "*/N" — N is the total count.
  const contentRange = res.headers.get('content-range') || '';
  const match = contentRange.match(/\/(\d+)$/);
  return match ? parseInt(match[1], 10) : 0;
}

// ─── Handler ──────────────────────────────────────────────────────────
export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const corsOk = ALLOWED_ORIGINS.has(origin) || LOCALHOST_RE.test(origin);
  if (corsOk) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') {
    return res.status(corsOk ? 204 : 403).end();
  }
  if (!corsOk) {
    return res.status(403).json({ error: { message: 'Origin not allowed' } });
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: { message: 'Method not allowed' } });
  }

  // ─── Auth ──────────────────────────────────────────────────────────
  const hs256Secret = process.env.SUPABASE_JWT_SECRET || '';

  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return res.status(401).json({ error: { message: 'Missing bearer token' } });
  }
  const userJwt = match[1].trim();
  let claims;
  try {
    claims = await verifySupabaseJWT(userJwt, hs256Secret);
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    return res.status(401).json({ error: { message: 'Invalid token' } });
  }

  // ─── Quota check ───────────────────────────────────────────────────
  // Fail-closed: if the quota query errors out, reject the call. Budget
  // safety > UX inconvenience. Frontend handles 503 by suggesting a retry.
  let scanCount;
  try {
    scanCount = await getCompletedScanCount(claims.sub, userJwt);
  } catch (err) {
    console.error('Scan-quota check failed:', err.message);
    return res.status(503).json({ error: { message: 'Scan quota check failed — please try again in a moment.' } });
  }
  if (scanCount >= SCAN_QUOTA) {
    return res.status(429).json({
      error: {
        message: `Free scan limit reached (${SCAN_QUOTA} of ${SCAN_QUOTA}). Email hello@ldpscout.com to request more.`,
        code: 'quota_exceeded',
        used: scanCount,
        limit: SCAN_QUOTA,
      },
    });
  }

  // ─── Validate body ─────────────────────────────────────────────────
  const body = req.body || {};
  const { model, max_tokens, system, messages } = body;

  if (!ALLOWED_MODELS.has(model)) {
    return res.status(400).json({ error: { message: 'Model not allowed' } });
  }
  if (typeof max_tokens !== 'number' || max_tokens <= 0 || max_tokens > MAX_TOKENS_CAP) {
    return res.status(400).json({ error: { message: `max_tokens must be 1..${MAX_TOKENS_CAP}` } });
  }
  if (typeof system !== 'string' || system.length > MAX_SYSTEM_LEN) {
    return res.status(400).json({ error: { message: 'Invalid system prompt' } });
  }
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 4) {
    return res.status(400).json({ error: { message: 'Invalid messages' } });
  }
  for (const m of messages) {
    if (!m || typeof m.role !== 'string' || typeof m.content !== 'string') {
      return res.status(400).json({ error: { message: 'Invalid message shape' } });
    }
    if (m.content.length > MAX_USER_LEN) {
      return res.status(400).json({ error: { message: 'Message too long' } });
    }
  }

  // ─── Forward to Anthropic ──────────────────────────────────────────
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({ model, max_tokens, system, messages }),
    });
    const data = await response.json();
    // Light audit log (Vercel captures stdout). Includes scanCount-at-time-of-call
    // so we can correlate quota state with usage.
    console.log(JSON.stringify({
      user: claims.sub,
      model,
      max_tokens,
      status: response.status,
      scans_used: scanCount,
      ts: Date.now(),
    }));
    return res.status(response.status).json(data);
  } catch (err) {
    return res.status(502).json({ error: { message: 'Upstream error' } });
  }
}
```

---

## Deploy instructions (proxy)

After committing the frontend changes (`ldp-scout/app.js`):

```bash
# 1. Commit & push frontend (from ldp-scout/)
git add app.js
git commit -m "Task 2: change scan quota from 5 to 3"
git push

# 2. Deploy the proxy (from ldp-proxy/ — not in git)
cd ../ldp-proxy
npx vercel --prod
```

Vercel will pick up the `SCAN_QUOTA = 3` change on the next deploy. No env-var
changes needed — the constant is hardcoded in the file.

---

## How to test the full flow

### Pre-condition checks (browser console)

1. Sign in, go to AI Fit tab.
2. Open DevTools → Console.
3. Confirm `[loadAndRenderLastScan]` logs fire and no 403/RLS errors appear.
4. Confirm the quota chip reads "**X of 3 scans used**" where X matches the
   actual row count in `user_scan_history` (verify in Supabase table editor).

### Scenario A — 0 scans used

- User with 0 rows in `user_scan_history`.
- Expected: upload zone visible, chip reads **"0 of 3 scans used"**.

### Scenario B — 2 scans used (one remaining)

- User with 2 rows.
- Expected: chip reads **"2 of 3 scans used"**, upload zone visible, scan
  proceeds normally.
- After the scan completes: chip reads **"3 of 3 scans used"**.

### Scenario C — 3 scans used (hard block)

- User with 3 rows (or use a test account that ran 3 scans).
- Expected: upload zone replaced by hard-block panel reading:
  > "You've used **3 of 3** free AI Fit scans. To unlock more, email
  > hello@ldpscout.com…"
- Attempting to trigger a scan anyway (e.g. via DevTools fetch) should return
  HTTP 429 from the proxy with `code: "quota_exceeded"`.

### Scenario D — server-side enforcement (bypass attempt)

- With browser DevTools, call the proxy directly with a valid JWT but a user
  who has 3 rows. The proxy should return 429 regardless of client state.
