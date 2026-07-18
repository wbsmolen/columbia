// Columbia - commons-cache
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The optional "public commons" tier: fetch each public, sessionless item ONCE
// and serve it to all clients, fronted by OHTTP so the operator can't
// profile reads. This service is the cache origin.
//
// Dependency-free (Node 20+: global fetch + built-in http). Structured JSON logs
// to stdout carry RED metrics only - NO IPs, NO user data, NO request bodies -
// matching the privacy-preserving observability design.
//
// Generic by design: it caches a public, sessionless upstream URL. Set the
// upstream origin via UPSTREAM_BASE and adapt the path template below to your
// own target. Anything tied to a user's identity should stay on-device and never
// reach this path.
//
// Endpoints:
//   GET /health     - liveness
//   GET /v1/probe   - diagnostic: can THIS host reach the configured upstream
//                     surfaces at all? Reports status, size, and latency.
//   GET /v1/commons - cached public feed (TTL + stale-while-revalidate)
//                     ?id=<feed-id>&sort=<sort>

const http = require('http');
const crypto = require('crypto');

// Front door origin lock (mirrors the relay). When REQUIRE_FDID is set, a request
// is accepted only if it arrives through a front door (a CDN/WAF, e.g. Azure Front
// Door) that injects the X-Azure-FDID header carrying the front door's profile id.
// This pins the public origin so the cache can't be driven directly (which would
// burn the upstream credential budget). Inert until an operator sets REQUIRE_FDID.
// The value is NEVER logged.
const REQUIRE_FDID = process.env.REQUIRE_FDID || '';
// Header the edge front door injects to prove a request came through it. Azure
// Front Door uses X-Azure-FDID; override FDID_HEADER for a non-Azure CDN/WAF.
// Node lowercases all incoming header names, so match on the lowercase form.
const FDID_HEADER = (process.env.FDID_HEADER || 'x-azure-fdid').toLowerCase();

const PORT = parseInt(process.env.PORT || '8080', 10); // non-root can't bind <1024
const TTL_MS = parseInt(process.env.COMMONS_TTL_MS || '60000', 10);        // fresh window
const SWR_MS = parseInt(process.env.COMMONS_SWR_MS || '300000', 10);       // serve-stale window
const UPSTREAM_BASE = (process.env.UPSTREAM_BASE || 'https://example.com').replace(/\/+$/, '');
// Path appended to UPSTREAM_BASE, with {id} and {sort} substituted (each
// sanitized and percent-encoded). Default is the generic form; an operator can
// set e.g. /feed/{id}/{sort}.xml to target a specific upstream without a code edit.
const UPSTREAM_PATH_TEMPLATE = process.env.UPSTREAM_PATH_TEMPLATE || '/{id}/{sort}.rss';
const UPSTREAM_UA = process.env.UPSTREAM_UA ||
  'columbia-commons/1.0 (+https://example.com)';
const MAX_ENTRIES = parseInt(process.env.COMMONS_MAX_ENTRIES || '5000', 10);     // cache bound (LRU)
const MAX_BODY_BYTES = parseInt(process.env.COMMONS_MAX_BODY_BYTES || '5000000', 10); // reject oversized bodies

// Imgur album resolution (/v1/imgur?id=<albumId>). imgur killed keyless album
// access, but its OWN web client uses a public embed Client-ID (not a registered
// app, not a secret - it ships in imgur.com's JS). We hold it HERE, server-side,
// so the app never carries an imgur key. The route fetches the album's image
// list and returns it normalized; cached like everything else (public, shared).
const IMGUR_BASE = (process.env.IMGUR_BASE || 'https://api.imgur.com').replace(/\/+$/, '');
const IMGUR_CLIENT_ID = process.env.IMGUR_CLIENT_ID || '546c25a59c58ad7';
const IMGUR_ID_RE = /^[A-Za-z0-9]{1,15}$/; // imgur album ids are short alphanumerics

// When true, on a cache MISS (or background revalidation) forward the INCOMING
// request's Authorization header to the upstream fetch, so this cache can front
// an upstream that requires an app-level credential to serve its PUBLIC listings.
//
// ================================ SAFETY INVARIANT ================================
// The cache key is (id, sort) ONLY - the Authorization header is NEVER part of the
// key. One upstream fetch is shared across all callers; a HIT serves those shared
// bytes with no upstream fetch and no credential. This is safe ONLY under BOTH of:
//
//   1) UPSTREAM_PATH_TEMPLATE stays a structured PUBLIC listing ({id}/{sort}) -
//      never an arbitrary or per-user/private path, or caller A's private response
//      gets cached under (id,sort) and served to caller B.
//
//   2) With FORWARD_UPSTREAM_AUTH on, the forwarded credential MUST be an ANONYMOUS
//      / app-level one. NOTE: an authenticated JSON listing API (e.g. an OAuth
//      listing) embeds per-USER fields keyed to the fetching bearer (vote state,
//      saved, hidden). Those are shareable ONLY because an anonymous credential has
//      no such state (they come back null/false, identical for every anon caller).
//      If a PER-USER token were ever forwarded, its vote/saved state would be cached
//      under (id,sort) and leaked cross-user. The client MUST only ever forward an
//      anonymous credential here (the client seals only its app-only, anonymous
//      token). Do NOT relax that, and do NOT forward a user token even to a
//      "public" listing.
// =================================================================================
const FORWARD_UPSTREAM_AUTH = /^(1|true|yes|on)$/i.test(process.env.FORWARD_UPSTREAM_AUTH || '');

// A sort/view is any short lowercase token. This validates input (prevents path
// injection); it deliberately fixes no vocabulary - your upstream defines it.
const SORT_RE = /^[a-z]+$/;

// Feed media types we are willing to echo back. Anything else is normalized to
// application/octet-stream so we never reflect an arbitrary upstream type.
const ALLOWED_CONTENT_TYPES = new Set([
  'application/rss+xml',
  'application/atom+xml',
  'application/xml',
  'text/xml',
  'application/json',
]);

// In-memory cache: key -> { body, contentType, fetchedAt, revalidating }
const cache = new Map();

function log(fields) {
  // route is a TEMPLATE (bounded cardinality), never a raw path with IDs.
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...fields }) + '\n');
}

// Bounded cache write with LRU eviction of the oldest insertion. Re-inserting on
// every write keeps the Map's insertion order acting as a recency list.
function cacheSet(key, val) {
  cache.delete(key);
  cache.set(key, val);
  while (cache.size > MAX_ENTRIES) cache.delete(cache.keys().next().value);
}

// Allowlist the upstream content-type's media type to known feed formats; never
// reflect an arbitrary upstream type back to clients.
function safeContentType(raw) {
  const media = String(raw || '').split(';')[0].trim().toLowerCase();
  return ALLOWED_CONTENT_TYPES.has(media) ? media : 'application/octet-stream';
}

// Guard against the operator repointing UPSTREAM_BASE at an internal/private
// surface, turning this cache into an SSRF relay. Called once at startup (below,
// only when run directly - not when required in-process by the test harness).
function validateUpstreamBase() {
  let parsed;
  try {
    parsed = new URL(UPSTREAM_BASE);
  } catch {
    log({ event: 'fatal', reason: 'upstream_base_invalid' });
    process.exit(1);
  }
  const host = parsed.hostname.toLowerCase();
  const isPrivate =
    parsed.protocol !== 'https:' ||
    host === 'localhost' ||
    host.startsWith('127.') ||
    host === '::1' ||
    host.startsWith('10.') ||
    host.startsWith('192.168.') ||
    host.startsWith('169.254.') ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host);
  if (isPrivate) {
    log({ event: 'fatal', reason: 'upstream_base_invalid' });
    process.exit(1);
  }
}

function upstreamHeaders(authHeader) {
  const headers = {
    'User-Agent': UPSTREAM_UA,
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
  };
  // Forward the caller's credential only when explicitly enabled. Used solely to
  // fetch PUBLIC listings on a MISS - see the SAFETY INVARIANT above (the cache key
  // never includes this header, so the fetched bytes are shared across all callers).
  if (FORWARD_UPSTREAM_AUTH && authHeader) headers['Authorization'] = authHeader;
  return headers;
}

async function fetchUpstream(url, authHeader) {
  const started = Date.now();
  try {
    const res = await fetch(url, {
      headers: upstreamHeaders(authHeader),
      redirect: 'manual',                 // never follow - a 3xx could point at an internal host (SSRF)
      signal: AbortSignal.timeout(10000), // bound slow/hung upstreams
    });
    // Treat any 3xx as an upstream error: we do not follow redirects.
    if (res.status >= 300 && res.status < 400) {
      return { status: res.status, body: Buffer.alloc(0), contentType: 'application/octet-stream', ms: Date.now() - started, error: true };
    }
    const body = Buffer.from(await res.arrayBuffer());
    // Reject oversized bodies - do not cache or serve (memory DoS guard).
    if (res.status === 200 && body.length > MAX_BODY_BYTES) {
      return { status: res.status, body: Buffer.alloc(0), contentType: 'application/octet-stream', ms: Date.now() - started, error: true };
    }
    return { status: res.status, body, contentType: res.headers.get('content-type') || 'application/json', ms: Date.now() - started };
  } catch {
    // Never surface the exception text - fixed, empty error result only.
    return { status: 0, body: Buffer.alloc(0), contentType: 'application/octet-stream', ms: Date.now() - started, error: true };
  }
}

// Build the upstream URL for an (id, sort) pair. The path is driven by
// UPSTREAM_PATH_TEMPLATE so the upstream layout is config, not code. id/sort are
// already sanitized by the caller; we percent-encode each before substituting so
// the template controls structure only and can never be used for path injection.
function upstreamUrl(id, sort) {
  const path = UPSTREAM_PATH_TEMPLATE
    .replace(/\{id\}/g, encodeURIComponent(id))
    .replace(/\{sort\}/g, encodeURIComponent(sort));
  return `${UPSTREAM_BASE}${path.startsWith('/') ? '' : '/'}${path}`;
}

// Cold-miss single-flight: concurrent requests for the same un-cached key share
// ONE upstream fetch instead of each hitting the upstream: thundering-herd
// protection for a shared, rate-limited upstream credential. Keyed by `id/sort`.
const inflight = new Map();

// Cache with stale-while-revalidate semantics. authHeader is the caller's
// credential to forward on a fetch (MISS or background revalidation) when
// FORWARD_UPSTREAM_AUTH is enabled; it is NEVER part of the cache key. A HIT below
// returns before any fetch, so a cached (shared, public) response is served without
// touching the upstream and without requiring the caller to present a credential.
async function getCachedFeed(id, sort, authHeader) {
  const key = `${id}/${sort}`;
  const url = upstreamUrl(id, sort);
  const now = Date.now();
  const entry = cache.get(key);

  if (entry) {
    const age = now - entry.fetchedAt;
    if (age < TTL_MS) return { ...entry, cacheState: 'HIT' };
    if (age < TTL_MS + SWR_MS) {
      // Serve stale immediately; refresh in the background (single-flight).
      if (!entry.revalidating) {
        entry.revalidating = true;
        fetchUpstream(url, authHeader)
          .then((up) => {
            if (up.status === 200 && !up.error) {
              cacheSet(key, { body: up.body, contentType: safeContentType(up.contentType), fetchedAt: Date.now(), upstreamStatus: up.status, revalidating: false });
            }
          })
          .catch(() => {})
          .finally(() => { entry.revalidating = false; }); // always reset - never get stuck revalidating
      }
      return { ...entry, cacheState: 'STALE' };
    }
  }

  // Cold or rotten - fetch with SINGLE-FLIGHT. The first request for this key (the
  // leader) performs the upstream fetch; concurrent requests (followers) await the
  // SAME promise instead of each hitting the upstream. Collapses a stampede on one
  // key to ONE upstream request, protecting the shared credential budget.
  let promise = inflight.get(key);
  const isLeader = !promise;
  if (isLeader) {
    promise = fetchUpstream(url, authHeader).finally(() => inflight.delete(key));
    inflight.set(key, promise);
  }
  const up = await promise;
  if (up.status === 200 && !up.error) {
    if (isLeader) {
      cacheSet(key, { body: up.body, contentType: safeContentType(up.contentType), fetchedAt: Date.now(), upstreamStatus: up.status, revalidating: false });
    }
    // Leader logs MISS (it fetched); followers coalesced onto its single fetch.
    return { body: up.body, contentType: safeContentType(up.contentType), fetchedAt: Date.now(), upstreamStatus: up.status, cacheState: isLeader ? 'MISS' : 'COALESCED', upstreamMs: up.ms };
  }
  // Upstream failed - fixed error result, no upstream body/status leaked downstream.
  return { cacheState: 'MISS', upstreamStatus: up.status, upstreamMs: up.ms, upstreamError: true };
}

// Imgur album: fetch the image list with the server-side public Client-ID and
// normalize to { images: [{ url, type, w, h }] }. Never surfaces imgur error text.
async function fetchImgurAlbum(id) {
  const url = `${IMGUR_BASE}/3/album/${encodeURIComponent(id)}/images`;
  const started = Date.now();
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': UPSTREAM_UA,
        'Accept': 'application/json',
        'Authorization': `Client-ID ${IMGUR_CLIENT_ID}`,
      },
      redirect: 'manual',                 // never follow a 3xx (SSRF guard)
      signal: AbortSignal.timeout(10000),
    });
    if (res.status !== 200) return { status: res.status, error: true, ms: Date.now() - started };
    const j = await res.json();
    const images = (Array.isArray(j.data) ? j.data : [])
      .map((i) => ({ url: i.link, type: i.type, w: i.width, h: i.height }))
      .filter((x) => typeof x.url === 'string' && x.url.startsWith('https://'));
    const body = Buffer.from(JSON.stringify({ images }));
    if (body.length > MAX_BODY_BYTES) return { status: 200, error: true, ms: Date.now() - started };
    return { status: 200, body, contentType: 'application/json', ms: Date.now() - started };
  } catch {
    return { status: 0, error: true, ms: Date.now() - started };
  }
}

// Cached imgur album - same TTL / stale-while-revalidate / single-flight semantics
// as getCachedFeed (public, shared bytes; keyed imgur/<id>, never per-caller).
async function getCachedImgur(id) {
  const key = `imgur/${id}`;
  const now = Date.now();
  const entry = cache.get(key);
  if (entry) {
    const age = now - entry.fetchedAt;
    if (age < TTL_MS) return { ...entry, cacheState: 'HIT' };
    if (age < TTL_MS + SWR_MS) {
      if (!entry.revalidating) {
        entry.revalidating = true;
        fetchImgurAlbum(id)
          .then((up) => { if (up.status === 200 && !up.error) cacheSet(key, { body: up.body, contentType: 'application/json', fetchedAt: Date.now(), upstreamStatus: 200, revalidating: false }); })
          .catch(() => {})
          .finally(() => { entry.revalidating = false; });
      }
      return { ...entry, cacheState: 'STALE' };
    }
  }
  let promise = inflight.get(key);
  const isLeader = !promise;
  if (isLeader) { promise = fetchImgurAlbum(id).finally(() => inflight.delete(key)); inflight.set(key, promise); }
  const up = await promise;
  if (up.status === 200 && !up.error) {
    if (isLeader) cacheSet(key, { body: up.body, contentType: 'application/json', fetchedAt: Date.now(), upstreamStatus: 200, revalidating: false });
    return { body: up.body, contentType: 'application/json', fetchedAt: Date.now(), upstreamStatus: 200, cacheState: isLeader ? 'MISS' : 'COALESCED', upstreamMs: up.ms };
  }
  return { cacheState: 'MISS', upstreamStatus: up.status, upstreamMs: up.ms, upstreamError: true };
}

async function handleProbe() {
  // Does this host reach the upstream's public surfaces? Try a few; report status only.
  const targets = [
    ['commons', upstreamUrl('example', 'latest')],
  ];
  const results = {};
  for (const [name, url] of targets) {
    const up = await fetchUpstream(url);
    results[name] = { status: up.status, bytes: up.body.length, ms: up.ms };
  }
  return results;
}

// Constant-time string compare (hash both, then timingSafeEqual) so the FDID
// check can't be probed by timing.
function timingSafeEqualStr(presented, expected) {
  if (typeof presented !== 'string' || presented.length === 0) return false;
  const ha = crypto.createHash('sha256').update(presented).digest();
  const hb = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// True if the request may proceed: lock disabled, or a matching X-Azure-FDID is
// present (a repeated header is comma-joined by Node; accept if ANY token matches).
function frontDoorAllowed(req) {
  if (!REQUIRE_FDID) return true;
  const raw = req.headers[FDID_HEADER];
  if (typeof raw !== 'string' || raw.length === 0) return false;
  for (const tok of raw.split(',')) {
    if (timingSafeEqualStr(tok.trim(), REQUIRE_FDID)) return true;
  }
  return false;
}

// Only the platform health probe is exempt (it hits /health in-environment with
// no front door in that hop). /v1/commons + /v1/probe require the FDID.
function fdidExempt(req, path) {
  return req.method === 'GET' && path === '/health';
}

const server = http.createServer(async (req, res) => {
  const started = Date.now();
  const u = new URL(req.url, `http://localhost`);
  const route = u.pathname;
  let status = 404, cacheState = '-';

  // Front door origin lock: when REQUIRE_FDID is set, every non-exempt request
  // must arrive through the front door (which injects X-Azure-FDID), else 403.
  if (REQUIRE_FDID && !fdidExempt(req, route) && !frontDoorAllowed(req)) {
    res.writeHead(403); res.end();
    log({ route, status: 403, cacheState: '-', durationMs: Date.now() - started });
    return;
  }

  try {
    if (route === '/health') {
      status = 200;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', service: 'commons-cache', ts: new Date().toISOString(), uptimeS: Math.round(process.uptime()), cacheKeys: cache.size }));
    } else if (route === '/v1/probe') {
      const results = await handleProbe();
      status = 200;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ note: 'upstream-surface reachability from this host: status, size, and latency', results }, null, 2));
    } else if (route === '/v1/commons') {
      const id = (u.searchParams.get('id') || '').replace(/[^A-Za-z0-9_]/g, '');
      const sort = (u.searchParams.get('sort') || 'latest').toLowerCase();
      if (!id || !SORT_RE.test(sort)) {
        status = 400;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'require ?id=<feed-id>&sort=<sort>' }));
      } else {
        // Forward the caller's credential only on a fetch (MISS/revalidate) and only
        // when enabled; a HIT never reaches the upstream so it needs no credential.
        const authHeader = FORWARD_UPSTREAM_AUTH ? (req.headers['authorization'] || undefined) : undefined;
        const out = await getCachedFeed(id, sort, authHeader);
        cacheState = out.cacheState;
        if (out.upstreamError) {
          // Fixed 502 - never leak upstream status, body, or error text.
          status = 502;
          res.writeHead(status, {
            'Content-Type': 'application/json',
            'X-Cache': cacheState,
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': 'no-store',
          });
          res.end(JSON.stringify({ error: 'upstream unavailable' }));
        } else {
          status = 200;
          const ageS = out.fetchedAt ? Math.max(0, Math.floor((Date.now() - out.fetchedAt) / 1000)) : 0;
          // CDN-ready: a downstream CDN can edge-cache public feeds, collapsing
          // the public-read tier to origin-shield traffic. Only cache successes.
          res.writeHead(status, {
            'Content-Type': safeContentType(out.contentType),
            'X-Cache': cacheState,
            // Upstream status behind the cached bytes. Only 200s are ever cached, so
            // this is 200 on HIT/STALE/MISS; the client reads it for transparency.
            'X-Upstream-Status': String(out.upstreamStatus || 200),
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': `public, max-age=${Math.floor(TTL_MS / 1000)}, stale-while-revalidate=${Math.floor(SWR_MS / 1000)}`,
            'Age': String(ageS),
          });
          res.end(out.body);
        }
      }
    } else if (route === '/v1/imgur') {
      const id = (u.searchParams.get('id') || '').trim();
      if (!IMGUR_ID_RE.test(id)) {
        status = 400;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'require ?id=<imgur album id>' }));
      } else {
        const out = await getCachedImgur(id);
        cacheState = out.cacheState;
        if (out.upstreamError) {
          status = 502; // fixed - never leak imgur status/body/error text
          res.writeHead(status, { 'Content-Type': 'application/json', 'X-Cache': cacheState, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' });
          res.end(JSON.stringify({ error: 'upstream unavailable' }));
        } else {
          status = 200;
          const ageS = out.fetchedAt ? Math.max(0, Math.floor((Date.now() - out.fetchedAt) / 1000)) : 0;
          res.writeHead(status, {
            'Content-Type': 'application/json',
            'X-Cache': cacheState,
            'X-Upstream-Status': String(out.upstreamStatus || 200),
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': `public, max-age=${Math.floor(TTL_MS / 1000)}, stale-while-revalidate=${Math.floor(SWR_MS / 1000)}`,
            'Age': String(ageS),
          });
          res.end(out.body);
        }
      }
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found', routes: ['/health', '/v1/probe', '/v1/commons?id=&sort=', '/v1/imgur?id='] }));
    }
  } catch {
    // Fixed 500 - never place exception text into the response body.
    status = 500;
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'internal' }));
  }

  // RED metric - route TEMPLATE only, no IPs, no query values, no bodies.
  log({ route, method: req.method, status, cache: cacheState, durationMs: Date.now() - started });
});

// Production runs `node server.js` directly, so require.main === module: the SSRF
// guard runs and the server binds. Under `require`/`import` (the in-process test
// harness) neither fires, letting the test point the fetch/cache path at a local
// mock upstream without tripping the loopback SSRF guard or double-binding a port.
if (require.main === module) {
  validateUpstreamBase();
  server.listen(PORT, () => log({ event: 'listen', port: PORT, ttlMs: TTL_MS, swrMs: SWR_MS }));
}

module.exports = { server, getCachedFeed, fetchUpstream, upstreamUrl, cache, validateUpstreamBase };
