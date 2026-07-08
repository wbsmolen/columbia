# commons-cache

The optional public-commons tier of Columbia. It fetches each public, sessionless item once and serves it to all clients (anything tied to a user's identity stays on their own device and never touches this path). It sits behind OHTTP so the operator can't profile reads. Dependency-free Node (global `fetch` plus built-in `http`).

This service is the cache origin at the end of the operator-blind path (`relay -> gateway -> commons-cache -> upstream`). Because public reads are identical for every client, the cache turns N clients times M reads into M upstream fetches, so upstream-facing volume stays flat as the number of clients grows. See the top-level [`../README.md`](../README.md) and [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

> Generic by design. This ships as a worked example that caches a public, sessionless upstream URL. Point it at any public content by adapting the upstream URL it builds in [`server.js`](./server.js), and set `UPSTREAM_UA` to match.

## Endpoints
| Route | Purpose |
|---|---|
| `GET /health` | liveness |
| `GET /v1/probe` | diagnostic: can this host reach the configured upstream surfaces? Reports status codes only |
| `GET /v1/commons?id=<feed-id>&sort=<sort>` | cached public feed, TTL plus stale-while-revalidate, `X-Cache: HIT\|MISS\|STALE` plus `X-Upstream-Status` |

## Caching behavior
- TTL (`COMMONS_TTL_MS`, default `60000`, 60s): the fresh window, served as `X-Cache: HIT`.
- Stale-while-revalidate (`COMMONS_SWR_MS`, default `300000`, 300s): inside this window past TTL, serve the stale copy right away (`X-Cache: STALE`) and refresh in the background, single-flight (one in-flight revalidation per key).
- Cold or rotten: fetch synchronously (`X-Cache: MISS`).
- CDN-ready headers on 200s: `Cache-Control: public, max-age=…, stale-while-revalidate=…` plus `Age`, so a downstream CDN can edge-cache public feeds and the tier only sees origin-shield traffic. Errors are `no-store`.
- Every 200 carries `X-Cache` (`HIT`/`MISS`/`STALE`) and `X-Upstream-Status` so the client can see the cache decision and the origin status behind the bytes. Only `200`s are cached, so `X-Upstream-Status` is `200` on a served response.

## Caching an authenticated JSON API
The cache is content-agnostic: it stores whatever bytes and `Content-Type` the upstream returns (allowlisted to feed/JSON media types), so the same code fronts a JSON listing API as easily as an RSS feed. Point the path template at a JSON endpoint and add `application/json` is already accepted:

```sh
UPSTREAM_BASE=https://api.example.com \
UPSTREAM_PATH_TEMPLATE='/r/{id}/{sort}?raw_json=1&limit=25' \
FORWARD_UPSTREAM_AUTH=true \
node server.js
```

Some public JSON APIs still require an app-level credential on the request even though the *content* they return is public and identical for every caller. Set `FORWARD_UPSTREAM_AUTH=true` and, on a cache **MISS** (or a background revalidation), the proxy forwards the **incoming** request's `Authorization` header to the upstream fetch. On a **HIT** it serves the shared cached bytes with no upstream fetch and requires no `Authorization` at all.

### Safety invariant (public listings only)
> The cache key is `(id, sort)` **only** — the `Authorization` header is **never** part of the key. This is correct **precisely because** `UPSTREAM_PATH_TEMPLATE` is restricted to the structured, public, token-agnostic listing form (`{id}`/`{sort}`): the upstream returns the *same public bytes* for every caller regardless of which credential fetched them, so one fetch is safely shared across all callers.
>
> **Never widen `UPSTREAM_PATH_TEMPLATE` to an arbitrary or per-user/private path.** If you did, one caller's private response would be cached under `(id, sort)` and served to a different caller — a cross-user data leak. Forward-auth caching-by-path is safe *only* for public listings.

## Configuration
| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | listen port (non-root can't bind below 1024) |
| `COMMONS_TTL_MS` | `60000` | fresh window before a feed is treated as stale |
| `COMMONS_SWR_MS` | `300000` | serve-stale window past TTL (background revalidate) |
| `UPSTREAM_BASE` | `https://example.com` | upstream origin the cache fetches from (https only, validated at startup) |
| `UPSTREAM_PATH_TEMPLATE` | `/{id}/{sort}.rss` | path appended to `UPSTREAM_BASE`, with `{id}` and `{sort}` substituted (each sanitized then percent-encoded). Set the layout for your upstream without editing code, for example `/feed/{id}/{sort}.xml` (RSS) or `/r/{id}/{sort}?raw_json=1` (JSON). **Public listings only** — see the safety invariant above. |
| `UPSTREAM_UA` | a generic UA string | `User-Agent` sent to the upstream origin |
| `FORWARD_UPSTREAM_AUTH` | `false` | when `true`, forward the incoming request's `Authorization` header to the upstream on a MISS/revalidation (for upstreams that gate public listings behind an anonymous app-level credential). The header is **never** part of the cache key; a HIT serves shared public bytes with no credential. Safe **only** for the public-listing path template — see the safety invariant above. |

## Observability
Structured JSON logs to stdout carry RED metrics only: route templates, method, status, cache state, duration. No IPs, no user data, no bodies.

```json
{"ts":"…","route":"/v1/commons","method":"GET","status":200,"cache":"HIT","durationMs":4}
```

## Run locally
```sh
PORT=8099 node server.js
curl localhost:8099/health
curl 'localhost:8099/v1/commons?id=example&sort=latest'
```

Run the self-test (Node built-ins only, no framework — spins the server against a local mock upstream):
```sh
node test.mjs
```

Or with Docker:
```sh
docker build -t columbia-commons .
docker run --rm -p 8099:8080 -e PORT=8080 columbia-commons
```

## Deploy
Runs as non-root on port 8080 (privileged `:80` fails for a non-root user on many managed hosts), and is built to scale to zero where the host supports it.

Plain Docker, as above, is the supported path. The repo also includes [`deploy-ghcr.sh`](./deploy-ghcr.sh) as one example of building the image, pushing it to a container registry, and creating or updating a managed container app. It uses placeholder names (`REGISTRY_OWNER`, `RESOURCE_GROUP`, `CONTAINER_ENV`, `APP_NAME`) you replace with your own. See [`../SELFHOSTING.md`](../SELFHOSTING.md) for the host-agnostic walkthrough.
