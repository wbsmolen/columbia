# commons-cache

The optional public-commons tier of Columbia. It fetches each public, sessionless item once and serves it to all clients (anything tied to a user's identity stays on their own device and never touches this path). It sits behind OHTTP so the operator can't profile reads. Dependency-free Node (global `fetch` plus built-in `http`).

This service is the cache origin at the end of the operator-blind path (`relay -> gateway -> commons-cache -> upstream`). Because public reads are identical for every client, the cache turns N clients times M reads into M upstream fetches, so upstream-facing volume stays flat as the number of clients grows. See the top-level [`../README.md`](../README.md) and [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

> Generic by design. This ships as a worked example that caches a public, sessionless upstream URL. Point it at any public content by adapting the upstream URL it builds in [`server.js`](./server.js), and set `UPSTREAM_UA` to match.

## Endpoints
| Route | Purpose |
|---|---|
| `GET /health` | liveness |
| `GET /v1/probe` | diagnostic: can this host reach the configured upstream surfaces? Reports status codes only |
| `GET /v1/commons?id=<feed-id>&sort=<sort>` | cached public feed, TTL plus stale-while-revalidate, `X-Cache: HIT\|MISS\|STALE` |

## Caching behavior
- TTL (`COMMONS_TTL_MS`, default `60000`, 60s): the fresh window, served as `X-Cache: HIT`.
- Stale-while-revalidate (`COMMONS_SWR_MS`, default `300000`, 300s): inside this window past TTL, serve the stale copy right away (`X-Cache: STALE`) and refresh in the background, single-flight (one in-flight revalidation per key).
- Cold or rotten: fetch synchronously (`X-Cache: MISS`).
- CDN-ready headers on 200s: `Cache-Control: public, max-age=…, stale-while-revalidate=…` plus `Age`, so a downstream CDN can edge-cache public feeds and the tier only sees origin-shield traffic. Errors are `no-store`.

## Configuration
| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | listen port (non-root can't bind below 1024) |
| `COMMONS_TTL_MS` | `60000` | fresh window before a feed is treated as stale |
| `COMMONS_SWR_MS` | `300000` | serve-stale window past TTL (background revalidate) |
| `UPSTREAM_BASE` | `https://example.com` | upstream origin the cache fetches from (https only, validated at startup) |
| `UPSTREAM_PATH_TEMPLATE` | `/{id}/{sort}.rss` | path appended to `UPSTREAM_BASE`, with `{id}` and `{sort}` substituted (each sanitized then percent-encoded). Set the layout for your upstream without editing code, for example `/feed/{id}/{sort}.xml`. |
| `UPSTREAM_UA` | a generic UA string | `User-Agent` sent to the upstream origin |

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

Or with Docker:
```sh
docker build -t columbia-commons .
docker run --rm -p 8099:8080 -e PORT=8080 columbia-commons
```

## Deploy
Runs as non-root on port 8080 (privileged `:80` fails for a non-root user on many managed hosts), and is built to scale to zero where the host supports it.

Plain Docker, as above, is the supported path. The repo also includes [`deploy-ghcr.sh`](./deploy-ghcr.sh) as one example of building the image, pushing it to a container registry, and creating or updating a managed container app. It uses placeholder names (`REGISTRY_OWNER`, `RESOURCE_GROUP`, `CONTAINER_ENV`, `APP_NAME`) you replace with your own. See [`../SELFHOSTING.md`](../SELFHOSTING.md) for the host-agnostic walkthrough.
