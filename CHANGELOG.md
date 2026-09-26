# Changelog

Notable changes to Columbia. Published releases and their exact tags are listed on [GitHub Releases](https://github.com/wbsmolen/columbia/releases).

## Unreleased

### Observability

- Commons keeps redirect responses as fixed `502` errors and never follows their `Location` URL. Bounded logs now include the upstream HTTP status and, for redirects, only a fixed target class (`same_origin`, `other_origin_https`, `unsafe_scheme`, `missing`, or `invalid`). Failed background refreshes are reported separately without a client HTTP status. No target URL, host, query, credential, or upstream body is logged or returned to clients. Socket-free regression tests cover fetch, HTTP response, and background refresh paths.

## v1.7.0 - 2026-09-20

### Added

- Optional Azure Table state for issuer registrations, assertion counters and epoch quotas, with atomic conflict handling and bounded readback of ambiguous writes. Re-attestation preserves existing counters and quotas.
- A separate optional shared relay redemption store with create-only spend claims, preventing duplicate redemption across replicas and restarts. Storage credentials and state remain separate from the issuer.
- Validated epoch-key manifests and bounded, single-flight relay key refresh. Invalid, expired or unavailable key/state results fail closed with typed status and retry guidance.
- Graceful issuer and relay shutdown that drains owned HTTP and asynchronous work within a fixed deadline, plus focused lifecycle and real-storage regression coverage.

### Fixed

- Relay admission retains its in-flight slot while token authentication is pending, including after a caller disconnects.
- Issuer diagnostics use a closed set of fields and reason categories instead of caller-controlled paths or exception text.
- The client lifecycle contract now documents interrupted enrollment, registration-loss recovery, payload binding and compatibility with earlier unversioned key responses.

### Upgrade notes

- An image rollout does not enable token authentication, rotate signing keys or configure shared storage. When explicitly configured, the adapters initialize their dedicated tables using the supplied operator credentials. Preserve existing enforcement and key identity during rollout; qualify durable storage, real-device App Attest and older clients before enabling token mode.
- Memory state is for a single process. Durable spend rows have no automatic expiry: safe cleanup requires permanent retirement of the actual signing-key material, not merely an old epoch number.
- README, self-hosting guidance and roadmap now distinguish implemented adapters from remaining deployment, retention and hardware acceptance work.

## v1.6.0 - 2026-09-16

### Added

- `commons-cache`: `GET /v1/imgur?image=<image-id>` resolves a single public imgur image — the extensionless `imgur.com/<id>` page a client otherwise has to guess an extension for — using the same server-held public Client-ID as the album route. Fetches `GET /3/image/{id}` and normalizes to `{ image: { url, type, w, h, animated } }`; an animated upload resolves to imgur's `mp4` (with `type: video/mp4`) when one is offered. Cached under `imgur-image/<id>` with the same TTL / stale-while-revalidate / single-flight semantics, id validation (`[A-Za-z0-9]{1,15}`), no-redirect SSRF guard, and fixed no-leak `502` as `?id=`. Exactly one of `?id=` / `?image=` is required; both or neither is a `400`. `?id=` album resolution is unchanged.
- `commons-cache`: imgur `502`s log a `not_found` reason category for an upstream `404` (deleted or unknown id), alongside the existing `upstream_429` (rate limited) and `upstream_5xx` / `network` / `timeout` categories. Upstream bodies and ids are never logged.

## v1.5.0 - 2026-09-12

### Fixed

- Relay ciphertext is never replayed automatically after an ambiguous connection reset: the gateway may already have committed an inner write. Read clients can make an informed retry decision.
- Relay and public-config response paths now share bounded buffering, caller-disconnect cancellation and single terminal logging. In-flight slots remain occupied until buffered output finishes or the connection closes.
- Commons stops oversized upstream bodies while reading, cancels rejected responses and bounds Imgur JSON before parsing. Fixed diagnostic categories distinguish timeouts, refusal/rate limiting, invalid bodies and network failures without recording browsing content.
- Gateway Prometheus histograms register once and measure seconds, matching their default buckets. Invalid registration fails at startup.

### Added

- Gateway active-minute operational summaries separate outer, payload, upstream and pipeline outcomes. They include the actual window duration and bounded latency buckets; an outer 200 no longer hides an upstream refusal in the diagnostics.
- Regression coverage for caller cancellation, partial gateway responses, ambiguous writes, memory bounds, collector registration, stage separation and exclusion of caller content from debug logs. The Commons concurrency test uses an arrival barrier instead of a timing-dependent mock delay.

### Changed

- Request diagnostics use fixed fields and categories. Relay exception messages/stacks and gateway caller-derived debug details are excluded from operational logs.
- Node services track Node 24 LTS; the gateway builder tracks Go 1.27 and Docker's requested target architecture. Rebuild with fresh supported patch images; runtime image updates do not alter the wire protocol.
- Updated source provenance and deployment documentation.

## v1.4.4 - 2026-08-02

### Fixed

- `ohttp-gateway`: a target response body that fails **mid-read** (e.g. the target resets the connection while streaming) now yields an inner (encapsulated) `500` instead of `400`, on both the binary-HTTP and protobuf paths. Clients fail open on 5xx but treat 4xx as a hard error, so the old mapping turned transient upstream hiccups into user-visible failures. Request-decode failures still return `400`. Covered by regression tests in `handler_test.go`.
- `ohttp-relay`: an error on the gateway **response** stream was an unhandled `'error'` event that killed the whole process; it is now handled (502 to the client, in-flight slot released, `reason: 'gres_error'` logged). Top-level `uncaughtException`/`unhandledRejection` handlers log a structured trace before exiting non-zero, so a crash always leaves evidence.
- `ohttp-relay`: 502s are now attributable — the gateway-request error path logs `reason`, `err.code`, and whether the socket was reused (`gw_error`), and the oversize-response path logs `reason: 'resp_too_large'` with the byte count, instead of discarding the error object.

### Changed

- `ohttp-gateway`: the upstream `http.Client` now has a 30s `Timeout` (was unbounded), so a stalled target can't pin a gateway worker forever.
- `ohttp-relay`: the relay→gateway hop uses a keep-alive `https.Agent` (`maxSockets: 128`) instead of a fresh TLS handshake per request, and retries a gateway `POST` **exactly once** on a fresh socket when a kept-alive socket is reset by the peer (`ECONNRESET` on a reused socket, nothing sent to the client yet). Retries are logged as `reason: 'gw_retry'`. This historical retry was removed in v1.5.0: buffering does not establish that the gateway has not already processed an opaque request.
- `ohttp-relay`: `MAX_RESP_BYTES` default raised from 1 MB to 5 MB — large comment threads legitimately exceeded the old cap. The env override is unchanged.

### Added

- `ohttp-relay/test.mjs`: dependency-free self-test (mirrors `commons-cache/test.mjs`, `node test.mjs`) driving the real `server.js` against an in-process mock https gateway: happy path, RST-on-reused-socket → single retry → success, mid-response gateway error → 502 without crashing, and in-flight-slot release afterwards.

## v1.4.3 (2026-07-28)

### Changed

- `ohttp-relay`, `commons-cache`, `token-issuer`: successful `GET /health` probe hits are no longer logged. At platform probe cadence they were ~315k log rows/day (~98% of all console-log ingestion) drowning the real RED signal and billing the log store for noise. Failing probes remain observable (they never reach the success branch, and the platform records its own probe events). `LOG_HEALTH=1` re-enables success logging for a debugging session. Documented in each service's README config table and `ARCHITECTURE.md`'s Observability section.

## v1.4.2 (2026-07-19)

### Added

- `commons-cache`: a second cache route, `GET /v1/imgur?id=<album-id>`, that resolves a public imgur album to its ordered image list. imgur ended keyless album access, so the route holds imgur's own **public** web-embed Client-ID server-side — the id that ships in imgur.com's JavaScript, a public embed id and not a secret — and fetches `GET /3/album/{id}/images` with it, so a downstream client resolves albums without carrying any imgur credential of its own. Normalizes to `{ images: [{ url, type, w, h }] }` and caches under `imgur/<id>` with the same TTL / stale-while-revalidate / single-flight semantics as `/v1/commons` (public, shared bytes, never keyed per caller). Album ids are validated against `[A-Za-z0-9]{1,15}`, redirects are never followed (SSRF guard), and any upstream failure returns a fixed `502` that never leaks imgur's status, body, or error text. Configurable via `IMGUR_BASE` and `IMGUR_CLIENT_ID`.

## v1.4.1 (2026-07-14)

### Security

- Bumped `golang.org/x/crypto` to v0.52.0 and `golang.org/x/sys` to v0.45.0 in the vendored gateway's dependency tree, and raised its Go builder image to 1.25 to match. Clears 13 Dependabot alerts (7 critical, 2 high, 4 medium) in transitive dependencies of the vendored code; no first-party source changed.

### Documentation

- Caught up ROADMAP.md's "Working today" list with capabilities that had already shipped: the token issuer / Privacy Pass flow, relay abuse controls and the configurable trusted-client-IP header, the gateway's optional outbound rate limit, the configurable front-door origin lock, and anonymous app-level authenticated read routing. Re-scoped the "relay at a separate operator" item — the two-operator split already works today via plain Docker; only a maintained edge-worker relay implementation remains open.
- Corrected two claims that had drifted from the code: the gateway's local modifications are three (relay-auth check, endpoint guard, rate limiter), not two, and its vendored dependency tree is no longer byte-identical to upstream now that it carries the security bump above; and the relay's spend-once (nullifier) set is not epoch-scoped like the issuer's per-device quota is — it's an in-memory store bounded by size, cleared on restart. Fixed both in every file that repeated them (`ARCHITECTURE.md`, `README.md`, `ohttp-gateway/VENDORED.md`, `ohttp-gateway/README.md`, `token-issuer/README.md`).
- Fixed the Quickstart and self-hosting walkthroughs to actually run as written: they pointed the relay at the gateway over `https` without ever configuring a certificate, so a copy-pasted walkthrough failed the TLS handshake. Added the missing self-signed-certificate and shared-network commands.
- Documented `LOG_LEVEL=debug` and `GATEWAY_DEBUG` as gateway settings that should never be turned on in production; the former logs the fetch target on a couple of error paths, the latter includes internal detail in error responses.
- Completed several config-reference gaps: `ohttp-relay/README.md`'s config table was missing `CLIENT_SECRET` and `CLIENT_AUTH_HEADER` (required to actually use `CLIENT_AUTH_MODE=secret`) plus six other documented-in-SELFHOSTING.md-but-not-here env vars; `ohttp-gateway/README.md`'s endpoint list was missing `/ohttp-keys` and `/gateway-metadata`, and its ciphersuite description named only the legacy classical KEM instead of both configs the gateway actually publishes.
- Pointed Columbia-specific vulnerability reports (in the gateway's local additions, or in how Columbia deploys it) at the repository's own `SECURITY.md` instead of Cloudflare's — the vendored gateway's `SECURITY.md` previously sent every report to Cloudflare regardless of whether the issue was in vendored code or Columbia's own additions.

## v1.4.0 (2026-07-10)

### Changed

- The front-door origin lock now reads a configurable request header. Set `FDID_HEADER` to change the header name the relay, commons cache, and token issuer check for the `REQUIRE_FDID` lock; it defaults to `x-azure-fdid`, so existing deployments are unchanged. This lets a deployment behind a non-Azure CDN or WAF point the lock at whatever header its edge injects.

## v1.3.0 (2026-07-08)

### Documentation

- Documented routing an **anonymous, app-level** authenticated read through the relay→gateway path: the client seals a `message/bhttp` `GET` carrying `Authorization` and `User-Agent`, and the gateway forwards those inner headers to an allowlisted host. The mechanism already existed in the vendored gateway (inner-header forwarding plus the exact-`Host` `ALLOWED_TARGET_ORIGINS` allowlist); only the docs are new.
- Clarified the scope boundary. User-identity-bound credentials (login sessions, per-user tokens) stay off the shared path; a non-identifying app-level credential (shared across all users, naming the application rather than a client) may be routed without breaking the operator-blind split. Reconciled this across `README.md`, `ARCHITECTURE.md`, and `SELFHOSTING.md`.
- Added a shared-egress note: one gateway egress IP and one shared credential mean one global budget and one point of failure. Documented throttling with the existing `GATEWAY_MAX_QPM` gateway limit and added it to the self-hosting env table.
- Documented the two key-config endpoints: `GET /ohttp-configs` (single classical X25519 config, what simple clients pin and the relay proxies) versus `GET /ohttp-keys` (the full list, the draft post-quantum hybrid plus classical X25519).
- Added short "connection check ≠ routing" and "fail-open vs fail-closed (client choice)" notes to clarify client responsibilities.

### Fixed

- Corrected the self-hosting and quickstart examples: the relay requires an `https` `GATEWAY_URL` and hard-exits at startup on a plain `http` value, so the examples now use `https` with a note on presenting TLS to the gateway (including for local single-host testing).
