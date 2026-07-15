# Changelog

Notable changes to Columbia. Releases are git tags; the most recent tagged release is `v1.4.1`.

## Unreleased

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
