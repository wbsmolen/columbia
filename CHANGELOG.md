# Changelog

Notable changes to Columbia. Releases are git tags; the most recent tagged release is `v1.3.0`.

## Unreleased

## v1.3.0 (2026-07-08)

### Documentation

- Documented routing an **anonymous, app-level** authenticated read through the relay→gateway path: the client seals a `message/bhttp` `GET` carrying `Authorization` and `User-Agent`, and the gateway forwards those inner headers to an allowlisted host. The mechanism already existed in the vendored gateway (inner-header forwarding plus the exact-`Host` `ALLOWED_TARGET_ORIGINS` allowlist); only the docs are new.
- Clarified the scope boundary. User-identity-bound credentials (login sessions, per-user tokens) stay off the shared path; a non-identifying app-level credential (shared across all users, naming the application rather than a client) may be routed without breaking the operator-blind split. Reconciled this across `README.md`, `ARCHITECTURE.md`, and `SELFHOSTING.md`.
- Added a shared-egress note: one gateway egress IP and one shared credential mean one global budget and one point of failure. Documented throttling with the existing `GATEWAY_MAX_QPM` gateway limit and added it to the self-hosting env table.
- Documented the two key-config endpoints: `GET /ohttp-configs` (single classical X25519 config, what simple clients pin and the relay proxies) versus `GET /ohttp-keys` (the full list, the draft post-quantum hybrid plus classical X25519).
- Added short "connection check ≠ routing" and "fail-open vs fail-closed (client choice)" notes to clarify client responsibilities.

### Fixed

- Corrected the self-hosting and quickstart examples: the relay requires an `https` `GATEWAY_URL` and hard-exits at startup on a plain `http` value, so the examples now use `https` with a note on presenting TLS to the gateway (including for local single-host testing).
