# Vendored: Cloudflare `privacy-gateway-server-go`

This directory is a vendored copy of Cloudflare's open-source OHTTP (RFC 9458) gateway reference implementation. It's checked into this repository directly, not as a git submodule, so the build is self-contained and the exact gateway source can be audited alongside the rest of the system.

## Upstream

| | |
|---|---|
| Project | `privacy-gateway-server-go` |
| Upstream repo | https://github.com/cloudflare/privacy-gateway-server-go |
| Vendored commit | `360d4136d5a7d3801b5b20216477b9dd548f48c2` |
| Commit date | 2026-02-19 |
| Commit subject | `Merge pull request #73 from ThePlexus/update-readme` |
| License | BSD 3-Clause (`LICENSE`, preserved unmodified) |
| Copyright | © 2022 Cloudflare Inc. |

The upstream `LICENSE` file (BSD 3-Clause) is preserved unmodified in this directory, as that license requires for redistribution in source form. This attribution and license notice is required when redistributing the vendored code.

## What this gateway does

It implements the OHTTP Gateway Resource from [RFC 9458 (OHTTP)](https://www.rfc-editor.org/rfc/rfc9458). It accepts HPKE-encapsulated [Binary HTTP](https://www.rfc-editor.org/rfc/rfc9292) requests (`message/ohttp-req`), HPKE-decapsulates them, fetches the inner target resource, and returns the HPKE-encapsulated response (`message/ohttp-res`). It sees request content but never the client's IP, because the relay terminates the client connection. See the top-level [`README.md`](../README.md) and [`ARCHITECTURE.md`](../ARCHITECTURE.md) for how it fits the operator-blind path.

The vendored gateway also exposes `/gateway-metadata` and `/gateway-echo`, which reflect back what the gateway received. They are useful as a relay-stripping self-test: drive `/gateway-metadata` through the full relay path and confirm it returns no client-identifying headers. Because they reflect inbound data, disable them or don't expose them in production.

The crypto is HPKE (RFC 9180). The gateway publishes two key configs: a primary config using KEM `X25519+Kyber768-draft00` (KEM id `0x30`), a draft, non-RFC, post-quantum hybrid of X25519 and Kyber768 (experimental), and a legacy config using `DHKEM(X25519, HKDF-SHA256)` (KEM id `0x20`), the classical RFC 9180 suite. Both pair the KEM with `HKDF-SHA256` and `AES-128-GCM`. A classical-only client must select the legacy config (KEM `0x20`); the primary config is a draft post-quantum suite that not every client supports.

## Local modifications

Two deviations from upstream: (1) the GCP App Engine example manifests (`gateway.yaml`, `gateway-protohttp.yaml`, `app.yaml`) were removed (see below); (2) two small env-gated access controls were added to `main.go` (see "Added: relay auth + endpoint guard" below). The vendored dependency tree is byte-identical to the upstream commit above, and the Go source is byte-identical apart from those two additions in `main.go`. Other deployment-specific behavior is supplied entirely at runtime through environment variables (documented in the upstream `README.md`), not by patching the source:

- `SEED_SECRET_KEY`, the 32-byte HPKE seed, injected at deploy time from the host's secret store and never committed. The gateway runs with `LOG_SECRETS=false`, so the seed is never printed.
- `ALLOWED_TARGET_ORIGINS`, restricts the gateway to an allowlist of origins it may fetch (everything else is refused). Matching is on the exact inner-request `Host`. The gateway forwards the decapsulated inner request as-is: it neither adds nor strips the sealed inner headers, and it enforces ONLY the exact-Host allowlist on that request. That passthrough is what lets an app-credential public read go through: the client seals an `Authorization` header inside the BHTTP `GET`, the relay never sees it, and the gateway forwards it to the allowlisted target verbatim.
- `RELAY_GATEWAY_SECRET`, the shared secret the relay attaches as `X-Columbia-Relay-Auth`; the gateway rejects `/gateway` requests without it (see below). Empty/unset = open.

## Added: relay auth + endpoint guard (`main.go`)

Two env-gated additions to `main.go`; nothing else in the Go source changes:

- **Relay→gateway auth.** A `requireRelaySecret` middleware wraps the main gateway endpoint and rejects any request whose `X-Columbia-Relay-Auth` header doesn't match `RELAY_GATEWAY_SECRET` (constant-time compare), **before** HPKE decapsulation. Empty/unset = check disabled (open), preserving upstream behavior. Set the SAME value on the relay (`RELAY_GATEWAY_SECRET`) and the gateway; set it on the relay first, then the gateway, so there's no window where the gateway 401s all relay traffic.
- **Endpoint registration guard.** Registration now skips any endpoint whose pattern is the empty string (Go's `http.HandleFunc` panics on `""`). In production set `ECHO_ENDPOINT=""` and `METADATA_ENDPOINT=""` to disable the reflective `/gateway-echo` and `/gateway-metadata` self-test handlers, which echo inbound request headers via `httputil.DumpRequest`. The in-code defaults are unchanged (`/gateway-echo`, `/gateway-metadata`), so the self-test path stays available in dev/staging.

## Removed: the GCP App Engine manifests

Upstream ships GCP App Engine manifests (`gateway.yaml`, `gateway-protohttp.yaml`, `app.yaml`). The two `*.yaml` env-variable files carried publicly-known 16-byte placeholder seeds in a committed `SEED_SECRET_KEY:` field. A gateway booted with one of those derives a publicly known keypair and offers no confidentiality, and committing a seed-shaped value to an open tree is an unsafe default. They are not used by the supported deploy path (Docker), so they are excluded from this vendored copy.

Provide a fresh 32-byte seed at runtime through the environment, never in a file (see [`../SELFHOSTING.md`](../SELFHOSTING.md)). Never commit a seed.

## Why vendored instead of a submodule

- Self-contained, auditable builds. `docker build` against this directory needs no network and no submodule init; the exact gateway bytes are present.
- Reproducibility. It pins the gateway to one reviewed commit, so upstream cannot shift underneath.
- Transparency goal. The long-term aim (see [`../ROADMAP.md`](../ROADMAP.md)) is reproducible builds plus a public transparency log of attested measurements, which needs the precise source present and pinned.

## Updating the vendored copy

To re-vendor a newer upstream commit:

```sh
# from a scratch dir
git clone https://github.com/cloudflare/privacy-gateway-server-go
cd privacy-gateway-server-go && git checkout <new-commit>
rm -rf .git
# copy contents over ohttp-gateway/, then update the commit hash in this file
```

Review the diff carefully (this code decrypts user traffic) and update the Vendored commit row above. If the seed or key handling changes, re-derive and re-pin the gateway key fingerprint in any client that pins it.
