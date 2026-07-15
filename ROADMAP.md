# Roadmap: Columbia

The cryptographic data path works end to end today. A client HPKE-seals a request, the relay forwards it without revealing the client, the gateway decrypts and fetches, and the response returns sealed. Remaining work is hardening and decentralization: moving from operator-blind by construction to operator-blind that can be verified.

Legend: ✅ done, 🟡 partial, ⬜ not started, 💲 has a recurring cost, 🔗 needs another operator or an external dependency.

---

## Working today

- ✅ OHTTP data path, end to end. Client HPKE-seal -> relay -> gateway (HPKE-decrypt) -> target -> back. Standard RFC 9458 / 9292 / 9180.
- ✅ OHTTP relay. Strips the client IP and all headers, forwards only the opaque `message/ohttp-req` ciphertext to the gateway.
- ✅ Vendored gateway. Cloudflare `privacy-gateway-server-go`, pinned commit, BSD-3 license preserved. Three small, documented Columbia-local additions on top (relay-auth check, endpoint guard, outbound rate limiter) — see `ohttp-gateway/VENDORED.md` for the full list.
- ✅ Commons cache. Optional public-content cache origin: TTL, stale-while-revalidate, single-flight, `X-Cache: HIT|MISS|STALE`, CDN-ready `Cache-Control` and `Age` headers.
- ✅ RED-only observability. Every service logs `{ts, route(template), status, durationMs[, cache]}`. No IP, no content, no bodies, and `LOG_SECRETS=false` on the gateway.
- ✅ Key-config pinning. Clients can pin the gateway's HPKE key-config SHA-256 fingerprint to catch a swapped key.
- ✅ Token issuer (Privacy Pass). Issues per-device, per-epoch tokens gated on real Apple App Attest validation; the relay verifies and spends a token before forwarding a request.
- ✅ Relay abuse controls. Per-client rate limiting and a configurable trusted client-IP header, for deployments that sit behind another proxy.
- ✅ Gateway outbound rate limit. Optional global cap on outbound requests (`GATEWAY_MAX_QPM`), so a burst of client traffic can't turn into a burst of upstream traffic.
- ✅ Configurable front-door origin lock. `FDID_HEADER` sets which request header the origin lock checks, so it isn't tied to any one CDN or WAF.
- ✅ Anonymous app-level authenticated read routing. The gateway forwards inner BHTTP headers (`Authorization`, `User-Agent`) verbatim to an allowlisted target, and the commons cache can optionally forward `Authorization` upstream on a cache miss (`FORWARD_UPSTREAM_AUTH`) — for a non-identifying, app-level credential only, not a user's own login session.
- ✅ Two-operator split. The relay and gateway can already run under separate operators: deploy each as its own container on different infrastructure and point one at the other. See SELFHOSTING.md. Identity (relay) and content (gateway) then sit in genuinely separate trust domains, no code changes required.

## Remaining work

### (a) Relay as a maintained edge worker, for global POPs ⬜🔗
The two-operator split (see Working today) already gets identity and content into separate trust domains. What's still missing is a relay implementation built for an edge-worker platform (Cloudflare Workers, Fastly Compute, etc.) — the relay is about 75 lines of stateless forwarding, a good fit for that model, and it would give a maintained, third-party-operated relay with points of presence close to clients everywhere, rather than a self-hoster's own single-region container.

### (b) Confidential-compute gateway on SEV-SNP ⬜🔗💲
Run the gateway in an AMD SEV-SNP confidential VM so the host and operator cannot read gateway memory. That closes the gap where the operator could otherwise read decrypted content or the HPKE key out of the process. Confidential SKUs cost more and usually do not scale to zero, so budget the always-on floor accordingly.

### (c) Client-side attestation verifier ⬜🔗
Make verification mean attested, not just pinned. The client fetches the gateway's platform attestation (a DCAP quote or an MAA JWT), validates the signature chain to the hardware root, checks the launch measurement against a pinned known-good value, and only then trusts the channel. Depends on (b).

### (d) Secure key release ⬜🔗💲
Keep the HPKE seed in an HSM with a release policy that only hands it to the gateway against a valid attestation matching the expected measurement, so the operator never holds the key. Depends on (b) and (c).

### (e) Key consistency (RFC 9540) ⬜🔗
Stop per-user key targeting, where a gateway hands one client a unique key to deanonymize them. Publish the key config through an RFC 9540 discovery mechanism and have clients cross-check the served key against an independent consistency source. Pinning catches a change; this catches per-user divergence.

### (f) CDN in front of the cache tier ⬜💲
The commons cache already emits CDN-ready headers. Put a CDN in front so public content is edge-cached globally and the cache tier only sees origin-shield traffic. It serves identical public content, so there's no per-user signal to leak.

### (g) Shared cache and shared redemption store ⬜💲
Each cache replica has its own in-memory store, so hit-rate drops as replicas fan out. A shared store (Redis, for instance) makes hit-rate replica-independent; keep single-flight across replicas with a distributed lock. Largely moot once (f) is in place. The relay's spend-once (nullifier) set has the same per-replica limitation, for a different reason: it should move to a shared, epoch-TTL'd store (e.g. Redis `SET NX`, keyed by nullifier, with a TTL past the token's epoch) so a token can't be double-spent across replicas and redemption state expires with the epoch instead of only on restart or a size cap.

### (h) Retries and resilience ⬜
The relay and cache make single-attempt upstream calls today. Add bounded retries with backoff and jitter, per-call timeouts, and circuit-breaking, so a transient upstream hiccup doesn't surface as a user-visible failure. Keep it RED-observable.

### (i) Reproducible builds and a public transparency log ⬜🔗
This is the verify-don't-trust end state. Make the gateway build reproducible, so anyone can rebuild the exact image and get the same digest and measurement, and publish each measurement to an append-only public log, so a pinned or attested measurement maps back to public, auditable source. Vendoring the gateway at a pinned commit is the prerequisite; the reproducibility and the log aren't built yet.
