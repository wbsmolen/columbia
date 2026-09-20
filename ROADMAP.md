# Roadmap: Columbia

The cryptographic data path works end to end today. A client HPKE-seals a request, the relay forwards it without revealing the client, the gateway decrypts and fetches, and the response returns sealed. Remaining work is hardening and decentralization: moving from operator-blind by construction to operator-blind that can be verified.

Legend: ✅ done, 🟡 partial, ⬜ not started, 💲 has a recurring cost, 🔗 needs another operator or an external dependency.

---

## Working today

- ✅ OHTTP data path, end to end. Client HPKE-seal -> relay -> gateway (HPKE-decrypt) -> target -> back. Standard RFC 9458 / 9292 / 9180.
- ✅ OHTTP relay. Strips the client IP and all headers, forwards only the opaque `message/ohttp-req` ciphertext to the gateway.
- ✅ Vendored gateway. Cloudflare `privacy-gateway-server-go`, pinned commit, BSD-3 license preserved. Documented Columbia-local changes include relay authentication, endpoint registration guards, outbound rate limiting, response-side error mapping and upstream timeouts, bounded operational diagnostics, corrected Prometheus accounting, and sanitized request logs — see `ohttp-gateway/VENDORED.md` for the full list.
- ✅ Commons cache. Optional public-content cache origin: TTL, stale-while-revalidate, single-flight, `X-Cache: HIT|MISS|STALE`, CDN-ready `Cache-Control` and `Age` headers.
- ✅ RED-only observability. Every service logs `{ts, route(template), status, durationMs[, cache]}`, and the relay's failure paths add a bounded `reason` plus the underlying error code, so a 502 is attributable to a cause. No IP, no content, no bodies, and `LOG_SECRETS=false` on the gateway.
- ✅ Key-config pinning. Clients can pin the gateway's HPKE key-config SHA-256 fingerprint to catch a swapped key.
- ✅ Token issuer (Privacy Pass). Issues per-device, per-epoch tokens gated on real Apple App Attest validation; the relay verifies and spends a token before forwarding a request.
- ✅ Optional shared state adapters. The issuer stores registrations, monotonic assertion counters and epoch quotas atomically; the relay uses a separate create-only anonymous redemption store. Azure storage errors and ambiguous writes fail closed unless readback proves the exact operation. Memory adapters remain available for one-process development.
- ✅ Bounded token lifecycle handling. Epoch publication validates actual key material; relay key refresh has a deadline, response-size bound and single-flight behavior. Graceful termination tracks HTTP and asynchronous work with a fixed drain deadline.
- ✅ Relay abuse controls. Per-client rate limiting and a configurable trusted client-IP header, for deployments that sit behind another proxy.
- ✅ Gateway outbound rate limit. Optional global cap on outbound requests (`GATEWAY_MAX_QPM`), so a burst of client traffic can't turn into a burst of upstream traffic.
- ✅ Configurable front-door origin lock. `FDID_HEADER` sets which request header the origin lock checks, so it isn't tied to any one CDN or WAF.
- ✅ Anonymous app-level authenticated read routing. The gateway forwards inner BHTTP headers (`Authorization`, `User-Agent`) verbatim to an allowlisted target, and the commons cache can optionally forward `Authorization` upstream on a cache miss (`FORWARD_UPSTREAM_AUTH`) — for a non-identifying, app-level credential only, not a user's own login session.
- ✅ Two-operator split. The relay and gateway can already run under separate operators: deploy each as its own container on different infrastructure and point one at the other. See SELFHOSTING.md. Identity (relay) and content (gateway) then sit in genuinely separate trust domains, no code changes required.

## Remaining work

### (a) Relay as a maintained edge worker, for global POPs ⬜🔗
The two-operator split (see Working today) already gets identity and content into separate trust domains. What's still missing is a maintained relay for an edge-worker platform (Cloudflare Workers, Fastly Compute, etc.), operated independently with points of presence close to clients. Such a port must preserve bounded buffering, cancellation, authentication admission and atomic shared spend decisions; copying only the forwarding handler is insufficient.

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

### (g) Shared cache and token-state operations 🟡💲
Each cache replica still has its own in-memory content store. A shared cache and distributed single-flight could improve hit-rate as replicas fan out; (f) may reduce that need.

Shared issuer and relay state are implemented as separate optional Azure Table adapters. Real-service acceptance covers atomic conflicts, replay prevention and ambiguous acknowledgments. Production provisioning, migration, older-client compatibility and real-device App Attest/registration-loss recovery remain separate rollout requirements. Keep an existing deployment's enforcement policy until those requirements are met.

Spend rows deliberately have no automatic TTL or capacity eviction. Safe cleanup requires a permanent retirement fence for the actual signing-key material: aging an epoch number alone must not permit a reused key to revive a spent token. Operational retention, storage growth and safe retirement remain open work.

### (h) Retries and resilience 🟡
The relay pools its gateway connections and bounds response memory, cancels outbound work when a caller disconnects, and returns one terminal outcome. It does **not** automatically replay ciphertext after a reset: a lost response may follow a committed inner write, and buffering the ciphertext does not make replay safe. The caller knows the inner method and owns any retry decision. This supersedes the v1.4.4 one-shot reused-socket retry.

The gateway maps response-side translation failures to inner `500` responses and bounds its upstream client at 30 seconds. Commons bounds upstream work at 10 seconds; the default relay gateway hop is 15 seconds. Long-poll clients must leave transit headroom within every hop's deadline. Operational summaries distinguish upstream statuses from outer transport statuses.

Still open: method-aware client retry/backoff budgets and circuit breakers for sustained target failures. A generic retry of opaque traffic is not an appropriate implementation of that goal.

### (i) Reproducible builds and a public transparency log ⬜🔗
This is the verify-don't-trust end state. Make the gateway build reproducible, so anyone can rebuild the exact image and get the same digest and measurement, and publish each measurement to an append-only public log, so a pinned or attested measurement maps back to public, auditable source. Vendoring the gateway at a pinned commit is the prerequisite; the reproducibility and the log aren't built yet.
