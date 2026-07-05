# Roadmap: Columbia

The cryptographic data path works end to end today. A client HPKE-seals a request, the relay forwards it without revealing the client, the gateway decrypts and fetches, and the response returns sealed. Remaining work is hardening and decentralization: moving from operator-blind by construction to operator-blind that can be verified.

Legend: ✅ done, 🟡 partial, ⬜ not started, 💲 has a recurring cost, 🔗 needs another operator or an external dependency.

---

## Working today

- ✅ OHTTP data path, end to end. Client HPKE-seal -> relay -> gateway (HPKE-decrypt) -> target -> back. Standard RFC 9458 / 9292 / 9180.
- ✅ OHTTP relay. Strips the client IP and all headers, forwards only the opaque `message/ohttp-req` ciphertext to the gateway.
- ✅ Vendored gateway. Cloudflare `privacy-gateway-server-go`, pinned commit, unmodified source, BSD-3 license preserved.
- ✅ Commons cache. Optional public-content cache origin: TTL, stale-while-revalidate, single-flight, `X-Cache: HIT|MISS|STALE`, CDN-ready `Cache-Control` and `Age` headers.
- ✅ RED-only observability. Every service logs `{ts, route(template), status, durationMs[, cache]}`. No IP, no content, no bodies, and `LOG_SECRETS=false` on the gateway.
- ✅ Key-config pinning. Clients can pin the gateway's HPKE key-config SHA-256 fingerprint to catch a swapped key.

## Remaining work

### (a) Relay at a separate operator, for true non-collusion ⬜🔗
Run the relay and the gateway under genuinely different operators, so identity (relay) and content (gateway) live in separate trust domains. The relay is about 75 lines of stateless forwarding, so moving it to an independent host (such as an edge worker) also provides global POPs. Low cost, high trust gain.

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

### (g) Shared cache ⬜💲
Each cache replica has its own in-memory store, so hit-rate drops as replicas fan out. A shared store (Redis, for instance) makes hit-rate replica-independent; keep single-flight across replicas with a distributed lock. Largely moot once (f) is in place.

### (h) Retries and resilience ⬜
The relay and cache make single-attempt upstream calls today. Add bounded retries with backoff and jitter, per-call timeouts, and circuit-breaking, so a transient upstream hiccup doesn't surface as a user-visible failure. Keep it RED-observable.

### (i) Reproducible builds and a public transparency log ⬜🔗
This is the verify-don't-trust end state. Make the gateway build reproducible, so anyone can rebuild the exact image and get the same digest and measurement, and publish each measurement to an append-only public log, so a pinned or attested measurement maps back to public, auditable source. Vendoring the gateway at a pinned commit is the prerequisite; the reproducibility and the log aren't built yet.
