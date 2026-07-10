# Self-Hosting Columbia

This guide runs the request-path components (relay, gateway, and optionally the commons cache) on plain Docker, on any host, plus the optional token issuer that gates who may use the relay. No managed cloud is required. One optional cloud example is at the end, using placeholders for your own resource names.

> Read this first. The operator-blind guarantee only holds when the relay and gateway are run by different operators who don't collude. Running both on one host is fine for testing, but it gives you no protection against that single operator. The [two-operator section](#running-relay-and-gateway-as-separate-operators) below explains how to split them for the real guarantee.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/), to build and run.
- `openssl`, to generate the HPKE seed.
- An OHTTP client (any RFC 9458 client library) to actually use the path.

## 1. Generate the gateway HPKE seed

The gateway derives its HPKE keypair from a 32-byte seed, `SEED_SECRET_KEY`, given as hex. This is the one real secret in the system, so keep it out of version control and out of logs.

```sh
openssl rand -hex 32
# Prints a fresh 64-hex-character seed. Use your own output; never reuse a seed from any doc.
```

Save it to an environment variable for the commands below:

```sh
export SEED_SECRET_KEY="$(openssl rand -hex 32)"
```

One seed deterministically derives BOTH published key configs (the primary `X25519+Kyber768-draft00` config and the legacy `DHKEM(X25519, HKDF-SHA256)` config). The vendored gateway has NO online key rotation: rotating `SEED_SECRET_KEY` is a hard cutover. Redeploying the gateway with the new seed breaks every client that pinned the old key config fingerprint until it re-pins the new one. Plan the cutover, because there is no overlap window where both old and new keys are served.

## 2. Create a shared Docker network (single-host testing)

So the containers can reach each other by name:

```sh
docker network create columbia
```

## 3. Build and run the gateway

The gateway HPKE-decrypts requests and fetches targets. Two settings matter most:

- `SEED_SECRET_KEY`, the seed from step 1.
- `ALLOWED_TARGET_ORIGINS`, a comma-separated allowlist of origins the gateway is allowed to fetch. Anything not on the list is refused with a 403. Set it tightly: only the upstreams you actually mean to reach, for example the commons cache or a specific public API origin.

> Warning: always set `ALLOWED_TARGET_ORIGINS`. The gateway does NOT fail closed on its own. If you leave it empty or unset, the gateway becomes an open, anonymous proxy that anyone can point at any origin, including an SSRF pivot into your internal network. Matching is by exact `Host` string: scheme, port, and subdomain are all literal, so `example.com` does not cover `api.example.com` or `https://example.com:8443`. List every origin you mean to allow, exactly.

```sh
cd ohttp-gateway
docker build -t columbia-gateway .

docker run -d --name gateway --network columbia -p 8080:8080 \
  -e PORT=8080 \
  -e SEED_SECRET_KEY="$SEED_SECRET_KEY" \
  -e LOG_SECRETS=false \
  -e ALLOWED_TARGET_ORIGINS="http://commons:8080" \
  columbia-gateway
```

| Env var | Required | Purpose |
|---|---|---|
| `SEED_SECRET_KEY` | yes | 32-byte hex HPKE seed (step 1); derives the keypair |
| `ALLOWED_TARGET_ORIGINS` | yes | comma-separated allowlist of fetchable origins; everything else is 403 |
| `LOG_SECRETS` | recommended `false` | keeps the seed from ever being printed |
| `PORT` | `8080` | listen port (runs as non-root; below 1024 needs privilege) |
| `GATEWAY_MAX_QPM` | `0` (off) | optional global cap on total outbound fetches per minute across all clients; over-budget requests get a `429` + `Retry-After` instead of a call (see [Shared egress](#shared-egress-one-ip-one-credential-one-budget)) |
| `RELAY_GATEWAY_SECRET` | (none) | when set, the gateway rejects `/gateway` requests that lack a matching `X-Columbia-Relay-Auth`; set the SAME value as the relay |
| `ECHO_ENDPOINT` | `/gateway-echo` | set to `""` in production to unregister the reflective echo self-test endpoint |
| `METADATA_ENDPOINT` | `/gateway-metadata` | set to `""` in production to unregister the reflective metadata self-test endpoint |

The `RELAY_GATEWAY_SECRET`, `ECHO_ENDPOINT`, and `METADATA_ENDPOINT` controls are described in detail in [`ohttp-gateway/VENDORED.md`](./ohttp-gateway/VENDORED.md). See [Abuse controls](#abuse-controls) below for how to set the shared secret without a window where the gateway 401s all relay traffic.

The gateway exposes the upstream reference endpoints, including:

- `POST /gateway`, accept an OHTTP request, fetch the target, return an OHTTP response.
- `GET /ohttp-configs`, publish the encoded HPKE key config (the public key clients pin).
- `GET /health`, liveness.

Fetch and pin the key config fingerprint (clients use this to catch a swapped key):

```sh
curl -s http://localhost:8080/ohttp-configs | sha256sum
```

## 4. Build and run the relay

The relay is the network endpoint clients connect to. It forwards the opaque ciphertext to the gateway in a fresh request with no client headers and no `X-Forwarded-For`, so the gateway never learns the client IP.

```sh
cd ../ohttp-relay
docker build -t columbia-relay .

docker run -d --name relay --network columbia -p 8081:8080 \
  -e PORT=8080 \
  -e GATEWAY_URL="https://gateway:8080/gateway" \
  columbia-relay
```

> The relay requires TLS to the gateway: it hard-exits at startup on a non-`https` `GATEWAY_URL`. Give the gateway a certificate (set its `CERT`/`KEY`, or terminate TLS at an ingress in front of it; a managed platform ingress does this for you). For single-host local testing against a self-signed gateway cert, set `NODE_TLS_REJECT_UNAUTHORIZED=0` on the relay to accept it. Local testing only, never in production.

| Env var | Required | Purpose |
|---|---|---|
| `GATEWAY_URL` | yes | full gateway endpoint, e.g. `https://<gateway-host>/gateway` (must be `https`) |
| `PORT` | `8080` | listen port |
| `MAX_BODY_BYTES` | `65536` | cap on the inbound ciphertext body buffered per request |
| `MAX_RESP_BYTES` | `1000000` | cap on the gateway response buffered per request |
| `GW_TIMEOUT_MS` | `15000` | timeout on the relay-to-gateway request |
| `RATE_LIMIT_RPM` | `120` | per-IP requests per minute; `0` disables per-IP limiting |
| `RATE_WINDOW_MS` | `60000` | length of the fixed rate-limit window |
| `MAX_INFLIGHT` | `256` | global cap on concurrent relays; further requests get a 429 |
| `RATE_MAX_KEYS` | `100000` | hard cap on tracked IP keys, so a spoofed-source flood can't grow the table unbounded |
| `TRUSTED_CLIENT_IP_HEADER` | _(empty)_ | header a trusted front proxy sets to the real client IP (e.g. `x-azure-clientip`, `cf-connecting-ip`). **Set this whenever a request crosses more than one proxy** (front proxy + platform ingress), or all clients share one rate-limit bucket. Empty keeps single-proxy rightmost-XFF behaviour |
| `CLIENT_AUTH_MODE` | `off` | client auth: `off`, `secret` (shared-secret header), or `token` (anonymous issuer token) |
| `CLIENT_SECRET` | (none) | shared secret required when `CLIENT_AUTH_MODE=secret` |
| `CLIENT_AUTH_HEADER` | `x-columbia-token` | header the client presents its credential in (both `secret` and `token` modes read it) |
| `ISSUER_KEYS_URL` | (none) | in `token` mode, the issuer's `GET /issuer-keys`, e.g. `https://<issuer-host>/issuer-keys` |
| `ISSUER_KEYS_TTL_MS` | `300000` | how often the relay refreshes the cached issuer epoch public keys |
| `TOKEN_PSS_SALT_LEN` | `48` | RSA-PSS salt length for token verification (matches SHA-384 and the issuer suite) |
| `REDEMPTION_MAX_KEYS` | `5000000` | spend-once set memory bound (single replica; a shared store is the real fix) |
| `RELAY_GATEWAY_SECRET` | (none) | shared secret sent to the gateway as `X-Columbia-Relay-Auth`; set the SAME value on the gateway |
| `GATEWAY_CONFIGS_URL` | gateway host + `/ohttp-configs` | where the relay fetches the key config to pass through |
| `CONFIG_TTL_MS` | `120000` | how long the relay caches the passed-through key config |
| `REQUIRE_FDID` | (none) | when set, reject any request that did not arrive through the edge front door (see [Edge front door](#edge-front-door-cdn--waf)); unset disables the check |
| `FDID_HEADER` | `x-azure-fdid` | name of the header the edge front door injects for the `REQUIRE_FDID` lock above; override for a non-Azure CDN or WAF that injects a differently named header |

> The relay forwards only the ciphertext body plus `Content-Type: message/ohttp-req`. Dropping every client header is the security property, not an oversight. The one extra header it adds to the outbound request is `X-Columbia-Relay-Auth` (when `RELAY_GATEWAY_SECRET` is set), which identifies the relay, never the client.

## 5. (Optional) Build and run the commons cache

The commons cache is one kind of upstream target: the right one for public, sessionless content that many clients read identically. It is not required: the gateway can target any allowlisted origin, including a direct API (see [Routing an authenticated public API](#routing-an-authenticated-public-api)), and you can run the path with no cache at all. When you do use it, the cache fetches a public URL once and serves it to many clients, with TTL, stale-while-revalidate, and single-flight. It is generic: point it at any public content by setting `UPSTREAM_BASE` and `UPSTREAM_PATH_TEMPLATE`, with no code edit. It must be listed in the gateway's `ALLOWED_TARGET_ORIGINS`.

```sh
cd ../commons-cache
docker build -t columbia-commons .

docker run -d --name commons --network columbia -p 8082:8080 \
  -e PORT=8080 \
  -e COMMONS_TTL_MS=60000 \
  -e COMMONS_SWR_MS=300000 \
  -e UPSTREAM_BASE="https://example.com" \
  -e UPSTREAM_PATH_TEMPLATE="/{id}/{sort}.rss" \
  -e UPSTREAM_UA="columbia-commons/1.0 (+https://example.com)" \
  columbia-commons
```

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | listen port |
| `COMMONS_TTL_MS` | `60000` | fresh window before an item is treated as stale (`X-Cache: HIT`) |
| `COMMONS_SWR_MS` | `300000` | serve-stale window past TTL, with a background revalidate (`X-Cache: STALE`) |
| `UPSTREAM_BASE` | `https://example.com` | upstream origin the cache fetches from; `https` only, validated at startup against private ranges so it can't be turned into an SSRF relay |
| `UPSTREAM_PATH_TEMPLATE` | `/{id}/{sort}.rss` | path appended to `UPSTREAM_BASE`, with `{id}` and `{sort}` substituted (each sanitized then percent-encoded) |
| `UPSTREAM_UA` | a generic UA string | `User-Agent` sent to the upstream origin |
| `COMMONS_MAX_ENTRIES` | `5000` | LRU bound on cached keys |
| `COMMONS_MAX_BODY_BYTES` | `5000000` | reject and never cache an upstream body larger than this |
| `FORWARD_UPSTREAM_AUTH` | `off` | when on, forward the incoming request's `Authorization` header to the upstream on a MISS or a background revalidate, for an upstream that gates its PUBLIC listings behind a credential. The header is NEVER part of the cache key, so a HIT serves the shared public bytes with no credential. Forward ONLY an anonymous, app-level credential, and ONLY for the public-listing path template. A per-user token would get its per-user response cached under `(id, sort)` and served to another caller (see the safety invariant in [`commons-cache/README.md`](./commons-cache/README.md)) |
| `REQUIRE_FDID` | (none) | when set, reject any request that did not arrive through the edge front door (see [Edge front door](#edge-front-door-cdn--waf)); the front door injects `X-Azure-FDID` and the cache checks it constant-time. Only `GET /health` is exempt. Unset disables the check |
| `FDID_HEADER` | `x-azure-fdid` | name of the header the edge front door injects for the `REQUIRE_FDID` lock above; override for a non-Azure CDN or WAF that injects a differently named header |

Responses carry `X-Cache: HIT|MISS|STALE` and CDN-ready `Cache-Control` and `Age` headers, so you can put a CDN in front later.

If you run the commons cache behind the same edge front door as the relay (see [Edge front door](#edge-front-door-cdn--waf)), set `REQUIRE_FDID` on it too, to the same front-door identifier. That pins the cache origin to the front door so nobody can drive it directly and burn the shared upstream credential budget.

## 6. (Optional) Build and run the token issuer

The issuer gates who may use the relay. It runs Apple App Attest verification and blind-signs anonymous tokens that the relay verifies offline. Run it only when the relay is in `CLIENT_AUTH_MODE=token`. It is the one component that learns a device identity, so run it under separate control that colludes with neither the relay nor the gateway. The wire format, the App Attest binding, and the epoch model are in [`token-issuer/PROTOCOL.md`](./token-issuer/PROTOCOL.md); the service's own walkthrough and the App Attest details are in [`token-issuer/README.md`](./token-issuer).

The issuer fails closed: with no signing key, or with App Attest unconfigured, it rejects every `/issue` request.

```sh
cd ../token-issuer
docker build -t columbia-token-issuer .

docker run -d --name issuer --network columbia -p 8083:8080 \
  -e PORT=8080 \
  -e ISSUER_SIGNING_KEY="$(cat issuer_key.b64)" \
  -e APPLE_APP_ATTEST_ROOT_CA_PEM_B64="$(cat apple_root_ca.b64)" \
  -e APPLE_TEAM_ID="<your team id>" \
  -e APPLE_BUNDLE_ID="<your bundle id>" \
  columbia-token-issuer
```

| Env var | Required | Purpose |
|---|---|---|
| `ISSUER_SIGNING_KEY` | yes | the epoch RSA private key (2048-bit), a PEM string or base64 of DER, PKCS#1 or PKCS#8; injected at runtime, never committed; missing or unparseable fails closed |
| `PORT` | `8080` | listen port |
| `EPOCH_SECONDS` | `604800` | epoch length; the keypair rotates per epoch (default one week) |
| `ISSUANCE_QUOTA_PER_EPOCH` | `256` | max tokens a single device may obtain per epoch; `0` disables the quota |
| `MAX_TOKENS_PER_REQUEST` | `64` | max blinded messages accepted per `/issue` call |
| `MAX_BODY_BYTES` | `262144` | request body cap |
| `REQUIRE_CLIENT_DATA_BINDING` | `1` (on) | require the App Attest `clientDataHash` to commit to the exact `blinded[]` batch and epoch; set `0` only during client bring-up |
| `APPLE_APP_ATTEST_ROOT_CA_PEM_B64` | to enforce | Apple's App Attest Root CA, PEM, base64; without it (and the two below) App Attest fails closed |
| `APPLE_TEAM_ID` | to enforce | your Apple Team ID, the first half of the appID the attestation must match |
| `APPLE_BUNDLE_ID` | to enforce | your app's bundle id, the second half of the appID |
| `APPLE_APP_ATTEST_AAGUID` | `appattest` | `appattest` for production, `appattestdevelop` for dev or TestFlight builds |
| `APP_ATTEST_CLOCK_SKEW_MS` | `300000` | tolerance when checking the attestation cert validity windows, for clock drift |
| `REQUIRE_FDID` | (none) | when set, reject any request that did not arrive through the edge front door (see [Edge front door](#edge-front-door-cdn--waf)); `GET /health` and `GET /issuer-keys` stay reachable |
| `FDID_HEADER` | `x-azure-fdid` | name of the header the edge front door injects for the `REQUIRE_FDID` lock above; override for a non-Azure CDN or WAF that injects a differently named header |

> Generate a local test signing key with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER | base64 | tr -d '\n'`. In production the key comes from your secret store at runtime, never from the repo, exactly like the gateway's `SEED_SECRET_KEY`.

Point the relay at the issuer by setting `CLIENT_AUTH_MODE=token` and `ISSUER_KEYS_URL=https://<issuer-host>/issuer-keys` on the relay. The relay fetches the issuer's epoch public keys once, caches them, and verifies every spent token offline, so there is no per-request call to the issuer.

## 7. Verify the path

Health-check each hop:

```sh
curl http://localhost:8080/health   # gateway
curl http://localhost:8081/health   # relay
curl http://localhost:8082/health   # commons cache
curl http://localhost:8083/health   # token issuer (if running)
```

To exercise the full encrypted path, use an OHTTP client. Fetch the gateway's key config (`/ohttp-configs`), HPKE-seal a `message/bhttp` request against it, and `POST` the resulting `message/ohttp-req` body to the relay. The relay returns the `message/ohttp-res` body for the client to open locally. Any RFC 9458 client library works, including the test client that ships with the upstream gateway.

## Routing an authenticated public API

The gateway forwards the inner request's headers to the target, so a public API that needs a **non-identifying, app-level** credential can be fetched through the split-trust path. Use this only for a credential that authenticates the *application* and is shared across all users; never route a per-user or login-bound credential (see the scope note in [README.md](./README.md#what-its-for)).

1. Allowlist the API origin on the gateway. Add the exact `Host` to `ALLOWED_TARGET_ORIGINS` (scheme, host, and port are literal):

   ```sh
   -e ALLOWED_TARGET_ORIGINS="https://api.example.com"
   ```

   The target must be reachable from the GATEWAY's egress IP. The gateway makes the outbound fetch, not the client, so allowlisting a host the gateway itself cannot route to still fails.

2. On the client, build the inner `message/bhttp` request with the credential in the headers:

   ```
   GET https://api.example.com/v1/resource
   Authorization: Bearer <anonymous app-level credential>
   User-Agent: your-app/1.0 (+https://YOUR_API_HOST)
   ```

   HPKE-seal it against the gateway key config (`/ohttp-configs`) and `POST` the `message/ohttp-req` body to the relay, exactly as for any other read. The `Authorization` and `User-Agent` headers ride inside the sealed BHTTP, so the relay never sees them; the gateway decrypts, checks the allowlist, and forwards those headers to the target verbatim.

3. The gateway returns the sealed `message/ohttp-res` for the client to open. A target not on the allowlist comes back as a BHTTP `403`; a momentarily exhausted upstream budget comes back as `429` with `Retry-After` (see [Shared egress](#shared-egress-one-ip-one-credential-one-budget)).

The relay still holds identity without content, and the gateway still holds content without identity. What changes is that the gateway now additionally sees the app-level credential, acceptable only because that credential names the app, not the client.

## Shared egress: one IP, one credential, one budget

Everything routed through a single gateway shares that gateway's egress. That sharing is the point (one shared fetcher is what makes reads unlinkable), but it has operational consequences you have to size for:

- **One egress IP.** Every routed fetch leaves from the gateway's IP. To the target, all clients look like one caller, so any per-IP limit or per-IP block the target applies is global; it hits everyone at once.
- **One shared credential.** When you route an app-level credential, every client presents the same credential to the target. Any per-credential quota the target enforces is a single global budget shared across your whole user base, not per client.
- **One point of failure.** If the target rate-limits or blocks that IP or credential, or the gateway tier is down, every client loses the routed path at once. Design the client to degrade; see fail-open vs fail-closed in [README.md](./README.md#fail-open-vs-fail-closed-client-choice).

Throttle your own outbound volume so you stay under the target's ceiling instead of tripping it. The gateway has an opt-in global outbound rate limit, `GATEWAY_MAX_QPM`, which caps total forwarded requests per minute across all clients:

```sh
-e GATEWAY_MAX_QPM=6000
```

When the budget is momentarily spent the gateway refuses with `429` + `Retry-After` rather than making the call, so clients back off instead of piling onto a budget that is already spent. Because the budget is global and shared, size it against the target's published limit, not against per-client expectations.

## Abuse controls

The relay is the one public surface, so it carries the abuse controls. All of them keep state in memory only, key nothing to request content, and are never logged, so they do not weaken the operator-blind property. They are off or permissive by default; turn them on for a public deployment.

- **Per-IP rate limiting and a concurrency cap.** `RATE_LIMIT_RPM` (default 120) bounds requests per minute per client IP over a `RATE_WINDOW_MS` window (default 60000); set `RATE_LIMIT_RPM=0` to disable it. `MAX_INFLIGHT` (default 256) caps concurrent relays across the whole process. Anything over either limit gets a 429. `RATE_MAX_KEYS` (default 100000) bounds the limiter's memory so a spoofed-source flood can't grow the table. Behind a single managed ingress the per-IP key is read from the rightmost `X-Forwarded-For` entry, because the TCP peer is the ingress, not the client. **If the request crosses more than one proxy** (e.g. a CDN or Front Door in front of the platform ingress), the rightmost `X-Forwarded-For` entry is the nearest proxy, not the client, so every client collapses into one bucket and gets 429'd in aggregate. Set `TRUSTED_CLIENT_IP_HEADER` to the front proxy's trusted client-IP header (`x-azure-clientip` for Azure Front Door, `cf-connecting-ip` for Cloudflare) to key per real client. That IP is used only as a transient counter key; it is never logged or forwarded to the gateway.
- **Strict request shape.** The relay answers only `POST /relay` with `Content-Type: message/ohttp-req`. A wrong content type returns 415; any other path or method returns 404. There is no general proxy surface to probe.
- **Client auth (`CLIENT_AUTH_MODE`).** `off` (default) relies on network controls only. `secret` requires a shared secret in the `CLIENT_AUTH_HEADER` (default `x-columbia-token`), checked in constant time against `CLIENT_SECRET`. A shared secret shipped in a client is extractable, so `secret` mode is a speed-bump against casual abuse, not real client authentication. `token` mode is the real client gate: the relay reads the same header, verifies an anonymous blind-RSA token offline against the issuer's epoch public key, and enforces spend-once. Point it at the issuer with `ISSUER_KEYS_URL`; it fails closed if it has no issuer keys. See [section 6](#6-optional-build-and-run-the-token-issuer) and [`token-issuer/PROTOCOL.md`](./token-issuer/PROTOCOL.md).

## Single public surface (internal gateway and commons)

The hardened posture is to make the relay the ONLY publicly reachable component and run the gateway and the commons cache on internal ingress, reachable only from inside the environment. This shrinks the attack surface to the one hop that has to be public, and it composes with the two-operator split below rather than replacing it: each operator still runs its own component, the gateway just stays off the open internet.

Two pieces make this work:

- **Relay→gateway shared secret.** Set `RELAY_GATEWAY_SECRET` to the same value on the relay and the gateway. The relay attaches it as `X-Columbia-Relay-Auth` on every outbound request, and the gateway rejects `/gateway` traffic that lacks it (constant-time, before any HPKE work). Set it on the relay FIRST, then the gateway, so there is no window where the gateway 401s relay traffic. The value is constant across all requests, so it identifies the relay, never a client.
- **Key-config passthrough.** With the gateway internal, clients cannot reach its `GET /ohttp-configs` to fetch and pin the public key config. The relay proxies it: `GET /ohttp-configs` on the relay returns the gateway's key-config bytes verbatim, cached for `CONFIG_TTL_MS` (default 120000). The key config is public material clients are meant to pin, so passing it through leaks nothing. By default the relay fetches it from the gateway's own host; override with `GATEWAY_CONFIGS_URL` if it lives elsewhere.

In production, also unregister the reflective self-test endpoints on the gateway by setting `ECHO_ENDPOINT=""` and `METADATA_ENDPOINT=""` (see [`ohttp-gateway/VENDORED.md`](./ohttp-gateway/VENDORED.md)).

> Internal-ingress gotcha. On some managed container hosts, "internal" means an in-environment-only address, and flipping a component to internal CHANGES its reachable hostname (for example it gains an `.internal.` segment). The public external FQDN does NOT keep working from inside the environment. When you internalize the gateway and commons, you MUST repoint:
>
> - the relay's `GATEWAY_URL` (and `GATEWAY_CONFIGS_URL`, if you set it) to the gateway's new internal hostname, and
> - the gateway's `ALLOWED_TARGET_ORIGINS` to the commons cache's new internal hostname.
>
> Skip the repoint and the relay hits the public edge and gets a 404. Update these in lockstep with the ingress change.

## Edge front door (CDN / WAF)

A CDN or WAF in front of the two public origins (the relay and the issuer) absorbs DDoS and applies per-IP rate limiting at the edge, before traffic reaches your container. A managed front door is one way to run this; any CDN or WAF that can inject a request header the origin can verify works the same way.

To stop someone from bypassing the front door and hitting the origin host directly, set `REQUIRE_FDID` on the relay and the issuer to the front door's identifier. Each origin reads the `X-Azure-FDID` request header and rejects any request whose value does not match `REQUIRE_FDID`. A managed Azure Front Door injects this header for its own profile id; a generic CDN or WAF works the same way as long as you configure it to inject a header named `X-Azure-FDID` (or whatever you set `FDID_HEADER` to) carrying the value you set in `REQUIRE_FDID`, and to strip any client-supplied copy. A repeated header carrying several comma-joined values passes if any one of them matches. The comparison is constant-time and the value is never logged.

- The check is inert when `REQUIRE_FDID` is unset, so you can deploy the origins first and turn the lock on once the front door is provisioned.
- `GET /health` is exempt on both services, so the platform's in-environment health probe still passes.
- The issuer also exempts `GET /issuer-keys`, because the relay fetches it directly, in-environment, and it is public key material.
- Every other route requires the header: `POST /relay` and `GET /ohttp-configs` on the relay, and `POST /issue` on the issuer.
- The commons cache implements the same `REQUIRE_FDID` lock. It runs on internal ingress by default (see [Single public surface](#single-public-surface-internal-gateway-and-commons)), but a deployment that exposes it publicly instead sets `REQUIRE_FDID` on it to the same identifier so the front door pins it too. On the cache only `GET /health` is exempt; `GET /v1/commons` and `GET /v1/probe` require the header.

This pairs with the single-public-surface posture above: by default the gateway and commons cache are internal, while the relay and issuer face the internet only through the front door. A deployment that instead exposes the commons cache publicly fronts it with the same origin lock.

## Running relay and gateway as separate operators

This is what makes the proxy genuinely operator-blind. Collapsing both onto one host defeats it: a single operator sees the IP at the relay and the content at the gateway, and can line them up.

To split them:

1. Deploy the gateway on host/operator A, with `SEED_SECRET_KEY` and a tight `ALLOWED_TARGET_ORIGINS`. Expose it over HTTPS and note its public `/gateway` URL.
2. Deploy the relay on a different host/operator B, ideally a different organization or provider, ideally not controlled by the same person as A. Set `GATEWAY_URL` to operator A's `https://<gateway-host>/gateway`.
3. Point your client at the relay (operator B). The client pins operator A's gateway key config fingerprint.

Now identity (relay, operator B) and content (gateway, operator A) live in separate trust domains, and linking you to what you fetched takes both operators colluding. For a stronger posture still, run the gateway in a confidential VM and have the client verify a hardware attestation before sealing. See [ARCHITECTURE.md](./ARCHITECTURE.md#attestation-chain-optional-advanced).

> Secrets hygiene: never commit `SEED_SECRET_KEY` or `ISSUER_SIGNING_KEY`. Inject them at runtime from your host's secret store (a Docker secret, a systemd `EnvironmentFile` with `0600` perms, or a managed secrets service). Keep `LOG_SECRETS=false`. The repo's `.gitignore` already excludes `.env`, `*.seed`, and key material as a backstop.

## Verifying the gateway

- Pin the key config. Have your client store the SHA-256 fingerprint of `/ohttp-configs` and refuse to seal to a gateway that presents a different one. That catches a swapped or unexpected key. Be clear about the limit: pinning only catches a key that CHANGES after first use. It does not catch a gateway that hands you a unique key from the very first request to single you out (trust-on-first-use). Closing that gap means cross-checking that everyone sees the same key (RFC 9540 key consistency or a transparency log), which is not yet built.
- Relay-stripping self-test. The vendored gateway exposes `/gateway-metadata` and `/gateway-echo`, which reflect back what the gateway received. Use `/gateway-metadata` through the full relay path as a self-test that header stripping works: confirm it returns no client-identifying headers (no `X-Forwarded-For`, no client `User-Agent`, nothing that ties back to you). Because these endpoints reflect inbound data, disable them or don't expose them in production.
- Attestation (advanced). If the gateway runs in a confidential VM, have the client fetch and validate the platform attestation (a DCAP quote or an MAA JWT), check the signature chain to the hardware root, and compare the launch measurement against a pinned known-good value before it trusts the channel. The attestation must also bind the HPKE key config you pin, or a good attestation and a separately pinned key don't compose into a trusted channel. See [ARCHITECTURE.md](./ARCHITECTURE.md).

## Optional: one example cloud deployment

Plain Docker, as above, is the supported path. For a managed container host, the pattern is the same: build the image, push it to a registry, and run it as a container with the same env vars. [`deploy/README.md`](./deploy/README.md) collects the deployment notes and points to one example CI automation in [`.github/workflows/deploy-azure-reference.yml`](./.github/workflows/deploy-azure-reference.yml). The repo also includes one example script, [`commons-cache/deploy-ghcr.sh`](./commons-cache/deploy-ghcr.sh), that builds the cache image, pushes it to a container registry, and creates or updates a managed container app. It uses placeholder names you have to replace:

| Placeholder in the script | Replace with |
|---|---|
| `REGISTRY_OWNER` | your container-registry namespace or owner |
| `RESOURCE_GROUP` | your cloud resource group or project |
| `CONTAINER_ENV` | your managed-container environment name |
| `APP_NAME` | the name you want for the deployed app |

The same env-var contracts apply on any host: the gateway needs `SEED_SECRET_KEY` and `ALLOWED_TARGET_ORIGINS` (inject the seed from the host's secret store, never from the repo), the relay needs `GATEWAY_URL`, the cache takes the optional `UPSTREAM_*` and `COMMONS_*` knobs, and the issuer (if you run `token` mode) needs `ISSUER_SIGNING_KEY` and the `APPLE_*` App Attest inputs, injected the same way. Run the relay and the gateway under separate operators for the non-collusion guarantee, and run the issuer under a third party that colludes with neither.
