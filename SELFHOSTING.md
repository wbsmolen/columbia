# Self-Hosting Columbia

This guide gets the three components (relay, gateway, and optionally the commons cache) running on plain Docker, on any host. You don't need a managed cloud. There's one optional cloud example at the end, with placeholders you swap for your own resource names.

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

One seed deterministically derives BOTH published key configs (the primary `X25519+Kyber768-draft00` config and the legacy `DHKEM(X25519, HKDF-SHA256)` config). The vendored gateway has NO online key rotation: rotating `SEED_SECRET_KEY` is a hard cutover. You redeploy the gateway with the new seed, and every client that pinned the old key config fingerprint breaks until it re-pins the new one. Plan the cutover, because there is no overlap window where both old and new keys are served.

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
  -e GATEWAY_URL="http://gateway:8080/gateway" \
  columbia-relay
```

| Env var | Required | Purpose |
|---|---|---|
| `GATEWAY_URL` | yes | full gateway endpoint, e.g. `https://<gateway-host>/gateway` |
| `PORT` | `8080` | listen port |

> The relay forwards only the ciphertext body plus `Content-Type: message/ohttp-req`. Dropping every client header is the security property, not an oversight.

## 5. (Optional) Build and run the commons cache

The cache is an example upstream target for the gateway. It fetches a public, sessionless URL once and serves it to many, with TTL, stale-while-revalidate, and single-flight. It's generic: point it at whatever public content you want by adapting the upstream URL it builds in `server.js`. It has to be listed in the gateway's `ALLOWED_TARGET_ORIGINS`.

```sh
cd ../commons-cache
docker build -t columbia-commons .

docker run -d --name commons --network columbia -p 8082:8080 \
  -e PORT=8080 \
  -e COMMONS_TTL_MS=60000 \
  -e COMMONS_SWR_MS=300000 \
  -e UPSTREAM_UA="columbia-commons/1.0 (+https://example.com)" \
  columbia-commons
```

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | listen port |
| `COMMONS_TTL_MS` | `60000` | fresh window before an item is treated as stale (`X-Cache: HIT`) |
| `COMMONS_SWR_MS` | `300000` | serve-stale window past TTL, with a background revalidate (`X-Cache: STALE`) |
| `UPSTREAM_UA` | a generic UA string | `User-Agent` sent to the upstream origin |

Responses carry `X-Cache: HIT|MISS|STALE` and CDN-ready `Cache-Control` and `Age` headers, so you can put a CDN in front later.

## 6. Verify the path

Health-check each hop:

```sh
curl http://localhost:8080/health   # gateway
curl http://localhost:8081/health   # relay
curl http://localhost:8082/health   # commons cache
```

To exercise the full encrypted path, use an OHTTP client. Fetch the gateway's key config (`/ohttp-configs`), HPKE-seal a `message/bhttp` request against it, and `POST` the resulting `message/ohttp-req` body to the relay. The relay returns the `message/ohttp-res` body for the client to open locally. Any RFC 9458 client library works, including the test client that ships with the upstream gateway.

## Running relay and gateway as separate operators

This is what makes the proxy genuinely operator-blind. Collapsing both onto one host defeats it: a single operator sees the IP at the relay and the content at the gateway, and can line them up.

To split them:

1. Deploy the gateway on host/operator A, with `SEED_SECRET_KEY` and a tight `ALLOWED_TARGET_ORIGINS`. Expose it over HTTPS and note its public `/gateway` URL.
2. Deploy the relay on a different host/operator B, ideally a different organization or provider, ideally not controlled by the same person as A. Set `GATEWAY_URL` to operator A's `https://<gateway-host>/gateway`.
3. Point your client at the relay (operator B). The client pins operator A's gateway key config fingerprint.

Now identity (relay, operator B) and content (gateway, operator A) live in separate trust domains, and linking you to what you fetched takes both operators colluding. For a stronger posture still, run the gateway in a confidential VM and have the client verify a hardware attestation before sealing. See [ARCHITECTURE.md](./ARCHITECTURE.md#attestation-chain-optional-advanced).

> Secrets hygiene: never commit `SEED_SECRET_KEY`. Inject it at runtime from your host's secret store (a Docker secret, a systemd `EnvironmentFile` with `0600` perms, or a managed secrets service). Keep `LOG_SECRETS=false`. The repo's `.gitignore` already excludes `.env`, `*.seed`, and key material as a backstop.

## Verifying the gateway

- Pin the key config. Have your client store the SHA-256 fingerprint of `/ohttp-configs` and refuse to seal to a gateway that presents a different one. That catches a swapped or unexpected key. Be clear about the limit: pinning only catches a key that CHANGES after first use. It does not catch a gateway that hands you a unique key from the very first request to single you out (trust-on-first-use). Closing that gap means cross-checking that everyone sees the same key (RFC 9540 key consistency or a transparency log), which is not yet built.
- Relay-stripping self-test. The vendored gateway exposes `/gateway-metadata` and `/gateway-echo`, which reflect back what the gateway received. Use `/gateway-metadata` through the full relay path as a self-test that header stripping works: confirm it returns no client-identifying headers (no `X-Forwarded-For`, no client `User-Agent`, nothing that ties back to you). Because these endpoints reflect inbound data, disable them or don't expose them in production.
- Attestation (advanced). If the gateway runs in a confidential VM, have the client fetch and validate the platform attestation (a DCAP quote or an MAA JWT), check the signature chain to the hardware root, and compare the launch measurement against a pinned known-good value before it trusts the channel. The attestation must also bind the HPKE key config you pin, or a good attestation and a separately pinned key don't compose into a trusted channel. See [ARCHITECTURE.md](./ARCHITECTURE.md).

## Optional: one example cloud deployment

Plain Docker, as above, is the supported path. If you'd rather use a managed container host, the pattern is the same: build the image, push it to a registry, and run it as a container with the same env vars. The repo includes one example script, [`commons-cache/deploy-ghcr.sh`](./commons-cache/deploy-ghcr.sh), that builds the cache image, pushes it to a container registry, and creates or updates a managed container app. It uses placeholder names you have to replace:

| Placeholder in the script | Replace with |
|---|---|
| `REGISTRY_OWNER` | your container-registry namespace or owner |
| `RESOURCE_GROUP` | your cloud resource group or project |
| `CONTAINER_ENV` | your managed-container environment name |
| `APP_NAME` | the name you want for the deployed app |

The same three env-var contracts apply on any host: the gateway needs `SEED_SECRET_KEY` and `ALLOWED_TARGET_ORIGINS` (inject the seed from the host's secret store, never from the repo), the relay needs `GATEWAY_URL`, and the cache takes the optional `COMMONS_*` and `UPSTREAM_UA` knobs. And run the relay and gateway under separate operators for the non-collusion guarantee.
