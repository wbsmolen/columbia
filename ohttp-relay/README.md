# ohttp-relay

The relay half of the OHTTP ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458)) split-trust pair. It's the only component that ever sees a client's IP address, and it can do nothing with it, because everything it forwards is an opaque HPKE ciphertext it can't decrypt.

Dependency-free Node (built-in `http` and `https` only).

## Why it exists

OHTTP deliberately keeps who and what with two different parties:

| Party | Sees the client IP? | Sees the request content? |
|---|---|---|
| Relay (this service) | yes | no, only `message/ohttp-req` ciphertext |
| Gateway | no, the relay sends a fresh request | yes, it holds the HPKE key |

Neither party ever holds identity and content together. That's the operator-blind guarantee. The relay's job is to be the network endpoint the client connects to, and to forward the sealed bytes to the gateway without leaking who the client is.

> Non-collusion caveat: for the guarantee to hold, the relay and gateway have to be run by different, non-colluding parties. Running both on one host proves the flow works but gives you no protection against the single operator. See [`../SELFHOSTING.md`](../SELFHOSTING.md).

## The OHTTP request/response flow

*The relay forwards opaque ciphertext to the gateway without leaking who the client is.*

```mermaid
sequenceDiagram
    participant client as Client
    participant relay as Relay
    participant gateway as Gateway
    participant commons as Commons Cache

    Note over client: HPKE-seal request
    client->>relay: POST / · Content-Type message/ohttp-req · opaque ciphertext
    Note over relay: strip ALL client headers + IP<br/>then fresh POST /gateway
    relay->>gateway: POST /gateway · Content-Type message/ohttp-req
    Note over gateway: HPKE-decapsulate<br/>to inner message/bhttp
    gateway->>commons: fetch target
    commons-->>gateway: content
    Note over gateway: HPKE-encapsulate response<br/>message/ohttp-res
    gateway-->>relay: message/ohttp-res
    relay-->>client: 200 · Content-Type message/ohttp-res
    Note over client: HPKE-open on device
```

### Content types

| Type | Where | What it is |
|---|---|---|
| `message/ohttp-req` | client -> relay -> gateway | the outer HPKE-encapsulated request envelope (RFC 9458). Opaque to the relay. |
| `message/ohttp-res` | gateway -> relay -> client | the outer HPKE-encapsulated response envelope. Opaque to the relay. |
| `message/bhttp` | inside the envelope, only after the gateway decrypts | the inner Binary HTTP ([RFC 9292](https://www.rfc-editor.org/rfc/rfc9292)) request/response, the actual GET to the target. The relay never sees this; only the gateway decrypts down to it. |

## Endpoints

| Route | Method | Purpose |
|---|---|---|
| `/health` | `GET` | liveness, returns `ok` |
| `/` | `POST` | accepts a `message/ohttp-req` body, forwards it to the gateway's `/gateway`, returns the `message/ohttp-res` body verbatim |

## What it deliberately does not forward

When it relays to the gateway, the service builds a fresh request and sends only:

- the opaque ciphertext body, and
- `Content-Type: message/ohttp-req` plus `Content-Length`.

It leaves out every client header and never adds `X-Forwarded-For`, so the gateway can't learn the client's IP. (See `server.js`. That omission is the security property, not an oversight.)

## Observability

RED metrics only, structured JSON to stdout:

```json
{"ts":"…","route":"/relay","status":200,"durationMs":212}
```

No IP, no content, no headers, no target. `route` is a fixed template.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | listen port (non-root can't bind below 1024) |
| `GATEWAY_URL` | required | full gateway endpoint, e.g. `https://<gateway-host>/gateway` |
| `CLIENT_AUTH_MODE` | `off` | `off`, `secret`, or `token` (Privacy Pass / Private Access Token) |
| `ISSUER_KEYS_URL` | unset | in `token` mode, the issuer's `GET /issuer-keys`, e.g. `https://<issuer-host>/issuer-keys` |
| `ISSUER_KEYS_TTL_MS` | `300000` | how often the relay refreshes the cached issuer public keys |
| `TOKEN_PSS_SALT_LEN` | `48` | RSA-PSS salt length for token verification (SHA-384 digest length) |
| `REDEMPTION_MAX_KEYS` | `5000000` | spend-once set memory bound (single replica; a shared store is the real fix) |

### Token mode (Privacy Pass)

In `token` mode the relay accepts an anonymous, unlinkable blind-RSA token in the
auth header and verifies it offline against the issuer's epoch public key
(RSA-PSS/SHA-384, the RFC 9578 / Apple PAT suite), then enforces spend-once. There
is no per-request call to the issuer: the relay fetches the public key once from
`ISSUER_KEYS_URL` and caches it, so the issuer never learns which token was spent.
That offline, public verification is what keeps the token unlinkable. The issuer
half lives in [`../token-issuer`](../token-issuer). The spend-once set is in-memory
and single-process for now; the code marks where a shared store goes for a
multi-replica deployment.

## Run locally

```sh
GATEWAY_URL='https://<gateway-host>/gateway' PORT=8080 node server.js
curl localhost:8080/health         # -> ok
# POST a real message/ohttp-req body produced by an OHTTP client to test the path
```

Or with Docker:

```sh
docker build -t columbia-relay .
docker run --rm -p 8080:8080 \
  -e PORT=8080 -e GATEWAY_URL='https://<gateway-host>/gateway' \
  columbia-relay
```

Runs as the non-root `node` user on port 8080. For the real operator-blind guarantee, deploy this on a different operator than the gateway. See [`../SELFHOSTING.md`](../SELFHOSTING.md).
