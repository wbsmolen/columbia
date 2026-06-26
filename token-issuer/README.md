# token-issuer

The token issuer is how Columbia answers a hard question: how do you let only the
genuine Lander app use the relay, rate limit even your own users, and still never
be able to link a user to the content they fetch?

The answer is the Privacy Pass pattern (the same one Apple's Private Access Tokens
use). This service plays the **Attester** and **Issuer** roles of the Privacy Pass
architecture ([RFC 9576](https://www.rfc-editor.org/rfc/rfc9576)). It is the one
component in the system that is allowed to learn a device's identity, and the whole
design makes that knowledge worthless: it only ever sees *blinded* token requests,
it blind-signs them ([RFC 9474](https://www.rfc-editor.org/rfc/rfc9474) blind RSA),
and it hands back blind signatures. It never sees the finished tokens, and it never
sees the content those tokens are later spent on.

The relay, run by a different operator, checks the tokens and sees content and IP
but never the device id. So no single party ever holds identity and content
together. That is the same operator-blind property the relay and gateway give you,
extended to "prove you're a real, rate-limited client" without a login.

## How a token flows

```
  device                         issuer                          relay
  ------                         ------                          -----
  App Attest assertion  ───────▶ validate attestation
  blind(tokenInput) ───────────▶ enforce per-device quota
                                 blind-sign each blinded_msg
                        ◀─────── blind signatures
  finalize() = real token
                                 (issuer never sees this)
  spend token in OHTTP  ──────────────────────────────────────▶ verify RSA-PSS
  outer header                                                  against epoch
                                                                public key,
                                                                spend-once
```

1. The device proves it is a genuine Lander install via Apple App Attest.
2. The device blinds one or more token inputs locally and sends the blinded
   messages (never the inputs) to `POST /issue`.
3. The issuer validates App Attest, checks the device's per-epoch quota, and
   blind-signs each blinded message with the current epoch RSA private key.
4. The device finalizes (unblinds) each blind signature into a real, anonymous
   token. The issuer cannot recognize these tokens later: blinding is randomized
   and the unblinding factor never leaves the device.
5. The device spends a token at the relay, in the OUTER OHTTP request header. The
   relay verifies the token's RSA-PSS signature against the issuer's epoch PUBLIC
   key (fetched once and cached, no per-request call to the issuer) and enforces
   spend-once.

## Token construction

`RSABSSA-SHA384-PSS-Deterministic` over a 2048-bit RSA key. This is the
publicly-verifiable Privacy Pass token (Token Type 2,
[RFC 9578](https://www.rfc-editor.org/rfc/rfc9578)) that Apple's Private Access
Tokens use. "Publicly verifiable" is the property that lets the relay verify a
spent token offline with only the public key.

The blind RSA math comes from `@cloudflare/blindrsa-ts`, Cloudflare's
implementation of RFC 9474. It is the exact construction Apple uses, which is why
it was chosen over rolling our own.

## Endpoints

| Route | Method | Purpose |
|---|---|---|
| `/health` | `GET` | liveness, returns `ok` |
| `/issuer-keys` | `GET` | publishes the current and previous epoch RSA PUBLIC keys (SPKI, base64) with their key ids, so the relay can verify tokens offline |
| `/issue` | `POST` | validates App Attest, checks the device quota, blind-signs the supplied blinded messages, returns the blind signatures |

### `POST /issue`

Request (JSON):

```json
{
  "keyId":          "<base64url App Attest key id, the device identifier>",
  "attestation":    "<base64 App Attest attestation, first call per device>",
  "assertion":      "<base64 App Attest assertion, subsequent calls>",
  "clientDataHash": "<base64 sha256 of the request the device signed>",
  "blinded":        ["<base64 blinded_msg>", "..."]
}
```

Response (JSON):

```json
{
  "epoch":     12345,
  "keyId":     "<issuer epoch public key id>",
  "blindSigs": ["<base64 blind signature>", "..."]
}
```

Same order in and out. The issuer blind-signs and returns. It never unblinds, so
it never sees the finished tokens.

### `GET /issuer-keys`

```json
{
  "suite":        "RSABSSA-SHA384-PSS-Deterministic",
  "epoch":        12345,
  "epochSeconds": 604800,
  "keys": [
    { "epoch": 12345, "keyId": "…", "publicKeySpki": "<base64 SPKI>" },
    { "epoch": 12344, "keyId": "…", "publicKeySpki": "<base64 SPKI>" }
  ]
}
```

The current and previous epoch are both published so tokens minted just before an
epoch boundary still verify. This is public material; serving it leaks nothing.

## The epoch model

The issuer keypair rotates per epoch. An epoch is just
`floor(unixSeconds / EPOCH_SECONDS)`, computed independently by issuer and relay,
default one week. Tokens carry no timestamp, only the epoch's key id, so spend time
leaks nothing finer than "this token was issued in epoch E". A coarse epoch keeps
the anonymity set large: everyone issued in the same epoch is indistinguishable at
spend time.

The per-device quota and the relay's spend-once set are both scoped to the epoch,
so they self-expire when the epoch rolls.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | listen port (non-root can't bind below 1024) |
| `ISSUER_SIGNING_KEY` | required | the epoch RSA private key (2048-bit). Either a PEM string or base64 of DER; PKCS#1 or PKCS#8 are both accepted. Injected at runtime, NEVER committed. Missing or unparseable => fails closed |
| `EPOCH_SECONDS` | `604800` | epoch length in seconds (default one week) |
| `ISSUANCE_QUOTA_PER_EPOCH` | `256` | max tokens a single device may obtain per epoch. `0` disables the quota |
| `MAX_TOKENS_PER_REQUEST` | `64` | max blinded messages per `/issue` call |
| `MAX_BODY_BYTES` | `262144` | request body cap |
| `APPLE_APP_ATTEST_ROOT_CA_PEM_B64` | unset | Apple's App Attest Root CA, PEM, base64. Required to ENFORCE App Attest |
| `APPLE_TEAM_ID` | unset | your Apple Team ID. Required to enforce App Attest |
| `APPLE_BUNDLE_ID` | unset | Lander's bundle id. Required to enforce App Attest |
| `APPLE_APP_ATTEST_AAGUID` | `appattest` | `appattest` for production, `appattestdevelop` for dev/TestFlight builds |

The signing key is injected exactly like the gateway's `SEED_SECRET_KEY`: from your
host's secret store at runtime, never written to disk in this repo.

## What is production ready vs what still needs work

Being honest about this matters, because the security of the whole pattern rests on
these pieces.

**Production ready:**

- The blind RSA issuance and verification. Blind, blind-sign, finalize, and
  verify all round-trip correctly under the epoch public key, using the vetted
  `@cloudflare/blindrsa-ts` (RFC 9474) library and the Apple PAT suite. Proven by
  `test.js`.
- The relay's token verification path. It verifies the RSA-PSS signature offline
  against the cached epoch public key and enforces spend-once. Valid tokens pass,
  double-spends are rejected, tampered and forged tokens are rejected. Proven by
  `test.js`.
- The epoch key model and the `/issuer-keys` publication.
- Fail-closed behavior. With no signing key, or with App Attest unconfigured, the
  issuer rejects every request rather than issuing under a key nobody controls or
  to a device nobody verified.

**Stubbed, and clearly marked as such:**

- **Apple App Attest validation** (`appattest.js`). The full structure is there,
  with every Apple-defined check as its own labeled function: cert chain to Apple's
  App Attest Root CA, nonce binding, key-id binding, rpId/appID hash, aaguid, and
  the assertion's monotonic sign counter. Each one that cannot be completed without
  operator input (Apple's root cert, your team and bundle id) or without CBOR/X.509
  parsing is a `STUB` that returns `false` with a precise `TODO`. The module
  fails closed until `APPLE_APP_ATTEST_ROOT_CA_PEM_B64`, `APPLE_TEAM_ID`, and
  `APPLE_BUNDLE_ID` are supplied AND the parsing is filled in. There is no
  silent-allow path. Wiring this up is the main remaining task before production.

- **Persistent quota and redemption state.** Both the issuer's per-device per-epoch
  quota and the relay's spend-once set are in-memory and single-process. That is
  fine for a first cut and for a single replica, but it has two gaps for a real
  multi-replica deployment: a device could get its full quota from each replica,
  and a restart forgets prior spends. The code marks exactly where a shared atomic
  store goes (Redis `INCR`/`EXPIRE` for the quota keyed by a salted device hash,
  Redis `SET NX` with an epoch TTL for the redemption nullifiers). The nullifier is
  derived from the token signature only and carries no identity, so the store never
  holds anything user-linking.

- **Attester / Issuer split.** Right now one service plays both Privacy Pass roles.
  RFC 9576 allows splitting the Attester (which sees the device) from the Issuer
  (which blind-signs) into separate parties for an even stronger posture. That split
  is future work and is noted in the roadmap.

## Deployment intent

This becomes a separate, public Azure Container App, built and deployed the same
way as the relay, gateway, and commons cache (see the repo's deploy workflow). Like
the gateway, **it must be run such that it never colludes with the relay.** If one
operator ran both the issuer and the relay, it could line up "device D asked for
tokens in epoch E" (the issuer's view) against "a token from epoch E was spent on
content C" (the relay's view) and, with enough traffic analysis, start to undo the
unlinkability. Run the issuer under separate control, in its own trust domain, for
the guarantee to hold. See the repo's `SELFHOSTING.md` for the non-collusion model.

## Run locally

```sh
# Generate an ephemeral signing key for local testing (do NOT use in production;
# in production the key is injected from your secret store). A plain openssl RSA
# key works; the issuer accepts PEM or base64-of-DER, PKCS#1 or PKCS#8:
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER \
  | base64 | tr -d '\n' > /tmp/issuer_key.b64

ISSUER_SIGNING_KEY="$(cat /tmp/issuer_key.b64)" PORT=8080 node server.js
curl localhost:8080/health        # -> ok
curl localhost:8080/issuer-keys   # -> current + previous epoch public keys
# /issue returns 401 until App Attest is configured (fail-closed by design)
```

Or with Docker:

```sh
docker build -t columbia-token-issuer .
docker run --rm -p 8080:8080 \
  -e PORT=8080 \
  -e ISSUER_SIGNING_KEY="$(cat /tmp/issuer_key.b64)" \
  columbia-token-issuer
```

Runs as the non-root `node` user on port 8080.

## Tests

```sh
npm install
node --test
```

The suite proves the blind-sign roundtrip, relay acceptance of a valid token,
double-spend rejection, tampered/forged-token rejection, an unlinkability sanity
check, and the quota accounting.

## Dependencies

Unlike the dependency-free relay and commons cache, this service uses npm packages,
because doing blind RSA by hand is exactly the kind of custom crypto you should not
write:

- `@cloudflare/blindrsa-ts` (RFC 9474 blind RSA, the Apple PAT construction). Its
  only transitive dependency is `sjcl` (the Stanford JS Crypto Library) for the
  big-integer math. Two packages total, no known vulnerabilities at the pinned
  version. The lockfile is committed so the image build is reproducible.
