# token-issuer

The token issuer gates relay access to genuine, attested clients, supports rate
limiting, and preserves unlinkability between a user and the content they fetch.

It is a reference token-issuance gate for a client using Apple App Attest. App
Attest is an Apple/iOS mechanism; on other platforms the attestation step is
replaced by the equivalent device-integrity primitive and the rest of the Privacy
Pass flow is unchanged.

The design uses the Privacy Pass pattern (as used by Apple's Private Access
Tokens). This service plays the **Attester** and **Issuer** roles of the Privacy
Pass architecture ([RFC 9576](https://www.rfc-editor.org/rfc/rfc9576)). It is the
one component allowed to learn a device's identity; the design renders that
knowledge unusable: it only ever sees *blinded* token requests, blind-signs them
([RFC 9474](https://www.rfc-editor.org/rfc/rfc9474) blind RSA), and returns blind
signatures. It never sees the finished tokens, and never sees the content those
tokens are later spent on.

The relay, run by a different operator, checks the tokens and sees content and IP
but never the device id, so no single party holds identity and content together.
This extends the operator-blind property of the relay and gateway to proving a
genuine, rate-limited client without a login.

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

1. The device proves it is a genuine install of the iOS client via Apple App Attest.
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
implementation of RFC 9474. It is the exact construction Apple uses, which is the
reason to use it rather than a hand-rolled implementation.

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

The issuer's per-device quota is scoped to the epoch and self-expires when it
rolls. The relay's in-memory spend-once set is not epoch-scoped — it's bounded
by `REDEMPTION_MAX_KEYS` with oldest-inserted eviction, cleared on restart. A
production, multi-replica deployment should move it to a shared, epoch-TTL'd
store (see PROTOCOL.md).

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
| `APPLE_BUNDLE_ID` | unset | the iOS client's bundle id. Required to enforce App Attest |
| `APPLE_APP_ATTEST_AAGUID` | `appattest` | `appattest` for production, `appattestdevelop` for dev/TestFlight builds |
| `APP_ATTEST_CLOCK_SKEW_MS` | `300000` | tolerance (ms) when checking the x5c certs' validity windows, for issuer/Apple clock drift |
| `REQUIRE_CLIENT_DATA_BINDING` | `1` (on) | require the App Attest `clientDataHash` to commit to the exact `blinded[]` batch + epoch (see below). Set to `0` only during client bring-up, before the iOS client computes the matching hash |
| `REQUIRE_FDID` | unset | when set, reject any request whose `X-Azure-FDID` header does not match, so the issuer only accepts traffic that arrived through your front door (a CDN or WAF, for example Azure Front Door). `/health` and `/issuer-keys` are exempt. Empty/unset disables the check |
| `FDID_HEADER` | `x-azure-fdid` | name of the header the edge front door injects for the `REQUIRE_FDID` lock above; override for a non-Azure CDN or WAF that injects a differently named header |

The signing key is injected exactly like the gateway's `SEED_SECRET_KEY`: from your
host's secret store at runtime, never written to disk in this repo.

### Request-payload binding (`clientDataHash` ↔ `blinded[]`)

App Attest proves "a genuine device signed this 32-byte `clientDataHash`." On its
own that authenticates the device but not the request: a captured valid
`{keyId, assertion, clientDataHash}` could be replayed against a *different*
`blinded[]` batch (still bounded by the per-device quota, but not request-integrity
checked). With `REQUIRE_CLIENT_DATA_BINDING=1` (the default), the issuer requires

```
clientDataHash == SHA-256( utf8(epoch) || 0x00 || blinded[0] || 0x00 || blinded[1] || 0x00 ... )
```

where each `blinded[i]` is the raw (base64-decoded) blinded message, so the
attestation/assertion is bound to the exact tokens being requested in this epoch
(the current or previous epoch is accepted, to tolerate an epoch-boundary crossing).
**The iOS client must compute its App Attest challenge as this same hash.** Before
the client computes the matching hash, run with `REQUIRE_CLIENT_DATA_BINDING=0`
(App Attest then bounds abuse per-device but does not bind the payload) and flip it
on once the client matches. This is the one piece of the App Attest gate whose other
half lives in the iOS client.

## What is production ready vs what still needs work

The security of the whole pattern rests on these pieces.

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

**Implemented:**

- **Apple App Attest validation** (`appattest.js`). The full server-side check
  follows Apple's "Validating Apps That Connect to Your Server through App Attest":
  - *Attestation* (one-time device registration): CBOR-decode the attestation
    object, verify the `x5c` certificate chain anchors to Apple's App Attest Root
    CA (real X.509 path + signature + validity checks via node's
    `crypto.X509Certificate`), verify the nonce in the leaf cert's
    `1.2.840.113635.100.8.2` extension equals `SHA256(authData || clientDataHash)`,
    verify `rpIdHash == SHA256(appID)`, verify the AAGUID matches the configured
    environment (`appattest` prod / `appattestdevelop` dev), verify `signCount == 0`,
    bind the keyId to `SHA256` of the credential's uncompressed EC point, and
    extract the device public key for storage.
  - *Assertion* (per issuance): verify the ECDSA-P256-SHA256 signature over
    `SHA256(authData || clientDataHash)` with the stored device key, re-check
    `rpIdHash`, and enforce a strictly increasing sign counter.

  It still **fails closed**: with `APPLE_APP_ATTEST_ROOT_CA_PEM_B64`,
  `APPLE_TEAM_ID`, or `APPLE_BUNDLE_ID` unset, the validator rejects every request,
  and any failed check rejects the request. There is no silent-allow path.

  The validation logic is exercised by `appattest.test.js` against a synthetic
  trust chain (a self-minted CA + leaf, built in pure JS in `appattest-fixtures.js`)
  that satisfies every Apple check, plus negative tests that each tampered field is
  rejected. The one remaining gap is a **real-device fixture**: a captured
  attestation/assertion from a physical iPhone running the iOS client, validated
  against Apple's real Root CA, to confirm byte-compatibility with Apple's actual
  encoder. See the capture procedure below.

**Stubbed, and clearly marked as such:**

- **Persistent quota, redemption, and attested-key state.** The issuer's per-device
  per-epoch quota, the relay's spend-once set, and the App Attest attested-key store
  (device public key + last sign counter per keyId) are all in-memory and
  single-process. That is fine for a first cut and for a single replica, but it has
  gaps for a real multi-replica deployment: a device could get its full quota from
  each replica, a restart forgets prior spends, and a device registered on one
  replica is unknown to another (its assertions are rejected as `unknown_device_key`
  until it re-attests; the iOS client handles this by re-attesting on rejection).
  The code marks exactly where a shared atomic store goes (Redis `INCR`/`EXPIRE` for
  the quota keyed by a salted device hash, Redis `SET NX` with an epoch TTL for the
  redemption nullifiers, and a Redis hash per keyId for the attested key with a
  compare-and-set on the sign counter so concurrent assertions cannot both pass with
  the same counter). The nullifier is derived from the token signature only and
  carries no identity; the attested key is device-PUBLIC material, and the store is
  keyed by a salted hash of the keyId, so the store never holds anything
  user-linking.

- **Attester / Issuer split.** One service plays both Privacy Pass roles. RFC 9576
  allows splitting the Attester (which sees the device) from the Issuer (which
  blind-signs) into separate parties for an even stronger posture. That split is a
  roadmap item.

## Deployment intent

The issuer runs as a separate, public service, built and deployed the same way as
the relay, gateway, and commons cache (plain Docker on any host; see [`deploy/`](../deploy)
for one example). Like the gateway, **it must be run such that it never colludes
with the relay.** If one
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

Run them under the deploy runtime (`node:20.18.1-alpine`), not a newer local node,
since a node-version mismatch can change runtime behavior between local and deploy:

```sh
# from the repo root (the Privacy Pass test imports the sibling relay)
docker run --rm -v "$PWD":/repo -w /repo/token-issuer node:20.18.1-alpine \
  sh -c 'npm ci && npm test'
```

`test.js` proves the blind-sign roundtrip, relay acceptance of a valid token,
double-spend rejection, tampered/forged-token rejection, an unlinkability sanity
check, the quota accounting, and a real-entrypoint boot.

`appattest.test.js` proves the App Attest validator: a well-formed (synthetic)
attestation is accepted and returns the device key, an assertion from that key
verifies and advances the sign counter, and each tampered field is rejected on its
own (wrong rpIdHash, wrong challenge/nonce, broken chain, untrusted root, wrong
aaguid, non-zero first counter, forged keyId, bad assertion signature,
non-increasing counter, unknown device key), plus fail-closed behaviour on missing
inputs. The synthetic trust chain is built in pure JS in `appattest-fixtures.js`
(a test helper; it is not imported by `server.js` and is not copied into the image).

### Capturing a real-device fixture (required follow-up)

The synthetic fixtures substitute one thing only, the trust anchor (the test root
in place of Apple's Root CA, injected exactly as an operator injects the real root).
Every cryptographic and structural check is the production one. Still, before
trusting this in production you should validate one **real** attestation from a
physical iPhone running the iOS client, against Apple's real Root CA, to confirm
byte-compatibility with Apple's actual CBOR/X.509 encoder. Two ways:

1. **Debug capture endpoint (temporary).** Add a short-lived `POST /attest-debug`
   to a NON-production instance that takes `{ keyId, attestation, clientDataHash }`,
   runs `validateAppAttest` with the real `APPLE_*` env set, and returns the result
   (and, in debug only, the failing check). Drive it from the iOS client's App
   Attest code path once, capture the request body, then **remove the endpoint**.
2. **Captured fixture (preferred, permanent regression).** Have the iOS client
   log one real `attestation` + `clientDataHash` + `keyId` for a known challenge,
   paste them into a new test alongside the **real** Apple Root CA PEM (base64), and
   assert `validateAppAttest` returns `ok: true`. Because a real attestation is not
   user-linking once the challenge is discarded, this fixture is safe to commit.

Until that fixture exists, treat App Attest as "implemented and unit-proven against
a synthetic chain, pending one real-device confirmation."

## Dependencies

Unlike the dependency-free relay and commons cache, this service uses npm packages,
because hand-rolling blind RSA is exactly the kind of custom cryptography to avoid:

- `@cloudflare/blindrsa-ts` (RFC 9474 blind RSA, the Apple PAT construction). Its
  only transitive dependency is `sjcl` (the Stanford JS Crypto Library) for the
  big-integer math. Two packages total, no known vulnerabilities at the pinned
  version. The lockfile is committed so the image build is reproducible.
