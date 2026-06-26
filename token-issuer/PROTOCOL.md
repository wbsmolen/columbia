# Columbia anonymous-token protocol

This is the wire contract between the three independently built pieces of
Columbia's Privacy Pass token auth:

- the **issuer** (`token-issuer/server.js` + `token-issuer/appattest.js`), which
  runs App Attest verification and blind-signs tokens,
- the **app** (Lander's `AppAttestTokenClient.swift`), which attests the device,
  blinds token nonces, unblinds the issuer's blind signatures, and spends the
  finished tokens, and
- the **relay** (`ohttp-relay/server.js`), which verifies a spent token offline
  and enforces spend-once.

The issuer code is the source of truth. Where the app or the relay disagreed with
it, they were changed to match, not the other way around. This document is derived
from the issuer's actual code, so if the code and this doc ever drift, the code
wins and this doc is the bug.

Everything here is built so the one party that learns the device identity (the
issuer, via App Attest) never sees the spent token, and the party that sees the
spent token and the content (the relay) never learns the device identity. The
blinding factor that breaks the link lives only on the device.

## Suite

All three sides MUST agree on exactly one blind-signature suite:

```
RSABSSA-SHA384-PSS-Deterministic
```

That is RFC 9474 blind RSA, 2048-bit modulus, RSA-PSS with SHA-384 and a 48-byte
salt, deterministic (identity) message preparation. This is the same suite Apple's
Private Access Tokens use (RFC 9578 Token Type 2), which is why a finished token is
publicly verifiable against the issuer's epoch public key with no callback to the
issuer.

Two consequences of "deterministic / identity preparation" that the contract
depends on:

- `prepare(nonce)` returns the nonce bytes unchanged. So the **token input** the
  relay verifies the signature over is exactly the 32 random nonce bytes the app
  drew. There is no extra random prefix to carry.
- A blinded message and a finished signature are each exactly 256 bytes (2048-bit
  RSA). The issuer rejects any blinded message that is not 256 bytes.

## Epochs

The issuer keypair is scoped to an epoch. The epoch id is an integer both sides
compute independently:

```
epoch = floor(unixSeconds / EPOCH_SECONDS)        // EPOCH_SECONDS default 604800 (one week)
```

Tokens carry no timestamp. They carry the epoch public key's **keyId**, so spend
time leaks nothing finer than which week the token was issued in. Everyone issued
in the same epoch is in one anonymity set.

The **keyId** of an epoch public key is:

```
keyId = hex( SHA-256( SPKI-DER of the epoch RSA public key ) )[0:32]    // first 32 hex chars
```

It is derived from public material only.

Around an epoch boundary the issuer publishes BOTH the current and the previous
epoch's public key, and accepts the App Attest binding hash computed against either
the current or the previous epoch (see `/issue`). The app keeps tokens for both
live epochs and drops the rest.

## Endpoints (issuer)

The issuer exposes exactly three routes. There is **no** `/attest-challenge` and
**no** separate `/attest` endpoint. Registration happens inside `/issue`. (An
earlier app proposal had those two endpoints; they do not exist on the issuer and
were removed from the app.)

### GET /health

Liveness only. Returns `200` with the body `ok` (text/plain). No JSON.

### GET /issuer-keys

Publishes the current and previous epoch RSA public keys so the relay (and the app)
can verify and blind against them. Public material only.

Response `200`, `application/json`:

```json
{
  "suite": "RSABSSA-SHA384-PSS-Deterministic",
  "epoch": 2871,
  "epochSeconds": 604800,
  "keys": [
    { "epoch": 2871, "keyId": "a1b2c3...32hex", "publicKeySpki": "<base64 SPKI DER>" },
    { "epoch": 2870, "keyId": "d4e5f6...32hex", "publicKeySpki": "<base64 SPKI DER>" }
  ]
}
```

- `keys[0]` is the current epoch, `keys[1]` is the previous epoch. Treat the
  presence of a second entry as optional (a fresh issuer with one epoch of history
  may publish one).
- `publicKeySpki` is the standard `SubjectPublicKeyInfo` DER of the RSA public key,
  **base64** (not base64url). The app tolerates base64url too, but the issuer emits
  base64.
- On a missing or unreadable signing key the issuer returns `503` (fail closed),
  not an empty key list.

### POST /issue

The one call that both registers a device (first contact) and mints tokens. Content
type MUST be `application/json` or the issuer returns `415`.

Request body, `application/json`:

```json
{
  "keyId":          "<base64 (or base64url) App Attest key id>",
  "attestation":    "<base64 App Attest attestation object>",   // first call per device only
  "assertion":      "<base64 App Attest assertion>",            // every later call
  "clientDataHash": "<base64 of the 32-byte binding hash>",
  "blinded":        [ "<base64 blinded message>", ... ]         // 1..MAX_TOKENS_PER_REQUEST (default 64)
}
```

Field rules, exactly as the issuer enforces them:

- `keyId` (required, non-empty string). The App Attest key id. It is base64 of the
  32-byte `SHA-256(device public key point)`. The issuer accepts base64 or
  base64url and normalizes internally.
- `attestation` XOR `assertion`. On a device's first ever call, send `attestation`
  (the CBOR App Attest attestation object, base64) and omit `assertion`. On every
  subsequent call, send `assertion` (the CBOR App Attest assertion, base64) and omit
  `attestation`. If both are absent the issuer rejects with `no_attestation_or_assertion`.
- `clientDataHash` (required) is the **base64 of the 32 raw bytes** of the binding
  hash defined in the next section. It is NOT a JSON object, NOT a preimage, NOT
  base64url. It must decode to exactly 32 bytes or the issuer rejects it. This is
  the single field the earlier app version got most wrong: it was sending the
  preimage bytes, not the 32-byte hash.
- `blinded` (required) is an array of 1..64 base64 blinded messages, each exactly
  256 bytes after decoding. Order is preserved into the response.

Response `200`, `application/json`:

```json
{
  "epoch":     2871,
  "keyId":     "a1b2c3...32hex",
  "blindSigs": [ "<base64 blind signature>", ... ]    // same length and order as request.blinded
}
```

- `epoch` is the integer epoch the tokens were signed under.
- `keyId` is the issuer **epoch public key id** (the same id `/issuer-keys`
  publishes), NOT the device keyId. The app banks this with each finished token so
  it can tell the relay which epoch key to verify under.
- `blindSigs[i]` is the base64 blind signature over `blinded[i]`. Same order, same
  length. The issuer never unblinds, so it never sees the finished token.

Error responses (no body, status only):

| Status | Meaning |
|---|---|
| `400` | bad JSON, missing/empty `keyId`, batch size 0 or over the max, a blinded entry that is not a string, or a blinded entry whose decoded length is not 256 bytes |
| `401` | App Attest validation failed, or the `clientDataHash` did not equal the binding hash for the current or previous epoch |
| `413` | request body over `MAX_BODY_BYTES` (default 262144) |
| `415` | content type was not `application/json` |
| `429` | the device's per-epoch issuance quota (default 256 tokens/epoch) would be exceeded by this batch |
| `503` | the issuer has no usable signing key |
| `500` | blind-sign or unhandled error |

The app treats `401`/`403` as "re-attest needed" and a fresh attestation is sent on
the next call.

## The binding hash (clientDataHash), byte for byte

This is the heart of the contract and the thing the device's App Attest assertion
signs. Get one byte wrong and every issuance fails.

The issuer computes, in `expectedClientDataHash(epoch, blinded)`:

```
clientDataHash = SHA-256(
    utf8( decimalString(epoch) )            // e.g. the ASCII bytes "2871", no quotes, no padding
    || 0x00 || rawBlinded[0]                 // one 0x00 separator BEFORE each blinded message
    || 0x00 || rawBlinded[1]
    || ...
    || 0x00 || rawBlinded[n-1]
)
```

where:

- `decimalString(epoch)` is the base-10 ASCII of the **epoch integer** (the same
  integer in the `/issuer-keys` and `/issue` responses). It is NOT the keyId string,
  NOT the appID, NOT zero-padded.
- `rawBlinded[i]` is the raw bytes you get by base64-decoding `blinded[i]` (each
  256 bytes), in the exact order they appear in the request `blinded` array.
- There is a single `0x00` byte BEFORE each blinded message. The leading epoch
  string has no trailing separator of its own; the first separator sits between the
  epoch string and `rawBlinded[0]`. There is no `0x00` after the last blinded
  message.

The 32-byte result is:

1. base64-encoded and sent as the request's `clientDataHash` field, and
2. passed verbatim (the 32 raw bytes) as the `clientDataHash` argument to Apple's
   `DCAppAttestService.attestKey(_:clientDataHash:)` / `generateAssertion(_:clientDataHash:)`.

Point 2 is what binds App Attest to this exact batch. Apple's device then signs
`nonce = SHA-256(authenticatorData || clientDataHash)`, and the issuer recomputes
the same `nonce` during attestation/assertion verification using the same
`clientDataHash`. So the device proves it authorized THESE blinded messages in THIS
epoch, not merely that a genuine device is present.

Worked micro-example (matches the cross-check test fixture):

```
epoch   = 2871
blinded = [ 0x11 repeated 256 times, 0x22 repeated 256 times ]   // two messages

preimage = "2871"
         || 0x00 || (0x11 x256)
         || 0x00 || (0x22 x256)

clientDataHash = SHA-256(preimage)        // 32 bytes
```

The same `(epoch, blinded)` always yields the same hash. Reordering the batch,
changing any blinded byte, or changing the epoch all change the hash, so a captured
assertion cannot be replayed against a different batch. The `0x00` separators make
the preimage unambiguous: `[ab]` as one message and `[a, b]` as two messages hash
differently.

### Epoch tolerance

The app computes the hash against the epoch it last saw from `/issuer-keys`. If the
request crosses an epoch boundary the issuer may already be one epoch ahead, so the
issuer accepts the hash computed against **either the current or the previous
epoch** and compares both in constant time. The app should use the current
epoch's integer; the previous-epoch acceptance is just slack for the boundary.

## App Attest flow and ordering

App Attest is two-phase. The issuer's `validateAppAttest` enforces all of it; the
app drives it.

1. **Generate key (once per install).** The app calls
   `DCAppAttestService.generateKey()` to mint a hardware-backed key and gets a
   `keyId`. It persists `keyId` in the Keychain.

2. **First `/issue` of the install = attestation.** Before it has registered, the
   app:
   - fetches `/issuer-keys`, picks the current epoch,
   - builds its batch of blinded messages,
   - computes the binding hash for `(currentEpochInteger, blinded)`,
   - calls `attestKey(keyId, clientDataHash: bindingHash)` to get the attestation
     object,
   - POSTs `/issue` with `attestation` set (and no `assertion`), `clientDataHash`
     = base64(bindingHash), and the `blinded` array.

   The issuer runs, in order: certificate chain to the pinned Apple root, nonce
   binding (`SHA-256(authData || clientDataHash)` equals the cert's Apple nonce
   extension), keyId equals `SHA-256(attested public key point)`, rpIdHash equals
   `SHA-256(teamID.bundleID)`, aaguid matches the configured environment, and first
   counter is 0. It then stores the device public key keyed by `keyId` and, in the
   same call, applies the binding check + quota + blind-signs the batch. So the
   first call registers AND issues.

3. **Every later `/issue` = assertion.** The app:
   - builds the batch and computes the binding hash for the current epoch,
   - calls `generateAssertion(keyId, clientDataHash: bindingHash)`,
   - POSTs `/issue` with `assertion` set (and no `attestation`).

   The issuer looks up the stored public key by `keyId`, verifies the ECDSA
   assertion over `SHA-256(authData || clientDataHash)`, checks the rpIdHash, and
   requires a strictly increasing sign counter (replay/rollback protection). Then
   binding + quota + blind-sign as above.

4. **Re-attest on rejection.** If the issuer has forgotten the device (process
   restart on a single-replica deployment) it answers an assertion with
   `unknown_device_key`. App Attest only allows ONE `attestKey` per key, so the app
   cannot re-attest the same key; on a persistent rejection it must mint a fresh
   key and attest that. The app should clear its "registered" marker and retry with
   a fresh attestation.

There is no separate challenge round trip. The binding hash IS the challenge, and
because it is derived from the batch + epoch it is fresh by construction.

## Token presentation to the relay

After unblinding, the app holds, per token:

- `keyId`     : the issuer epoch public key id (from the `/issue` response),
- `tokenInput`: the 32 nonce bytes (identity preparation, so prepared == nonce),
- `signature` : the finished 256-byte RSA-PSS signature.

It presents one token per relay POST in a single header. The agreed header name is:

```
x-lander-token: PrivateToken <base64url( JSON{ keyId, tokenInput, signature } )>
```

- The value is a `PrivateToken ` prefix (the relay also accepts `Bearer `, or no
  prefix) followed by the **base64url** of the UTF-8 JSON object
  `{ "keyId": "...", "tokenInput": "<base64>", "signature": "<base64>" }`.
- Inside that JSON, `tokenInput` and `signature` are **standard base64** (the relay
  decodes them with a base64 decoder). Only the outer envelope is base64url.
- There is exactly ONE header. The earlier app proposal split this into
  `x-lander-token` (signature only) plus `x-lander-token-epoch` (keyId). That cannot
  work, because the relay needs `tokenInput` to verify the signature, and it reads a
  single header containing the whole JSON. `x-lander-token-epoch` is gone; the keyId
  travels inside the JSON.

The relay reads the header named by `CLIENT_AUTH_HEADER`, whose default is now
`x-lander-token` so it matches what the app sends with no extra configuration. An
operator may point it at `authorization` instead if they prefer to carry the token
there; the app would then send the same value under that header.

## Relay verification and spend-once

In `CLIENT_AUTH_MODE=token`, for each `/relay` POST the relay runs
`verifyAccessToken(headerValue)`:

1. Strip an optional `PrivateToken ` / `Bearer ` prefix (case-insensitive).
2. Refresh the issuer public keys from `GET /issuer-keys` if the cache is stale
   (default TTL 5 minutes). This is the ONLY issuer contact and it fetches public
   material only, so the issuer never learns which token is being spent. If the
   cache is empty it fails closed.
3. base64url-decode the envelope and JSON-parse it. Require `keyId`, `tokenInput`,
   and `signature` to all be strings.
4. Look up the epoch public key by `keyId`. Unknown or expired epoch => reject.
5. Verify offline:
   `RSA-PSS.verify(pub, hash=SHA-384, saltLength=48, message=base64decode(tokenInput), signature=base64decode(signature))`.
   Any failure => reject.
6. Spend-once. The nullifier is `SHA-256(rawSignatureBytes)` as hex. If it is
   already in the redemption set, reject (double spend). Otherwise record it and
   accept.

All four of steps 4-6 must pass. A token verifies exactly once. The nullifier is
derived from the signature alone and carries no device identity. On a `200` from
the relay the request was authorized; `401` means the token was missing, malformed,
unverifiable, or already spent.

Notes the relay deployment depends on:

- Salt length is 48 bytes (`TOKEN_PSS_SALT_LEN`), matching SHA-384, matching the
  suite. Do not change one without the others.
- The spend-once set is in-process on a single replica. A multi-replica relay needs
  a shared atomic store (e.g. Redis `SET NX` keyed by the nullifier with a TTL past
  the epoch). Same applies to the issuer's attested-key store and quota counter.
- Logs are RED-only on both services: never the token, never the device id, never
  the IP, never content. Only aggregate counters and coarse status.

## What is pinned by tests vs what still needs a device

A cross-check vector pins the binding hash bytes on both sides:

- issuer: `test.js` asserts `expectedClientDataHash(epoch, blinded)` for a fixed
  `(epoch, blinded)` input equals a known hex value.
- app: `BlindRSATokenTests` recomputes the SAME construction in Swift for the SAME
  input and asserts the SAME hex. If either side changes the byte layout, one of the
  two tests goes red.

What the vector does NOT cover, and which still needs a physical device plus a live
issuer to exercise end to end:

- Real `DCAppAttestService` attestation and assertion (the Simulator cannot attest;
  CI uses a synthetic Apple-rooted chain via `appattest-fixtures.js`).
- The full network round trip `/issuer-keys` -> blind -> `/issue` -> unblind ->
  spend at `/relay`.
- Re-attestation after an issuer restart.

Those are device-only and are called out in the PR notes.
