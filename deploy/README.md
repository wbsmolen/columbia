# Deploying Columbia

Columbia is a set of plain Docker services. It self-hosts on any host that can run
containers: a single VM, a container platform, a Kubernetes cluster, or your own
machine for testing. There is no required platform and no required orchestrator.

The authoritative, host-agnostic build and run instructions live in
[`../SELFHOSTING.md`](../SELFHOSTING.md). Follow that for the canonical setup:
generate the gateway HPKE seed, build each service image, run the relay and gateway
under separate operators so the non-collusion property holds, and (optionally) add
the commons cache and token issuer.

## Cloudflare Workers

`workers/` is the Workers port: `columbia-relay`, `columbia-gateway`, `columbia-commons`
and `columbia-issuer`. Deploy from a machine signed in to wrangler (`npx wrangler login`):

```sh
cd workers && npm ci && (cd issuer && npm ci) && npm run deploy
```

That runs the Workers tests, then deploys commons, gateway and relay in binding order
(relay calls gateway, gateway calls commons), then tests and deploys the issuer. Secrets
are set once per Worker with `npx wrangler secret put` and are never committed.

There is no deploy workflow. `.github/workflows/test.yml` only runs the unit tests on
pull requests and on main.

## Container hosts

A container deployment follows the same shape on any host:

1. Build each service image from its directory (`ohttp-relay/`, `ohttp-gateway/`,
   `commons-cache/`, `token-issuer/`).
2. Tag the image with the immutable commit SHA.
3. Roll the running service to the new image.
4. Inject every secret (the gateway `SEED_SECRET_KEY`, the issuer signing key, the
   Apple App Attest inputs, any shared secrets) from the host's secret store at
   runtime. Nothing secret is baked into an image or committed to this repo.

## Oracle Cloud egress (one example)

[`oracle/`](oracle/README.md) runs the relay, gateway and commons cache on one
Oracle Cloud Always Free VM behind Caddy, as the Reddit-facing egress for the
Cloudflare Workers. It covers provisioning, secrets, DNS and cutover.

## Non-collusion

Whatever host you pick, the operator-blind guarantee holds only when the relay and
the gateway (and the token issuer, if used) are run by separate, non-colluding
operators in separate trust domains. Running everything under one operator validates
the flow but provides no protection against that single operator. See
[`../SELFHOSTING.md`](../SELFHOSTING.md) for the non-collusion model.
