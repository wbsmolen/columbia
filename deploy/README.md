# Deploying Columbia

Columbia is a set of plain Docker services. It self-hosts on any host that can run
containers: a single VM, a container platform, a Kubernetes cluster, or your own
machine for testing. There is no required platform and no required orchestrator.

The authoritative, host-agnostic build and run instructions live in
[`../SELFHOSTING.md`](../SELFHOSTING.md). Follow that for the canonical setup:
generate the gateway HPKE seed, build each service image, run the relay and gateway
under separate operators so the non-collusion property holds, and (optionally) add
the commons cache and token issuer.

## Reference automation (one example)

[`.github/workflows/deploy-azure-reference.yml`](../.github/workflows/deploy-azure-reference.yml)
is one example of automating a deployment, targeting Azure Container Apps. It is
optional and not required to run Columbia. Use it as a template if you deploy on
Azure, or adapt the same build-and-update steps to whatever container host you run.

The shape it follows is portable to any host:

1. Build each service image from its directory (`ohttp-relay/`, `ohttp-gateway/`,
   `commons-cache/`, `token-issuer/`).
2. Tag the image with the immutable commit SHA.
3. Roll the running service to the new image.
4. Inject every secret (the gateway `SEED_SECRET_KEY`, the issuer signing key, the
   Apple App Attest inputs, any shared secrets) from the host's secret store at
   runtime. Nothing secret is baked into an image or committed to this repo.

## Non-collusion

Whatever host you pick, the operator-blind guarantee holds only when the relay and
the gateway (and the token issuer, if used) are run by separate, non-colluding
operators in separate trust domains. Running everything under one operator validates
the flow but provides no protection against that single operator. See
[`../SELFHOSTING.md`](../SELFHOSTING.md) for the non-collusion model.
