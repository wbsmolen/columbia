#!/usr/bin/env bash
# Example deploy: build → push (container registry) → deploy (managed container app)
# for the commons-cache. This is ONE optional cloud example; plain Docker (see
# ../SELFHOSTING.md) is the supported path. Replace the placeholders below with
# your own resource names.
#
# Prereq: Docker running (`open -a Docker`), a logged-in container registry, and
# whatever CLI your managed-container host uses. Run from this directory.
set -euo pipefail

# ── Replace these placeholders with your own values ──
OWNER=REGISTRY_OWNER             # your container-registry namespace/owner
RG=RESOURCE_GROUP                # your cloud resource group / project
ENVNAME=CONTAINER_ENV            # your managed-container environment name
APP=APP_NAME                     # the name for the deployed app
# ─────────────────────────────────────────────────────

IMAGE="ghcr.io/${OWNER}/commons-cache:latest"

echo "==> docker login ghcr.io"
# Provide your registry credentials however you manage secrets (never commit them).
gh auth token | docker login ghcr.io -u "$OWNER" --password-stdin

echo "==> build $IMAGE (linux/amd64 for the managed host)"
docker build --platform linux/amd64 -t "$IMAGE" .

echo "==> push"
docker push "$IMAGE"

echo "==> NOTE: make the GHCR package public once (Packages -> package -> Settings ->"
echo "    Change visibility -> Public). Then the host pulls without registry creds and"
echo "    no token has to be passed on a command line. The create below assumes this."
echo "    If you must keep the package private, supply the registry password to your"
echo "    host's CLI via a secret/stdin path, never as an inline \$(gh auth token)"
echo "    argument (command-line args are visible in the process list)."

echo "==> deploy/update container app $APP (target-port 8080, scale-to-zero)"
# The example below uses an Azure-style CLI; adapt to your managed-container host.
# Pulling a PUBLIC GHCR package needs no registry credentials, so no token ever
# lands on the command line.
if az containerapp show -n "$APP" -g "$RG" >/dev/null 2>&1; then
  az containerapp update -n "$APP" -g "$RG" --image "$IMAGE"
else
  az containerapp create -n "$APP" -g "$RG" \
    --environment "$ENVNAME" \
    --image "$IMAGE" \
    --target-port 8080 --ingress external \
    --min-replicas 0 --max-replicas 2 \
    --cpu 0.25 --memory 0.5Gi
fi

FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
echo "==> deployed: https://${FQDN}"
echo "    health : curl https://${FQDN}/health"
echo "    probe  : curl https://${FQDN}/v1/probe   # can this host reach the upstream?"
echo "    commons: curl 'https://${FQDN}/v1/commons?id=example&sort=latest'"
