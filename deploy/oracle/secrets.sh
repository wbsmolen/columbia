#!/usr/bin/env bash
# Ship the egress stack's secrets to the Oracle VM and (re)start it.
#
#   ./secrets.sh save   read values from Azure (or the cf-migration keys dir) into
#                       ~/Documents/lander-ops/oracle-egress/secrets/egress.env (mode 600)
#   ./secrets.sh push   copy that file to the VM as /etc/columbia/egress.env (mode 600),
#                       make the gateway's internal TLS cert, docker compose up --build
#   ./secrets.sh        save (only if the file is missing), then push
#
# Values never go into git or onto the command line of the VM.
set -euo pipefail

OPS=${OPS_DIR:-$HOME/Documents/lander-ops/oracle-egress}
ENV_FILE=$OPS/secrets/egress.env
KEYS=${KEYS_DIR:-$HOME/Documents/lander-ops/cf-migration-20261114/keys}
SUB=bc58fed0-7479-4056-ac3f-25d05cb1da2f
RG=lander-middleware-poc

az_secret() { az containerapp secret list --subscription "$SUB" -g "$RG" -n "$1" --show-values --query "[?name=='$2'].value | [0]" -o tsv 2>/dev/null || true; }
az_env() { az containerapp show --subscription "$SUB" -g "$RG" -n "$1" --query "properties.template.containers[0].env[?name=='$2'].value | [0]" -o tsv 2>/dev/null || true; }
from_keys() { [ -r "$KEYS/$1" ] && tr -d '[:space:]' <"$KEYS/$1" || true; }

save() {
  local seed relay fdid imgur
  seed=$(az_secret lander-mw-ohttp-gw seed); [ -n "$seed" ] || seed=$(from_keys seed.hex)
  relay=$(az_secret lander-mw-ohttp-gw relay-gw-secret); [ -n "$relay" ] || relay=$(from_keys relay-gw-secret.txt)
  # Plain env vars on Azure, and Worker secrets (write-only) on Cloudflare: Azure is
  # the only place to read them back, so save them before the credit runs out.
  fdid=$(az_env lander-mw-ohttp-relay REQUIRE_FDID)
  imgur=$(az_env lander-mw-commons IMGUR_CLIENT_ID)
  [[ $seed =~ ^[0-9a-fA-F]{64}$ ]] || { echo "SEED_SECRET_KEY: not found or not 32-byte hex" >&2; exit 1; }
  [ -n "$relay" ] || { echo "RELAY_GATEWAY_SECRET: not found" >&2; exit 1; }
  [[ $fdid =~ ^[A-Za-z0-9-]{16,}$ ]] || { echo "REQUIRE_FDID: not found (is Azure gone? see README)" >&2; exit 1; }
  install -d -m 700 "$OPS" "$OPS/secrets"
  (umask 077; cat >"$ENV_FILE" <<EOF
# Columbia Oracle egress secrets, saved $(date -u +%FT%TZ). Never commit.
SEED_SECRET_KEY=$seed
RELAY_GATEWAY_SECRET=$relay
REQUIRE_FDID=$fdid
IMGUR_CLIENT_ID=$imgur
EOF
)
  chmod 600 "$ENV_FILE"
  echo "saved $ENV_FILE"
  [ -n "$imgur" ] || echo "note: IMGUR_CLIENT_ID is empty; commons falls back to imgur's public client id"
}

push() {
  [ -s "$ENV_FILE" ] || { echo "missing $ENV_FILE: run ./secrets.sh save" >&2; exit 1; }
  # shellcheck disable=SC1091
  [ -n "${EGRESS_IP:-}" ] || . "$OPS/state.env"
  ssh -i "$OPS/ssh/id_ed25519" -o UserKnownHostsFile="$OPS/ssh/known_hosts" -o StrictHostKeyChecking=accept-new \
    "ubuntu@$EGRESS_IP" 'set -e
      cloud-init status --wait </dev/null >/dev/null || true
      sudo install -d -m 700 /etc/columbia </dev/null
      sudo sh -c "umask 077; cat > /etc/columbia/egress.env" # stdin: the local egress.env
      # The relay only talks https to the gateway; this cert never leaves the VM.
      sudo test -s /etc/columbia/gateway.key || sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes -days 3650 -subj /CN=gateway -addext subjectAltName=DNS:gateway \
        -keyout /etc/columbia/gateway.key -out /etc/columbia/gateway.crt 2>/dev/null
      sudo chmod 644 /etc/columbia/gateway.crt
      cd /opt/columbia/deploy/oracle
      sudo docker compose --env-file /etc/columbia/egress.env up -d --build --remove-orphans
      sudo docker compose --env-file /etc/columbia/egress.env ps' <"$ENV_FILE"
}

case ${1:-} in
  save) save ;;
  push) push ;;
  '') [ -s "$ENV_FILE" ] || save; push ;;
  *) echo "usage: $0 [save|push]" >&2; exit 2 ;;
esac
