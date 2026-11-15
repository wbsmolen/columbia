#!/usr/bin/env bash
# Provision the Columbia egress VM on Oracle Cloud Always Free. Idempotent: every
# resource is found by display name first, so re-running only fills gaps (and
# refreshes the ssh rule to the caller's current IP).
#
#   ./up.sh                       COLUMBIA_REF=<branch> picks the repo ref the VM runs (default main)
#
# Creates in the tenancy root compartment: VCN, internet gateway + default route,
# security list (443 open, 22 from this machine's IP), public subnet, a
# VM.Standard.A1.Flex (2 OCPU / 12 GB, Ubuntu 24.04 aarch64) and a reserved public IP.
# Writes ~/Documents/lander-ops/oracle-egress/{ssh/id_ed25519,state.env}.
set -euo pipefail

NAME=columbia-egress
OPS=${OPS_DIR:-$HOME/Documents/lander-ops/oracle-egress}
HERE=$(cd "$(dirname "$0")" && pwd)
REF=${COLUMBIA_REF:-main}
OCPUS=${OCPUS:-2} MEMORY_GB=${MEMORY_GB:-12}
RETRY_SECONDS=${RETRY_SECONDS:-60} MAX_ROUNDS=${MAX_ROUNDS:-120} # ~2 h of capacity retries

TENANCY=$(awk -F= '/^\[/{p=($0=="[" ENVIRON["OCI_PROFILE"] "]" || (ENVIRON["OCI_PROFILE"]=="" && $0=="[DEFAULT]"))} p&&/^tenancy *=/{gsub(/ /,"",$2);print $2;exit}' "${OCI_CONFIG:-$HOME/.oci/config}")
[ -n "$TENANCY" ] || { echo "no tenancy in ~/.oci/config" >&2; exit 1; }
C=(--compartment-id "$TENANCY")
first() { jq -r "${1:-.data[0].id} // empty"; } # oci prints nothing for an empty list
log() { echo "• $*" >&2; }

VCN=$(oci network vcn list "${C[@]}" --display-name $NAME --lifecycle-state AVAILABLE | first)
[ -n "$VCN" ] || { log "creating VCN"; VCN=$(oci network vcn create "${C[@]}" --display-name $NAME --cidr-blocks '["10.42.0.0/16"]' --wait-for-state AVAILABLE | first .data.id); }

IGW=$(oci network internet-gateway list "${C[@]}" --vcn-id "$VCN" --display-name $NAME --lifecycle-state AVAILABLE | first)
[ -n "$IGW" ] || { log "creating internet gateway"; IGW=$(oci network internet-gateway create "${C[@]}" --vcn-id "$VCN" --display-name $NAME --is-enabled true --wait-for-state AVAILABLE | first .data.id); }
RT=$(oci network vcn get --vcn-id "$VCN" | first '.data."default-route-table-id"')
oci network route-table update --rt-id "$RT" --force \
  --route-rules "[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$IGW\"}]" >/dev/null

MYIP=$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')
INGRESS=$(jq -nc --arg me "$MYIP/32" '[
  {protocol:"6", source:"0.0.0.0/0", description:"https (Caddy)", tcpOptions:{destinationPortRange:{min:443,max:443}}},
  {protocol:"6", source:$me, description:"ssh from the operator", tcpOptions:{destinationPortRange:{min:22,max:22}}},
  {protocol:"1", source:"0.0.0.0/0", description:"path MTU discovery", icmpOptions:{type:3,code:4}}]')
EGRESS='[{"protocol":"all","destination":"0.0.0.0/0"}]'
SL=$(oci network security-list list "${C[@]}" --vcn-id "$VCN" --display-name $NAME --lifecycle-state AVAILABLE | first)
if [ -n "$SL" ]; then
  oci network security-list update --security-list-id "$SL" --force --ingress-security-rules "$INGRESS" --egress-security-rules "$EGRESS" >/dev/null
else
  log "creating security list"
  SL=$(oci network security-list create "${C[@]}" --vcn-id "$VCN" --display-name $NAME --ingress-security-rules "$INGRESS" --egress-security-rules "$EGRESS" --wait-for-state AVAILABLE | first .data.id)
fi
log "ssh allowed from $MYIP"

SUBNET=$(oci network subnet list "${C[@]}" --vcn-id "$VCN" --display-name $NAME --lifecycle-state AVAILABLE | first)
[ -n "$SUBNET" ] || { log "creating public subnet"; SUBNET=$(oci network subnet create "${C[@]}" --vcn-id "$VCN" --display-name $NAME --cidr-block 10.42.0.0/24 \
  --route-table-id "$RT" --security-list-ids "[\"$SL\"]" --prohibit-public-ip-on-vnic false --wait-for-state AVAILABLE | first .data.id); }

KEY=$OPS/ssh/id_ed25519
[ -f "$KEY" ] || { install -d -m 700 "$OPS" "$OPS/ssh"; ssh-keygen -q -t ed25519 -N '' -C $NAME -f "$KEY"; }

INSTANCE=$(oci compute instance list "${C[@]}" --display-name $NAME |
  first '[.data[]? | select(."lifecycle-state" | test("TERMINAT") | not)][0].id')
if [ -n "$INSTANCE" ]; then
  if [ "$(oci compute instance get --instance-id "$INSTANCE" | first '.data."lifecycle-state"')" = STOPPED ]; then
    log "starting stopped instance"; oci compute instance action --instance-id "$INSTANCE" --action START --wait-for-state RUNNING >/dev/null
  fi
else
  IMAGE=$(oci compute image list "${C[@]}" --operating-system "Canonical Ubuntu" --operating-system-version 24.04 \
    --shape VM.Standard.A1.Flex --sort-by TIMECREATED --sort-order DESC --all | first '[.data[] | select(."display-name" | test("aarch64"))][0].id')
  [ -n "$IMAGE" ] || { echo "no Ubuntu 24.04 aarch64 image found" >&2; exit 1; }
  USER_DATA=$(mktemp) ERR=$(mktemp); trap 'rm -f "$USER_DATA" "$ERR"' EXIT
  sed "s|@COLUMBIA_REF@|$REF|" "$HERE/cloud-init.yaml" >"$USER_DATA"
  ADS=$(oci iam availability-domain list "${C[@]}" | jq -r '.data[].name')
  # Always Free A1 capacity is scarce: walk every AD, wait, repeat.
  for ((round = 1; round <= MAX_ROUNDS; round++)); do
    for AD in $ADS; do
      log "launching in $AD (round $round)"
      if INSTANCE=$(oci compute instance launch "${C[@]}" --availability-domain "$AD" --display-name $NAME \
          --shape VM.Standard.A1.Flex --shape-config "{\"ocpus\":$OCPUS,\"memoryInGBs\":$MEMORY_GB}" \
          --image-id "$IMAGE" --subnet-id "$SUBNET" --assign-public-ip false \
          --ssh-authorized-keys-file "$KEY.pub" --user-data-file "$USER_DATA" \
          --no-retry --wait-for-state RUNNING 2>"$ERR" | first .data.id); then
        break 2
      fi
      grep -qi 'out of host capacity' "$ERR" || { cat "$ERR" >&2; exit 1; }
      log "$AD: out of host capacity"
    done
    if [ "$round" -lt "$MAX_ROUNDS" ]; then sleep "$RETRY_SECONDS"; fi
  done
  [ -n "$INSTANCE" ] || { echo "no A1 capacity after $MAX_ROUNDS rounds; re-run later" >&2; exit 1; }
fi
log "instance $INSTANCE"

VNIC=$(oci compute vnic-attachment list "${C[@]}" --instance-id "$INSTANCE" | first '[.data[] | select(."lifecycle-state"=="ATTACHED")][0]."vnic-id"')
PRIVATE_IP=$(oci network private-ip list --vnic-id "$VNIC" | first '[.data[] | select(."is-primary")][0].id')
PUBLIC=$(oci network public-ip list "${C[@]}" --scope REGION --lifetime RESERVED --all | jq -c --arg n $NAME '[.data[]? | select(."display-name"==$n)][0] // empty')
if [ -z "$PUBLIC" ]; then
  log "reserving public IP"
  PUBLIC=$(oci network public-ip create "${C[@]}" --display-name $NAME --lifetime RESERVED --private-ip-id "$PRIVATE_IP" --wait-for-state ASSIGNED | jq -c .data)
elif [ "$(jq -r '."private-ip-id" // ""' <<<"$PUBLIC")" != "$PRIVATE_IP" ]; then
  log "attaching reserved public IP"
  PUBLIC=$(oci network public-ip update --public-ip-id "$(jq -r .id <<<"$PUBLIC")" --private-ip-id "$PRIVATE_IP" --wait-for-state ASSIGNED | jq -c .data)
fi
IP=$(jq -r '."ip-address"' <<<"$PUBLIC")

printf 'EGRESS_IP=%s\nINSTANCE_ID=%s\n' "$IP" "$INSTANCE" >"$OPS/state.env"
cat <<EOF
Egress VM ready: $IP   (state in $OPS/state.env)
  ssh -i $KEY ubuntu@$IP
Next: ./dns.sh && ./secrets.sh && ./cutover.sh check
EOF
