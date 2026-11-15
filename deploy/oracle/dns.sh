#!/usr/bin/env bash
# Point egress.landerapp.xyz at the Oracle VM: an A record, DNS only (not proxied),
# so Reddit sees Oracle's IP and Caddy can get its own certificate.
#
#   ./dns.sh [ip]       default ip: EGRESS_IP from up.sh's state.env
#   DRY_RUN=1 ./dns.sh  show what would change
set -euo pipefail

ZONE=05fa9b8e0b7011f9ba9bc7ff5b001c0a # landerapp.xyz
HOST=${EGRESS_HOST:-egress.landerapp.xyz}
OPS=${OPS_DIR:-$HOME/Documents/lander-ops/oracle-egress}
# shellcheck disable=SC1091
[ -n "${1:-}" ] || [ -n "${EGRESS_IP:-}" ] || . "$OPS/state.env"
IP=${1:-$EGRESS_IP}
# env.sh exports CLOUDFLARE_API_TOKEN; it finds its key file from the git root unless told.
export HMB_CF_FILE=${HMB_CF_FILE:-$HOME/git/howsmybet/.cloudflare-api}
# shellcheck disable=SC1091
. "$HOME/git/howsmybet/tools/cf/env.sh"

api() { curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' "$@"; }
URL=https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records
REC=$(api "$URL?type=A&name=$HOST" | jq -c '.result[0] // empty')
BODY=$(jq -nc --arg n "$HOST" --arg ip "$IP" '{type:"A", name:$n, content:$ip, proxied:false, ttl:300, comment:"Columbia Reddit egress (Oracle VM)"}')

if [ -n "$REC" ] && [ "$(jq -r '"\(.content) \(.proxied)"' <<<"$REC")" = "$IP false" ]; then
  echo "$HOST already -> $IP (DNS only)"
elif [ -n "${DRY_RUN:-}" ]; then
  echo "would $([ -n "$REC" ] && echo update || echo create) $HOST -> $IP (DNS only); current: ${REC:-none}"
  exit 0
elif [ -n "$REC" ]; then
  api -X PUT "$URL/$(jq -r .id <<<"$REC")" --data "$BODY" | jq -r '"updated \(.result.name) -> \(.result.content) proxied=\(.result.proxied)"'
else
  api -X POST "$URL" --data "$BODY" | jq -r '"created \(.result.name) -> \(.result.content) proxied=\(.result.proxied)"'
fi

for _ in $(seq 30); do
  [ "$(dig +short @1.1.1.1 "$HOST" A | tail -1)" = "$IP" ] && { echo "resolves on 1.1.1.1"; exit 0; }
  sleep 10
done
echo "not resolving on 1.1.1.1 yet; Caddy retries certificates on its own" >&2
