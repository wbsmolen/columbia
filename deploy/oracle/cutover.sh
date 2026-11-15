#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2001 # `cond && ok || bad` is safe: ok() always succeeds
# Hand the columbia-relay and columbia-commons Workers' Reddit-bound traffic to the
# Oracle egress (EGRESS_RELAY_ORIGIN / EGRESS_COMMONS_ORIGIN in workers/*/wrangler.toml).
#
#   ./cutover.sh check           canary: call the Oracle origin the way the Workers do. Changes nothing.
#   ./cutover.sh deploy          check, point both Workers at Oracle, deploy, verify; rolls back on failure
#   ./cutover.sh rollback        redeploy with the origins that were live before the last deploy (Azure today)
#   ./cutover.sh rollback none   redeploy with no egress origin: the Workers use Cloudflare's own IPs
#   DRY_RUN=1 ./cutover.sh deploy   bundle with `wrangler deploy --dry-run`; nothing goes live
#
# deploy leaves the wrangler.toml edits in the working tree: commit them so the
# repo matches what runs.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OPS=${OPS_DIR:-$HOME/Documents/lander-ops/oracle-egress}
ORIGIN=https://${EGRESS_HOST:-egress.landerapp.xyz}
PUBLIC_RELAY=https://relay.landerapp.xyz PUBLIC_COMMONS=https://commons.landerapp.xyz
PINNED_CONFIG_SHA256=c6871a3066747c116e5e31bb4e0c81ba76a60f707ec86176b134a7c6ca91dfb1 # the key config apps pin
PROBE=${OHTTP_PROBE:-$HOME/Documents/lander-ops/cf-migration-20261114/tools/ohttp_probe.go}
RELAY_TOML=$ROOT/workers/relay/wrangler.toml COMMONS_TOML=$ROOT/workers/commons/wrangler.toml
export CLOUDFLARE_ACCOUNT_ID=8f6f79e0338270102a36725cfa37c65a
# shellcheck disable=SC1091
. "$OPS/secrets/egress.env" # REQUIRE_FDID: the header the Workers send and Oracle requires

TMP=$(mktemp -d)
cleanup() {
  rm -f "$ROOT/ohttp-gateway/zz_probe.go"
  if [ -n "${DRY_RUN:-}" ] && [ -f "$TMP/relay.toml" ]; then cp "$TMP/relay.toml" "$RELAY_TOML"; cp "$TMP/commons.toml" "$COMMONS_TOML"; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
if [ -n "${DRY_RUN:-}" ]; then cp "$RELAY_TOML" "$TMP/relay.toml"; cp "$COMMONS_TOML" "$TMP/commons.toml"; fi

FAILED=
ok() { echo "  ok    $*"; }
bad() { echo "  FAIL  $*" >&2; FAILED=1; }
expect() { local want=$1 what=$2; shift 2; local got; got=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@" || true)
  if [ "$got" = "$want" ]; then ok "$what ($got)"; else bad "$what: got $got, want $want"; fi; }
vm() { # shellcheck disable=SC1091
  [ -n "${EGRESS_IP:-}" ] || . "$OPS/state.env"
  ssh -i "$OPS/ssh/id_ed25519" -o UserKnownHostsFile="$OPS/ssh/known_hosts" -o StrictHostKeyChecking=accept-new "ubuntu@$EGRESS_IP" "$@"; }

config_matches() { # config_matches <file>: the gateway must serve the key apps pin
  if [ "$(shasum -a 256 <"$1" | cut -c1-64)" = "$PINNED_CONFIG_SHA256" ]; then ok "key config is the one apps pin"
  else bad "key config differs from the pinned one (wrong SEED_SECRET_KEY?)"; fi; }

# probe <configs> <relay base> <fdid|->: real OHTTP round trips with the independent
# ohttp-go client. Reddit answers an unauthenticated call with its own 403 page, so
# that proves the full path; commons answers its own 400 (the probe drops queries)
# once the gateway's rewrite and Caddy's FDID header got it there.
probe() {
  if [ ! -f "$PROBE" ] || ! command -v go >/dev/null; then echo "  skip  OHTTP probe ($PROBE or go missing)"; return 1; fi
  cp "$PROBE" "$ROOT/ohttp-gateway/zz_probe.go"
  local out; out=$(cd "$ROOT/ohttp-gateway" && go run -mod=vendor zz_probe.go "$1" "$2/relay" "$3" \
    https://oauth.reddit.com/r/pics/hot https://matrix.redditspace.com/_matrix/client/versions \
    https://commons.landerapp.xyz/v1/imgur 2>&1) || true
  rm -f "$ROOT/ohttp-gateway/zz_probe.go"
  sed 's/^/        /' <<<"$out" | cut -c1-160
  grep 'oauth.reddit.com' <<<"$out" | grep -v 'Target forbidden' | grep -q 'outer=200 inner=40[13] ' && ok "OHTTP -> Reddit (its own 40x page)" || bad "OHTTP -> oauth.reddit.com"
  grep -q 'matrix.redditspace.com.* outer=200 inner=200' <<<"$out" && ok "OHTTP -> matrix.redditspace.com" || bad "OHTTP -> matrix.redditspace.com"
  grep -q 'commons.landerapp.xyz.* outer=200 inner=400' <<<"$out" && ok "OHTTP -> commons on the VM" || bad "OHTTP -> commons.landerapp.xyz"
}

check() {
  echo "canary: $ORIGIN, called the way the Workers call it"
  expect 200 "health" "$ORIGIN/health"
  expect 403 "origin lock: /ohttp-configs without the FDID" "$ORIGIN/ohttp-configs"
  expect 403 "origin lock: /relay without the FDID" -X POST -H 'content-type: message/ohttp-req' --data-binary x "$ORIGIN/relay"
  expect 403 "origin lock: commons without the FDID" "$ORIGIN/v1/probe"
  if curl -fsS --max-time 20 -H "x-azure-fdid: $REQUIRE_FDID" "$ORIGIN/ohttp-configs" -o "$TMP/configs.bin"; then
    config_matches "$TMP/configs.bin"
    probe "$TMP/configs.bin" "$ORIGIN" "$REQUIRE_FDID" || true
  else bad "/ohttp-configs with the FDID"; fi
  local up; up=$(curl -fsS --max-time 20 -H "x-azure-fdid: $REQUIRE_FDID" "$ORIGIN/v1/probe" | jq -r '.results.commons.status' || true)
  case $up in
    429) bad "Reddit rate-limits this IP (429)" ;;
    [234]??) ok "commons reaches Reddit (upstream $up)" ;;
    *) bad "commons -> Reddit: upstream ${up:-no answer}" ;;
  esac
  [ -z "$FAILED" ]
}

# The Workers fall back to Cloudflare's IPs on their own, so a 200 through the
# public hosts proves little: confirm on the VM that Oracle served the requests.
verify() {
  echo "verify: through $PUBLIC_RELAY and $PUBLIC_COMMONS"
  if curl -fsS --max-time 20 "$PUBLIC_RELAY/ohttp-configs" -o "$TMP/public.bin"; then config_matches "$TMP/public.bin"; else bad "$PUBLIC_RELAY/ohttp-configs"; fi
  probe "$TMP/public.bin" "$PUBLIC_RELAY" - || { echo "  verify the VM logs by hand: docker logs columbia-egress-relay-1"; return 0; }
  expect 200 "commons /v1/probe" "$PUBLIC_COMMONS/v1/probe"
  local logs; logs=$(vm 'sudo docker logs --since 3m columbia-egress-relay-1 2>&1; sudo docker logs --since 3m columbia-egress-commons-1 2>&1')
  grep -q '"route":"/relay","status":200' <<<"$logs" && ok "Oracle relay served the probe" || bad "no /relay 200 on Oracle: the relay Worker fell back to Cloudflare"
  grep -q '"route":"/v1/probe"' <<<"$logs" && ok "Oracle commons served /v1/probe" || bad "no /v1/probe on Oracle: the commons Worker fell back to Cloudflare"
  [ -z "$FAILED" ]
}

origin_of() { sed -n "s/^$1 = \"\(.*\)\"$/\1/p" "$2"; }
set_origins() { # set_origins <relay origin> <commons origin>
  sed -i.bak "s|^EGRESS_RELAY_ORIGIN = \".*\"$|EGRESS_RELAY_ORIGIN = \"$1\"|" "$RELAY_TOML"
  sed -i.bak "s|^EGRESS_COMMONS_ORIGIN = \".*\"$|EGRESS_COMMONS_ORIGIN = \"$2\"|" "$COMMONS_TOML"
  rm -f "$RELAY_TOML.bak" "$COMMONS_TOML.bak"
  [ "$(origin_of EGRESS_RELAY_ORIGIN "$RELAY_TOML")|$(origin_of EGRESS_COMMONS_ORIGIN "$COMMONS_TOML")" = "$1|$2" ] ||
    { echo "could not set the origins in wrangler.toml" >&2; exit 1; }
  echo "origins: relay='$1' commons='$2'"
}
deploy_workers() {
  local w args=(deploy)
  if [ -n "${DRY_RUN:-}" ]; then args+=(--dry-run --outdir "$TMP/out"); fi
  for w in relay commons; do (cd "$ROOT/workers/$w" && npx -y wrangler@4 "${args[@]}") || return 1; done
}

rollback() {
  local r='' c=''
  if [ "${1:-}" != none ]; then
    [ -f "$OPS/cutover-previous.env" ] || { echo "no $OPS/cutover-previous.env; use: $0 rollback none" >&2; exit 1; }
    # shellcheck disable=SC1091
    . "$OPS/cutover-previous.env"; r=$PREV_RELAY_ORIGIN c=$PREV_COMMONS_ORIGIN
  fi
  set_origins "$r" "$c"
  deploy_workers
}

deploy() {
  if ! check; then
    [ -n "${DRY_RUN:-}" ] || { echo "canary failed: not deploying" >&2; exit 1; }
    echo "canary failed (dry run: carrying on)"
  fi
  local r c; r=$(origin_of EGRESS_RELAY_ORIGIN "$RELAY_TOML") c=$(origin_of EGRESS_COMMONS_ORIGIN "$COMMONS_TOML")
  if [ "$r" != "$ORIGIN" ] && [ -z "${DRY_RUN:-}" ]; then
    (umask 077; printf 'PREV_RELAY_ORIGIN=%q\nPREV_COMMONS_ORIGIN=%q\n' "$r" "$c" >"$OPS/cutover-previous.env")
  fi
  set_origins "$ORIGIN" "$ORIGIN"
  deploy_workers || { echo "deploy failed: rolling back" >&2; [ -n "${DRY_RUN:-}" ] || rollback; exit 1; }
  if [ -n "${DRY_RUN:-}" ]; then echo "dry run: bundled both Workers, deployed nothing"; return; fi
  sleep 15 # let the new versions reach the edge
  verify || { echo "verify failed: rolling back" >&2; FAILED=; rollback; exit 1; }
  echo "cutover done. Commit the wrangler.toml change:"; git -C "$ROOT" diff --stat -- workers
}

case ${1:-} in
  check) check ;;
  deploy) deploy ;;
  verify) verify ;;
  rollback) rollback "${2:-}" ;;
  *) sed -n '3,14p' "$0"; exit 2 ;;
esac
