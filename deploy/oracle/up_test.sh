#!/usr/bin/env bash
# Runs up.sh against a fake `oci` (no Oracle account needed): capacity retries
# across ADs, aarch64 image choice, cloud-init templating, idempotent re-run, and
# failing fast on errors that aren't capacity.   ./up_test.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/state"
printf '[DEFAULT]\ntenancy = ocid1.tenancy.oc1..test\n' >"$T/config"
printf '#!/bin/sh\necho 198.51.100.9\n' >"$T/bin/curl"
cat >"$T/bin/oci" <<'EOF'
#!/usr/bin/env bash
S=$FAKE_STATE; echo "$*" >>"$S/calls"
has() { [ -f "$S/$1" ]; }
mk() { touch "$S/$1"; }
arg() { local want=$1 prev='' a; shift; for a; do [ "$prev" = "$want" ] && { echo "$a"; return; }; prev=$a; done; }
case "$1 $2 $3" in
  "network vcn list") has vcn && echo '{"data":[{"id":"vcn1"}]}' ;;
  "network vcn create") mk vcn; echo '{"data":{"id":"vcn1"}}' ;;
  "network vcn get") echo '{"data":{"default-route-table-id":"rt1"}}' ;;
  "network internet-gateway list") has igw && echo '{"data":[{"id":"igw1"}]}' ;;
  "network internet-gateway create") mk igw; echo '{"data":{"id":"igw1"}}' ;;
  "network route-table update" | "network security-list update") echo '{"data":{}}' ;;
  "network security-list list") has sl && echo '{"data":[{"id":"sl1"}]}' ;;
  "network security-list create") mk sl; echo '{"data":{"id":"sl1"}}' ;;
  "network subnet list") has subnet && echo '{"data":[{"id":"sub1"}]}' ;;
  "network subnet create") mk subnet; echo '{"data":{"id":"sub1"}}' ;;
  "compute instance list") has inst && echo '{"data":[{"id":"gone","lifecycle-state":"TERMINATED"},{"id":"inst1","lifecycle-state":"RUNNING"}]}' ;;
  "compute instance get") echo '{"data":{"lifecycle-state":"RUNNING"}}' ;;
  "compute image list") echo '{"data":[{"id":"img-x86","display-name":"Canonical-Ubuntu-24.04-2026.10.01-0"},{"id":"img-arm","display-name":"Canonical-Ubuntu-24.04-aarch64-2026.10.01-0"}]}' ;;
  "iam availability-domain list") echo '{"data":[{"name":"x:AD-1"},{"name":"x:AD-2"},{"name":"x:AD-3"}]}' ;;
  "compute instance launch")
    shift 3; echo "$(arg --availability-domain "$@") $(arg --image-id "$@")" >>"$S/launches"
    cp "$(arg --user-data-file "$@")" "$S/user-data"
    if [ "$(wc -l <"$S/launches")" -le "${FAKE_CAPACITY_FAILS:-0}" ]; then
      echo 'ServiceError: {"code": "InternalError", "message": "Out of host capacity.", "status": 500}' >&2; exit 1
    fi
    [ -z "${FAKE_LAUNCH_ERROR:-}" ] || { echo "ServiceError: $FAKE_LAUNCH_ERROR" >&2; exit 1; }
    mk inst; echo "Action completed. Waiting until the resource has entered state: ('RUNNING',)" >&2
    echo '{"data":{"id":"inst1"}}' ;;
  "compute vnic-attachment list") echo '{"data":[{"vnic-id":"vnic1","lifecycle-state":"ATTACHED"}]}' ;;
  "network private-ip list") echo '{"data":[{"id":"priv1","is-primary":true}]}' ;;
  "network public-ip list") has pip && echo '{"data":[{"id":"pip1","display-name":"columbia-egress","private-ip-id":"priv1","ip-address":"203.0.113.7"}]}' ;;
  "network public-ip create") mk pip; echo '{"data":{"id":"pip1","private-ip-id":"priv1","ip-address":"203.0.113.7"}}' ;;
  *) echo "fake oci: unexpected: $*" >&2; exit 9 ;;
esac
exit 0 # like oci, an empty list is success
EOF
chmod +x "$T/bin/"*
run() { env PATH="$T/bin:$PATH" OCI_CONFIG="$T/config" OPS_DIR="$T/ops" FAKE_STATE="$T/state" RETRY_SECONDS=0 "$@" "$HERE/up.sh"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# 1. Fresh tenancy, AD-1..3 full on round 1 and AD-1 on round 2: lands in AD-2, round 2.
run FAKE_CAPACITY_FAILS=4 COLUMBIA_REF=feat/x >/dev/null 2>"$T/log1"
[ "$(wc -l <"$T/state/launches")" -eq 5 ] || fail "expected 5 launch attempts"
[ "$(tail -1 "$T/state/launches")" = "x:AD-2 img-arm" ] || fail "should land in AD-2 with the aarch64 image"
grep -q -- '--branch, "feat/x"' "$T/state/user-data" || fail "cloud-init ref not filled in"
grep -q '^EGRESS_IP=203.0.113.7$' "$T/ops/state.env" || fail "state.env missing the reserved IP"
grep -q '198.51.100.9/32' "$T/state/calls" || fail "ssh rule should use the caller IP"
[ -f "$T/ops/ssh/id_ed25519.pub" ] || fail "ssh key not generated"

# 2. Re-run: nothing new is created or launched; the ssh rule is refreshed.
: >"$T/state/calls"
run >/dev/null 2>&1
! grep -Eq ' create | launch ' "$T/state/calls" || fail "re-run created resources: $(grep -E ' create | launch ' "$T/state/calls")"
grep -q 'security-list update' "$T/state/calls" || fail "re-run should refresh the security list"

# 3. A non-capacity error stops at once instead of retrying.
rm -f "$T/state/inst" "$T/state/launches"
if run FAKE_LAUNCH_ERROR=LimitExceeded >/dev/null 2>"$T/log3"; then fail "LimitExceeded should fail"; fi
[ "$(wc -l <"$T/state/launches")" -eq 1 ] || fail "LimitExceeded should not be retried"
grep -q LimitExceeded "$T/log3" || fail "error not shown"
echo "up_test: ok"
