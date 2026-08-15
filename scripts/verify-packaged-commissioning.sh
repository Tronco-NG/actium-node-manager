#!/usr/bin/env sh
set -eu

SCRIPT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PAYLOAD=${1:-$SCRIPT_ROOT/../src-tauri/resources/node}
PAYLOAD=$(CDPATH= cd -- "$PAYLOAD" && pwd)
TMP_BASE=${TMPDIR:-/tmp}
ROOT=$(mktemp -d "$TMP_BASE/actium-packaged-commissioning.XXXXXX")

cleanup() {
  case "$ROOT" in
    "$TMP_BASE"/actium-packaged-commissioning.*) rm -rf -- "$ROOT" ;;
    *) echo "Cleanup rechazo root inesperado: $ROOT" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

cp -a "$PAYLOAD/." "$ROOT/payload"
cp "$ROOT/payload/node.env.example" "$ROOT/node.env"
openssl genpkey -algorithm ED25519 -out "$ROOT/private.pem" >/dev/null 2>&1
openssl pkey -in "$ROOT/private.pem" -pubout -out "$ROOT/public.pem" >/dev/null 2>&1

sed -i \
  -e "s|^ACTIUM_TERMINAL_PUBLIC_KEY_PATH=.*|ACTIUM_TERMINAL_PUBLIC_KEY_PATH=$ROOT/public.pem|" \
  -e "s|^ACTIUM_OPERATOR_PUBLIC_KEY_PATH=.*|ACTIUM_OPERATOR_PUBLIC_KEY_PATH=$ROOT/public.pem|" \
  -e 's|^ACTIUM_PROFILES=.*|ACTIUM_PROFILES=telemetry|' \
  -e 's|^ACTIUM_HOST_INSTALLATION_ID=.*|ACTIUM_HOST_INSTALLATION_ID=11111111-1111-4111-8111-111111111111|' \
  -e 's|^ACTIUM_DEPLOYMENT_ID=.*|ACTIUM_DEPLOYMENT_ID=22222222-2222-4222-8222-222222222222|' \
  -e "s|^RADIO_ARCHIVE_HOST_PATH=.*|RADIO_ARCHIVE_HOST_PATH=$ROOT/radio-archive|" \
  "$ROOT/node.env"

/bin/sh "$ROOT/payload/install-node.sh" \
  --config "$ROOT/node.env" \
  --enrollment-token "adpe_$(printf 'a%.0s' $(seq 1 64))" \
  --profiles telemetry \
  --prepare-only >/dev/null

ENV_FILE="$ROOT/secrets/data-plane.env"
grep -qx 'ACTIUM_PROFILES=telemetry' "$ENV_FILE"
grep -qx 'ACTIUM_ACTIVE_PROFILES=telemetry' "$ENV_FILE"
printf '%s\n' \
  'packaged_commissioning_prepare_only=PASS' \
  'ACTIUM_PROFILES=telemetry' \
  'ACTIUM_ACTIVE_PROFILES=telemetry'
