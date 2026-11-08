#!/usr/bin/env bash
# Sign a JSON body for MetricCupid Push Relay and POST it with curl.
#
#   RELAY_URL=http://127.0.0.1:8080 RELAY_SECRET=... scripts/sign.sh '{"message":"hello"}'
#   echo '{"message":"hello"}' | RELAY_URL=... RELAY_SECRET=... scripts/sign.sh
#
# Options (env):
#   MC_TS=<unix seconds>   use a fixed timestamp (default: now)
#   SIGN_ONLY=1            print the headers instead of sending
#
# Note: the secret is passed to openssl on its command line, so it is visible
# to other local users via `ps` while the command runs. Use on trusted hosts.
set -euo pipefail

: "${RELAY_SECRET:?set RELAY_SECRET}"
path="/v1/notify"
method="POST"

if [[ $# -ge 1 ]]; then
  body="$1"
else
  body="$(cat)"
fi

ts="${MC_TS:-$(date +%s)}"
sig="$(printf '%s\n%s\n%s\n%s' "$ts" "$method" "$path" "$body" \
  | openssl dgst -sha256 -hmac "$RELAY_SECRET" -hex \
  | awk '{print $NF}')"

if [[ "${SIGN_ONLY:-0}" == "1" ]]; then
  echo "X-MC-Timestamp: $ts"
  echo "X-MC-Signature: $sig"
  exit 0
fi

: "${RELAY_URL:?set RELAY_URL, e.g. http://127.0.0.1:8080}"
exec curl -sS -w '\nHTTP %{http_code}\n' -X "$method" "${RELAY_URL%/}${path}" \
  -H 'Content-Type: application/json' \
  -H "X-MC-Timestamp: $ts" \
  -H "X-MC-Signature: $sig" \
  --data-binary "$body"
