#!/usr/bin/env bash
# Local load test (loopback only, mock APNs): builds the release binary and
# examples/loadgen, starts the server with a temporary DATA_DIR, runs loadgen
# (which samples the server's RSS / CPU / open fds every second into its
# JSON report) and stops the server.
#
#   scripts/loadtest.sh [N] [scenario]
#
#   N         users (1 Mac + 2 phones each), default 10
#   scenario  ramp-steady (default) | alert-storm | reconnect-storm | abuse
#
# Env:
#   DURATION=150   steady phase in seconds      COMPRESS=10  time compression
#   RAMP=<secs>    user setup spread            PORT=18080
#   DEFAULTS=1     keep the server's default limits (only the load-test basics
#                  below are set), to see which limits the modelled traffic hits
#   KEEP=1         keep the temporary run directory (server log, database)
#   NO_BUILD=1     skip cargo build
#   Any other server variable set in the environment as SERVER_<NAME>=value is
#   passed to the server as <NAME>=value (it overrides the computed values).
#
# Output: target/loadtest/<N>[-<scenario>].json plus a markdown summary on
# stdout. Exit code: loadgen's (1 when an SLO failed).
set -euo pipefail

N="${1:-10}"
SCENARIO="${2:-ramp-steady}"
DURATION="${DURATION:-150}"
COMPRESS="${COMPRESS:-10}"
PORT="${PORT:-18080}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Streams, pooled HTTP connections and the server's own files.
if [[ "$(ulimit -n)" != unlimited && "$(ulimit -n)" -lt 65536 ]]; then
  ulimit -n 65536
fi

if [[ -z "${NO_BUILD:-}" ]]; then
  cargo build --release --locked --bin metriccupid-push --example loadgen >&2
fi

RUN="$(mktemp -d "${TMPDIR:-/tmp}/mc-loadtest.XXXXXX")"
mkdir -p "$RUN/data"

# ---- server environment
max() { if (($1 > $2)); then echo "$1"; else echo "$2"; fi; }
# Modelled signed requests per user and hour (PLAN section B): ~75.
RPS=$((N * 75 * COMPRESS / 3600 + 1))
ENV=(
  "MODE=hosted"
  "APNS_MODE=mock"
  "LICENCE_MODE=open"
  "BIND=127.0.0.1:$PORT"
  "DATA_DIR=$RUN/data"
  "TRUST_PROXY=xff:127.0.0.1/32"
  "MOCK_APNS_LATENCY_MS=30..80"
  "MOCK_APNS_FAIL_PPM=1000"
)
if [[ -z "${DEFAULTS:-}" ]]; then
  # Room for 3x the steady rate plus a storm of N (alerts or reconnects).
  GLOBAL=$(max 50 $((3 * RPS + N)))
  RAMP_SECS="${RAMP:-$( ((N >= 100)) && echo 60 || echo 10)}"
  ANON=$(max 20 $((2 * N / RAMP_SECS + 1)))
  ENV+=(
    "RATE_GLOBAL_PER_SEC=$GLOBAL"
    "RATE_GLOBAL_BURST=$(max 100 $((2 * GLOBAL)))"
    "RATE_PRE_AUTH_PER_SEC=$(max 200 "$GLOBAL")"
    "RATE_PRE_AUTH_BURST=$(max 400 $((2 * GLOBAL)))"
    "RATE_ANON_GLOBAL_PER_SEC=$ANON"
    "RATE_ANON_GLOBAL_BURST=$(max 60 $((3 * ANON)))"
    # (global + gateway 20/s) x 600 s replay window + bursts.
    "REPLAY_CAP=$(max 100000 $(((GLOBAL + 20) * 600 + 2 * GLOBAL + 100)))"
    "WS_MAX_STREAMS=$(max 1024 $((N + N / 10 + 300)))"
    "MAX_CONNECTIONS=$(max 8192 $((3 * N + 1000)))"
  )
fi
while IFS='=' read -r k v; do
  [[ "$k" == SERVER_* ]] && ENV+=("${k#SERVER_}=$v")
done < <(env)

{
  for kv in "${ENV[@]}"; do printf 'export %q\n' "$kv"; done
} >"$RUN/server.env"

cat >"$RUN/start.sh" <<EOF
#!/usr/bin/env bash
set -eu
ulimit -n $(ulimit -n)
. "$RUN/server.env"
nohup "$ROOT/target/release/metriccupid-push" >>"$RUN/server.log" 2>&1 &
echo \$! >"$RUN/server.pid"
for _ in \$(seq 1 200); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/healthz" 2>/dev/null && exit 0
  sleep 0.05
done
echo "server did not come up, see $RUN/server.log" >&2
exit 1
EOF
cat >"$RUN/restart.sh" <<EOF
#!/usr/bin/env bash
kill -9 "\$(cat "$RUN/server.pid")" 2>/dev/null || true
while kill -0 "\$(cat "$RUN/server.pid")" 2>/dev/null; do sleep 0.02; done
exec "$RUN/start.sh"
EOF
chmod +x "$RUN/start.sh" "$RUN/restart.sh"

stop_server() {
  if [[ -f "$RUN/server.pid" ]]; then
    kill "$(cat "$RUN/server.pid")" 2>/dev/null || true
    sleep 1
    kill -9 "$(cat "$RUN/server.pid")" 2>/dev/null || true
  fi
  if [[ -n "${KEEP:-}" ]]; then
    echo "run directory kept: $RUN" >&2
  else
    rm -rf "$RUN"
  fi
}
trap stop_server EXIT

echo "server env: ${ENV[*]}" | sed "s|$RUN|\$RUN|g" >&2
"$RUN/start.sh"

ARGS=(--n "$N" --scenario "$SCENARIO" --duration "$DURATION" --compress "$COMPRESS"
  --url "http://127.0.0.1:$PORT" --pid-file "$RUN/server.pid"
  --server-env "$(printf '%s ' "${ENV[@]}" | sed "s|$RUN|\$RUN|g")")
[[ -n "${RAMP:-}" ]] && ARGS+=(--ramp "$RAMP")
[[ "$SCENARIO" == reconnect-storm ]] && ARGS+=(--restart-cmd "$RUN/restart.sh")

set +e
"$ROOT/target/release/examples/loadgen" "${ARGS[@]}"
CODE=$?
set -e
echo "server log lines: $(wc -l <"$RUN/server.log"), warnings/errors: $(grep -cE '"level":"(WARN|ERROR)"|WARN|ERROR' "$RUN/server.log" || true)" >&2
exit "$CODE"
