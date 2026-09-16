#!/usr/bin/env bash
# Run the current tree and a baseline binary against a mock AWS account and
# compare the graphs they produce.
#
#   ./run.sh                     compare against $BASELINE_BIN
#   ./run.sh --fail-nodegroups   make eks:ListNodegroups return AccessDenied
#
# Outputs are written to out/ and kept, so both graphs can be imported into
# BloodHound afterwards.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"
WORK="$HERE/.work"
VENV="$WORK/venv"

MOTO_PORT="${MOTO_PORT:-5111}"
PROXY_PORT="${PROXY_PORT:-5110}"
REGIONS="${REGIONS:-us-east-1,eu-west-1}"
BASELINE_BIN="${BASELINE_BIN:-$HOME/go/bin/IAMhounddog}"

FAIL_NODEGROUPS=0
[ "${1:-}" = "--fail-nodegroups" ] && FAIL_NODEGROUPS=1

mkdir -p "$OUT" "$WORK"

cleanup() {
  [ -n "${MOTO_PID:-}" ] && kill "$MOTO_PID" 2>/dev/null || true
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [ ! -x "$VENV/bin/python" ]; then
  echo "==> creating venv"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --disable-pip-version-check -r "$HERE/requirements.txt"
fi
PY="$VENV/bin/python"

if [ ! -x "$BASELINE_BIN" ]; then
  echo "baseline binary not found: $BASELINE_BIN" >&2
  echo "set BASELINE_BIN, or: go install github.com/VirtueSecurity/IAMhounddog@<baseline>" >&2
  exit 1
fi

echo "==> building current tree"
( cd "$REPO" && go build -o "$WORK/iamhd-current" . )

echo "==> starting moto on :$MOTO_PORT"
MOTO_IAM_LOAD_MANAGED_POLICIES=true "$PY" -m moto.server -p "$MOTO_PORT" > "$WORK/moto.log" 2>&1 &
MOTO_PID=$!

echo "==> starting proxy on :$PROXY_PORT (fail-nodegroups=$FAIL_NODEGROUPS)"
MOCK_UPSTREAM="http://127.0.0.1:$MOTO_PORT" MOCK_FAIL_NODEGROUPS="$FAIL_NODEGROUPS" \
  "$PY" "$HERE/proxy.py" "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY_PID=$!

for _ in $(seq 30); do
  curl -sf -o /dev/null "http://127.0.0.1:$PROXY_PORT/" && break
  sleep 0.5
done

echo "==> seeding"
curl -sf -X POST "http://127.0.0.1:$MOTO_PORT/moto-api/reset" > /dev/null
# Most of the seed goes straight to moto. The second endpoint is the proxy,
# which the seeder uses only for the APIs moto answers with a 500.
"$PY" "$HERE/seed.py" "http://127.0.0.1:$MOTO_PORT" "http://127.0.0.1:$PROXY_PORT"

export AWS_ENDPOINT_URL="http://127.0.0.1:$PROXY_PORT"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1

# The baseline predates -output and writes ./output.json, so each run needs its
# own directory. A guard is required because a baseline paginator can spin
# forever when an API it lists is denied.
run_guarded() {
  local label=$1 dir=$2 limit=$3; shift 3
  rm -rf "$dir"; mkdir -p "$dir"
  ( cd "$dir" && "$@" > run.log 2>&1 ) &
  local pid=$! waited=0
  while kill -0 $pid 2>/dev/null && [ $waited -lt "$limit" ]; do sleep 1; waited=$((waited+1)); done
  if kill -0 $pid 2>/dev/null; then
    pkill -9 -P $pid 2>/dev/null || true; kill -9 $pid 2>/dev/null || true
    echo "    $label: NO EXIT after ${limit}s, killed"
    return 1
  fi
  echo "    $label: done in ${waited}s"
}

echo "==> running baseline ($BASELINE_BIN)"
run_guarded baseline "$WORK/base" 120 "$BASELINE_BIN" -regions "$REGIONS" || true

echo "==> running current"
run_guarded current "$WORK/cur" 120 "$WORK/iamhd-current" -regions "$REGIONS" -output out.json || true

[ -f "$WORK/base/output.json" ] && cp "$WORK/base/output.json" "$OUT/baseline.json"
[ -f "$WORK/cur/out.json" ] && cp "$WORK/cur/out.json" "$OUT/current.json"
cp "$WORK/base/run.log" "$OUT/baseline.log" 2>/dev/null || true
cp "$WORK/cur/run.log" "$OUT/current.log" 2>/dev/null || true

if [ -f "$OUT/baseline.json" ] && [ -f "$OUT/current.json" ]; then
  echo
  "$PY" "$HERE/compare.py" "$OUT/baseline.json" "$OUT/current.json" | tee "$OUT/report.txt"
  echo
  echo "==> graphs kept for BloodHound import:"
  ls -lh "$OUT"/*.json
else
  echo "one or both runs produced no graph, see $OUT/*.log"
fi
