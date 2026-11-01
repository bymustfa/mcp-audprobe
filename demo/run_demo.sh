#!/usr/bin/env bash
# End-to-end demo: fake auth server + vulnerable MCP server + hardened MCP server, all on 127.0.0.1.
# Runs mcp-audprobe against each, saves output to demo/output/, renders demo/output/demo.png, cleans up.
# Exit 0 only if vulnerable -> FAIL (exit 1) and hardened -> PASS (exit 0).
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=$ROOT/demo/output
AS_PORT=${AS_PORT:-19000}; VULN_PORT=${VULN_PORT:-18001}; HARD_PORT=${HARD_PORT:-18002}
ISSUER=http://127.0.0.1:$AS_PORT
if [ -x "$ROOT/.venv/bin/python" ]; then PY=$ROOT/.venv/bin/python; else PY=${PYTHON:-python3}; fi
PROBE="$PY -m mcp_audprobe"
WORK=$(mktemp -d); KEY=$WORK/key.pem
mkdir -p "$OUT"; rm -f "$OUT"/*.txt "$OUT"/*.json "$OUT"/demo.png
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

wait_http() { # url
  for _ in $(seq 1 60); do
    curl -s -o /dev/null --max-time 1 "$1" && return 0; sleep 0.25
  done
  echo "timeout waiting for $1" >&2; return 1
}

echo "== starting fake auth server ($ISSUER), vulnerable (:$VULN_PORT) and hardened (:$HARD_PORT) MCP servers"
$PROBE auth-server --port "$AS_PORT" --issuer "$ISSUER" --key-file "$KEY" >"$WORK/as.log" 2>&1 & PIDS+=($!)
$PY demo/demo_server.py --mode vulnerable --port "$VULN_PORT" --issuer "$ISSUER" >"$WORK/vuln.log" 2>&1 & PIDS+=($!)
$PY demo/demo_server.py --mode hardened   --port "$HARD_PORT" --issuer "$ISSUER" >"$WORK/hard.log" 2>&1 & PIDS+=($!)
wait_http "$ISSUER/health" && wait_http "http://127.0.0.1:$VULN_PORT/mcp" && wait_http "http://127.0.0.1:$HARD_PORT/mcp" || { cat "$WORK"/*.log; exit 2; }

run() { # name port
  local name=$1 port=$2 url=http://127.0.0.1:$2/mcp
  echo; echo "### $name MCP server ($url)"
  $PROBE probe "$url" --audience "$url" --issuer "$ISSUER" --auth-server "$ISSUER" --key-file "$KEY" \
      --no-color --json-out "$OUT/$name.json" | tee "$OUT/$name.txt"
  local rc=${PIPESTATUS[0]}; echo "(exit code: $rc)" | tee -a "$OUT/$name.txt"
  return $rc
}

{
  run vulnerable "$VULN_PORT"; VRC=$?
  run hardened   "$HARD_PORT"; HRC=$?
} 2>&1 | tee "$OUT/demo.txt" >/dev/null
# the subshell above hides rc values; recompute from the saved JSON
VRC=$($PY -c "import json;print(json.load(open('$OUT/vulnerable.json'))['exit_code'])")
HRC=$($PY -c "import json;print(json.load(open('$OUT/hardened.json'))['exit_code'])")
cat "$OUT/demo.txt"

$PY demo/render_png.py "$OUT/vulnerable.json" "$OUT/hardened.json" "$OUT/demo.png" || echo "PNG render failed (is Pillow installed: pip install -e .[demo]?)" >&2

echo; echo "== summary: vulnerable exit=$VRC (expect 1=FAIL), hardened exit=$HRC (expect 0=PASS)"
if [ "$VRC" = 1 ] && [ "$HRC" = 0 ]; then echo "== DEMO OK: vulnerable=FAIL, hardened=PASS"; exit 0; fi
echo "== DEMO UNEXPECTED RESULT" >&2; exit 1
