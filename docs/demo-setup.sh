# Sourced (hidden) by docs/demo.tape: starts the fake auth server + vulnerable/hardened demo servers on 127.0.0.1.
# Only loopback servers started right here are ever probed.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$ROOT/.venv/bin:$PATH"
DEMO_DIR=$(mktemp -d); cd "$DEMO_DIR" || return
mcp-audprobe auth-server --port 9000 --key-file key.pem >as.log 2>&1 & AS_PID=$!
python "$ROOT/demo/demo_server.py" --mode vulnerable --port 18001 >v.log 2>&1 & V_PID=$!
python "$ROOT/demo/demo_server.py" --mode hardened --port 18002 >h.log 2>&1 & H_PID=$!
for p in 9000 18001 18002; do
  for _ in $(seq 1 80); do curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$p/" && break; sleep 0.25; done
done
stop_demo() { kill $AS_PID $V_PID $H_PID 2>/dev/null; cd /; rm -rf "$DEMO_DIR"; }
export PS1='$ '
