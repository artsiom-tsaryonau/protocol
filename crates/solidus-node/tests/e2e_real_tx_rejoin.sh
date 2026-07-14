#!/usr/bin/env bash
# E2E: real-transaction validator restart-rejoin (convergent pre-join catch-up).
# Submits transfers (non-empty blocks -> real state), kills a validator, restarts
# it, asserts it catches up STATE (getBalance == peers') and commits again.
# Run ONCE, isolated (ports clear) -- never back-to-back (macOS TIME_WAIT).
set -uo pipefail
cd "$(dirname "$0")/../../.."
source "$HOME/.cargo/env" 2>/dev/null || true
BIN="$PWD/target/debug/solidus-node"; D="${TMPDIR:-/tmp}/sol-rejoin-$$"; FAIL=0
pass(){ echo "  PASS: $1"; }; fail(){ echo "  FAIL: $1"; FAIL=1; }
trap 'pkill -f "solidus-node run --consensus" 2>/dev/null' EXIT
cargo build -q -p solidus-node || { echo "build failed"; exit 1; }
rm -rf "$D"; cargo run -q -p solidus-node -- genesis -n 4 -o "$D" >/dev/null
RECIP=$(python3 -c "import json;print(json.load(open('$D/genesis.json'))['validators'][0]['address'])")
bal(){ curl -s -X POST 127.0.0.1:$1 -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"solidus_getBalance\",\"params\":[\"$RECIP\"]}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('result','err'))" 2>/dev/null||echo err; }
# Submit each tx to ALL nodes' mempools. The chain does not gossip NewTransaction
# yet (separate feature), so a tx submitted to one node only is proposed by that
# node and orphaned (never finalized). Broadcasting to all mempools makes every
# leader include the tx -> committed blocks carry txs (idempotent on re-apply).
submit(){ J=$("$BIN" sign-transfer --key "$D/treasury.key" --to "$RECIP" --amount 100 --nonce $1 2>/dev/null);
  P=$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$J");
  for port in 8080 8081 8082 8083; do
    curl -s -X POST 127.0.0.1:$port -H 'content-type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"solidus_sendTransaction\",\"params\":[$P]}" >/dev/null 2>&1
  done; }
pkill -9 -f "solidus-node" 2>/dev/null; sleep 8
for i in 0 1 2 3; do RUST_LOG=info nohup "$BIN" run --consensus --config "$D/validator-$i/config.toml" > "$D/v$i.log" 2>&1 & done
for _ in $(seq 1 40); do grep -q "block committed" "$D/v0.log" 2>/dev/null && break; sleep 1; done
echo "=== submit txs (nonce 0-9), all up ==="; for nbr in $(seq 0 9); do submit $nbr; sleep 0.6; done; sleep 4
echo "=== kill v3, keep submitting (nonce 10-19) ==="; pkill -f "validator-3/config.toml"; sleep 2
for nbr in $(seq 10 19); do submit $nbr; sleep 0.6; done; sleep 4
echo "  v0 recipient balance (v3 down) = $(bal 8080)"
echo "=== restart v3, wait for catch-up ==="; RUST_LOG=info nohup "$BIN" run --consensus --config "$D/validator-3/config.toml" > "$D/v3r.log" 2>&1 & sleep 22
grep -q "startup catch-up finished" "$D/v3r.log" && pass "v3 ran catch-up" || fail "v3 no catch-up log"
grep -q "block committed" "$D/v3r.log" && pass "v3 committed after restart (rejoined)" || fail "v3 did not commit after restart"
echo "  v3 post-restart state_root mismatches: $(grep -c 'state_root mismatch' "$D/v3r.log")"
echo "=== DECISIVE: v3 state == v0 state? ==="
b0=$(bal 8080); b3=$(bal 8083); echo "  v0=$b0  v3=$b3"
[ "$b0" = "$b3" ] && [ "$b3" != "err" ] && pass "v3 balance == v0 (state rebuilt)" || fail "v3 balance != v0 (state stale)"
echo "=== result ==="; [ "$FAIL" = 0 ] && echo "E2E PASSED" || echo "E2E FAILED"; exit $FAIL
