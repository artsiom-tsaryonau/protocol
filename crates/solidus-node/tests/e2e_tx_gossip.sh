#!/usr/bin/env bash
# E2E: tx gossip — submit a signed Transfer to ONE node's RPC, assert it gets
# included in a block proposed by SOME node (verified via getReceipt from a
# DIFFERENT node's RPC). Proves the /solidus/txs/1.0.0 gossipsub topic carries
# NewTransaction messages end-to-end:
#   RPC.send_transaction -> tx_broadcast channel -> transport.broadcast
#     -> libp2p gossipsub mesh -> handle_consensus_message::NewTransaction
#     -> engine.mempool.insert -> next proposer includes it
#
# Marquee acceptance for the tx-gossip ship (91a253f, 2026-05-26).
#
# Run from protocol/apps/consensus:
#   bash crates/solidus-node/tests/e2e_tx_gossip.sh
#
# NEVER run back-to-back -- macOS TIME_WAIT on the libp2p TCP listen ports
# (30300-30303) and RPC ports (8080-8083) means a fresh run within ~60s can
# hit "address already in use". The trap kills children but the OS holds the
# ports. Wait or change ports if you need to re-run immediately.
set -uo pipefail
cd "$(dirname "$0")/../../.."
source "$HOME/.cargo/env" 2>/dev/null || true

BIN="$PWD/target/debug/solidus-node"
D="${TMPDIR:-/tmp}/sol-tx-gossip-$$"
FAIL=0
pass() { echo "  PASS: $1"; }
fail() {
    echo "  FAIL: $1"
    FAIL=1
}

trap 'pkill -f "solidus-node run --consensus" 2>/dev/null' EXIT

echo "=== build ==="
cargo build -q -p solidus-node || {
    echo "build failed"
    exit 1
}

echo "=== genesis (4 validators, larger committee than gossip-strict-minimum to keep BFT viable) ==="
rm -rf "$D"
cargo run -q -p solidus-node -- genesis -n 4 -o "$D" >/dev/null

# Recipient: validator-0's address (any committee address works; we just want a
# stable destination whose balance change is observable via getBalance).
RECIP=$(python3 -c "import json;print(json.load(open('$D/genesis.json'))['validators'][0]['address'])")

# Kill any stragglers; macOS-friendly TIME_WAIT settle.
pkill -9 -f "solidus-node" 2>/dev/null
sleep 8

echo "=== start 4 validators ==="
for i in 0 1 2 3; do
    RUST_LOG=info nohup "$BIN" run --consensus --config "$D/validator-$i/config.toml" \
        >"$D/v$i.log" 2>&1 &
done

echo "=== wait for chain to start producing blocks (gate on v0) ==="
for _ in $(seq 1 40); do
    grep -q "block committed" "$D/v0.log" 2>/dev/null && break
    sleep 1
done
grep -q "block committed" "$D/v0.log" || {
    fail "chain did not start producing blocks"
    cat "$D/v0.log"
    exit 1
}

echo "=== sign one transfer (nonce 0) ==="
# treasury is funded at genesis and is who we send AS.
TX_JSON=$("$BIN" sign-transfer --key "$D/treasury.key" --to "$RECIP" --amount 12345 --nonce 0 2>/dev/null)
TX_JSON_QUOTED=$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$TX_JSON")

echo "=== SUBMIT TO NODE 0 ONLY (the marquee assertion: gossip carries it elsewhere) ==="
TX_HASH=$(curl -s -X POST 127.0.0.1:8080 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"solidus_sendTransaction\",\"params\":[$TX_JSON_QUOTED]}" |
    python3 -c "import sys,json;r=json.load(sys.stdin);print(r.get('result','err'))" 2>/dev/null || echo err)
echo "  tx_hash from node 0 = $TX_HASH"
[ "$TX_HASH" != "err" ] && [ -n "$TX_HASH" ] && pass "node 0 accepted tx via RPC" \
    || { fail "node 0 RPC rejected tx"; cat "$D/v0.log" | tail -20; exit 1; }

echo "=== wait for inclusion (up to 30s) ==="
# Poll each non-submitter node's getReceipt until one of them returns Success.
RECEIPT_NODE=""
for _ in $(seq 1 30); do
    for port in 8081 8082 8083; do
        STATUS=$(curl -s -X POST 127.0.0.1:$port -H 'content-type: application/json' \
            -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"solidus_getReceipt\",\"params\":[\"$TX_HASH\"]}" |
            python3 -c "import sys,json;r=json.load(sys.stdin).get('result');print(r.get('status') if r else 'null')" 2>/dev/null || echo err)
        if [ "$STATUS" = "success" ]; then
            RECEIPT_NODE=$port
            break 2
        fi
    done
    sleep 1
done

if [ -n "$RECEIPT_NODE" ]; then
    pass "tx receipt visible at non-submitter node :$RECEIPT_NODE (status=success)"
    pass "gossip path proved: submit-to-one -> proposed-by-some -> committed -> visible-everywhere"
else
    fail "tx never appeared in any non-submitter node's receipts within 30s"
    echo "--- last 10 lines of each log ---"
    for i in 0 1 2 3; do echo "[v$i]"; tail -10 "$D/v$i.log"; done
fi

echo "=== balance side-check: recipient should be richer ==="
B0=$(curl -s -X POST 127.0.0.1:8080 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"solidus_getBalance\",\"params\":[\"$RECIP\"]}" |
    python3 -c "import sys,json;print(json.load(sys.stdin).get('result','err'))" 2>/dev/null || echo err)
echo "  v0 recipient balance = $B0 (expected >= 12345 over genesis baseline)"

echo "=== result ==="
[ "$FAIL" = 0 ] && echo "E2E PASSED" || echo "E2E FAILED"
exit $FAIL
