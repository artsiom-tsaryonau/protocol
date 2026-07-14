#!/usr/bin/env bash
# E2E (C2): a non-validating FULL NODE joins a running 4-validator testnet given
# ONLY a single bootstrap multiaddr, discovers the mesh (C1 DHT), syncs the full
# contiguous canon by libp2p PeerId, and serves RPC — without ever proposing.
#
# HARD assertions:
#   1. Baseline: the 4 validators produce a chain (sanity).
#   2. Discovery: the bootstrap-only full node reaches >=2 peers (bootstrap + a
#      DHT-discovered validator) — proves open discovery, not a static dial.
#   3. RPC: the full node's solidus_getLatestBlock reports a synced height > 0.
#   4. Sync: stopped, the full node's canon (CF_CANON) is CONTIGUOUS and matches
#      validator-0's canon hash-for-hash at the common prefix.
#
# Run from protocol/apps/consensus:  bash crates/solidus-node/tests/e2e_node_join.sh
# Run ISOLATED (clear ports) — never back-to-back (macOS TIME_WAIT on 303xx).
set -uo pipefail

cd "$(dirname "$0")/../../.." # -> protocol/apps/consensus
source "$HOME/.cargo/env" 2>/dev/null || true

BIN="$PWD/target/debug/solidus-node"
D="${TMPDIR:-/tmp}/sol-node-join-e2e-$$"
FAIL=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAIL=1; }
cleanup() {
  pkill -f "solidus-node run --consensus" 2>/dev/null
  pkill -f "solidus-node run --full-node" 2>/dev/null
}
trap cleanup EXIT

echo "=== build + generate 4-node testnet ==="
cargo build -q -p solidus-node || { echo "build failed"; exit 1; }
rm -rf "$D"; cargo run -q -p solidus-node -- genesis -n 4 -o "$D" >/dev/null

# Harvest a standalone key pair for the full node (its keys are used ONLY for the
# libp2p identity; the full node is NOT in the genesis committee). A throwaway
# genesis run gives us a fresh, distinct node.key/bls.key.
rm -rf "$D/keygen"; cargo run -q -p solidus-node -- genesis -n 1 -o "$D/keygen" >/dev/null
mkdir -p "$D/full-node"
cp "$D/keygen/validator-0/node.key" "$D/full-node/node.key"
cp "$D/keygen/validator-0/bls.key" "$D/full-node/bls.key"

ht() { curl -s -X POST "127.0.0.1:$1" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"solidus_getLatestBlock","params":[]}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin).get('result');print(d['height'] if d else 'none')" 2>/dev/null || echo down; }

echo "=== start 4 validators ==="
cleanup; sleep 1
for i in 0 1 2 3; do
  RUST_LOG=info nohup "$BIN" run --consensus --config "$D/validator-$i/config.toml" > "$D/v$i.log" 2>&1 &
done
# Join EARLY (short canon to walk): the full node syncs by walking the chain
# backward one block per round-trip, so a fresh joiner catches up fastest when
# the chain is still short. A few seconds of production is enough for h>3.
for _ in $(seq 1 40); do grep -q "block committed" "$D/v0.log" 2>/dev/null && break; sleep 1; done
sleep 4

echo "=== baseline: chain producing ==="
h0=$(ht 8080)
[ "$h0" != "none" ] && [ "$h0" != "down" ] && [ "$h0" -gt 3 ] 2>/dev/null \
  && pass "validators producing (v0 h=$h0)" || fail "validators not producing (v0 h=$h0)"

echo "=== derive validator-0 bootstrap multiaddr ==="
V0_PID=$("$BIN" peer-id --key "$D/validator-0/node.key")
BOOT="/ip4/127.0.0.1/tcp/30300/p2p/$V0_PID"
echo "  bootstrap = $BOOT"

# Full-node config: EMPTY [[peers]], single bootstrap_peers, full_node = true,
# distinct ports + data_dir, own keys. bootstrap_peers MUST precede [node]
# (top-level bare key — TOML rule).
cat > "$D/full-node/config.toml" <<EOF
bootstrap_peers = [
  "$BOOT",
]

[node]
chain_id = "solidus-testnet-1"
listen_port = 30310
data_dir = "./data"
genesis = "../genesis.json"
ed25519_key = "node.key"
bls_key = "bls.key"
rpc_port = 8090
node_index = 0
full_node = true
EOF

echo "=== start full node (bootstrap-only) ==="
RUST_LOG=info nohup "$BIN" run --full-node --config "$D/full-node/config.toml" > "$D/full.log" 2>&1 &
# Give it time to discover + walk the canon back to genesis (one round-trip per
# block) + stay current as the chain advances.
sleep 30

echo "=== discovery: full node reached >=2 peers ==="
# The follower heartbeat logs `peers=N`; assert N>=2 at some point (bootstrap +
# a DHT-discovered validator). >=2 proves discovery beyond the single bootstrap.
# Strip ANSI color codes first (RUST_LOG colorizes structured fields).
MAXPEERS=$(sed -E 's/\x1b\[[0-9;]*m//g' "$D/full.log" \
  | grep -oE "peers=[0-9]+" | grep -oE "[0-9]+" | sort -n | tail -1)
[ -n "$MAXPEERS" ] && [ "$MAXPEERS" -ge 2 ] 2>/dev/null \
  && pass "full node discovered >=2 peers (max observed=$MAXPEERS)" \
  || fail "full node did NOT reach >=2 peers (max observed=${MAXPEERS:-none})"

echo "=== RPC: full node reports a synced height > 0 ==="
hf=$(ht 8090)
[ "$hf" != "none" ] && [ "$hf" != "down" ] && [ "$hf" -gt 0 ] 2>/dev/null \
  && pass "full node RPC height synced (h=$hf)" || fail "full node RPC height not synced (h=$hf)"

echo "=== stop all, dump canon (full node vs validator-0) ==="
cleanup
for _ in $(seq 1 20); do
  pgrep -f "solidus-node run --consensus" >/dev/null && { sleep 1; continue; }
  pgrep -f "solidus-node run --full-node" >/dev/null && { sleep 1; continue; }
  break
done
sleep 2
"$BIN" canon-dump --config "$D/validator-0/config.toml" > "$D/canon-v0.txt" 2>/dev/null
"$BIN" canon-dump --config "$D/full-node/config.toml" > "$D/canon-full.txt" 2>/dev/null

# Full node canon contiguous — HARD.
grep -q "contiguous=true" "$D/canon-full.txt" \
  && pass "full node canon contiguous ($(grep canon_head_seq "$D/canon-full.txt"))" \
  || fail "full node canon NOT contiguous ($(grep -E 'canon_head|contiguous|NONE' "$D/canon-full.txt" | tr '\n' ' '))"

# Full node canon == validator-0 canon at common prefix — HARD.
SF=$(grep canon_head_seq "$D/canon-full.txt" | grep -oE "[0-9]+")
S0=$(grep canon_head_seq "$D/canon-v0.txt" | grep -oE "[0-9]+")
if [ -n "$SF" ] && [ -n "$S0" ]; then
  MIN=$([ "$SF" -le "$S0" ] && echo "$SF" || echo "$S0")
  head -n $((MIN+2)) "$D/canon-v0.txt"   | grep -E "^canon\[" > "$D/pf-v0.txt"
  head -n $((MIN+2)) "$D/canon-full.txt" | grep -E "^canon\[" > "$D/pf-full.txt"
  diff -q "$D/pf-v0.txt" "$D/pf-full.txt" >/dev/null \
    && pass "full node canon IDENTICAL to v0 at common prefix seq 0..$MIN" \
    || fail "full node canon differs from v0 at common prefix seq 0..$MIN"
else
  fail "could not determine canon prefix (full=${SF:-none} v0=${S0:-none})"
fi

echo "=== result ==="
[ "$FAIL" = 0 ] && echo "E2E PASSED" || echo "E2E FAILED"
exit $FAIL
