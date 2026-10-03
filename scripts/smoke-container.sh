#!/usr/bin/env bash
# Quick container smoke for docs/container.md claims (image tag passed as $1).
# docker by default (the podman-docker shim on Fedora); CONTAINER_CLI=podman to call podman directly.
set -euo pipefail
C="${CONTAINER_CLI:-docker}"
IMAGE="${1:?usage: smoke-container.sh <image>}"
CHAIN="$(mktemp -d)"
trap '"$C" rm -f solidus-smoke-n1 solidus-smoke-dt solidus-smoke-dt-peer 2>/dev/null; rm -rf "$CHAIN"' EXIT

# Health and chainInfo answer on a node that never commits, so each mode also sends one
# faucet transfer and waits for the committed height to move (idle heartbeat is 10 min).
assert_commits() {  # <rpc port> <genesis dir>
  local port="$1" dir="$2" to tx height=0
  to="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validators"][0]["address"])' "$dir/genesis.json")"
  tx="$("$C" run --rm --user 0 -v "$dir:/g:ro,Z" --entrypoint solidus-node "$IMAGE" \
    sign-transfer --key /g/faucet.key --to "$to" --amount 1 --nonce 0)"
  python3 -c 'import json,sys; print(json.dumps({"jsonrpc":"2.0","id":1,"method":"solidus_sendTransaction","params":[sys.argv[1]]}))' "$tx" |
    curl -sf -X POST "http://127.0.0.1:$port" -H 'Content-Type: application/json' -d @- | grep -q '"result"'
  for _ in $(seq 1 30); do
    height="$(curl -sf "http://127.0.0.1:$port/health" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')"
    [ "$height" -ge 1 ] && { echo "   committed: height $height"; return 0; }
    sleep 1
  done
  echo "FAIL: height still $height 30 s after a transfer on :$port" >&2
  return 1
}

echo "== build check: $IMAGE"
"$C" run --rm "$IMAGE" --help >/dev/null

echo "== n=1 run --consensus commits"
"$C" run --rm --user 0 -v "$CHAIN:/out:Z" --entrypoint solidus-node "$IMAGE" \
  genesis --validators 1 --chain-id solidus-smoke-1 --output /out
mkdir -p "$CHAIN/etc" && cp "$CHAIN/genesis.json" "$CHAIN/validator-0/node.key" "$CHAIN/validator-0/bls.key" "$CHAIN/etc/"
cat >"$CHAIN/etc/config.toml" <<EOF
[node]
chain_id = "solidus-smoke-1"
listen_port = 30300
data_dir = "/data"
genesis = "/etc/solidus/genesis.json"
ed25519_key = "/etc/solidus/node.key"
bls_key = "/etc/solidus/bls.key"
rpc_port = 9944
rpc_listen = "0.0.0.0"
node_index = 0
EOF
"$C" volume rm solidus-smoke-n1-data 2>/dev/null || true
"$C" volume create solidus-smoke-n1-data >/dev/null
"$C" run --rm --user 0 -v solidus-smoke-n1-data:/data:Z docker.io/library/busybox:1.36 \
  sh -c 'chown 10001:10001 /data'
"$C" run -d --name solidus-smoke-n1 -p 127.0.0.1:19944:9944 \
  -v "$CHAIN/etc:/etc/solidus:ro,Z" -v solidus-smoke-n1-data:/data:Z \
  "$IMAGE" run --consensus --config /etc/solidus/config.toml
for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:19944/health" >/dev/null && break
  sleep 1
done
curl -sf -X POST "http://127.0.0.1:19944" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"solidus_chainInfo","params":[]}' | grep -q solidus-smoke-1
curl -sf "http://127.0.0.1:19944/health" | grep -q '"status":"ok"'
assert_commits 19944 "$CHAIN"
"$C" stop -t 25 solidus-smoke-n1 >/dev/null

echo "== dev-testnet RPC on 0.0.0.0"
mkdir -p "$CHAIN/dt"
"$C" run --rm --user 0 -v "$CHAIN/dt:/out:Z" --entrypoint solidus-node "$IMAGE" \
  genesis --validators 4 --chain-id solidus-smoke-dt --output /out
"$C" volume rm solidus-smoke-dt-data 2>/dev/null || true
"$C" volume create solidus-smoke-dt-data >/dev/null
"$C" run --rm --user 0 -v solidus-smoke-dt-data:/data:Z docker.io/library/busybox:1.36 \
  sh -c 'chown 10001:10001 /data'
"$C" run -d --name solidus-smoke-dt -p 127.0.0.1:19945:9944 \
  -v "$CHAIN/dt:/chain/dt:ro,Z" -v solidus-smoke-dt-data:/data:Z \
  "$IMAGE" dev-testnet --testnet-dir /chain/dt --rpc-port 9944 --rpc-host 0.0.0.0 --data-dir /data
for i in $(seq 1 30); do curl -sf "http://127.0.0.1:19945/health" >/dev/null && break; sleep 1; done
curl -sf -X POST "http://127.0.0.1:19945" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"solidus_chainInfo","params":[]}' | grep -q solidus-smoke-dt
curl -sf "http://127.0.0.1:19945/health" | grep -q '"status":"ok"'
assert_commits 19945 "$CHAIN/dt"
"$C" stop -t 25 solidus-smoke-dt >/dev/null

echo "OK: smoke passed"
