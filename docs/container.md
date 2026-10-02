# Running solidus-node in a container

A private lab chain in one container. Verified 2026-10-02 with podman; reconciled with upstream
2026-10-03 (n = 1 commit, `--data-dir`, `GET /health`).

| Mode | Commits blocks | Survives restart | RPC reachable from other pods |
|------|----------------|------------------|-------------------------------|
| `dev-testnet` (4 validators in one process) | Yes (~1 s after a tx) | Yes (height kept, keeps committing) | Pass **`--rpc-host 0.0.0.0`** (default is `127.0.0.1`); optional **`--data-dir /data`** for keys vs DB split |
| `run --consensus`, 1 validator | Yes (upstream 2026-10-03) | Yes (`data_dir` on PVC) | Yes (`rpc_listen` in config) |
| `run` (legacy, no `--consensus`) — from code, not run | Likely | **No** — proposer restarts at height 0 and overwrites stored blocks | Yes |

For Kubernetes, prefer **`run --consensus`** with one validator when you want a single pod;
use **`dev-testnet`** when you want four validators in one process for lab throughput.

## 1. Build

```bash
docker build -t solidus-node .
```

The build stage installs the toolchain from `rust-toolchain.toml` (stable) plus
`clang`/`cmake` for RocksDB. The runtime image is `debian:bookworm-slim` running as
UID 10001.

## 2. Generate genesis and keys (once)

```bash
docker run --rm -v "$PWD/chain:/out" --user "$(id -u)" --entrypoint solidus-node \
  solidus-node genesis --validators 1 --chain-id solidus-lab-1 --output /out
```

`chain/` now holds `genesis.json`, `validator-0/{config.toml,node.key,bls.key}`, and
`treasury.key` / `faucet.key` (accounts funded in genesis — keep the faucet key if
you need to fund issuer accounts later).
The chain id must look like `solidus-<network>-<n>`: DIDs on it are
`did:solidus:<network>:…`.

`node.key` and `bls.key` are the validator's secrets. Store them like any other
private key (Vault, a Kubernetes Secret); losing them means a new chain.

## 3. Adjust config.toml for the container

The generated `validator-0/config.toml` binds RPC to `127.0.0.1:8080`, uses relative
paths, and expects `genesis.json` one directory up. In the container, paths resolve against the config file's directory, and an
absolute path is used as-is:

```toml
[node]
chain_id = "solidus-lab-1"
listen_port = 30300
data_dir = "/data"            # persistent volume, not under /etc/solidus
genesis = "genesis.json"      # /etc/solidus/genesis.json
ed25519_key = "node.key"
bls_key = "bls.key"
rpc_port = 9944
rpc_listen = "0.0.0.0"        # reachable from other pods; RPC has no auth — keep it cluster-internal
node_index = 0
```

## 4. Run

```bash
mkdir -p etc && cp chain/genesis.json chain/validator-0/{node.key,bls.key} etc/
# write etc/config.toml from step 3
docker run -d --name solidus -p 127.0.0.1:9944:9944 \
  -v "$PWD/etc:/etc/solidus:ro" -v solidus-data:/data solidus-node

curl -s -X POST http://127.0.0.1:9944 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"solidus_chainInfo","params":[]}'
```

`docker stop` sends SIGTERM; the node shuts down the proposer and RPC cleanly
before exiting.

## Kubernetes notes

- One replica, `StatefulSet` with a `ReadWriteOnce` volume at `/data` (RocksDB is
  single-writer — never run two pods on one volume).
- Mount `config.toml`, `genesis.json` (ConfigMap) and `node.key`, `bls.key` (Secret)
  into `/etc/solidus`.
- Expose 9944 with a `ClusterIP` Service only.
- Liveness/readiness: `GET /health` → `{"status":"ok","height":N}` (JSON-RPC remains POST-only).
- `terminationGracePeriodSeconds: 30` leaves room for the SIGTERM shutdown.
