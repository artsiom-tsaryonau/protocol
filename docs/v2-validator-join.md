# Solidus L1 v2 — Validator Runbook

Status: written + **rehearsed end-to-end locally** 2026-07-13 (every command
in Part 1 was executed verbatim on a clean devnet; outputs shown are real).
Audience: an operator outside the Solidus team. You should not need to talk
to us to follow Part 1; Part 2 needs one message to the network coordinator
because the committee is fixed at genesis (see "What is not possible yet").

> **Which network this is.** Solidus v2 networks are **parallel networks
> with their own chain-ids** — separate from the live legacy testnet at
> `rpc.solidus.network`. Everything here is testnet-grade: unaudited, no
> token, no mainnet.

## What you can do today — and what you can't (read first)

| You want to | Status |
|---|---|
| Run your own local 4-validator v2 network | ✅ Part 1, verified |
| Send a transaction and watch it commit | ✅ Part 1 (faucet + balance query) |
| Generate keys + join a **new** network at genesis | ✅ Part 2 |
| Join a **running** network mid-flight | ❌ not yet — no state-sync/catch-up protocol; the committee is fixed in config at genesis |
| Restart a validator that went offline | ❌ not yet — same gap: it cannot re-fetch the blocks it missed (BFT tolerates f = ⌊(n−1)/3⌋ nodes offline meanwhile) |
| Run a non-validator observer / RPC-only node | ❌ not yet — the daemon always runs a committee member |
| Become a validator via on-chain `Stake` | ❌ not yet — stake payloads execute on-chain, but committee rotation from stake state is a flagged work item |

The ❌ rows are the honest boundary of the current build (flagged Stage-7+
work items), not fine print.

## Prerequisites

- Linux x86_64/arm64 or macOS; 8+ cores, 16 GB RAM, NVMe recommended.
- Rust (stable) + clang: `curl https://sh.rustup.rs -sSf | sh` and
  `apt-get install -y build-essential clang` (Linux).
- **macOS note:** AirPlay Receiver listens on `*:7000`, which collides with
  the generated devnet's first p2p port. Either disable AirPlay Receiver
  (System Settings → General → AirDrop & Handoff) or shift the devnet's p2p
  ports: `sed -i '' 's|tcp/700|tcp/711|g' devnet/node*.toml`.

```bash
git clone https://github.com/solidusnetwork/protocol.git && cd protocol
cargo build --release -p solidus-noded     # → target/release/solidus-noded
```

## Part 1 — your own local v2 network (verified)

```bash
BIN=target/release/solidus-noded

# 1. Generate a 4-validator devnet (pick any chain-id; 41414 below):
$BIN gen ./devnet 4 41414
#    → devnet/node{0..3}.toml + genesis-keys.txt (funded dev accounts)
#      + faucet.toml (dev-account-0's key, pointed at node0's RPC)

# 2. Launch the validators (4 terminals, or backgrounded):
for i in 0 1 2 3; do $BIN run ./devnet/node$i.toml > node$i.log 2>&1 & done

# 3. Watch block production (each node boots once a BFT quorum connects):
curl -s localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"solidus_getBlockHeight","params":[]}'
# rehearsal output, ~10s after boot:  {"jsonrpc":"2.0","id":1,"result":121}

# 4. Start the faucet and fund any address (base58, 20 bytes):
$BIN faucet ./devnet/faucet.toml &
curl -s localhost:8600 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"faucet_drip","params":["<your address>"]}'
# rehearsal output:
#   {"jsonrpc":"2.0","id":1,"result":{"amount":"1000000","txHash":"a8b23b6e…"}}

# 5. Confirm the transfer committed — query a DIFFERENT node:
curl -s localhost:8548 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"solidus_getBalance","params":["<your address>"]}'
# rehearsal: balance visible on node3 0.16s after the drip call returned.
```

RPC surface: `solidus_getBalance` · `getNonce` · `getBlockHeight` ·
`getStateRoot` · `getReceipt(height, txHash)` · `submitTransaction(hex)` —
conventions: base58 addresses, hex hashes, submitted tx = hex(bincode) per
the v2 wire format (`docs/v2-wire-format.md`), balances as decimal strings.

## Part 2 — join a new network at genesis

A v2 committee is fixed in every validator's config. Joining therefore
happens when a network is **formed** (or deliberately re-formed):

1. **Generate your keys on your own box** (secrets never leave it):
   ```bash
   $BIN keygen
   # secrets — keep on this box, put in YOUR node config only
   bls_secret_hex = "…"
   p2p_secret_hex = "…"
   # public — send these to the network coordinator
   bls_pubkey_hex = "…"
   peer_id = "12D3KooW…"
   ```
2. **Send the coordinator** the two public lines plus your public dial
   address (`/ip4/<your-ip>/tcp/<port>`). The coordinator assembles the
   shared `validators[]` + `peers[]` + `genesis[]` lists and your `index`.
3. **Author your `node.toml`** — the shared lists + your `index`, your two
   secret hexes, your `data_dir`, `listen_addr` (bind `0.0.0.0`), and
   `rpc_addr` (bind `127.0.0.1` and reverse-proxy if you expose it). Field
   reference: `crates/solidus-noded/README.md`.
4. **Firewall:** open your p2p TCP port to the other validators; do not
   expose the RPC port raw.
5. **Run it** — `solidus-noded run /etc/solidus/node.toml`, ideally under
   systemd (unit template in the README). The node waits for a quorum of
   peers, then joins consensus; your health checks are `getBlockHeight`
   climbing and your logs staying free of `bad bls`/`dial` errors.

## Operator notes

- **Faucet** (network operator only): write a `faucet.toml` with a
  genesis-funded key and run `solidus-noded faucet` behind a reverse proxy.
  Testnet-grade: plain-hex key, in-memory rate limit.
- **Data:** one RocksDB dir per node (`data_dir`); deleting it currently
  means the node cannot recover (no catch-up — see the table above).
- **Fees:** every transfer costs 10,000 (v2 default policy burns fees), so
  a 1,000,000 drip funds ~100 transfers.
