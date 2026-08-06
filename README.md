<p align="center">
  <img src="https://raw.githubusercontent.com/solidusnetwork/.github/main/profile/solidus_icon.png" alt="Solidus Network" height="80" />
</p>

# Solidus Protocol

The original blockchain at the core of the [Solidus Network](https://solidus.network) — a layer-1
purpose-built as a trust anchor for decentralized identity, verifiable credentials, and
identity-bound staking.

- **Consensus:** HotStuff-style Byzantine Fault Tolerant (pacemaker, quorum certificates),
  ~1–2 s single-block finality
- **Cryptography:** Ed25519 per-validator signatures, BLS12-381 aggregates, BBS+ on BLS12-381
  for selective-disclosure credentials, BLAKE3-256 everywhere (state, tx, block)
- **State machine:** RocksDB with dedicated column families for `accounts`, `dids`,
  `credentials`, `validators`, `receipts`, `blocks`; sparse Merkle commitments
- **DID method:** `did:solidus` — see [`did-solidus-spec`](https://github.com/solidusnetwork/did-solidus-spec)
- **Public testnet:** JSON-RPC at <https://rpc.solidus.network>, block explorer at
  <https://explorer.solidus.network>

## What's in this repo

Two generations share this workspace. **v1** is the chain running the live testnet
today; **v2** is a ground-up rebuild of execution, consensus, and storage — a
**separate network with its own chain-id** that does not touch the live testnet.

v1 (the live testnet chain):

```
crates/
├── solidus-consensus   # HotStuff state machine, pacemaker, leader election (VRF)
├── solidus-crypto      # Ed25519, BLS12-381, BLAKE3, BBS+ (zkryptium 0.6, byte-compatible with @solidus-network/bbs)
├── solidus-node        # Validator binary — bootstraps state, p2p, RPC, consensus
├── solidus-p2p         # libp2p transport, gossipsub, peer discovery
├── solidus-rpc         # JSON-RPC server — solidus_didResolve, solidus_credentialResolve, getValidators, etc.
├── solidus-state       # Executor, store, state-root computation
└── solidus-txns        # Transaction payloads (DidCreate, DidUpdate, DidDeactivate, CredentialIssue, ...) + handlers
```

v2 (the two-lane rebuild — code public, **no public v2 network yet**):

```
crates/
├── solidus-exec         # Two-lane executor: parallel payment lane + serialized identity lane, differential-tested vs a serial oracle
├── solidus-state-tree   # BLAKE3 sparse Merkle tree, O(touched) root apply
├── solidus-store2       # v2 storage engine (RocksDB column families, durable block writes)
├── solidus-mempool-dag  # DAG mempool / transaction dissemination
├── solidus-hotstuff2    # Consensus core + TLA+ model (crates/solidus-hotstuff2/tla+/)
├── solidus-p2p2         # v2 libp2p networking
├── solidus-rpc2         # v2 JSON-RPC surface
├── solidus-node2        # v2 node assembly + load harness
├── solidus-noded        # Deployable node daemon: keygen, config generation, faucet
├── solidus-subnet       # Subnet scaffolding
└── solidus-evm          # EVM subnet scaffold + identity precompiles
```

## v2 — read this before quoting any number

- **Testnet-grade and unaudited.** No external audit has occurred on any part of
  this protocol. What an auditor would need to start is written up per component in
  [`docs/v2-audit-readiness.md`](docs/v2-audit-readiness.md).
- **The headline target — 50K TPS sustained on a 21-validator, 3-region network —
  has never been measured.** Every published figure was measured on one 10-core
  laptop and is labelled as such. The exact commands, hardware, and raw unedited
  outputs are in [`docs/v2-benchmarks.md`](docs/v2-benchmarks.md) and
  [`docs/bench/`](docs/bench/). If you cannot reproduce a number, open an issue.
- **There is no public v2 network yet** — no v2 RPC, no faucet, nothing to join.
  You can run the full stack locally today:
  [`docs/v2-validator-join.md`](docs/v2-validator-join.md) is a rehearsed runbook
  (keygen → config → 4-validator devnet → faucet-funded transfer), and it states
  the current limits honestly: the committee is config-static and there is no
  state-sync yet, so mid-flight join and restart-recovery are named open work items.
- **No token.** There is no $SLDS or any other token; nothing here mints, promises,
  or redeems value.
- `did:solidus` is **registered** in the W3C DID Method Registry — PR
  [w3c/did-extensions#713](https://github.com/w3c/did-extensions/pull/713) merged 2026-07-04,
  listed at [w3.org/TR/did-extensions-methods](https://www.w3.org/TR/did-extensions-methods/).
  Registration records that a method exists and is documented; it is **not** a W3C endorsement,
  and it says nothing about whether this implementation is secure. (Solidus is a DIF Associate
  Member.)

Design docs: [`docs/v2-execution-model.md`](docs/v2-execution-model.md) ·
[`docs/v2-consensus.md`](docs/v2-consensus.md) ·
[`docs/v2-wire-format.md`](docs/v2-wire-format.md)

## Status

v1: live on **testnet**, still producing blocks. The committee is whatever
`solidus_getValidators` returns — this page does not restate a count, because one typed here is
wrong the next time the set changes.

⚠ **The testnet is currently idle**, emitting an empty heartbeat block roughly every 10 minutes
(`tx_count: 0`). Do not read its current block rate as throughput. During its productive period it
sustained about **1 block/second** (measured from on-chain `timestamp_ms` over 20 000 consecutive
canonical blocks: 0.98 s/block, then 1.25 s/block), which is where the ~1–2 s finality figure above
comes from. Re-measure it yourself with `solidus_getBlockBySeq` rather than trusting this paragraph.

Mainnet launch is gated on independent security audit.

v2: code, benchmark harness, and local-devnet tooling are public in this repo as of
2026-07-14. No public v2 network exists yet; a mainnet-*candidate* is not a mainnet.

## Build

```bash
cargo build --release
```

## Run a local devnet

`solidus-node` is subcommand-driven. Generate a genesis + validator set, then run them:

```bash
# genesis.json, validator-N/ dirs and keys under ./testnet
target/release/solidus-node genesis \
  --validators 4 \
  --output ./testnet \
  --chain-id solidus-devnet-1

# all validators in one process, RPC on 127.0.0.1:9944
target/release/solidus-node dev-testnet \
  --testnet-dir ./testnet \
  --rpc-port 9944
```

`solidus-node run --config config.toml` starts a single node against an existing config;
`--help` lists the rest (`peer-id`, `canon-dump`, `sign-transfer`).

Confirm it is alive:

```bash
curl -s -X POST http://127.0.0.1:9944 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"solidus_chainInfo","params":[]}'
```

A freshly generated chain contains **no DIDs**, so `solidus_didResolve` returns `null` on it
until you create one — issue a DID with [`@solidus-network/sdk`](https://www.npmjs.com/package/@solidus-network/sdk)
(`did.create`) and resolve that. Against the public testnet, resolve any DID that exists there.

## Shipped features

- W3C DID Method `did:solidus` — all seven DID Core gaps closed (key rotation,
  deactivated-DID resolution metadata, full `verificationMethod`/relationship surface
  on chain, parameterised network in identifier, controller reassignment, `versionId`
  in resolution metadata)
- W3C Verifiable Credentials Data Model 2.0 (`validFrom` / `validUntil` / `@context` v2)
- BBS+ selective disclosure end-to-end — a holder can reveal "over 18" without
  disclosing the underlying date of birth
- SD-JWT VC issuance and verification (EUDI Wallet-compatible reference libraries),
  including KB-JWT, status-list revocation, and nested-path disclosure
- HotStuff BFT with TC formation correctness fix (handles the case where the local
  node misses a peer's `Vote`), committee surface via `getValidators`

## Reference clients

- [`@solidus-network/sdk`](https://github.com/solidusnetwork/sdk) — TypeScript SDK
  with DID, credential, BBS+ and SD-JWT VC primitives
- [Solidus Verify](https://verify.solidus.network) — production KYC service issuing
  BBS+ credentials (source not public)
- [Solidus Identity](https://identity.solidus.network) — self-sovereign identity
  wallet, credential holder, OIDC bridge (source not public)

## License

Apache-2.0.
