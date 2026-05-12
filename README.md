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

## Status

Live on **testnet** with four validators, single-block finality, ~35 k blocks/15 s
under load. Mainnet launch is gated on independent security audit.

## Build

```bash
cargo build --release
```

## Run a single-node devnet

```bash
target/release/solidus-node \
  --chain-id solidus-devnet-1 \
  --data-dir ./dev-data \
  --rpc-listen 127.0.0.1:9944
```

Then resolve a sample DID:

```bash
curl -s -X POST http://127.0.0.1:9944 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "solidus_didResolve",
    "params": ["did:solidus:testnet:5dXc8vN3kzGm7p6L9HsQrR2hYfBaT1Wj"]
  }'
```

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
- [`solidus-verify`](https://github.com/solidusnetwork/verify) — production KYC
  service issuing BBS+ credentials
- [`solidus-identity`](https://github.com/solidusnetwork/identity) — self-sovereign
  identity wallet, credential holder, OIDC bridge

## License

Apache-2.0.
