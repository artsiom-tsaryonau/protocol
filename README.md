<p align="center">
  <img src="brand/logos/solidus_icon.png" alt="Solidus Protocol" height="80" />
</p>

<h3 align="center">Solidus Protocol</h3>

<p align="center">
  An original blockchain built from first principles around<br/>
  <strong>Proof of Identity</strong> consensus and <strong>DID-native</strong> state management.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/consensus-HotStuff_BFT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/tests-85_passing-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/license-proprietary-lightgrey?style=flat-square" />
</p>

---

## Overview

Solidus Protocol is the consensus engine for the [Solidus Network](https://github.com/solidusnetwork) — a decentralized identity and authentication protocol. It replaces centralized providers (Auth0, Okta) with an open protocol at 95% lower cost.

**Key features:**
- **HotStuff-inspired BFT** — 3-phase pipelined consensus with VRF leader election
- **1.5s finality** — deterministic finality via chained quorum certificates
- **Sparse Merkle tree** — Jellyfish-style, 256-bit depth, BLAKE3-backed
- **Native state transitions** — DID registry, credential registry, token transfers, staking
- **Ed25519 + BLAKE3** — modern cryptographic primitives throughout

## Architecture

```
solidus-protocol/
├── crates/
│   ├── solidus-crypto/       Ed25519, BLAKE3, VRF, address derivation
│   ├── solidus-txns/         Transaction types, Transfer handler
│   ├── solidus-state/        RocksDB store, Account model, Sparse Merkle tree, Block executor
│   ├── solidus-consensus/    Block types, Mempool, single-node Proposer
│   ├── solidus-p2p/          P2P networking (libp2p — Slice 2)
│   ├── solidus-rpc/          JSON-RPC server (7 methods)
│   └── solidus-node/         CLI binary: config, genesis, wiring
├── Cargo.toml                Workspace root
└── rust-toolchain.toml       Nightly toolchain
```

## Current Status: Slice 1 Complete

Single-node block production with token transfers, JSON-RPC API, and end-to-end integration testing.

| Crate | Purpose | Tests |
|-------|---------|-------|
| solidus-crypto | BLAKE3, Ed25519, Address (Base58) | 19 |
| solidus-txns | Transaction types, Transfer handler | 11 |
| solidus-state | RocksDB, Account, Merkle tree, Executor | 26 |
| solidus-consensus | Block/Header, Mempool, Proposer | 9 |
| solidus-rpc | JSON-RPC (7 methods) | 15 |
| solidus-node | Config, genesis, wiring, E2E test | 5 |
| **Total** | | **85** |

## Roadmap

| Slice | Scope | Status |
|-------|-------|--------|
| 1 | Single-node block production + token transfers | Done |
| 2 | Multi-node HotStuff consensus (VRF, BLS, libp2p) | Next |
| 3 | DID registry on-chain | Planned |
| 4 | Credential registry on-chain | Planned |
| 5 | Staking + slashing | Planned |
| 6 | TypeScript SDK swap | Planned |

## Build & Test

```bash
# Prerequisites: Rust nightly
rustup install nightly

# Build
cargo build

# Test (85 tests)
cargo test --workspace

# Clippy
cargo clippy --workspace -- -D warnings
```

## Technical Specs

| Parameter | Value |
|-----------|-------|
| Consensus | HotStuff-inspired BFT (3-phase pipelined) |
| Block time | 500ms target |
| Finality | ~1.5s (3 rounds) |
| Hash | BLAKE3-256 |
| Signatures | Ed25519 (individual), BLS12-381 (aggregate — Slice 2) |
| State | Sparse Merkle tree over RocksDB |
| Address | Base58(HASH160(Ed25519 public key)) |
| DID format | `did:solidus:<network>:<identifier>` |
| Fee model | Flat per-operation (no gas metering for MVP) |
| Fee split | 70% validators, 20% treasury, 10% burn |

## License

Proprietary. All rights reserved. See [Solidus Network](https://github.com/solidusnetwork) for more information.
