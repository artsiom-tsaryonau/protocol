# Solidus v2 — Wire Format (R-WIRE pin, Stage 0, frozen)

Status: Stage-0 design freeze, 2026-07-11. The v2 chain is a **parallel
network on a new chain-id** (BD-6); every breaking wire change below is
absorbed by that new chain-id at once. The live testnet is untouched.

## Transaction signing & hashing: serde_json → bincode

| | Live chain | v2 (`solidus-exec/src/wire.rs`) |
|---|---|---|
| signing bytes | `BLAKE3(pubkey ‖ nonce_le ‖ serde_json(payload))` | `BLAKE3(pubkey ‖ nonce_le ‖ bincode(payload))` |
| tx hash | `BLAKE3(serde_json(tx))` | `BLAKE3(bincode(tx))` |

- Every v2 tx hash and signature differs from the live chain **by
  design**; the two networks never exchange transactions.
- `solidus-txns` is reused unchanged, so its inherent
  `Transaction::signing_bytes()/hash()` remain the legacy definitions.
  All v2 code paths call `solidus_exec::wire::{signing_bytes, tx_hash,
  verify_signature}` with `WireMode::BinaryV2`. `WireMode::LegacyJson`
  exists solely for the parity anchor.
- Pinned by tests (`wire::tests`): v2/legacy hashes must differ; a v2
  signature must not verify as a legacy signature.

## What deliberately does NOT change (state-root compatibility)

State-record leaf encodings are kept byte-identical to the live chain,
because (a) they live in `solidus-txns`/record `to_bytes()` methods that
are reused unchanged, and (b) keeping them identical lets the Stage-0
parity anchor demand **exact** state-root equality:

| Record | Encoding | Where defined |
|---|---|---|
| `Account` | bincode | `solidus-exec/src/account.rs`, byte-compatible clone of the live struct (pinned by test) |
| `DidDocument` | serde_json | `solidus-txns/src/did.rs` (reused) |
| `CredentialRecord` | serde_json | `solidus-txns/src/credential.rs` (reused) |
| `ValidatorInfo` | serde_json | `solidus-txns/src/staking.rs` (reused) |
| credential secondary indexes | serde_json `Vec<String>` | mirrors live executor helpers |

Crucially, **no tx hash feeds the state root**: credential ids derive from
`(issuer, subject, hash, block_height)` and receipts live outside the
root-bearing trees. So the JSON→bincode tx-hash change does not perturb
state roots — verified by the 879k-tx differential run (zero root
divergence).

The §4.6 "binary everywhere" mandate targets the *hot paths* — signing
bytes, tx hashing, and the consensus commit path (the live
`hotstuff.rs`'s serde_json block/receipt serialization is retired when
Stage 1/4 land). Re-encoding the JSON record leaves is a possible Stage-4
optimization; if taken, it changes state roots and must be re-anchored
deliberately — do not fold it into an unrelated change.

## Consensus & mempool wire (frozen shape, Stage 1–2 fill the details)

- Blocks carry `Vec<BatchCertificate>` — 32-byte BLAKE3 digests of
  bincode-serialized worker batches (`solidus-mempool-dag`), never tx
  bodies. Consensus headers stay in the kilobytes at full capacity.
- `BatchCertificate.attestation` and the HotStuff-2 QC encoding are
  opaque `Vec<u8>` at Stage 0; Stage 1 (QC) and Stage 2 (availability
  attestation) finalize them as bincode structs. All consensus-path
  serialization is binary — serde_json never enters the v2 hot path.
- Receipts persist bincode-encoded at the node layer (Stage 4), keyed by
  the v2 tx hash.
