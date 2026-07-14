//! Lane partition — the Hazard-A invariant, proposer-enforced and
//! re-derived identically at execution:
//!
//! ```text
//! S_identity = { sender : sender has ≥1 sig-valid non-Transfer tx in this block }
//! lane(tx)   = Identity  if tx.sender ∈ S_identity  else  Payment
//! ```
//!
//! A sender is therefore wholly in one lane: any sender doing an
//! identity/staking op has *all* of its txs (including its Transfers)
//! routed to the serial lane, so per-lane per-sender nonce order equals
//! global per-sender nonce order — nonce-correct by construction.
//!
//! **The partition runs over signature-valid transactions only** (§5.3:
//! the parallel signature pre-pass precedes the lane split). Sig-invalid
//! txs enter neither lane — they still owe "invalid signature" receipts,
//! but they have no state effects and (crucially) must not influence any
//! sender's lane assignment; nor can their sender address even be derived
//! when the embedded pubkey is off-curve.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;
use solidus_crypto::keys::Address;
use solidus_txns::types::{Transaction, TxPayload};

use crate::error::ExecError;
use crate::types::ExecOrder;

/// Non-panicking sender derivation (a malformed embedded pubkey yields
/// `None`; such a tx can only ever produce an invalid-signature receipt).
pub fn safe_sender(tx: &Transaction) -> Option<Address> {
    VerifyingKey::from_bytes(&tx.sender_pubkey)
        .ok()
        .map(|vk| Address::from_public_key(&vk))
}

/// The block's lane assignment. Each list holds input-tx indices in block
/// order; every index appears in exactly one list.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LanePlan {
    pub identity: Vec<usize>,
    pub payment: Vec<usize>,
    /// Signature-invalid txs: receipts only, no lane, no state effect.
    pub invalid: Vec<usize>,
}

/// Partition a block under the Hazard-A invariant. `valid[i]` is the
/// signature pre-pass verdict for `txs[i]`.
pub fn partition_lanes(txs: &[Transaction], valid: &[bool]) -> LanePlan {
    debug_assert_eq!(txs.len(), valid.len());

    let mut identity_senders: HashSet<Address> = HashSet::new();
    for (i, tx) in txs.iter().enumerate() {
        if valid[i] && !matches!(tx.payload, TxPayload::Transfer { .. }) {
            if let Some(sender) = safe_sender(tx) {
                identity_senders.insert(sender);
            }
        }
    }

    let mut plan = LanePlan::default();
    for (i, tx) in txs.iter().enumerate() {
        if !valid[i] {
            plan.invalid.push(i);
            continue;
        }
        match safe_sender(tx) {
            Some(sender) if identity_senders.contains(&sender) => plan.identity.push(i),
            Some(_) => plan.payment.push(i),
            // Unreachable for sig-valid txs (a valid signature implies a
            // decodable pubkey), kept total for safety:
            None => plan.invalid.push(i),
        }
    }
    plan
}

/// Resolve the canonical execution order of a block under the given
/// [`ExecOrder`].
///
/// - `RawBlock` (legacy parity anchor): committed order, verbatim; the
///   validity mask is not consulted (the live chain checks signatures
///   inline, per tx).
/// - `LanePartitioned` (v2 semantics, D-ORDER): identity lane, then
///   payment lane, then sig-invalid txs — each preserving relative block
///   order. Invalid txs have no state effects, so their position is
///   state-irrelevant; placing them last keeps the lanes contiguous. The
///   identity cap is enforced here: an over-cap block is invalid by
///   construction (the proposer must defer overflow), so execution
///   refuses it outright.
pub fn execution_order(
    txs: &[Transaction],
    valid: &[bool],
    order: ExecOrder,
    identity_cap: usize,
) -> Result<Vec<usize>, ExecError> {
    match order {
        ExecOrder::RawBlock => Ok((0..txs.len()).collect()),
        ExecOrder::LanePartitioned => {
            let plan = partition_lanes(txs, valid);
            if plan.identity.len() > identity_cap {
                return Err(ExecError::IdentityCapExceeded {
                    count: plan.identity.len(),
                    cap: identity_cap,
                });
            }
            let mut flat = plan.identity;
            flat.extend(plan.payment);
            flat.extend(plan.invalid);
            Ok(flat)
        }
    }
}

#[cfg(test)]
mod tests {
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;

    use super::*;

    fn signed_tx(key: &ed25519_dalek::SigningKey, nonce: u64, payload: TxPayload) -> Transaction {
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce,
            payload,
            signature: [0u8; 64],
        };
        let msg = tx.signing_bytes();
        tx.signature = sign(key, &msg);
        tx
    }

    fn transfer(key: &ed25519_dalek::SigningKey, nonce: u64) -> Transaction {
        signed_tx(
            key,
            nonce,
            TxPayload::Transfer {
                to: Address::from_bytes([9u8; 20]),
                amount: 1,
            },
        )
    }

    fn stake(key: &ed25519_dalek::SigningKey, nonce: u64) -> Transaction {
        signed_tx(key, nonce, TxPayload::Stake { amount: 1 })
    }

    fn all_valid(n: usize) -> Vec<bool> {
        vec![true; n]
    }

    #[test]
    fn pure_payment_sender_goes_to_payment_lane() {
        let alice = generate_signing_key();
        let txs = vec![transfer(&alice, 0), transfer(&alice, 1)];
        let plan = partition_lanes(&txs, &all_valid(2));
        assert!(plan.identity.is_empty());
        assert_eq!(plan.payment, vec![0, 1]);
    }

    #[test]
    fn mixed_sender_is_wholly_in_identity_lane() {
        let alice = generate_signing_key();
        let bob = generate_signing_key();
        let txs = vec![transfer(&alice, 0), stake(&alice, 1), transfer(&bob, 0)];
        let plan = partition_lanes(&txs, &all_valid(3));
        assert_eq!(plan.identity, vec![0, 1]);
        assert_eq!(plan.payment, vec![2]);
    }

    #[test]
    fn sig_invalid_identity_tx_does_not_drag_sender_into_serial_lane() {
        // Alice sends valid transfers plus a Stake with a BAD signature.
        // The invalid Stake must not reroute her transfers to the identity
        // lane (a forger could otherwise serialize anyone's payments).
        let alice = generate_signing_key();
        let mut bad_stake = stake(&alice, 5);
        bad_stake.signature[0] ^= 0xFF;
        let txs = vec![transfer(&alice, 0), bad_stake, transfer(&alice, 1)];
        let valid = vec![true, false, true];
        let plan = partition_lanes(&txs, &valid);
        assert_eq!(plan.payment, vec![0, 2]);
        assert_eq!(plan.invalid, vec![1]);
        assert!(plan.identity.is_empty());
    }

    #[test]
    fn garbage_pubkeys_cannot_panic_partition() {
        // Whatever bytes sit in sender_pubkey (decodable or not),
        // partitioning must never panic, and a sig-invalid tx lands in
        // the invalid list without influencing any lane membership.
        for pattern in [[0xFFu8; 32], [0u8; 32], [0xABu8; 32]] {
            let tx = Transaction {
                sender_pubkey: pattern,
                nonce: 0,
                payload: TxPayload::Stake { amount: 1 },
                signature: [0u8; 64],
            };
            let _ = safe_sender(&tx); // must not panic either way
            let plan = partition_lanes(&[tx], &[false]);
            assert_eq!(plan.invalid, vec![0]);
            assert!(plan.identity.is_empty() && plan.payment.is_empty());
        }
    }

    #[test]
    fn lane_partitioned_order_is_identity_then_payment_then_invalid() {
        let alice = generate_signing_key();
        let bob = generate_signing_key();
        let mut bad = transfer(&bob, 7);
        bad.signature[3] ^= 0xFF;
        // Block order: bob-transfer, alice-stake, BAD, bob-transfer, alice-transfer
        let txs = vec![
            transfer(&bob, 0),
            stake(&alice, 0),
            bad,
            transfer(&bob, 1),
            transfer(&alice, 1),
        ];
        let valid = vec![true, true, false, true, true];
        let order =
            execution_order(&txs, &valid, ExecOrder::LanePartitioned, usize::MAX).expect("order");
        assert_eq!(order, vec![1, 4, 0, 3, 2]);
    }

    #[test]
    fn raw_block_order_is_identity_function() {
        let alice = generate_signing_key();
        let txs = vec![transfer(&alice, 0), stake(&alice, 1)];
        let order = execution_order(&txs, &all_valid(2), ExecOrder::RawBlock, 0).expect("order");
        assert_eq!(order, vec![0, 1]);
    }

    #[test]
    fn identity_cap_is_enforced() {
        let alice = generate_signing_key();
        let txs = vec![stake(&alice, 0), stake(&alice, 1)];
        let err = execution_order(&txs, &all_valid(2), ExecOrder::LanePartitioned, 1)
            .expect_err("cap must reject");
        assert!(matches!(
            err,
            ExecError::IdentityCapExceeded { count: 2, cap: 1 }
        ));
    }
}
