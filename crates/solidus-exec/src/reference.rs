//! The **serial reference executor** — the permanent differential oracle
//! (§5.6). Single lane, fully serial, direct `DeltaSet`, same handlers as
//! every production executor. For any tx stream, the two-lane executor
//! (Stage 3) must produce byte-identical receipts and `GlobalRoot` against
//! this implementation.
//!
//! Two configurations matter:
//! - **v2 oracle:** `ExecOptions::v2_defaults(chain_id)` — binary wire,
//!   lane-partitioned canonical order (D-ORDER), burn fees.
//! - **Parity anchor:** `ExecOptions::legacy_anchor(..)` — legacy JSON
//!   wire, raw block order, 70/20/10 fee split; byte-identical to the live
//!   chain's `execute_block` + `compute_state_root` (differential-tested
//!   in `tests/legacy_parity.rs`).

use solidus_state_tree::StateForest;
use solidus_txns::types::{Receipt, Transaction};

use crate::delta::{DeltaSet, StateReader};
use crate::error::ExecError;
use crate::fee::{self, FeeAccumulator};
use crate::handlers;
use crate::lane::execution_order;
use crate::types::{BlockCtx, ExecOptions};
use crate::view::SerialView;

/// Everything one executed block produces.
pub struct BlockOutcome {
    /// Receipt for `txs[i]` at index `i` (input order, regardless of
    /// execution order).
    pub receipts: Vec<Receipt>,
    /// The block's finalized write set (fee settlement included).
    pub delta: DeltaSet,
    /// Events not tied to one transaction (bridge heartbeats). Empty before V2.
    pub block_events: Vec<solidus_txns::types::Event>,
}

impl BlockOutcome {
    /// Apply this block's root-bearing writes to a forest and return the
    /// new global state root (incremental, O(touched · depth)).
    pub fn global_root_into(&self, forest: &mut StateForest) -> [u8; 32] {
        self.delta.apply_to_forest(forest);
        forest.global_root()
    }
}

/// Execute a block serially against `baseline`, in the canonical order
/// selected by `opts.order`, and settle fees per `opts.fee_policy`.
///
/// This function is intentionally boring: resolve order → run each tx
/// through the shared handler pipeline over a serial view → settle fees
/// once. All interesting semantics live in [`crate::handlers`] (shared
/// with the two-lane executor) — that sharing is what makes this a
/// meaningful oracle rather than a second implementation to diverge from.
pub fn execute_block_reference<R: StateReader + ?Sized>(
    baseline: &R,
    txs: &[Transaction],
    ctx: &BlockCtx<'_>,
    opts: &ExecOptions,
) -> Result<BlockOutcome, ExecError> {
    // ⛔ The wire is a function of HEIGHT, not of config: at a V2 height a
    // BinaryV2 base becomes BinaryV3 bound to this chain id.
    let wire = crate::wire::wire_for_height(opts.wire, opts.chain_id, ctx.height);
    // Lane partition runs over sig-valid txs only (§5.3: the signature
    // pre-pass precedes the lane split; the oracle verifies serially —
    // simplest correct). RawBlock ignores the mask: the live chain checks
    // signatures inline per tx, and run_tx reproduces that verbatim.
    let valid: Vec<bool> = match opts.order {
        crate::types::ExecOrder::RawBlock => Vec::new(),
        crate::types::ExecOrder::LanePartitioned => txs
            .iter()
            .map(|tx| crate::wire::verify_signature(tx, wire))
            .collect(),
    };
    let order = execution_order(txs, &valid, opts.order, opts.identity_cap)?;

    let mut delta = DeltaSet::new();
    let mut fees = FeeAccumulator::new();
    let mut receipts: Vec<Option<Receipt>> = (0..txs.len()).map(|_| None).collect();

    for &i in &order {
        let mut view = SerialView::new(&mut delta, baseline, &mut fees);
        let receipt = handlers::run_tx(&mut view, &txs[i], ctx, wire)?;
        receipts[i] = Some(receipt);
    }

    let mut block_events = Vec::new();
    if ctx.protocol_version() >= crate::protocol::ProtocolVersion::V2 {
        let mut view = SerialView::new(&mut delta, baseline, &mut fees);
        block_events = crate::bridge::on_block_end(&mut view, ctx)?;
    }

    fee::settle(&opts.fee_policy, &fees, &mut delta, baseline)?;

    let receipts: Vec<Receipt> = receipts
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            debug_assert!(r.is_some(), "execution order must cover every tx index");
            r.unwrap_or_else(|| {
                handlers::failed_receipt(
                    crate::wire::tx_hash(&txs[i], wire),
                    ctx.height,
                    0,
                    "internal: tx not covered by execution order".to_string(),
                )
            })
        })
        .collect();

    Ok(BlockOutcome {
        receipts,
        delta,
        block_events,
    })
}

#[cfg(test)]
mod tests {
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_txns::types::{TxPayload, TxStatus, FEE_TRANSFER};

    use super::*;
    use crate::account::{Account, AccountType};
    use crate::delta::InMemoryState;
    use crate::types::{StateKey, WireMode};
    use crate::wire;

    fn ctx() -> BlockCtx<'static> {
        BlockCtx {
            height: 1,
            timestamp_ms: 1_700_000_000_000,
            network: "testnet",
            parent_state_root: [0u8; 32],
        }
    }

    fn fund(state: &mut InMemoryState, addr: Address, balance: u64) {
        let acct = Account::with_balance(addr, balance, AccountType::Regular);
        state.set(StateKey::account(&addr), acct.to_bytes());
    }

    fn signed_transfer(
        key: &ed25519_dalek::SigningKey,
        to: Address,
        amount: u64,
        nonce: u64,
        mode: WireMode,
    ) -> Transaction {
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce,
            payload: TxPayload::Transfer { to, amount },
            signature: [0u8; 64],
        };
        let msg = wire::signing_bytes(&tx, mode);
        tx.signature = sign(key, &msg);
        tx
    }

    fn account_at(state_bytes: &[u8]) -> Account {
        Account::from_bytes(state_bytes).expect("account decode")
    }

    #[test]
    fn v2_defaults_execute_a_transfer_and_burn_fees() {
        let mut state = InMemoryState::new();
        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let recipient = Address::from_bytes([0xCD; 20]);
        fund(&mut state, sender_addr, 1_000_000);

        let tx = signed_transfer(&sender_key, recipient, 500, 0, WireMode::BinaryV2);
        let opts = ExecOptions::v2_defaults(50_002);
        let outcome = execute_block_reference(&state, &[tx], &ctx(), &opts).expect("execute");

        assert_eq!(outcome.receipts.len(), 1);
        assert_eq!(outcome.receipts[0].status, TxStatus::Success);
        assert_eq!(outcome.receipts[0].fee_paid, FEE_TRANSFER);

        let sender_after = account_at(
            outcome
                .delta
                .get(&StateKey::account(&sender_addr))
                .expect("sender in delta"),
        );
        assert_eq!(sender_after.balance, 1_000_000 - FEE_TRANSFER - 500);
        assert_eq!(sender_after.nonce, 1);

        let recipient_after = account_at(
            outcome
                .delta
                .get(&StateKey::account(&recipient))
                .expect("recipient in delta"),
        );
        assert_eq!(recipient_after.balance, 500);

        // Burn policy: the fee landed in the meta counter, not any account.
        let burned = outcome
            .delta
            .get(&StateKey::meta(crate::fee::META_FEES_BURNED))
            .expect("burn counter");
        assert_eq!(
            u64::from_le_bytes(burned.as_slice().try_into().expect("8 bytes")),
            FEE_TRANSFER
        );
    }

    #[test]
    fn receipts_align_with_input_order_under_lane_partition() {
        // Block order: [bob transfer, alice stake] — execution order is
        // [alice stake, bob transfer] (identity first), but receipts[0]
        // must still be bob's transfer receipt.
        let mut state = InMemoryState::new();
        let alice = generate_signing_key();
        let bob = generate_signing_key();
        let alice_addr = Address::from_public_key(&alice.verifying_key());
        let bob_addr = Address::from_public_key(&bob.verifying_key());
        fund(&mut state, alice_addr, 10_000_000_000_000);
        fund(&mut state, bob_addr, 1_000_000);

        let recipient = Address::from_bytes([0xEE; 20]);
        let t_bob = signed_transfer(&bob, recipient, 100, 0, WireMode::BinaryV2);

        let mut t_alice = Transaction {
            sender_pubkey: alice.verifying_key().to_bytes(),
            nonce: 0,
            payload: TxPayload::Stake {
                amount: 1_000_000_000_000,
            },
            signature: [0u8; 64],
        };
        let msg = wire::signing_bytes(&t_alice, WireMode::BinaryV2);
        t_alice.signature = sign(&alice, &msg);

        let opts = ExecOptions::v2_defaults(50_002);
        let outcome =
            execute_block_reference(&state, &[t_bob, t_alice], &ctx(), &opts).expect("execute");

        assert_eq!(outcome.receipts.len(), 2);
        // receipts[1] is alice's stake.
        assert!(
            matches!(
                outcome.receipts[1].events.first(),
                Some(solidus_txns::types::Event::Staked { .. })
            ),
            "receipt order must follow input order, got {:?}",
            outcome.receipts[1]
        );
        assert_eq!(outcome.receipts[0].status, TxStatus::Success);
    }

    /// A block at a V2 height accepts only V3 signatures for this chain; before
    /// it, only V2. `TxStatus` has only `Success` and `Failed(_)`, so "rejected"
    /// is asserted as "not Success" on an otherwise valid, funded transfer.
    #[cfg(feature = "test-activation-schedule")]
    #[test]
    fn signature_wire_follows_the_block_height_across_v2_activation() {
        use crate::protocol::V2_ACTIVATION_HEIGHT;
        const CHAIN: u64 = 50_002;

        let run = |height: u64, mode: WireMode| -> TxStatus {
            let mut state = InMemoryState::new();
            let key = generate_signing_key();
            fund(
                &mut state,
                Address::from_public_key(&key.verifying_key()),
                1_000_000,
            );
            let tx = signed_transfer(&key, Address::from_bytes([0xCD; 20]), 500, 0, mode);
            let ctx = BlockCtx {
                height,
                timestamp_ms: 1_700_000_000_000,
                network: "testnet",
                parent_state_root: [0u8; 32],
            };
            execute_block_reference(&state, &[tx], &ctx, &ExecOptions::v2_defaults(CHAIN))
                .expect("execute")
                .receipts[0]
                .status
                .clone()
        };

        let before = V2_ACTIVATION_HEIGHT - 1;
        assert_eq!(run(before, WireMode::BinaryV2), TxStatus::Success);
        assert_ne!(
            run(before, WireMode::BinaryV3 { chain_id: CHAIN }),
            TxStatus::Success
        );

        let at = V2_ACTIVATION_HEIGHT;
        assert_eq!(
            run(at, WireMode::BinaryV3 { chain_id: CHAIN }),
            TxStatus::Success
        );
        assert_ne!(
            run(at, WireMode::BinaryV2),
            TxStatus::Success,
            "a v2 signature must stop working at activation"
        );
        assert_ne!(
            run(
                at,
                WireMode::BinaryV3 {
                    chain_id: CHAIN + 1
                }
            ),
            TxStatus::Success,
            "replay from another chain"
        );
    }
}
