//! The payment-lane parallel scheduler: bespoke Block-STM-family
//! optimistic concurrency (BD-7 — Aptos MVMemory as reference, not fork),
//! realized as **wave-OCC**:
//!
//! 1. Execute every pending tx **blind and in parallel** against an
//!    immutable `&MvMemory` snapshot (plus the frozen identity delta and
//!    the store baseline), recording each tx's read-set (version origins)
//!    and write-set. Handlers are the exact same [`crate::handlers::run_tx`]
//!    the serial oracle uses — only the view differs.
//! 2. **Serial validate-and-apply by lane index**: rebuild the
//!    multi-version table from scratch — for each tx in order, check every
//!    recorded read still resolves to the same origin against the
//!    table-so-far; if yes, apply its writes; if no, queue it for
//!    re-execution.
//! 3. Repeat until no tx is invalid.
//!
//! Serial-equivalence is by construction: the final pass certifies every
//! committed tx's reads against exactly the multi-version prefix below
//! it. Termination: the lowest-indexed invalid tx re-executes against its
//! final prefix and must validate next wave (≤ N waves; 1–2 in practice —
//! the payment lane is `Transfer`-only over mostly-disjoint accounts, and
//! the fee hot-key is gone per Hazard-C).

use std::collections::BTreeMap;

use rayon::prelude::*;
use solidus_txns::types::{Receipt, Transaction};

use crate::delta::{read_through, DeltaSet, StateReader};
use crate::error::ExecError;
use crate::handlers;
use crate::mvmemory::{MvMemory, ReadOrigin, ReadOutcome};
use crate::types::{BlockCtx, StateKey, WireMode};
use crate::view::TxView;

/// Result of the payment lane over one block.
pub struct PaymentOutcome {
    /// (input tx index, receipt) for every payment-lane tx.
    pub receipts: Vec<(usize, Receipt)>,
    /// Final key → value map of the lane's writes.
    pub writes: BTreeMap<StateKey, Vec<u8>>,
    /// Total fees charged by the lane (commutative — merged into the
    /// block accumulator).
    pub fees: u64,
    /// Number of execution waves it took (telemetry: 1 = conflict-free).
    pub waves: usize,
}

/// One tx's blind execution artifacts.
struct TxRun {
    read_set: Vec<(StateKey, ReadOrigin)>,
    write_set: BTreeMap<StateKey, Vec<u8>>,
    receipt: Receipt,
    fee: u64,
}

/// The payment-lane view: reads own-writes → multi-version (< own index)
/// → frozen identity delta → baseline store; writes buffer locally;
/// read origins are recorded for validation.
struct MvView<'a, R: StateReader + ?Sized> {
    mv: &'a MvMemory,
    frozen: &'a DeltaSet,
    baseline: &'a R,
    lane_index: usize,
    read_set: Vec<(StateKey, ReadOrigin)>,
    write_set: BTreeMap<StateKey, Vec<u8>>,
    fee: u64,
}

impl<'a, R: StateReader + ?Sized> MvView<'a, R> {
    fn new(mv: &'a MvMemory, frozen: &'a DeltaSet, baseline: &'a R, lane_index: usize) -> Self {
        Self {
            mv,
            frozen,
            baseline,
            lane_index,
            read_set: Vec::new(),
            write_set: BTreeMap::new(),
            fee: 0,
        }
    }
}

impl<R: StateReader + ?Sized> TxView for MvView<'_, R> {
    fn read(&mut self, key: &StateKey) -> Result<Option<Vec<u8>>, ExecError> {
        // Read-own-write: self-consistent, never invalidated, not recorded.
        if let Some(v) = self.write_set.get(key) {
            return Ok(Some(v.clone()));
        }
        match self.mv.read(key, self.lane_index) {
            ReadOutcome::Versioned {
                writer,
                incarnation,
                value,
            } => {
                self.read_set.push((
                    key.clone(),
                    ReadOrigin::Version {
                        writer,
                        incarnation,
                    },
                ));
                Ok(Some(value))
            }
            ReadOutcome::Baseline => {
                self.read_set.push((key.clone(), ReadOrigin::Baseline));
                // The frozen identity delta and the store are immutable for
                // the whole lane — one "Baseline" origin covers both.
                read_through(self.frozen, self.baseline, key)
            }
        }
    }

    fn write(&mut self, key: StateKey, value: Vec<u8>) -> Result<(), ExecError> {
        self.write_set.insert(key, value);
        Ok(())
    }

    fn charge_fee(&mut self, amount: u64) {
        self.fee = self.fee.saturating_add(amount);
    }
}

/// Run the payment lane. `payment_idx` are input-tx indices in canonical
/// lane order (block order among payment txs). `frozen` must be frozen.
pub fn run_payment_lane<R: StateReader + Sync + ?Sized>(
    baseline: &R,
    frozen: &DeltaSet,
    txs: &[Transaction],
    payment_idx: &[usize],
    ctx: &BlockCtx<'_>,
    wire: WireMode,
) -> Result<PaymentOutcome, ExecError> {
    debug_assert!(frozen.is_frozen(), "identity delta must be frozen first");
    let n = payment_idx.len();
    let mut mv = MvMemory::new();
    let mut runs: Vec<Option<TxRun>> = (0..n).map(|_| None).collect();
    let mut incarnations = vec![0u32; n];
    let mut pending: Vec<usize> = (0..n).collect();
    let mut waves = 0usize;

    while !pending.is_empty() {
        waves += 1;
        debug_assert!(waves <= n + 1, "wave-OCC failed to converge");

        // ---- Parallel blind execution against the immutable snapshot ----
        let executed: Vec<(usize, Result<TxRun, ExecError>)> = pending
            .par_iter()
            .map(|&p| {
                let mut view = MvView::new(&mv, frozen, baseline, p);
                let result =
                    handlers::run_tx(&mut view, &txs[payment_idx[p]], ctx, wire).map(|receipt| {
                        TxRun {
                            read_set: std::mem::take(&mut view.read_set),
                            write_set: std::mem::take(&mut view.write_set),
                            receipt,
                            fee: view.fee,
                        }
                    });
                (p, result)
            })
            .collect();
        for (p, result) in executed {
            runs[p] = Some(result?);
            incarnations[p] = incarnations[p].wrapping_add(1);
        }

        // ---- Serial validate-and-apply: rebuild the table by index ----
        mv = MvMemory::new();
        pending.clear();
        for p in 0..n {
            #[allow(clippy::expect_used)]
            let run = runs[p].as_ref().expect("every lane tx executed in wave 1");
            let valid = run
                .read_set
                .iter()
                .all(|(key, origin)| mv.origin_of(key, p) == *origin);
            if valid {
                mv.apply_write_set(p, incarnations[p], &run.write_set);
            } else {
                pending.push(p);
            }
        }
    }

    let mut receipts = Vec::with_capacity(n);
    let mut fees = 0u64;
    for (p, run) in runs.into_iter().enumerate() {
        #[allow(clippy::expect_used)]
        let run = run.expect("all lane txs committed");
        fees = fees.saturating_add(run.fee);
        receipts.push((payment_idx[p], run.receipt));
    }

    Ok(PaymentOutcome {
        receipts,
        writes: mv.into_finalized(),
        fees,
        waves,
    })
}

#[cfg(test)]
mod tests {
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_txns::types::{TxPayload, TxStatus};

    use super::*;
    use crate::account::{Account, AccountType};
    use crate::delta::InMemoryState;
    use crate::wire;

    fn ctx() -> BlockCtx<'static> {
        BlockCtx {
            height: 1,
            timestamp_ms: 1_700_000_000_000,
            network: "testnet",
        }
    }

    fn signed_transfer(
        key: &ed25519_dalek::SigningKey,
        to: Address,
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce,
            payload: TxPayload::Transfer { to, amount },
            signature: [0u8; 64],
        };
        let msg = wire::signing_bytes(&tx, WireMode::BinaryV2);
        tx.signature = sign(key, &msg);
        tx
    }

    fn fund(state: &mut InMemoryState, addr: Address, balance: u64) {
        state.set(
            StateKey::account(&addr),
            Account::with_balance(addr, balance, AccountType::Regular).to_bytes(),
        );
    }

    #[test]
    fn disjoint_transfers_commit_in_one_wave() {
        let mut state = InMemoryState::new();
        let mut txs = Vec::new();
        for i in 0..16u8 {
            let key = generate_signing_key();
            let addr = Address::from_public_key(&key.verifying_key());
            fund(&mut state, addr, 1_000_000);
            txs.push(signed_transfer(&key, Address::from_bytes([i; 20]), 100, 0));
        }
        let idx: Vec<usize> = (0..txs.len()).collect();
        let mut frozen = DeltaSet::new();
        frozen.freeze();

        let outcome = run_payment_lane(&state, &frozen, &txs, &idx, &ctx(), WireMode::BinaryV2)
            .expect("lane");
        assert_eq!(outcome.waves, 1, "disjoint traffic must not re-execute");
        assert!(outcome
            .receipts
            .iter()
            .all(|(_, r)| r.status == TxStatus::Success));
        assert_eq!(outcome.fees, 16 * 10_000);
    }

    #[test]
    fn dependent_chain_converges_to_serial_result() {
        // A pays B, then B pays C using money that only exists if A→B
        // landed first: a read-write chain across the whole lane. Blind
        // wave 1 executes B→C against the baseline (insufficient funds),
        // so validation must force re-execution until the chain settles
        // serially-equivalent.
        let mut state = InMemoryState::new();
        let a = generate_signing_key();
        let b = generate_signing_key();
        let c = generate_signing_key();
        let a_addr = Address::from_public_key(&a.verifying_key());
        let b_addr = Address::from_public_key(&b.verifying_key());
        let c_addr = Address::from_public_key(&c.verifying_key());
        fund(&mut state, a_addr, 1_000_000);
        fund(&mut state, b_addr, 20_000); // just fees; needs A's credit to pay C

        let txs = vec![
            signed_transfer(&a, b_addr, 500_000, 0),
            signed_transfer(&b, c_addr, 400_000, 0),
        ];
        let idx = vec![0usize, 1];
        let mut frozen = DeltaSet::new();
        frozen.freeze();

        let outcome = run_payment_lane(&state, &frozen, &txs, &idx, &ctx(), WireMode::BinaryV2)
            .expect("lane");
        assert!(
            outcome.waves >= 2,
            "the dependency must trigger re-execution"
        );
        assert!(
            outcome
                .receipts
                .iter()
                .all(|(_, r)| r.status == TxStatus::Success),
            "serial-equivalent order lets both succeed: {:?}",
            outcome.receipts
        );

        let c_account = Account::from_bytes(
            outcome
                .writes
                .get(&StateKey::account(&c_addr))
                .expect("c written"),
        )
        .expect("decode");
        assert_eq!(c_account.balance, 400_000);
    }

    #[test]
    fn payment_lane_reads_frozen_identity_delta() {
        // The identity lane debited the sender's fee and bumped its nonce
        // before freezing; the payment lane must see that state.
        let mut state = InMemoryState::new();
        let a = generate_signing_key();
        let a_addr = Address::from_public_key(&a.verifying_key());
        fund(&mut state, a_addr, 1_000_000);

        // Simulate an identity-lane write: nonce already at 3.
        let mut frozen = DeltaSet::new();
        let mut acct = Account::with_balance(a_addr, 500_000, AccountType::Regular);
        acct.nonce = 3;
        frozen
            .insert(StateKey::account(&a_addr), acct.to_bytes())
            .expect("seed");
        frozen.freeze();

        let good = signed_transfer(&a, Address::from_bytes([9; 20]), 100, 3);
        let stale = signed_transfer(&a, Address::from_bytes([9; 20]), 100, 0);

        let outcome = run_payment_lane(
            &state,
            &frozen,
            &[good, stale],
            &[0, 1],
            &ctx(),
            WireMode::BinaryV2,
        )
        .expect("lane");
        assert_eq!(outcome.receipts[0].1.status, TxStatus::Success);
        assert!(
            matches!(&outcome.receipts[1].1.status, TxStatus::Failed(r) if r.contains("invalid nonce"))
        );
    }
}
