//! The two-lane block executor — the v2 production pipeline (§5.3):
//!
//! ```text
//! parallel Ed25519 pre-pass → lane partition (Hazard-A) →
//! identity/serial lane FIRST → freeze delta →
//! payment-lane wave-OCC (baseline = store + frozen delta) →
//! merge → one fee settlement → incremental root
//! ```
//!
//! Both lanes run the exact same payload handlers as the serial reference
//! oracle ([`crate::handlers::run_tx`]); the differential gate
//! (`tests/twolane_vs_oracle.rs`) holds this pipeline to byte-identical
//! receipts and state against `execute_block_reference` under
//! `LanePartitioned` order.

use rayon::prelude::*;
use solidus_txns::types::{Receipt, Transaction};

use crate::delta::{DeltaSet, StateReader};
use crate::error::ExecError;
use crate::fee::{self, FeeAccumulator};
use crate::handlers;
use crate::lane::partition_lanes;
use crate::payment::run_payment_lane;
use crate::reference::BlockOutcome;
use crate::types::{BlockCtx, ExecOptions, ExecOrder};
use crate::view::SerialView;
use crate::wire;

/// Execute a block through the two-lane pipeline.
///
/// `opts.order` must be [`ExecOrder::LanePartitioned`] — the two-lane
/// pipeline *is* the lane semantics; requesting `RawBlock` here is a
/// harness bug (the raw order exists only for the legacy anchor on the
/// serial oracle).
pub fn execute_block_twolane<R: StateReader + Sync + ?Sized>(
    baseline: &R,
    txs: &[Transaction],
    ctx: &BlockCtx<'_>,
    opts: &ExecOptions,
) -> Result<BlockOutcome, ExecError> {
    // ⛔ The wire is a function of HEIGHT, not of config: at a V2 height a
    // BinaryV2 base becomes BinaryV3 bound to this chain id.
    let wire = crate::wire::wire_for_height(opts.wire, opts.chain_id, ctx.height);
    if opts.order == ExecOrder::RawBlock {
        return Err(ExecError::StateRead(
            "two-lane executor only implements LanePartitioned order".to_string(),
        ));
    }

    // ---- 1. Parallel signature pre-pass (lane-agnostic, §5.3) ----------
    let valid: Vec<bool> = txs
        .par_iter()
        .map(|tx| wire::verify_signature(tx, wire))
        .collect();

    // ---- 2. Deterministic lane partition (Hazard-A) --------------------
    let plan = partition_lanes(txs, &valid);
    if plan.identity.len() > opts.identity_cap {
        return Err(ExecError::IdentityCapExceeded {
            count: plan.identity.len(),
            cap: opts.identity_cap,
        });
    }

    let mut delta = DeltaSet::new();
    let mut fees = FeeAccumulator::new();
    let mut receipts: Vec<Option<Receipt>> = (0..txs.len()).map(|_| None).collect();

    // ---- 3. Sig-invalid txs: receipts only, zero state effect ----------
    // Run through the shared per-tx pipeline for exact oracle parity (the
    // signature gate exits before any state access).
    for &i in &plan.invalid {
        let mut view = SerialView::new(&mut delta, baseline, &mut fees);
        receipts[i] = Some(handlers::run_tx(&mut view, &txs[i], ctx, wire)?);
    }

    // ---- 4. Identity / serial lane (FIRST — Hazard-B ordering) ---------
    for &i in &plan.identity {
        let mut view = SerialView::new(&mut delta, baseline, &mut fees);
        receipts[i] = Some(handlers::run_tx(&mut view, &txs[i], ctx, wire)?);
    }

    // ---- 4b. Bridge block-end step (V2). Serial and before the freeze: it
    //          writes only bridge keys, which the payment lane never touches.
    let mut block_events = Vec::new();
    if ctx.protocol_version() >= crate::protocol::ProtocolVersion::V2 {
        let mut view = SerialView::new(&mut delta, baseline, &mut fees);
        block_events = crate::bridge::on_block_end(&mut view, ctx)?;
    }

    // ---- 5. Freeze: the identity delta becomes the immutable payment
    //         baseline (Hazard-B rule) --------------------------------
    delta.freeze();

    // ---- 6. Payment lane: parallel wave-OCC over Transfer only ---------
    let payment = run_payment_lane(baseline, &delta, txs, &plan.payment, ctx, wire)?;
    for (i, receipt) in payment.receipts {
        receipts[i] = Some(receipt);
    }

    // ---- 7. Merge payment writes into the block delta ------------------
    delta.thaw();
    for (key, value) in payment.writes {
        delta.insert(key, value)?;
    }
    fees.charge(payment.fees);

    // ---- 8. One fee settlement (Hazard-C) -------------------------------
    fee::settle(&opts.fee_policy, &fees, &mut delta, baseline)?;

    let receipts = receipts
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            debug_assert!(r.is_some(), "lane plan must cover every tx index");
            r.unwrap_or_else(|| {
                handlers::failed_receipt(
                    wire::tx_hash(&txs[i], wire),
                    ctx.height,
                    0,
                    "internal: tx not covered by lane plan".to_string(),
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
