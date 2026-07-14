//! DID payloads — `DidCreate` / `DidUpdate` / `DidDeactivate` /
//! `DidRecover` (ported verbatim from the live executor's arms, including
//! the pristine-anchor rule and the recover-key equality check).

use std::cell::RefCell;

use solidus_crypto::keys::Address;
use solidus_txns::did::{
    execute_did_create, execute_did_deactivate, execute_did_recover, execute_did_update,
    DidDocument, DidPatch, GuardianApproval, Service,
};
use solidus_txns::types::{Event, Receipt, TxStatus};

use super::{failed_receipt, load_did, save_account, save_did};
use crate::account::Account;
use crate::error::ExecError;
use crate::types::BlockCtx;
use crate::view::TxView;

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_did_create<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    tx_nonce: u64,
    public_key: &[u8; 32],
    service_endpoints: &[Service],
) -> Result<Receipt, ExecError> {
    // Pristine-anchor requirement: a DID may only be created on a fresh
    // identity key with no value history. `tx_nonce == 0` means first tx;
    // `sender.balance == 0` (DidCreate is fee-exempt, balance unchanged)
    // means it never received value.
    if tx_nonce != 0 || sender.balance != 0 {
        save_account(view, &sender)?;
        return Ok(failed_receipt(
            tx_hash,
            ctx.height,
            fee,
            "DidCreate requires a pristine identity key (zero balance, first transaction)"
                .to_string(),
        ));
    }

    let did_str = solidus_txns::did::build_did(ctx.network, &sender_addr);
    let existing = load_did(view, &did_str)?;

    match execute_did_create(
        &sender_addr,
        public_key,
        service_endpoints.to_vec(),
        existing.as_ref(),
        ctx.timestamp_ms,
        ctx.network,
    ) {
        Ok(result) => {
            save_did(view, &result.did, &result.document)?;
            save_account(view, &sender)?;
            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: vec![Event::DidCreated {
                    did: result.did,
                    controller: sender_addr,
                }],
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_did_update<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    did: &str,
    patches: &[DidPatch],
) -> Result<Receipt, ExecError> {
    let existing = load_did(view, did)?;

    // SetController validation resolves candidate-controller documents
    // through the same block-visible state. The live code reads its store
    // directly inside a closure and surfaces I/O errors as `None`; the
    // RefCell gives the Fn closure interior access to the &mut view in
    // this strictly serial, non-reentrant lane — same visibility, same
    // error-swallowing contract.
    let view_cell = RefCell::new(view);
    let lookup = |did_str: &str| -> Option<DidDocument> {
        load_did(&mut **view_cell.borrow_mut(), did_str)
            .ok()
            .flatten()
    };

    let outcome = execute_did_update(
        &sender_addr,
        did,
        patches,
        existing.as_ref(),
        lookup,
        ctx.timestamp_ms,
        ctx.network,
    );
    let view = view_cell.into_inner();

    match outcome {
        Ok(updated_doc) => {
            save_did(view, did, &updated_doc)?;
            save_account(view, &sender)?;
            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: vec![Event::DidUpdated {
                    did: did.to_string(),
                }],
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}

pub(super) fn handle_did_deactivate<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    did: &str,
) -> Result<Receipt, ExecError> {
    let existing = load_did(view, did)?;

    match execute_did_deactivate(
        &sender_addr,
        did,
        existing.as_ref(),
        ctx.timestamp_ms,
        ctx.network,
    ) {
        Ok(deactivated_doc) => {
            save_did(view, did, &deactivated_doc)?;
            save_account(view, &sender)?;
            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: vec![Event::DidDeactivated {
                    did: did.to_string(),
                }],
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_did_recover<V: TxView>(
    view: &mut V,
    sender: Account,
    _sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    sender_pubkey: &[u8; 32],
    did: &str,
    new_public_key: &[u8; 32],
    approvals: &[GuardianApproval],
) -> Result<Receipt, ExecError> {
    // The envelope must be signed by the key being installed.
    if sender_pubkey != new_public_key {
        save_account(view, &sender)?;
        return Ok(failed_receipt(
            tx_hash,
            ctx.height,
            fee,
            "recovery sender must equal new_public_key".to_string(),
        ));
    }

    let existing = load_did(view, did)?;

    // Guardian resolution reads block-visible state; same RefCell pattern
    // (and the same swallow-to-None error contract) as handle_did_update.
    let view_cell = RefCell::new(view);
    let resolve = |guardian_did: &str| -> Option<DidDocument> {
        load_did(&mut **view_cell.borrow_mut(), guardian_did)
            .ok()
            .flatten()
    };

    let outcome = execute_did_recover(
        did,
        existing.as_ref(),
        new_public_key,
        approvals,
        resolve,
        ctx.network,
        ctx.timestamp_ms,
    );
    let view = view_cell.into_inner();

    match outcome {
        Ok(updated_doc) => {
            save_did(view, did, &updated_doc)?;
            save_account(view, &sender)?;
            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: vec![Event::DidRecovered {
                    did: did.to_string(),
                }],
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}
