//! The 10 payload handlers, ported 1:1 from the live chain's
//! `executor.rs` with every store call re-pointed at [`TxView`]. Failure
//! strings, fee/nonce behaviors, event contents, and write orders are
//! preserved **verbatim** — the Stage-0 differential anchor
//! (`tests/legacy_parity.rs`) holds this port to byte-identical receipts
//! and state roots against the live executor.

mod credential;
mod did;
mod staking;
mod transfer;

use solidus_crypto::keys::Address;
use solidus_txns::credential::CredentialRecord;
use solidus_txns::did::DidDocument;
use solidus_txns::staking::ValidatorInfo;
use solidus_txns::types::{Receipt, Transaction, TxPayload, TxStatus};

use crate::account::Account;
use crate::error::ExecError;
use crate::types::{BlockCtx, StateKey, WireMode};
use crate::view::TxView;
use crate::wire;

// ---------------------------------------------------------------------------
// Typed state IO over TxView (ports of the live load_*/save_* helpers)
// ---------------------------------------------------------------------------

pub(crate) fn load_account<V: TxView>(view: &mut V, addr: &Address) -> Result<Account, ExecError> {
    match view.read(&StateKey::account(addr))? {
        Some(bytes) => {
            Account::from_bytes(&bytes).map_err(|e| ExecError::StateDecode(e.to_string()))
        }
        None => Ok(Account::new(*addr)),
    }
}

pub(crate) fn save_account<V: TxView>(view: &mut V, account: &Account) -> Result<(), ExecError> {
    view.write(StateKey::account(&account.address), account.to_bytes())
}

pub(crate) fn load_did<V: TxView>(
    view: &mut V,
    did: &str,
) -> Result<Option<DidDocument>, ExecError> {
    match view.read(&StateKey::did(did))? {
        Some(bytes) => Ok(Some(
            DidDocument::from_bytes(&bytes).map_err(|e| ExecError::StateDecode(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

pub(crate) fn save_did<V: TxView>(
    view: &mut V,
    did: &str,
    doc: &DidDocument,
) -> Result<(), ExecError> {
    view.write(StateKey::did(did), doc.to_bytes())
}

/// True if `addr` is a registered DID-anchor (document exists — active OR
/// deactivated). Anchors are forbidden from holding or moving value.
pub(crate) fn is_did_anchor<V: TxView>(
    view: &mut V,
    network: &str,
    addr: &Address,
) -> Result<bool, ExecError> {
    let did = solidus_txns::did::build_did(network, addr);
    Ok(load_did(view, &did)?.is_some())
}

pub(crate) fn load_credential<V: TxView>(
    view: &mut V,
    credential_id: &str,
) -> Result<Option<CredentialRecord>, ExecError> {
    match view.read(&StateKey::credential(credential_id))? {
        Some(bytes) => Ok(Some(
            CredentialRecord::from_bytes(&bytes)
                .map_err(|e| ExecError::StateDecode(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

pub(crate) fn save_credential<V: TxView>(
    view: &mut V,
    cred: &CredentialRecord,
) -> Result<(), ExecError> {
    view.write(StateKey::credential(&cred.id), cred.to_bytes())
}

/// Load a credential-id list from a secondary index (serde_json `Vec<String>`
/// — same encoding as the live chain; not root-bearing).
pub(crate) fn load_credential_ids<V: TxView>(
    view: &mut V,
    index_key: &StateKey,
) -> Result<Vec<String>, ExecError> {
    match view.read(index_key)? {
        Some(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| ExecError::StateDecode(e.to_string()))
        }
        None => Ok(vec![]),
    }
}

pub(crate) fn append_credential_index<V: TxView>(
    view: &mut V,
    index_key: StateKey,
    credential_id: &str,
) -> Result<(), ExecError> {
    let mut ids = load_credential_ids(view, &index_key)?;
    ids.push(credential_id.to_string());
    let bytes = serde_json::to_vec(&ids).map_err(|e| ExecError::StateDecode(e.to_string()))?;
    view.write(index_key, bytes)
}

pub(crate) fn load_validator<V: TxView>(
    view: &mut V,
    addr: &Address,
) -> Result<Option<ValidatorInfo>, ExecError> {
    match view.read(&StateKey::validator(addr))? {
        Some(bytes) => Ok(Some(
            ValidatorInfo::from_bytes(&bytes).map_err(|e| ExecError::StateDecode(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

pub(crate) fn save_validator<V: TxView>(
    view: &mut V,
    info: &ValidatorInfo,
) -> Result<(), ExecError> {
    view.write(StateKey::validator(&info.address), info.to_bytes())
}

// ---------------------------------------------------------------------------
// Receipt helpers
// ---------------------------------------------------------------------------

pub(crate) fn failed_receipt(
    tx_hash: [u8; 32],
    block_height: u64,
    fee_paid: u64,
    reason: String,
) -> Receipt {
    Receipt {
        tx_hash,
        status: TxStatus::Failed(reason),
        block_height,
        fee_paid,
        events: vec![],
    }
}

// ---------------------------------------------------------------------------
// Fee exemption (ported verbatim)
// ---------------------------------------------------------------------------

/// DID and issuer-credential operations are fee-exempt: their signer is a
/// DID-anchor (or, for `DidCreate`, a fresh identity key becoming one),
/// and anchors are value-free by construction.
pub(crate) fn is_fee_exempt(payload: &TxPayload) -> bool {
    matches!(
        payload,
        TxPayload::DidCreate { .. }
            | TxPayload::DidUpdate { .. }
            | TxPayload::DidDeactivate { .. }
            | TxPayload::DidRecover { .. }
            | TxPayload::CredentialIssue { .. }
            | TxPayload::CredentialIssueBbs { .. }
            | TxPayload::CredentialRevoke { .. }
    )
}

// ---------------------------------------------------------------------------
// The per-transaction pipeline (ported steps 1–6 + dispatch)
// ---------------------------------------------------------------------------

/// Execute one transaction against the view, producing its receipt.
///
/// Mirrors the live per-tx pipeline exactly:
/// 1. verify signature (under `wire`) — fail: receipt, fee 0, no state write
/// 2. load sender
/// 3. nonce check — fail: receipt, fee 0, no state write
/// 4. fee = 0 if exempt else scheduled fee
/// 5. balance-covers-fee check — fail: receipt, fee 0, no state write
/// 6. debit fee, bump nonce, charge accumulator, dispatch to the payload arm
///
/// Every post-step-6 path — success or handler failure — persists the
/// sender (nonce bump included) and reports `fee_paid = fee`.
///
/// The live receipt-idempotency short-circuit is intentionally absent
/// (see crate docs): v2 executes a committed block exactly once per store.
pub fn run_tx<V: TxView>(
    view: &mut V,
    tx: &Transaction,
    ctx: &BlockCtx<'_>,
    wire_mode: WireMode,
) -> Result<Receipt, ExecError> {
    let tx_hash = wire::tx_hash(tx, wire_mode);

    // 1. Signature (must precede sender_address(), which requires a valid key).
    if !wire::verify_signature(tx, wire_mode) {
        return Ok(failed_receipt(
            tx_hash,
            ctx.height,
            0,
            "invalid signature".to_string(),
        ));
    }

    let sender_addr = tx.sender_address();

    // 2. Load sender.
    let mut sender = load_account(view, &sender_addr)?;

    // 3. Nonce.
    if sender.nonce != tx.nonce {
        return Ok(failed_receipt(
            tx_hash,
            ctx.height,
            0,
            format!("invalid nonce: expected {}, got {}", sender.nonce, tx.nonce),
        ));
    }

    // 4. Fee schedule (exemptions preserved verbatim).
    let fee = if is_fee_exempt(&tx.payload) {
        0
    } else {
        tx.payload.fee()
    };

    // 5. Balance covers fee.
    if sender.balance < fee {
        return Ok(failed_receipt(
            tx_hash,
            ctx.height,
            0,
            format!(
                "insufficient balance for fee: have {}, need {}",
                sender.balance, fee
            ),
        ));
    }

    // 6. Debit fee, bump nonce, charge the block accumulator once.
    //    (The live code adds `total_fees += fee` in every dispatch path;
    //    charging here once is the same total.)
    sender.balance -= fee;
    sender.nonce += 1;
    view.charge_fee(fee);

    // Dispatch.
    match &tx.payload {
        TxPayload::Transfer { to, amount } => {
            transfer::handle_transfer(view, sender, sender_addr, ctx, tx_hash, fee, *to, *amount)
        }
        TxPayload::DidCreate {
            public_key,
            service_endpoints,
        } => did::handle_did_create(
            view,
            sender,
            sender_addr,
            ctx,
            tx_hash,
            fee,
            tx.nonce,
            public_key,
            service_endpoints,
        ),
        TxPayload::DidUpdate { did, patches } => {
            did::handle_did_update(view, sender, sender_addr, ctx, tx_hash, fee, did, patches)
        }
        TxPayload::DidDeactivate { did } => {
            did::handle_did_deactivate(view, sender, sender_addr, ctx, tx_hash, fee, did)
        }
        TxPayload::DidRecover {
            did,
            new_public_key,
            approvals,
        } => did::handle_did_recover(
            view,
            sender,
            sender_addr,
            ctx,
            tx_hash,
            fee,
            &tx.sender_pubkey,
            did,
            new_public_key,
            approvals,
        ),
        TxPayload::CredentialIssue {
            subject_did,
            credential_type,
            hash,
        } => credential::handle_credential_issue(
            view,
            sender,
            sender_addr,
            ctx,
            tx_hash,
            fee,
            subject_did,
            *credential_type,
            *hash,
        ),
        TxPayload::CredentialIssueBbs {
            subject_did,
            credential_type,
            hash,
            bbs_pubkey,
            bbs_message_count,
        } => credential::handle_credential_issue_bbs(
            view,
            sender,
            sender_addr,
            ctx,
            tx_hash,
            fee,
            subject_did,
            *credential_type,
            *hash,
            *bbs_pubkey,
            *bbs_message_count,
        ),
        TxPayload::CredentialRevoke { credential_id } => credential::handle_credential_revoke(
            view,
            sender,
            sender_addr,
            ctx,
            tx_hash,
            fee,
            credential_id,
        ),
        TxPayload::Stake { amount } => {
            staking::handle_stake(view, sender, sender_addr, ctx, tx_hash, fee, *amount)
        }
        TxPayload::Unstake { amount } => {
            staking::handle_unstake(view, sender, sender_addr, ctx, tx_hash, fee, *amount)
        }
        // Compute-module transactions (rebuild #5) exist on the legacy chain
        // only; the v2 executor rejects them with a normal failed receipt —
        // fee already debited, nonce already bumped (step 6 above), exactly
        // like any other in-handler failure. Grouped EXPLICITLY (no `_`
        // wildcard) so the next new TxPayload variant is a compile error
        // here, not a silent fall-through. Never panic in dispatch: a
        // `todo!()` would be a consensus-crash DoS one signed tx away.
        TxPayload::ComputeAdmit { .. }
        | TxPayload::ComputeRemove { .. }
        | TxPayload::ComputeRegister { .. }
        | TxPayload::ComputeAnchor { .. }
        | TxPayload::ComputeSlash { .. } => {
            save_account(view, &sender)?;
            Ok(failed_receipt(
                tx_hash,
                ctx.height,
                fee,
                "compute-module transactions are not supported on this network".to_string(),
            ))
        }
    }
}
