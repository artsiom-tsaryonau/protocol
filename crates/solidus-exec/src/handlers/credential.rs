//! Credential payloads — `CredentialIssue` / `CredentialIssueBbs` /
//! `CredentialRevoke` (ported verbatim, including both secondary-index
//! appends on issue).

use solidus_crypto::keys::Address;
use solidus_txns::credential::{
    execute_credential_issue, execute_credential_issue_bbs, execute_credential_issue_v2,
    execute_credential_revoke, subject_commitment_index_key, CredentialType,
};
use solidus_txns::types::{Event, Receipt, TxStatus};

use super::{
    append_credential_index, failed_receipt, load_credential, load_did, save_account,
    save_credential,
};
use crate::account::Account;
use crate::error::ExecError;
use crate::types::{BlockCtx, StateKey};
use crate::view::TxView;

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_credential_issue<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    subject_did: &str,
    credential_type: CredentialType,
    hash: [u8; 32],
) -> Result<Receipt, ExecError> {
    let issuer_did = solidus_txns::did::build_did(ctx.network, &sender_addr);
    if credential_type == CredentialType::AccreditedIssuer {
        if ctx.protocol_version() < crate::protocol::ProtocolVersion::V2 {
            save_account(view, &sender)?;
            return Ok(failed_receipt(
                tx_hash,
                ctx.height,
                fee,
                "AccreditedIssuer is not active at this height".to_string(),
            ));
        }
        if !crate::bridge::store::flag(view, &StateKey::bridge_trust_root(&issuer_did))? {
            save_account(view, &sender)?;
            return Ok(failed_receipt(
                tx_hash,
                ctx.height,
                fee,
                "issuer is not a bridge trust root".to_string(),
            ));
        }
    }

    let issuer_doc = load_did(view, &issuer_did)?;
    let subject_doc = load_did(view, subject_did)?;

    let issuer_active = issuer_doc.as_ref().map(|d| d.active).unwrap_or(false);
    let subject_active = subject_doc.as_ref().map(|d| d.active).unwrap_or(false);

    match execute_credential_issue(
        &issuer_did,
        subject_did,
        credential_type,
        hash,
        issuer_active,
        subject_active,
        ctx.height,
        ctx.timestamp_ms,
    ) {
        Ok(cred) => {
            let credential_id = cred.id.clone();
            let issuer_did_clone = cred.issuer_did.clone();
            let subject_did_clone = cred.subject_did.clone();

            save_credential(view, &cred)?;
            append_credential_index(
                view,
                StateKey::cred_by_subject(&subject_did_clone),
                &credential_id,
            )?;
            append_credential_index(
                view,
                StateKey::cred_by_issuer(&issuer_did_clone),
                &credential_id,
            )?;
            save_account(view, &sender)?;

            let mut events = vec![Event::CredentialIssued {
                credential_id,
                issuer: issuer_did_clone,
                subject: subject_did_clone.clone(),
            }];
            if credential_type == CredentialType::AccreditedIssuer {
                events.extend(crate::bridge::fanout::on_accredited(
                    view,
                    ctx,
                    &subject_did_clone,
                )?);
            }
            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events,
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}

/// `CredentialIssueV2` (Rebuild #2 BD-6b): issue without publishing the subject.
///
/// Three differences from [`handle_credential_issue`], each deliberate:
///
/// 1. **No `load_did` on the subject.** The chain has a commitment, not a DID, so there
///    is nothing to resolve and the `SubjectDidInvalid` check is gone by founder
///    decision. The ISSUER check is unchanged.
/// 2. **The subject index is keyed by the COMMITMENT**, not retired. A holder who knows
///    their own nonces can still find their own credentials; an observer cannot
///    enumerate, because reproducing the key needs the nonce. Retiring it would have
///    thrown away a legitimate first-party lookup to stop an attacker who is already
///    stopped by the entropy.
/// 3. **`Event::CredentialIssuedV2`**, which carries the commitment. Emitting the v1
///    event here would republish a subject the payload deliberately withheld, which is
///    the surface the 08-20 measurement found the original plan had missed entirely.
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_credential_issue_v2<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    subject_commitment: [u8; 32],
    credential_type: CredentialType,
    hash: [u8; 32],
) -> Result<Receipt, ExecError> {
    if credential_type == CredentialType::AccreditedIssuer {
        save_account(view, &sender)?;
        return Ok(failed_receipt(
            tx_hash,
            ctx.height,
            fee,
            "AccreditedIssuer must name its subject: use CredentialIssue".to_string(),
        ));
    }
    let issuer_did = solidus_txns::did::build_did(ctx.network, &sender_addr);
    let issuer_active = load_did(view, &issuer_did)?
        .as_ref()
        .map(|d| d.active)
        .unwrap_or(false);

    match execute_credential_issue_v2(
        &issuer_did,
        subject_commitment,
        credential_type,
        hash,
        issuer_active,
        ctx.height,
        ctx.timestamp_ms,
    ) {
        Ok(cred) => {
            let credential_id = cred.id.clone();
            let issuer_did_clone = cred.issuer_did.clone();

            save_credential(view, &cred)?;
            append_credential_index(
                view,
                StateKey::cred_by_subject(&subject_commitment_index_key(&subject_commitment)),
                &credential_id,
            )?;
            append_credential_index(
                view,
                StateKey::cred_by_issuer(&issuer_did_clone),
                &credential_id,
            )?;
            save_account(view, &sender)?;

            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: vec![Event::CredentialIssuedV2 {
                    credential_id,
                    issuer: issuer_did_clone,
                    subject_commitment,
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
pub(super) fn handle_credential_issue_bbs<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    subject_did: &str,
    credential_type: CredentialType,
    hash: [u8; 32],
    bbs_pubkey: [u8; 96],
    bbs_message_count: u32,
) -> Result<Receipt, ExecError> {
    if credential_type == CredentialType::AccreditedIssuer {
        save_account(view, &sender)?;
        return Ok(failed_receipt(
            tx_hash,
            ctx.height,
            fee,
            "AccreditedIssuer must name its subject: use CredentialIssue".to_string(),
        ));
    }
    let issuer_did = solidus_txns::did::build_did(ctx.network, &sender_addr);

    let issuer_doc = load_did(view, &issuer_did)?;
    let subject_doc = load_did(view, subject_did)?;

    let issuer_active = issuer_doc.as_ref().map(|d| d.active).unwrap_or(false);
    let subject_active = subject_doc.as_ref().map(|d| d.active).unwrap_or(false);

    match execute_credential_issue_bbs(
        &issuer_did,
        subject_did,
        credential_type,
        hash,
        bbs_pubkey,
        bbs_message_count,
        issuer_active,
        subject_active,
        ctx.height,
        ctx.timestamp_ms,
    ) {
        Ok(cred) => {
            let credential_id = cred.id.clone();
            let issuer_did_clone = cred.issuer_did.clone();
            let subject_did_clone = cred.subject_did.clone();

            save_credential(view, &cred)?;
            append_credential_index(
                view,
                StateKey::cred_by_subject(&subject_did_clone),
                &credential_id,
            )?;
            append_credential_index(
                view,
                StateKey::cred_by_issuer(&issuer_did_clone),
                &credential_id,
            )?;
            save_account(view, &sender)?;

            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: vec![Event::CredentialIssued {
                    credential_id,
                    issuer: issuer_did_clone,
                    subject: subject_did_clone,
                }],
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}

pub(super) fn handle_credential_revoke<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    credential_id: &str,
) -> Result<Receipt, ExecError> {
    let sender_did = solidus_txns::did::build_did(ctx.network, &sender_addr);

    let existing = load_credential(view, credential_id)?;

    match execute_credential_revoke(&sender_did, existing.as_ref(), ctx.timestamp_ms) {
        Ok(revoked_cred) => {
            let cred_id = revoked_cred.id.clone();
            save_credential(view, &revoked_cred)?;
            let mut events = vec![Event::CredentialRevoked {
                credential_id: cred_id,
            }];
            if ctx.protocol_version() >= crate::protocol::ProtocolVersion::V2 {
                events.extend(crate::bridge::fanout::on_revoked(view, ctx, &revoked_cred)?);
            }
            save_account(view, &sender)?;
            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events,
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}
