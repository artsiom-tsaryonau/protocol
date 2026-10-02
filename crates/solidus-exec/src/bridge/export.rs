//! Export and unexport (spec §5.1 step 4, §5.2 step 2).

use solidus_bridge_codec::{
    credential_type_hash, export_id, issuer_did_hash, BridgeMessage, CredentialStatusBody,
    ExportConsent, ExportStatus,
};
use solidus_crypto::keys::Address;
use solidus_txns::bridge::{ExportEntry, EXPORT_STATUS_ACTIVE, EXPORT_STATUS_UNBOUND};
use solidus_txns::credential::CredentialRecord;
use solidus_txns::types::{Event, Receipt, TxStatus};

use super::consent::verify_consent;
use super::fail;
use super::queue::queue_message;
use super::store::{flag, load_domain, load_exports, save_exports};
use crate::account::Account;
use crate::error::ExecError;
use crate::handlers::{load_credential, save_account};
use crate::types::{BlockCtx, StateKey};
use crate::view::TxView;

pub(crate) struct ExportArgs<'a> {
    pub credential_id: &'a str,
    pub domain: u32,
    pub holder: [u8; 32],
    pub valid_until: u64,
    pub consent_sig: &'a [u8],
    pub consent_expiry: u64,
}

/// The status body for one export of `record`. `issuer_accredited` is read at
/// queue time, so every message carries the accreditation as it is now.
pub(crate) fn status_body<V: TxView>(
    view: &mut V,
    record: &CredentialRecord,
    export_id: [u8; 32],
    holder: [u8; 32],
    status: ExportStatus,
    valid_until: u64,
) -> Result<CredentialStatusBody, ExecError> {
    let name = serde_json::to_value(record.credential_type)
        .map_err(|e| ExecError::StateDecode(e.to_string()))?;
    let name = name.as_str().ok_or_else(|| {
        ExecError::StateDecode("credential type did not serialise to a string".into())
    })?;
    Ok(CredentialStatusBody {
        export_id,
        issuer_did_hash: issuer_did_hash(&record.issuer_did),
        credential_type_hash: credential_type_hash(name),
        holder,
        status,
        valid_until,
        issuer_accredited: flag(view, &StateKey::bridge_accredited(&record.issuer_did))?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_export<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    a: ExportArgs<'_>,
) -> Result<Receipt, ExecError> {
    let now = ctx.timestamp_ms / 1000;
    let sender_did = solidus_txns::did::build_did(ctx.network, &sender_addr);
    let Some(record) = load_credential(view, a.credential_id)? else {
        return fail(view, &sender, ctx, tx_hash, fee, "unknown credential");
    };
    if record.issuer_did != sender_did {
        return fail(
            view,
            &sender,
            ctx,
            tx_hash,
            fee,
            "sender is not the credential's issuer",
        );
    }
    if record.revoked {
        return fail(view, &sender, ctx, tx_hash, fee, "credential is revoked");
    }
    let Some(domain) = load_domain(view, a.domain)?.filter(|d| d.enabled) else {
        return fail(
            view,
            &sender,
            ctx,
            tx_hash,
            fee,
            "unknown or disabled bridge domain",
        );
    };
    if a.consent_expiry <= now {
        return fail(view, &sender, ctx, tx_hash, fee, "consent has expired");
    }
    if a.valid_until != 0 && a.valid_until <= now {
        return fail(
            view,
            &sender,
            ctx,
            tx_hash,
            fee,
            "valid_until is in the past",
        );
    }
    let consent = ExportConsent {
        credential_id: a.credential_id.to_string(),
        domain: a.domain,
        holder: a.holder,
        consent_expiry: a.consent_expiry,
    };
    if let Err(reason) = verify_consent(&domain, &consent, a.consent_sig) {
        return fail(view, &sender, ctx, tx_hash, fee, reason);
    }

    let id = export_id(a.credential_id, a.domain, &a.holder);
    let mut set = load_exports(view, a.credential_id)?;
    match set
        .entries
        .iter_mut()
        .find(|e| e.domain == a.domain && e.holder == a.holder)
    {
        Some(e) if e.status != EXPORT_STATUS_UNBOUND => {
            return fail(
                view,
                &sender,
                ctx,
                tx_hash,
                fee,
                "credential is already exported to this holder on this domain",
            );
        }
        Some(e) => {
            e.status = EXPORT_STATUS_ACTIVE;
            e.valid_until = a.valid_until;
        }
        None => set.entries.push(ExportEntry {
            domain: a.domain,
            holder: a.holder,
            export_id: id,
            valid_until: a.valid_until,
            status: EXPORT_STATUS_ACTIVE,
        }),
    }
    save_exports(view, a.credential_id, &set)?;

    let body = status_body(
        view,
        &record,
        id,
        a.holder,
        ExportStatus::Active,
        a.valid_until,
    )?;
    let queued = queue_message(view, a.domain, ctx.height, |seq| {
        BridgeMessage::credential_status(seq, ctx.height, body)
    })?;
    save_account(view, &sender)?;
    Ok(Receipt {
        tx_hash,
        status: TxStatus::Success,
        block_height: ctx.height,
        fee_paid: fee,
        events: vec![
            Event::CredentialExported {
                credential_id: a.credential_id.to_string(),
                domain: a.domain,
                export_id: id,
            },
            queued,
        ],
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_unexport<V: TxView>(
    view: &mut V,
    sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    credential_id: &str,
    domain: u32,
    holder: [u8; 32],
) -> Result<Receipt, ExecError> {
    let sender_did = solidus_txns::did::build_did(ctx.network, &sender_addr);
    let Some(record) = load_credential(view, credential_id)? else {
        return fail(view, &sender, ctx, tx_hash, fee, "unknown credential");
    };
    if record.issuer_did != sender_did {
        return fail(
            view,
            &sender,
            ctx,
            tx_hash,
            fee,
            "sender is not the credential's issuer",
        );
    }
    let mut set = load_exports(view, credential_id)?;
    let Some(entry) = set
        .entries
        .iter_mut()
        .find(|e| e.domain == domain && e.holder == holder)
    else {
        return fail(view, &sender, ctx, tx_hash, fee, "no such export");
    };
    if entry.status != EXPORT_STATUS_ACTIVE {
        return fail(view, &sender, ctx, tx_hash, fee, "export is not active");
    }
    entry.status = EXPORT_STATUS_UNBOUND;
    let (id, valid_until) = (entry.export_id, entry.valid_until);
    save_exports(view, credential_id, &set)?;

    let body = status_body(
        view,
        &record,
        id,
        holder,
        ExportStatus::Unbound,
        valid_until,
    )?;
    let queued = queue_message(view, domain, ctx.height, |seq| {
        BridgeMessage::credential_status(seq, ctx.height, body)
    })?;
    save_account(view, &sender)?;
    Ok(Receipt {
        tx_hash,
        status: TxStatus::Success,
        block_height: ctx.height,
        fee_paid: fee,
        events: vec![
            Event::CredentialUnexported {
                credential_id: credential_id.to_string(),
                domain,
                export_id: id,
            },
            queued,
        ],
    })
}
