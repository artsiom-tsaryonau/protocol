//! Changes on Solidus that every destination must hear, queued in the same block.

use solidus_bridge_codec::{issuer_did_hash, BridgeMessage, ExportStatus, IssuerStatusBody};
use solidus_txns::bridge::{EXPORT_STATUS_ACTIVE, EXPORT_STATUS_REVOKED};
use solidus_txns::credential::{CredentialRecord, CredentialType};
use solidus_txns::types::Event;

use super::export::status_body;
use super::queue::queue_message;
use super::store::{load_domains_index, load_exports, save_exports, set_flag};
use crate::error::ExecError;
use crate::types::{BlockCtx, StateKey};
use crate::view::TxView;

/// After `record` was revoked: every ACTIVE export gets a Revoked status. Unbound
/// exports are already dead on their destination and get nothing.
pub(crate) fn on_revoked<V: TxView>(
    view: &mut V,
    ctx: &BlockCtx<'_>,
    record: &CredentialRecord,
) -> Result<Vec<Event>, ExecError> {
    let mut events = Vec::new();
    let mut set = load_exports(view, &record.id)?;
    let mut changed = false;
    for i in 0..set.entries.len() {
        if set.entries[i].status != EXPORT_STATUS_ACTIVE {
            continue;
        }
        set.entries[i].status = EXPORT_STATUS_REVOKED;
        changed = true;
        let e = set.entries[i].clone();
        let body = status_body(
            view,
            record,
            e.export_id,
            e.holder,
            ExportStatus::Revoked,
            e.valid_until,
        )?;
        events.push(queue_message(view, e.domain, ctx.height, |seq| {
            BridgeMessage::credential_status(seq, ctx.height, body)
        })?);
    }
    if changed {
        save_exports(view, &record.id, &set)?;
    }
    if record.credential_type == CredentialType::AccreditedIssuer {
        set_flag(
            view,
            StateKey::bridge_accredited(&record.subject_did),
            false,
        )?;
        events.extend(issuer_status_everywhere(
            view,
            ctx,
            &record.subject_did,
            false,
        )?);
    }
    Ok(events)
}

pub(crate) fn on_accredited<V: TxView>(
    view: &mut V,
    ctx: &BlockCtx<'_>,
    subject_did: &str,
) -> Result<Vec<Event>, ExecError> {
    set_flag(view, StateKey::bridge_accredited(subject_did), true)?;
    issuer_status_everywhere(view, ctx, subject_did, true)
}

/// Every REGISTERED domain, enabled or not: a domain re-enabled later must not
/// hold a stale accreditation.
fn issuer_status_everywhere<V: TxView>(
    view: &mut V,
    ctx: &BlockCtx<'_>,
    issuer_did: &str,
    accredited: bool,
) -> Result<Vec<Event>, ExecError> {
    let body = IssuerStatusBody {
        issuer_did_hash: issuer_did_hash(issuer_did),
        accredited,
    };
    let mut events = Vec::new();
    for domain in load_domains_index(view)? {
        events.push(queue_message(view, domain, ctx.height, |seq| {
            BridgeMessage::issuer_status(seq, ctx.height, body)
        })?);
    }
    Ok(events)
}
