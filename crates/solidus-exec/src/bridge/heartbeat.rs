//! Liveness (spec §5.2 step 4). A destination gate treats a stale heartbeat as
//! "Solidus unreachable" and rejects, so silence fails safe.

use solidus_bridge_codec::{BridgeMessage, HeartbeatBody};
use solidus_txns::types::Event;

use super::queue::queue_message;
use super::store::{load_domain, load_domains_index, read_u64, write_u64};
use crate::error::ExecError;
use crate::types::{BlockCtx, StateKey};
use crate::view::TxView;

/// Deterministic end-of-block step. Reads only block data and state.
pub(crate) fn on_block_end<V: TxView>(
    view: &mut V,
    ctx: &BlockCtx<'_>,
) -> Result<Vec<Event>, ExecError> {
    let now = ctx.timestamp_ms / 1000;
    let mut events = Vec::new();
    for domain_id in load_domains_index(view)? {
        let Some(domain) = load_domain(view, domain_id)? else {
            continue;
        };
        if !domain.enabled {
            continue;
        }
        let key = StateKey::bridge_heartbeat(domain_id);
        let last = read_u64(view, &key)?;
        if last != 0 && now < last.saturating_add(domain.heartbeat_interval_secs) {
            continue;
        }
        let body = HeartbeatBody {
            solidus_timestamp: now,
            global_root: ctx.parent_state_root,
        };
        events.push(queue_message(view, domain_id, ctx.height, |seq| {
            BridgeMessage::heartbeat(seq, ctx.height, body)
        })?);
        write_u64(view, key, now)?;
    }
    Ok(events)
}
