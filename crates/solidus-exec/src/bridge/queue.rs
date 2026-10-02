//! The per-domain outbox. A message's `domain_seq` is its queue position, so a
//! destination that applies messages strictly in sequence can detect any gap.

use solidus_bridge_codec::{encode, keccak256, BridgeMessage};
use solidus_txns::bridge::OutboxEntry;
use solidus_txns::types::Event;

use super::store::{self, read_u64, write_u64};
use crate::error::ExecError;
use crate::types::StateKey;
use crate::view::TxView;

pub(crate) fn queue_message<V: TxView>(
    view: &mut V,
    domain: u32,
    solidus_height: u64,
    build: impl FnOnce(u64) -> BridgeMessage,
) -> Result<Event, ExecError> {
    let seq = read_u64(view, &StateKey::bridge_seq(domain))?
        .checked_add(1)
        .ok_or_else(|| ExecError::StateDecode("bridge sequence exhausted".into()))?;
    let message = build(seq);
    let bytes = encode(&message);
    let message_id = keccak256(&bytes);
    let kind = message.header().kind as u8;
    view.write(
        StateKey::bridge_outbox(domain, seq),
        store::encode(&OutboxEntry {
            solidus_height,
            message: bytes,
        }),
    )?;
    write_u64(view, StateKey::bridge_seq(domain), seq)?;
    Ok(Event::BridgeMessageQueued {
        domain,
        domain_seq: seq,
        kind,
        message_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::{DeltaSet, InMemoryState};
    use crate::fee::FeeAccumulator;
    use crate::view::SerialView;
    use solidus_bridge_codec::{decode, keccak256, BridgeMessage, HeartbeatBody};
    use solidus_txns::bridge::OutboxEntry;

    #[test]
    fn sequences_start_at_one_increase_by_one_and_are_per_domain() {
        let base = InMemoryState::new();
        let mut delta = DeltaSet::new();
        let mut fees = FeeAccumulator::new();
        let mut view = SerialView::new(&mut delta, &base, &mut fees);
        let hb = |seq| {
            BridgeMessage::heartbeat(
                seq,
                10,
                HeartbeatBody {
                    solidus_timestamp: 5,
                    global_root: [1; 32],
                },
            )
        };

        let e1 = queue_message(&mut view, 7, 10, hb).unwrap();
        let e2 = queue_message(&mut view, 7, 10, hb).unwrap();
        let e3 = queue_message(&mut view, 8, 10, hb).unwrap();
        assert!(matches!(
            e1,
            Event::BridgeMessageQueued {
                domain: 7,
                domain_seq: 1,
                kind: 3,
                ..
            }
        ));
        assert!(matches!(
            e2,
            Event::BridgeMessageQueued {
                domain: 7,
                domain_seq: 2,
                ..
            }
        ));
        assert!(matches!(
            e3,
            Event::BridgeMessageQueued {
                domain: 8,
                domain_seq: 1,
                ..
            }
        ));

        let raw = view
            .read(&StateKey::bridge_outbox(7, 2))
            .unwrap()
            .expect("entry stored");
        let entry: OutboxEntry = bincode::deserialize(&raw).unwrap();
        assert_eq!(entry.solidus_height, 10);
        assert_eq!(
            decode(&entry.message).unwrap().header().domain_seq,
            2,
            "the header carries the queue sequence"
        );
        let Event::BridgeMessageQueued { message_id, .. } = e2 else {
            unreachable!()
        };
        assert_eq!(message_id, keccak256(&entry.message));
    }
}
