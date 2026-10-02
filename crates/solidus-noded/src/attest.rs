//! This validator's own view of the outbox, signed at commit.
//!
//! ⚠ EVERY VALIDATOR SIGNS INDEPENDENTLY AND NOBODY AGGREGATES HERE. A mirror wants m of n
//! signatures over one digest; this node produces exactly one of them and serves it. Assembly is
//! the gateway's job (Task 5), which is why nothing in this file knows the threshold.
//!
//! ⛔ THE SIGNATURE IS OVER THE EIP-191 ETH-SIGNED HASH, NOT THE BARE §3.2 DIGEST. Solidity's
//! `AttestationLib.verify` computes `ethSigned(d)` and hands THAT to `ecrecover`, so a signature
//! over the bare digest recovers a stranger and the mirror rejects it. `solidus-crypto::attest`
//! deliberately signs whatever 32 bytes it is given and leaves this choice to the caller, because
//! Solana recovers from the digest itself.

use std::sync::atomic::{AtomicUsize, Ordering};

use solidus_bridge_codec::{attestation_digest, eth_signed_message_hash};
use solidus_crypto::attest::AttestationKey;
use solidus_exec::{StateKey, StateReader};
use solidus_store2::Store2;
use solidus_txns::bridge::OutboxEntry;
use solidus_txns::types::{Event, Receipt};

/// Counts the "this node does not attest" warning. A node without a key is the normal state until
/// the key is deployed, so the warning is emitted once per process rather than once per block.
static UNCONFIGURED_WARNINGS: AtomicUsize = AtomicUsize::new(0);

/// A configured attestation key, bound to the chain it signs for.
///
/// ⚠ THE CHAIN ID IS IN THE DIGEST, so an `Attestor` built for devnet cannot produce a signature a
/// testnet mirror accepts. Holding it here rather than passing it per call makes that binding a
/// property of the key, which is what it is.
pub struct Attestor {
    key: AttestationKey,
    chain_id: u64,
}

impl Attestor {
    pub fn new(key: AttestationKey, chain_id: u64) -> Self {
        Self { key, chain_id }
    }

    pub fn from_hex(
        secret_hex: &str,
        chain_id: u64,
    ) -> Result<Self, solidus_crypto::attest::AttestError> {
        Ok(Self::new(AttestationKey::from_hex(secret_hex)?, chain_id))
    }

    /// The address a mirror recovers, and the one `solidus_getCommittee` reports.
    pub fn address(&self) -> [u8; 20] {
        self.key.address()
    }
}

/// Sign every bridge message the committed block queued.
///
/// `height` is the height of the block being committed, and it goes into every digest. A caller
/// that passes the current head instead produces signatures no mirror will accept, which is why
/// this takes the height explicitly rather than reading it back from a store.
///
/// Returns `(domain, domain_seq, signature)` in the order the events appear. A node with no key
/// returns an empty vector: not attesting is a supported configuration, and a block must never fail
/// because a bridge key is absent.
pub fn sign_committed(
    attestor: Option<&Attestor>,
    height: u64,
    block_events: &[Event],
    receipts: &[Receipt],
) -> Vec<(u32, u64, [u8; 65])> {
    let Some(attestor) = attestor else {
        warn_unconfigured_once();
        return Vec::new();
    };

    // Block events first, then per-transaction events in receipt order, so two nodes replaying the
    // same block emit the same sequence. The signatures themselves are deterministic, but the
    // ORDER is only deterministic because this traversal is fixed.
    let events = block_events
        .iter()
        .chain(receipts.iter().flat_map(|r| r.events.iter()));

    let mut out = Vec::new();
    for event in events {
        let Event::BridgeMessageQueued {
            domain,
            domain_seq,
            message_id,
            ..
        } = event
        else {
            continue;
        };
        let digest =
            attestation_digest(attestor.chain_id, *domain, *domain_seq, message_id, height);
        let sig = attestor.key.sign(&eth_signed_message_hash(&digest));
        out.push((*domain, *domain_seq, sig));
    }
    out
}

fn warn_unconfigured_once() {
    if UNCONFIGURED_WARNINGS.fetch_add(1, Ordering::Relaxed) == 0 {
        eprintln!(
            "solidus-noded: no bridge attestation key configured; this node validates but does \
             not attest. Set bridge_attestation_secret_hex to attest."
        );
    }
}

impl solidus_node2::BlockAttestor for Attestor {
    fn sign_committed(
        &self,
        height: u64,
        block_events: &[Event],
        receipts: &[Receipt],
    ) -> Vec<(u32, u64, [u8; 65])> {
        sign_committed(Some(self), height, block_events, receipts)
    }
}

/// The newest `per_domain` sequences are the window the start-up pass re-signs.
///
/// ⚠ A WINDOW, NOT THE WHOLE OUTBOX, AND NOT FOR SPEED. A validator that has been down for a week
/// would otherwise re-sign every message ever queued at boot, and a mirror has already applied the
/// old ones. The window has to exceed anything a gateway would still be assembling.
pub const BACKFILL_WINDOW: u64 = 1000;

/// Sequences this pass will visit for a domain whose highest queued sequence is `last`.
///
/// `None` means there is nothing to visit. Sequences start at 1, so a domain with nothing queued
/// has no range at all, and saying that with `None` rather than a reversed `1..=0` keeps the empty
/// case from looking like an off-by-one.
fn backfill_range(last: u64, per_domain: u64) -> Option<std::ops::RangeInclusive<u64>> {
    if last == 0 || per_domain == 0 {
        return None;
    }
    Some(last.saturating_sub(per_domain - 1).max(1)..=last)
}

/// Sign any outbox entry in the window that this node has no signature for, and return how many it
/// wrote.
///
/// ⛔ THIS IS WHAT MAKES "SIGN AFTER PERSIST" SAFE. The commit path deliberately signs after the
/// block is stored, so a crash in between loses a signature. Without this pass that loss is
/// permanent and the message never crosses.
///
/// Errors are counted, not propagated: a node must boot even if one outbox record will not decode.
pub fn backfill_unsigned(attestor: &Attestor, store: &Store2, per_domain: u64) -> usize {
    let domains: Vec<u32> = match store.get(&StateKey::bridge_domains_index()) {
        Ok(Some(bytes)) => bincode::deserialize(&bytes).unwrap_or_default(),
        _ => Vec::new(),
    };

    let mut written = 0usize;
    for domain in domains {
        let last = match store.get(&StateKey::bridge_seq(domain)) {
            Ok(Some(b)) => <[u8; 8]>::try_from(b.as_slice()).map_or(0, u64::from_le_bytes),
            _ => 0,
        };
        let Some(window) = backfill_range(last, per_domain) else {
            continue;
        };
        for seq in window {
            // Already signed is the common case; check before decoding anything.
            if matches!(store.attestation(domain, seq), Ok(Some(_))) {
                continue;
            }
            let Ok(Some(bytes)) = store.get(&StateKey::bridge_outbox(domain, seq)) else {
                continue;
            };
            let Ok(entry) = bincode::deserialize::<OutboxEntry>(&bytes) else {
                eprintln!("solidus-noded: outbox {domain}/{seq} will not decode; not attesting it");
                continue;
            };
            // ⚠ THE HEIGHT COMES FROM THE RECORD, NOT FROM THE HEAD. This pass runs at boot, when
            // the head is far past the block that queued the message, and a digest built from the
            // head recovers a stranger on the mirror.
            let message_id = solidus_bridge_codec::keccak256(&entry.message);
            let digest = attestation_digest(
                attestor.chain_id,
                domain,
                seq,
                &message_id,
                entry.solidus_height,
            );
            let sig = attestor.key.sign(&eth_signed_message_hash(&digest));
            match store.put_attestation(domain, seq, &sig) {
                Ok(()) => written += 1,
                Err(e) => {
                    eprintln!("solidus-noded: cannot store attestation {domain}/{seq}: {e:?}")
                }
            }
        }
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::attest::recover;
    use solidus_txns::types::TxStatus;

    /// Synthetic, and it is only ever a test key: 32 bytes of 0x01.
    const TEST_KEY: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";
    const CHAIN_ID: u64 = 5_042_002;

    fn attestor() -> Attestor {
        Attestor::from_hex(TEST_KEY, CHAIN_ID).expect("test key parses")
    }

    fn queued(domain: u32, domain_seq: u64, tag: u8) -> Event {
        Event::BridgeMessageQueued {
            domain,
            domain_seq,
            kind: 1,
            message_id: [tag; 32],
        }
    }

    fn receipt(events: Vec<Event>) -> Receipt {
        Receipt {
            tx_hash: [0u8; 32],
            status: TxStatus::Success,
            block_height: 0,
            fee_paid: 0,
            events,
        }
    }

    /// An unrelated event, so "we signed three things" cannot pass by signing everything it saw.
    fn noise() -> Event {
        Event::CredentialUnexported {
            credential_id: "urn:test:1".into(),
            domain: 11_155_111,
            export_id: [0xEE; 32],
        }
    }

    #[test]
    fn every_queued_message_gets_one_signature_recovering_to_this_key() {
        let a = attestor();
        let height = 4_242;
        let events = [
            queued(11_155_111, 1, 0xA1),
            queued(43_113, 7, 0xB2),
            queued(11_155_111, 2, 0xC3),
        ];
        let sigs = sign_committed(Some(&a), height, &events, &[]);

        assert_eq!(sigs.len(), 3, "one signature per queued message");
        for (i, (domain, seq, sig)) in sigs.iter().enumerate() {
            let Event::BridgeMessageQueued {
                domain: want_domain,
                domain_seq: want_seq,
                message_id,
                ..
            } = &events[i]
            else {
                unreachable!("fixture is all queued events")
            };
            assert_eq!((domain, seq), (want_domain, want_seq), "event {i} identity");

            let digest = attestation_digest(CHAIN_ID, *domain, *seq, message_id, height);
            let signer = recover(&eth_signed_message_hash(&digest), sig).expect("recovers");
            assert_eq!(signer, a.address(), "event {i} recovers to this node's key");
        }
    }

    /// ⛔ THE CONTROL FOR THE TEST ABOVE. Recovery returns an address for almost any well-formed
    /// signature, so "it recovered" proves nothing on its own. Over the WRONG digest it must
    /// recover to somebody else.
    fn wrong_digest_recovers_a_stranger() {
        let a = attestor();
        let sigs = sign_committed(Some(&a), 10, &[queued(11_155_111, 1, 0xA1)], &[]);
        let wrong = attestation_digest(CHAIN_ID, 11_155_111, 1, &[0xA1; 32], 11);
        let signer = recover(&eth_signed_message_hash(&wrong), &sigs[0].2).expect("recovers");
        assert_ne!(
            signer,
            a.address(),
            "a digest for another height is another signer"
        );
    }

    #[test]
    fn the_recovery_check_is_not_vacuous() {
        wrong_digest_recovers_a_stranger();
    }

    #[test]
    fn transaction_events_are_signed_too_and_non_bridge_events_are_ignored() {
        let a = attestor();
        let receipts = [
            receipt(vec![noise(), queued(11_155_111, 9, 0xD4)]),
            receipt(vec![noise()]),
        ];
        let sigs = sign_committed(Some(&a), 100, &[noise()], &receipts);

        assert_eq!(sigs.len(), 1, "only the queued message is signed");
        assert_eq!((sigs[0].0, sigs[0].1), (11_155_111, 9));
    }

    #[test]
    fn a_block_with_no_bridge_events_produces_nothing() {
        let a = attestor();
        assert!(sign_committed(Some(&a), 7, &[], &[]).is_empty());
        assert!(sign_committed(Some(&a), 7, &[noise()], &[receipt(vec![noise()])]).is_empty());
    }

    #[test]
    fn a_node_with_no_key_produces_nothing_and_warns_once() {
        let before = UNCONFIGURED_WARNINGS.load(Ordering::Relaxed);
        assert!(sign_committed(None, 7, &[queued(11_155_111, 1, 0xA1)], &[]).is_empty());
        assert!(sign_committed(None, 8, &[queued(11_155_111, 2, 0xA2)], &[]).is_empty());
        assert!(
            UNCONFIGURED_WARNINGS.load(Ordering::Relaxed) > before,
            "the unconfigured path is counted"
        );
    }

    #[test]
    fn signing_the_same_block_twice_yields_identical_bytes() {
        let a = attestor();
        let events = [queued(11_155_111, 1, 0xA1), queued(43_113, 4, 0xB2)];
        assert_eq!(
            sign_committed(Some(&a), 500, &events, &[]),
            sign_committed(Some(&a), 500, &events, &[]),
            "ECDSA here is deterministic (RFC 6979); a random k would break every cross-check"
        );
    }

    /// ⚠ THE HEIGHT IS THE QUEUEING BLOCK'S, NOT THE HEAD'S. If this ever reads a head instead, the
    /// two signatures below become equal and this fails.
    #[test]
    fn the_height_in_the_digest_is_the_block_that_queued_the_message() {
        let a = attestor();
        let events = [queued(11_155_111, 1, 0xA1)];
        let at_100 = sign_committed(Some(&a), 100, &events, &[]);
        let at_101 = sign_committed(Some(&a), 101, &events, &[]);

        assert_ne!(at_100[0].2, at_101[0].2, "height is inside the digest");
        let digest = attestation_digest(CHAIN_ID, 11_155_111, 1, &[0xA1; 32], 100);
        assert_eq!(
            recover(&eth_signed_message_hash(&digest), &at_100[0].2).expect("recovers"),
            a.address(),
            "the height 100 signature is over the height 100 digest"
        );
    }
    /// ⚠ THE WINDOW IS THE NEWEST SEQUENCES, NOT THE OLDEST, and an off-by-one here re-signs the
    /// wrong thousand silently: every signature is valid, just for messages a mirror applied days
    /// ago, while the recent ones stay missing.
    #[test]
    fn the_backfill_window_is_the_newest_sequences_and_never_reaches_below_one() {
        assert_eq!(
            backfill_range(0, 1000),
            None,
            "nothing queued, nothing to sign"
        );
        assert_eq!(backfill_range(1, 1000), Some(1..=1));
        assert_eq!(
            backfill_range(500, 1000),
            Some(1..=500),
            "shorter than the window"
        );
        assert_eq!(
            backfill_range(1000, 1000),
            Some(1..=1000),
            "exactly the window"
        );
        assert_eq!(
            backfill_range(1001, 1000),
            Some(2..=1001),
            "the oldest falls out"
        );
        assert_eq!(backfill_range(10_000, 1000), Some(9001..=10_000));
        assert_eq!(
            backfill_range(10_000, 1000).expect("a window").count(),
            1000,
            "the bound is honoured"
        );
    }
}
