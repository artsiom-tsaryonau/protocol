//! Double-sign detection for the HotStuff consensus engine.
//!
//! A double-sign (equivocation) occurs when a validator casts two votes for
//! different blocks in the same consensus round. This is a slashable offense.

use serde::{Deserialize, Serialize};

use crate::types::Vote;

// ---------------------------------------------------------------------------
// DoubleSignEvidence
// ---------------------------------------------------------------------------

/// Evidence that a validator double-signed in a given round: two votes for
/// different blocks from the same voter in the same round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    /// The round in which the double-sign occurred.
    pub round: u64,
    /// Index of the validator that double-signed.
    pub voter_index: usize,
    /// The first vote.
    pub vote_a: Vote,
    /// The second vote (same round and voter, different block hash).
    pub vote_b: Vote,
}

// ---------------------------------------------------------------------------
// detect_double_sign
// ---------------------------------------------------------------------------

/// Check if two votes constitute a double-sign.
///
/// Returns `Some(DoubleSignEvidence)` if:
/// - Both votes are from the same round.
/// - Both votes are from the same voter (by `voter_index`).
/// - The two votes reference different block hashes.
///
/// Returns `None` otherwise (same block hash = redundant but not equivocation).
pub fn detect_double_sign(vote_a: &Vote, vote_b: &Vote) -> Option<DoubleSignEvidence> {
    if vote_a.round == vote_b.round
        && vote_a.voter_index == vote_b.voter_index
        && vote_a.block_hash != vote_b.block_hash
    {
        Some(DoubleSignEvidence {
            round: vote_a.round,
            voter_index: vote_a.voter_index,
            vote_a: vote_a.clone(),
            vote_b: vote_b.clone(),
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::bls::BlsSecretKey;

    /// Build a minimal `Vote` for testing. Uses a real BLS signature over dummy bytes
    /// so the struct is valid (detect_double_sign only checks hashes, not sig validity).
    fn make_vote(round: u64, voter_index: usize, block_hash: [u8; 32]) -> Vote {
        let sk = BlsSecretKey::generate();
        let bls_signature = sk.sign(&block_hash);
        Vote {
            block_hash,
            round,
            voter_index,
            bls_signature,
        }
    }

    #[test]
    fn detect_double_sign_found() {
        // Same round, same voter, DIFFERENT block hashes — this is a double-sign.
        let vote_a = make_vote(5, 2, [0xAAu8; 32]);
        let vote_b = make_vote(5, 2, [0xBBu8; 32]);

        let evidence = detect_double_sign(&vote_a, &vote_b);
        assert!(evidence.is_some(), "should detect double-sign");

        let ev = evidence.unwrap();
        assert_eq!(ev.round, 5);
        assert_eq!(ev.voter_index, 2);
        assert_eq!(ev.vote_a.block_hash, [0xAAu8; 32]);
        assert_eq!(ev.vote_b.block_hash, [0xBBu8; 32]);
    }

    #[test]
    fn detect_double_sign_not_found_same_hash() {
        // Same round, same voter, SAME block hash — not a double-sign.
        let vote_a = make_vote(5, 2, [0xAAu8; 32]);
        let vote_b = make_vote(5, 2, [0xAAu8; 32]);

        let evidence = detect_double_sign(&vote_a, &vote_b);
        assert!(
            evidence.is_none(),
            "same block hash votes should not be double-sign"
        );
    }

    #[test]
    fn detect_double_sign_not_found_different_round() {
        // Different rounds — not equivocation (validator voted in different rounds).
        let vote_a = make_vote(5, 2, [0xAAu8; 32]);
        let vote_b = make_vote(6, 2, [0xBBu8; 32]);

        let evidence = detect_double_sign(&vote_a, &vote_b);
        assert!(
            evidence.is_none(),
            "votes from different rounds should not be double-sign"
        );
    }

    #[test]
    fn detect_double_sign_not_found_different_voter() {
        // Same round, different voters — not equivocation.
        let vote_a = make_vote(5, 1, [0xAAu8; 32]);
        let vote_b = make_vote(5, 2, [0xBBu8; 32]);

        let evidence = detect_double_sign(&vote_a, &vote_b);
        assert!(
            evidence.is_none(),
            "votes from different voters should not be double-sign"
        );
    }
}
