//! Two credentials for the SAME subject must not be linkable from chain data.
//!
//! ⛔ THIS IS THE PROPERTY KVKK TURNS ON, AND NOTHING ASSERTED IT.
//! An empty `subject_did` proves nothing on its own. If the commitment were
//! deterministic in the subject alone, anyone reading the ledger could group
//! every credential belonging to one person, and **that grouping is what makes a
//! record personal data rather than anonymous.** The nonce is the whole defence,
//! and until now no test said so.
//!
//! ⚠ MEASURED CONTEXT, 2026-09-04. The v1 chain carries 1,268 real subject DIDs
//! in the clear. Every product moved to v2 earlier the same day, and the v2 chain
//! carries 7 credentials with **zero** visible subjects. These tests are what
//! entitles us to describe that difference as privacy rather than as an empty
//! column.

use solidus_txns::credential::{
    build_credential_id_v2, build_subject_commitment, SUBJECT_COMMITMENT_DOMAIN,
};

const SUBJECT: &str = "did:solidus:testnet:zSAMEPERSON000000000000000000";
const OTHER: &str = "did:solidus:testnet:zDIFFERENTPERSON00000000000000";

#[test]
fn same_subject_two_credentials_produce_unlinkable_commitments() {
    // The core property. A person who is verified twice must not become one
    // browsable cluster on a public ledger.
    let c1 = build_subject_commitment(SUBJECT, &[1u8; 32]);
    let c2 = build_subject_commitment(SUBJECT, &[2u8; 32]);

    assert_ne!(
        c1, c2,
        "same subject with different nonces produced identical commitments: \
         every credential belonging to one person would be linkable on-chain"
    );
}

#[test]
fn commitment_is_reproducible_by_whoever_holds_the_nonce() {
    // ⚠ THE OTHER HALF, AND IT IS NOT OPTIONAL. Unlinkability alone is satisfied
    // by a random number, which would also make the commitment useless: the
    // holder could never prove a credential is theirs. The binding has to be
    // re-derivable by someone who has the nonce.
    let nonce = [42u8; 32];
    assert_eq!(
        build_subject_commitment(SUBJECT, &nonce),
        build_subject_commitment(SUBJECT, &nonce),
        "the same subject and nonce must reproduce the commitment, or a holder \
         can never prove the binding"
    );
}

#[test]
fn the_commitment_is_not_derivable_from_the_subject_alone() {
    // ⛔ THE DICTIONARY ATTACK. The DID space an attacker cares about is small
    // and enumerable: they have a list of customers and want to know which
    // records are theirs. Without a nonce they would simply hash each candidate
    // and match. The nonce is 32 bytes from a CSPRNG and never touches the
    // chain, so a guess of the SUBJECT is not enough.
    let real = build_subject_commitment(SUBJECT, &[99u8; 32]);
    let guessed_with_zero_nonce = build_subject_commitment(SUBJECT, &[0u8; 32]);

    assert_ne!(
        real, guessed_with_zero_nonce,
        "a commitment derivable from the subject alone would let anyone with a \
         customer list identify their records"
    );
}

#[test]
fn different_subjects_do_not_collide_under_the_same_nonce() {
    // The complement of the first test, and the reason it is not vacuous. A
    // function returning a constant would satisfy "not derivable from the
    // subject" while destroying the binding entirely.
    let nonce = [7u8; 32];
    assert_ne!(
        build_subject_commitment(SUBJECT, &nonce),
        build_subject_commitment(OTHER, &nonce),
        "two different subjects produced the same commitment under one nonce"
    );
}

#[test]
fn the_credential_id_is_derived_from_the_commitment_and_not_the_subject() {
    // ⛔ THE CHANNEL THE PLAN DID NOT LIST, AND IT WOULD HAVE UNDONE THE REST.
    // `build_credential_id` (v1) takes `subject_did`. If v2 had reused it, the
    // subject would be protected in the record field and reconstructible from
    // the ID: an attacker with a candidate DID could recompute the id and match
    // it, which is the same dictionary attack one layer down.
    //
    // v2 uses `build_credential_id_v2`, which takes the COMMITMENT. This pins
    // that, by showing the id changes when only the commitment changes.
    let hash = [0xAB; 32];
    let issuer = "did:solidus:testnet:zISSUER0000000000000000000000";

    let id_a = build_credential_id_v2(
        issuer,
        &build_subject_commitment(SUBJECT, &[1u8; 32]),
        &hash,
        100,
    );
    let id_b = build_credential_id_v2(
        issuer,
        &build_subject_commitment(SUBJECT, &[2u8; 32]),
        &hash,
        100,
    );

    // Same subject, same issuer, same payload, same height. Only the nonce
    // differs, and the ids must still differ.
    assert_ne!(
        id_a, id_b,
        "two credentials for one subject produced the same id: the id is a \
         correlation handle even though the record field is not"
    );

    // And the subject string must appear nowhere in the id.
    assert!(
        !id_a.contains("SAMEPERSON"),
        "the subject leaked into the credential id: {id_a}"
    );
}

#[test]
fn the_domain_separator_is_part_of_the_preimage() {
    // ⚠ Domain separation is what stops a commitment being replayable as some
    // other BLAKE3 hash in this system. Asserted by construction rather than by
    // reimplementing the hash: a commitment must not equal the bare hash of
    // subject-and-nonce with no domain prefix.
    let nonce = [5u8; 32];
    let with_domain = build_subject_commitment(SUBJECT, &nonce);

    let mut without_domain = Vec::new();
    without_domain.extend_from_slice(SUBJECT.as_bytes());
    without_domain.extend_from_slice(&nonce);
    // ⚠ The workspace's own hash helper, not the `blake3` crate directly: this
    // crate does not depend on it, and adding a dependency to make a test
    // compile would be the test changing the code to suit itself.
    let bare = solidus_crypto::hash::blake3_hash(&without_domain);

    assert_ne!(
        with_domain, bare,
        "the commitment is a bare hash of subject-and-nonce, with no domain \
         separation: it could be replayed as another hash in this system"
    );
    assert!(
        !SUBJECT_COMMITMENT_DOMAIN.is_empty(),
        "the domain separator must not be empty"
    );
}
