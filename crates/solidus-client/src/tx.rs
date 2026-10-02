//! Building and signing Solidus transactions.
//!
//! The signing preimage is fixed by the chain and reproduced here rather than
//! reimplemented — `solidus_txns::Transaction::signing_bytes` is the definition:
//!
//! ```text
//! signing_bytes = BLAKE3-256(sender_pubkey ‖ nonce_le_u64 ‖ serde_json(payload))
//! ```
//!
//! ⚠ The payload is hashed as its **JSON serialisation**, so field order and
//! serde attributes are consensus-relevant. A port to another language cannot
//! guess this from a struct definition — it has to match serde's output, which
//! is why `test-vectors/did/tx-create-v1.json` pins a signature rather than a
//! shape.

use ed25519_dalek::{Signer, SigningKey};
use solidus_txns::did::Service;
use solidus_txns::types::{Transaction, TxPayload};

/// A transaction that has been signed and is ready to submit.
pub struct SignedTransaction {
    pub sender_pubkey: [u8; 32],
    pub signature: [u8; 64],
    pub inner: Transaction,
}

/// Build and sign a `DidCreate`.
///
/// ```
/// # use solidus_client::tx::sign_did_create;
/// // The vector's signer key: 32 bytes of 0xab.
/// let signed = sign_did_create(&[0xab; 32], 0, Vec::new());
///
/// // Frozen by test-vectors/did/tx-create-v1.json. The preimage hashes the
/// // payload's JSON, so this value pins serde's output as consensus-relevant.
/// assert_eq!(
///     hex::encode(signed.signature),
///     "7b6f809c46a4a136515d532bffb331519afe2fb24bc187854a6288b7765237af\
///      a36aea1c1bab47f131f9179ed7b8a7412cfcff7f6fc16ecf0047addecb42f70b",
/// );
/// ```
///
/// The DID's public key is the signer's own: creating a DID for a key you do not
/// hold is rejected on chain, so the API does not offer the mistake.
pub fn sign_did_create(
    private_key: &[u8; 32],
    nonce: u64,
    service_endpoints: Vec<Service>,
) -> SignedTransaction {
    let signing = SigningKey::from_bytes(private_key);
    let sender_pubkey = signing.verifying_key().to_bytes();

    let mut tx = Transaction {
        sender_pubkey,
        nonce,
        payload: TxPayload::DidCreate {
            public_key: sender_pubkey,
            service_endpoints,
        },
        // Filled in below; signing_bytes() does not read it.
        signature: [0u8; 64],
    };

    let signature = signing.sign(&tx.signing_bytes()).to_bytes();
    tx.signature = signature;

    SignedTransaction {
        sender_pubkey,
        signature,
        inner: tx,
    }
}
