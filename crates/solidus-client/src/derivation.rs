//! Key derivation — BIP-39 seed, identity key, and the per-verifier pairwise
//! hierarchy.
//!
//! ⚠ **FROZEN.** These bytes are locked by `test-vectors/did/derivation-v1.json`
//! and asserted in three other places (the TypeScript SDK, the identity backend,
//! the identity frontend). **Changing any of it re-keys real users.** This module
//! reproduces the TypeScript implementation
//! (`packages/@solidus/sdk/src/chain/derivation.ts`) rather than reinterpreting
//! the prose describing it, because the prose is a description and the vector is
//! the contract.
//!
//! ```text
//! seed64        = PBKDF2-HMAC-SHA512(NFKD(mnemonic), NFKD("mnemonic"), c=2048, 64)
//! identity_priv = seed64[0..32]
//! pairwise_priv = HKDF-SHA512(ikm=seed64, salt=∅, info="solidus.pairwise.v1"‖id, 32)
//! address       = base58(BLAKE3-256(ed25519_public(priv))[0..20])
//! ```
//!
//! Note `identity_priv` is a raw slice of the seed and does **not** pass through
//! the HKDF hierarchy — that asymmetry is deliberate and load-bearing.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha512;
use solidus_crypto::keys::Address;

/// Info tag for the per-verifier pairwise key. Versioned so a future hierarchy
/// can coexist with this one instead of replacing it.
const PAIRWISE_INFO_TAG: &[u8] = b"solidus.pairwise.v1";

/// BIP-39 iteration count. Fixed by the standard; here so it is greppable.
const PBKDF2_ROUNDS: u32 = 2048;

/// An Ed25519 keypair with its Solidus address already derived.
#[derive(Clone)]
pub struct DerivedKey {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub address: Address,
}

impl DerivedKey {
    fn from_private(private_key: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&private_key);
        let verifying = signing.verifying_key();
        Self {
            private_key,
            public_key: verifying.to_bytes(),
            address: Address::from_public_key(&verifying),
        }
    }

    /// `did:solidus:<network>:<address>` for this key.
    ///
    /// ```
    /// # use solidus_client::derivation::{seed_from_mnemonic_nfkd, identity_key};
    /// # let m = ["abandon"; 23].join(" ") + " art";
    /// # let key = identity_key(&seed_from_mnemonic_nfkd(&m));
    /// // The network is part of the identifier syntax, not metadata attached to it.
    /// assert!(key.did("testnet").starts_with("did:solidus:testnet:"));
    /// assert!(key.did("mainnet").starts_with("did:solidus:mainnet:"));
    /// ```
    pub fn did(&self, network: &str) -> String {
        format!("did:solidus:{network}:{}", self.address.to_base58())
    }
}

/// BIP-39 mnemonic → 64-byte seed, with an empty passphrase.
///
/// ```
/// # use solidus_client::derivation::{seed_from_mnemonic_nfkd, identity_key};
/// // The Trezor all-`abandon` test mnemonic.
/// let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon \
///                 abandon abandon abandon abandon abandon abandon abandon abandon \
///                 abandon abandon abandon abandon abandon abandon abandon art";
/// let seed = seed_from_mnemonic_nfkd(&mnemonic.split_whitespace().collect::<Vec<_>>().join(" "));
/// assert_eq!(seed.len(), 64);
///
/// // Frozen by test-vectors/did/derivation-v1.json.
/// assert_eq!(identity_key(&seed).address.to_base58(), "3tBoVe6XRtirzr8SdRotGgbkuEQN");
/// ```
///
/// Takes the mnemonic **already NFKD-normalised**. Normalisation is the caller's
/// job because Rust has no normaliser in `std`, and silently accepting
/// un-normalised input would produce a different seed for a visually identical
/// phrase — the worst possible failure for a wallet.
pub fn seed_from_mnemonic_nfkd(mnemonic_nfkd: &str) -> [u8; 64] {
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(
        mnemonic_nfkd.as_bytes(),
        b"mnemonic",
        PBKDF2_ROUNDS,
        &mut seed,
    );
    seed
}

/// The identity key: `seed64[0..32]`, untouched by the HKDF hierarchy.
///
/// ```
/// # use solidus_client::derivation::{seed_from_mnemonic_nfkd, identity_key};
/// # let m = ["abandon"; 23].join(" ") + " art";
/// let key = identity_key(&seed_from_mnemonic_nfkd(&m));
///
/// // The public key is derived from the seed slice, not from the HKDF tree —
/// // that asymmetry is deliberate and is what this vector locks.
/// assert_eq!(
///     hex::encode(key.public_key),
///     "1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961",
/// );
/// assert_eq!(key.did("testnet"), "did:solidus:testnet:3tBoVe6XRtirzr8SdRotGgbkuEQN");
/// ```
pub fn identity_key(seed64: &[u8; 64]) -> DerivedKey {
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&seed64[..32]);
    DerivedKey::from_private(private_key)
}

/// The pairwise key for one verifier. A wallet derives a distinct key per
/// verifier so two verifiers cannot correlate the same user.
///
/// ```
/// # use solidus_client::derivation::{seed_from_mnemonic_nfkd, pairwise_key};
/// # let m = ["abandon"; 23].join(" ") + " art";
/// let seed = seed_from_mnemonic_nfkd(&m);
///
/// let a = pairwise_key(&seed, "rp-a.example.com");
/// let b = pairwise_key(&seed, "rp-b.example.com");
///
/// // Same seed, different verifier, unlinkable identifiers. This is the whole
/// // point of the hierarchy.
/// assert_ne!(a.address.to_base58(), b.address.to_base58());
///
/// // Frozen by test-vectors/did/derivation-v1.json.
/// assert_eq!(a.did("testnet"), "did:solidus:testnet:3ThmUf3VBefVuaQSBGzC1fcP5iKS");
/// ```
pub fn pairwise_key(seed64: &[u8; 64], verifier_id: &str) -> DerivedKey {
    let mut info = Vec::with_capacity(PAIRWISE_INFO_TAG.len() + verifier_id.len());
    info.extend_from_slice(PAIRWISE_INFO_TAG);
    info.extend_from_slice(verifier_id.as_bytes());

    // Empty salt, matching the TypeScript. HKDF treats an absent salt as a
    // zero-filled block of the hash length, so "∅" and "absent" agree here —
    // but they are written explicitly because they do not agree in every HKDF
    // implementation.
    let hk = Hkdf::<Sha512>::new(Some(&[]), seed64);
    let mut private_key = [0u8; 32];
    hk.expand(&info, &mut private_key)
        .expect("32 bytes is well within HKDF-SHA512's output limit");
    DerivedKey::from_private(private_key)
}
