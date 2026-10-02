//! Committed attestation vectors: the §3.2 preimage, the digest, the eth-signed hash, and one real
//! signature per case from a fixed test key.
//!
//! Same discipline as `vectors.rs`: the JSON is COMMITTED and this test holds it still. Regenerate
//! deliberately and read the diff as a wire change:
//!
//!     UPDATE_VECTORS=1 cargo test -p solidus-bridge-codec --test attest_vectors
//!
//! ⚠ THE SIGNATURE IS IN THE FILE SO THAT FOUR LANGUAGES CHECK A REAL RECOVERY, not only a hash.
//! A digest that every side computes identically still fails on chain if one of them frames or
//! orders the 65 bytes differently, and a hash-only vector cannot see that.

use std::path::{Path, PathBuf};

use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use solidus_bridge_codec::attest::{
    attestation_digest, attestation_preimage, eth_signed_message_hash,
};
use solidus_bridge_codec::keccak256;

/// Anvil account #1. A published test key: it holds nothing, anywhere, ever.
const TEST_KEY_HEX: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const TEST_ADDRESS: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

fn vectors_dir() -> PathBuf {
    let mut dir: &Path = &std::env::current_dir().expect("cwd");
    loop {
        let candidate = dir.join("test-fixtures");
        if candidate.is_dir() {
            return candidate.join("bridge");
        }
        dir = dir.parent().expect("test-fixtures/ not found above the cwd");
    }
}

fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&hex::decode(TEST_KEY_HEX).unwrap()).expect("test key")
}

/// keccak256 of the uncompressed public key without its 0x04 tag, last 20 bytes.
fn address_of(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// 65 bytes, `r ‖ s ‖ v` with `v` in {27, 28}: what Solidity's `ecrecover` takes, and what the
/// mirror's `AttestationLib` slices. k256 normalises to low-s, which EIP-2 requires.
fn sign_eth(key: &SigningKey, eth_signed: &[u8; 32]) -> [u8; 65] {
    let (sig, recid) = key
        .sign_prehash_recoverable(eth_signed)
        .expect("sign prehash");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + recid.to_byte();
    out
}

/// name, chain id, destination domain, sequence, message id, Solidus height. A named struct only
/// because clippy reads the bare tuple as too complex; the fields are the §3.2 digest inputs in
/// digest order, which is the order to keep them in.
struct Input(&'static str, u64, u32, u64, [u8; 32], u64);

fn cases() -> Value {
    let key = signing_key();
    let signer = address_of(&key);

    // Four cases: the three testnet destination domains, plus the u64 edge on sequence and height.
    // The chain id is the Solidus testnet's (registry §3.4, measured 50002 on the live chain).
    let inputs: [Input; 4] = [
        Input("sepolia-first", 50_002, 11_155_111, 1, [0xA1; 32], 900),
        Input("fuji-seq-7", 50_002, 43_113, 7, [0xA2; 32], 3_150_000),
        Input("arc-devnet-chain-id", 50_001, 5_042_002, 2, [0xA3; 32], 42),
        Input(
            "max-seq-and-height",
            50_002,
            11_155_111,
            u64::MAX,
            [0xFF; 32],
            u64::MAX,
        ),
    ];

    let mut out = Vec::new();
    for Input(name, chain_id, domain, domain_seq, message_id, height) in inputs {
        let preimage = attestation_preimage(chain_id, domain, domain_seq, &message_id, height);
        let digest = attestation_digest(chain_id, domain, domain_seq, &message_id, height);
        let eth_signed = eth_signed_message_hash(&digest);
        let signature = sign_eth(&key, &eth_signed);
        out.push(json!({
            "name": name,
            // u64 as a string: 18446744073709551615 does not survive a JSON number.
            "chainId": chain_id.to_string(),
            "domain": domain,
            "domainSeq": domain_seq.to_string(),
            "messageId": h(&message_id),
            "solidusHeight": height.to_string(),
            "preimage": h(&preimage),
            "digest": h(&digest),
            "ethSigned": h(&eth_signed),
            "signature": h(&signature),
            "signer": h(&signer),
        }));
    }

    json!({ "version": 1, "signer": h(&signer), "cases": out })
}

#[test]
fn attestation_vectors_match_the_committed_file() {
    let dir = vectors_dir();
    let path = dir.join("attestation-v2.json");
    let value = cases();

    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
        )
        .expect("write");
        eprintln!("wrote {}", path.display());
        return;
    }

    let existing = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("no vectors at {}. Generate deliberately:\n  UPDATE_VECTORS=1 cargo test -p solidus-bridge-codec --test attest_vectors", path.display())
    });
    let committed: Value = serde_json::from_str(&existing).expect("valid json");
    assert_eq!(
        committed, value,
        "attestation-v2.json drifted from the codec. If intended, regenerate and review the diff."
    );
}

/// ⚠ A CONTROL, and it is not decoration: the key and the address are written down in two plans and
/// in the EVM tests. If they ever stop being a pair, every "recovered the wrong signer" failure
/// downstream points at the contract instead of at this line.
#[test]
fn the_fixed_test_key_derives_the_documented_address() {
    assert_eq!(h(&address_of(&signing_key())), TEST_ADDRESS);
}

/// The recovery has to work in this crate before four other implementations are asked to reproduce
/// it. Recovering from the ETH-SIGNED hash is what Solidity does; recovering from the digest would
/// give a different address, which is exactly the framing mistake this vector file exists to catch.
#[test]
fn every_committed_signature_recovers_to_the_signer() {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use k256::elliptic_curve::scalar::IsHigh;

    let value = cases();
    let all = value["cases"].as_array().unwrap();
    assert_eq!(all.len(), 4, "case count changed");

    for case in all {
        let eth_signed: [u8; 32] = hex::decode(&case["ethSigned"].as_str().unwrap()[2..])
            .unwrap()
            .try_into()
            .unwrap();
        let sig_bytes = hex::decode(&case["signature"].as_str().unwrap()[2..]).unwrap();
        assert_eq!(sig_bytes.len(), 65, "{}", case["name"]);

        let sig = Signature::from_slice(&sig_bytes[..64]).unwrap();
        assert!(
            sig.s().is_high().unwrap_u8() == 0,
            "{} is not low-s; EIP-2 refuses it and the mirror reverts HighS",
            case["name"]
        );
        let recid = RecoveryId::from_byte(sig_bytes[64] - 27).unwrap();
        let recovered =
            VerifyingKey::recover_from_prehash(&eth_signed, &sig, recid).expect("recover");

        let point = recovered.to_encoded_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        assert_eq!(
            h(&hash[12..]),
            case["signer"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}
