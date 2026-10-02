//! Holder consent to an export (spec §5.1 step 2). Verified here, on Solidus;
//! destination contracts never see consent signatures.

use solidus_bridge_codec::{ed25519_consent_bytes, eip712_consent_digest, ExportConsent};
use solidus_txns::bridge::{BridgeDomain, BridgeDomainVm};

pub(crate) fn verify_consent(
    domain: &BridgeDomain,
    consent: &ExportConsent,
    sig: &[u8],
) -> Result<(), &'static str> {
    match domain.vm {
        BridgeDomainVm::Evm => verify_evm(domain, consent, sig),
        BridgeDomainVm::Svm => verify_svm(domain, consent, sig),
        BridgeDomainVm::Cosmos => Err("cosmos consent is not active until bridge phase 7"),
    }
}

fn verify_evm(
    domain: &BridgeDomain,
    consent: &ExportConsent,
    sig: &[u8],
) -> Result<(), &'static str> {
    if consent.holder[..12] != [0u8; 12] {
        return Err("holder is not an EVM address");
    }
    if sig.len() != 65 {
        return Err("consent signature must be 65 bytes");
    }
    let mut mirror20 = [0u8; 20];
    mirror20.copy_from_slice(&domain.inbox[12..]);
    let digest = eip712_consent_digest(consent, u64::from(domain.domain), &mirror20);
    // ⚠ ONE RECOVERY PRIMITIVE FOR THE CHAIN (registry §2.7). The parse, the EIP-2 high-s refusal
    // and the recovery-byte mapping used to be inlined here; three callers each with their own copy
    // drift one at a time and silently, and the signing side is a fourth.
    let address = crate::bridge::ecdsa::recover_eth_address(&digest, sig)?;
    if address != consent.holder[12..] {
        return Err("consent signed by a different address");
    }
    Ok(())
}

fn verify_svm(
    domain: &BridgeDomain,
    consent: &ExportConsent,
    sig: &[u8],
) -> Result<(), &'static str> {
    let Ok(sig) = <[u8; 64]>::try_from(sig) else {
        return Err("consent signature must be 64 bytes");
    };
    let key = ed25519_dalek::VerifyingKey::from_bytes(&consent.holder)
        .map_err(|_| "holder is not an ed25519 key")?;
    let msg = ed25519_consent_bytes(consent, &domain.inbox);
    if solidus_crypto::ed25519::verify(&key, &msg, &sig) {
        Ok(())
    } else {
        Err("consent signature does not verify")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_bridge_codec::eip712_consent_digest;
    use solidus_txns::bridge::BridgeDomainVm;

    const ANVIL_1_KEY: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const ANVIL_1_ADDR: &str = "70997970c51812dc3a010c7d01b50e0d17dc79c8";
    const ANVIL_2_KEY: &str = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

    fn evm_domain() -> BridgeDomain {
        let mut mirror = [0u8; 32];
        mirror[12..]
            .copy_from_slice(&hex::decode("5fbdb2315678afecb367f032d93f642f64180aa3").unwrap());
        BridgeDomain {
            domain: 11_155_111,
            vm: BridgeDomainVm::Evm,
            inbox: mirror,
            heartbeat_interval_secs: 600,
            enabled: true,
        }
    }

    fn consent(holder_hex20: &str) -> ExportConsent {
        let mut holder = [0u8; 32];
        holder[12..].copy_from_slice(&hex::decode(holder_hex20).unwrap());
        ExportConsent {
            credential_id: "urn:solidus:credential:00ff".into(),
            domain: 11_155_111,
            holder,
            consent_expiry: 1_900_000_000,
        }
    }

    fn sign_evm(key_hex: &str, c: &ExportConsent, d: &BridgeDomain) -> Vec<u8> {
        let sk = k256::ecdsa::SigningKey::from_slice(&hex::decode(key_hex).unwrap()).unwrap();
        let mirror20: [u8; 20] = d.inbox[12..].try_into().unwrap();
        let (sig, rid) = sk
            .sign_prehash_recoverable(&eip712_consent_digest(c, u64::from(d.domain), &mirror20))
            .unwrap();
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + rid.to_byte());
        out
    }

    #[test]
    fn anvil_account_one_consent_verifies_and_recovers_its_known_address() {
        let (d, c) = (evm_domain(), consent(ANVIL_1_ADDR));
        assert_eq!(
            verify_consent(&d, &c, &sign_evm(ANVIL_1_KEY, &c, &d)),
            Ok(())
        );
    }

    #[test]
    fn a_zero_or_one_recovery_byte_is_accepted_too() {
        let (d, c) = (evm_domain(), consent(ANVIL_1_ADDR));
        let mut sig = sign_evm(ANVIL_1_KEY, &c, &d);
        sig[64] -= 27;
        assert_eq!(verify_consent(&d, &c, &sig), Ok(()));
    }

    #[test]
    fn another_accounts_signature_is_refused() {
        let (d, c) = (evm_domain(), consent(ANVIL_1_ADDR));
        assert_eq!(
            verify_consent(&d, &c, &sign_evm(ANVIL_2_KEY, &c, &d)),
            Err("consent signed by a different address")
        );
    }

    #[test]
    fn a_consent_for_another_domain_is_refused() {
        let d = evm_domain();
        let mut other = consent(ANVIL_1_ADDR);
        other.domain = 43_113;
        let sig = sign_evm(
            ANVIL_1_KEY,
            &other,
            &BridgeDomain {
                domain: 43_113,
                ..evm_domain()
            },
        );
        assert_eq!(
            verify_consent(&d, &consent(ANVIL_1_ADDR), &sig),
            Err("consent signed by a different address")
        );
    }

    #[test]
    fn a_high_s_signature_is_refused() {
        let (d, c) = (evm_domain(), consent(ANVIL_1_ADDR));
        let sig = sign_evm(ANVIL_1_KEY, &c, &d);
        let low = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
        let (r, s) = low.split_scalars();
        let high = k256::ecdsa::Signature::from_scalars(r, -s).unwrap();
        let mut bad = high.to_bytes().to_vec();
        bad.push(sig[64]);
        assert_eq!(
            verify_consent(&d, &c, &bad),
            Err("high-s consent signature")
        );
    }

    #[test]
    fn malformed_evm_inputs_are_refused_without_panicking() {
        let (d, c) = (evm_domain(), consent(ANVIL_1_ADDR));
        assert_eq!(
            verify_consent(&d, &c, &[0u8; 64]),
            Err("consent signature must be 65 bytes")
        );
        let mut sig = sign_evm(ANVIL_1_KEY, &c, &d);
        sig[64] = 29;
        assert_eq!(verify_consent(&d, &c, &sig), Err("bad recovery id"));
        let mut not_address = c.clone();
        not_address.holder[0] = 1;
        assert_eq!(
            verify_consent(&d, &not_address, &sig),
            Err("holder is not an EVM address")
        );
    }

    #[test]
    fn svm_consent_is_an_ed25519_signature_over_the_codec_bytes() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let d = BridgeDomain {
            domain: 1_399_811_151,
            vm: BridgeDomainVm::Svm,
            inbox: [0x07; 32],
            heartbeat_interval_secs: 600,
            enabled: true,
        };
        let c = ExportConsent {
            credential_id: "urn:solidus:credential:00ff".into(),
            domain: d.domain,
            holder: key.verifying_key().to_bytes(),
            consent_expiry: 1_900_000_000,
        };
        let sig = solidus_crypto::ed25519::sign(
            &key,
            &solidus_bridge_codec::ed25519_consent_bytes(&c, &d.inbox),
        );
        assert_eq!(verify_consent(&d, &c, &sig), Ok(()));
        let mut wrong = sig;
        wrong[0] ^= 1;
        assert_eq!(
            verify_consent(&d, &c, &wrong),
            Err("consent signature does not verify")
        );
    }

    #[test]
    fn cosmos_consent_is_not_active_yet() {
        let d = BridgeDomain {
            vm: BridgeDomainVm::Cosmos,
            ..evm_domain()
        };
        assert_eq!(
            verify_consent(&d, &consent(ANVIL_1_ADDR), &[0u8; 65]),
            Err("cosmos consent is not active until bridge phase 7")
        );
    }
}
