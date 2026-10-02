//! `solidus-noded bls-pop <config.toml>`: print this node's BLS proof of possession.

use anyhow::{anyhow, Result};
use solidus_crypto::bls::BlsSecretKey;

pub fn pop_line(config_text: &str) -> Result<String> {
    let cfg: crate::config::DaemonConfig =
        toml::from_str(config_text).map_err(|e| anyhow!("parse config: {e}"))?;
    let secret: [u8; 32] = hex::decode(&cfg.bls_secret_hex)
        .map_err(|_| anyhow!("bls_secret_hex is not hex"))?
        .try_into()
        .map_err(|_| anyhow!("bls_secret_hex is not 32 bytes"))?;
    let key = BlsSecretKey::from_bytes(&secret).map_err(|e| anyhow!("bad bls secret: {e:?}"))?;
    Ok(format!(
        "bls_pop_hex = \"{}\"",
        hex::encode(key.prove_possession().to_bytes())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_printed_pop_verifies_for_the_configs_public_key_and_contains_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        crate::gen::generate(path, 4, 31337).unwrap();
        let text = std::fs::read_to_string(format!("{path}/node0.toml")).unwrap();
        let cfg: crate::config::DaemonConfig = toml::from_str(&text).unwrap();
        let line = pop_line(&text).unwrap();
        assert!(
            !line.contains(&cfg.bls_secret_hex),
            "never print the secret"
        );
        let pop_hex = line
            .trim_start_matches("bls_pop_hex = \"")
            .trim_end_matches('"');
        let pop = solidus_crypto::bls::BlsSignature::from_bytes(
            &hex::decode(pop_hex).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let own = cfg
            .validators
            .iter()
            .find(|v| v.index == cfg.index)
            .unwrap();
        assert!(
            solidus_crypto::bls::BlsPublicKey::from_hex(&own.bls_pubkey_hex)
                .unwrap()
                .verify_possession(&pop)
        );
    }
}
