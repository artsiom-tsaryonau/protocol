//! Bridge state keys (registry §2.6). All live in the Credentials tree so every
//! bridge record and message is provable against the global root.

use solidus_state_tree::TreeId;

use crate::types::{StateKey, StateSpace};

fn cred(key: Vec<u8>) -> StateKey {
    StateKey {
        space: StateSpace::Tree(TreeId::Credentials),
        key,
    }
}

fn prefixed(prefix: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(prefix.len() + tail.len());
    k.extend_from_slice(prefix);
    k.extend_from_slice(tail);
    k
}

impl StateKey {
    pub fn bridge_domain(domain: u32) -> Self {
        cred(prefixed(b"bridge:domain:", &domain.to_be_bytes()))
    }
    pub fn bridge_trust_root(did: &str) -> Self {
        cred(prefixed(b"bridge:trustroot:", did.as_bytes()))
    }
    pub fn bridge_exports(credential_id: &str) -> Self {
        cred(prefixed(b"bridge:export:", credential_id.as_bytes()))
    }
    pub fn bridge_seq(domain: u32) -> Self {
        cred(prefixed(b"bridge:seq:", &domain.to_be_bytes()))
    }
    pub fn bridge_outbox(domain: u32, seq: u64) -> Self {
        let mut tail = domain.to_be_bytes().to_vec();
        tail.extend_from_slice(&seq.to_be_bytes());
        cred(prefixed(b"bridge:outbox:", &tail))
    }
    pub fn bridge_heartbeat(domain: u32) -> Self {
        cred(prefixed(b"bridge:hb:", &domain.to_be_bytes()))
    }
    pub fn bridge_domains_index() -> Self {
        cred(b"bridge:domains".to_vec())
    }
    pub fn bridge_gov_nonce() -> Self {
        cred(b"bridge:gov:nonce".to_vec())
    }
    pub fn bridge_accredited(did: &str) -> Self {
        cred(prefixed(b"bridge:accredited:", did.as_bytes()))
    }
}
