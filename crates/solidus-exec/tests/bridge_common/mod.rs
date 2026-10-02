#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use solidus_bridge_codec::{decode, eip712_consent_digest, BridgeMessage, ExportConsent};
use solidus_crypto::ed25519::sign;
use solidus_crypto::keys::Address;
use solidus_exec::protocol::V2_ACTIVATION_HEIGHT;
use solidus_exec::{
    execute_block_reference, execute_block_twolane, Account, BlockCtx, BlockOutcome, ExecOptions,
    InMemoryState, StateKey, StateReader, WireMode,
};
use solidus_txns::bridge::{
    governance_signing_message, BridgeDomainVm, BridgeGovAction, GovernorApproval, OutboxEntry,
};
use solidus_txns::credential::{build_subject_commitment, CredentialType};
use solidus_txns::types::{Event, Receipt, Transaction, TxPayload, TxStatus};

pub const CHAIN: u64 = 50_002;
pub const NETWORK: &str = "testnet";
pub const SEPOLIA: u32 = 11_155_111;
pub const MIRROR20: [u8; 20] = [
    0x5f, 0xbd, 0xb2, 0x31, 0x56, 0x78, 0xaf, 0xec, 0xb3, 0x67, 0xf0, 0x32, 0xd9, 0x3f, 0x64, 0x2f,
    0x64, 0x18, 0x0a, 0xa3,
];

pub fn mirror32() -> [u8; 32] {
    let mut m = [0u8; 32];
    m[12..].copy_from_slice(&MIRROR20);
    m
}

/// A V2 chain driven through BOTH executors every block; they must agree.
pub struct Chain {
    pub state: InMemoryState,
    pub height: u64,
    pub ts_ms: u64,
    pub parent_root: [u8; 32],
}

impl Chain {
    pub fn new() -> Self {
        Self {
            state: InMemoryState::new(),
            height: V2_ACTIVATION_HEIGHT,
            ts_ms: 1_758_000_000_000,
            parent_root: [0x77; 32],
        }
    }

    pub fn at_height(height: u64) -> Self {
        Self {
            height,
            ..Self::new()
        }
    }

    pub fn read(&self, key: &StateKey) -> Option<Vec<u8>> {
        self.state.get(key).expect("state read")
    }

    fn nonce_of(&self, key: &SigningKey) -> u64 {
        let addr = Address::from_public_key(&key.verifying_key());
        self.read(&StateKey::account(&addr))
            .map(|b| Account::from_bytes(&b).expect("account").nonce)
            .unwrap_or(0)
    }

    pub fn tx(&self, key: &SigningKey, payload: TxPayload) -> Transaction {
        let mode = solidus_exec::wire::wire_for_height(WireMode::BinaryV2, CHAIN, self.height);
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce: self.nonce_of(key),
            payload,
            signature: [0; 64],
        };
        tx.signature = sign(key, &solidus_exec::wire::signing_bytes(&tx, mode));
        tx
    }

    pub fn run(&mut self, txs: Vec<Transaction>) -> BlockOutcome {
        let ctx = BlockCtx {
            height: self.height,
            timestamp_ms: self.ts_ms,
            network: NETWORK,
            parent_state_root: self.parent_root,
        };
        let opts = ExecOptions::v2_defaults(CHAIN);
        let reference =
            execute_block_reference(&self.state, &txs, &ctx, &opts).expect("reference executor");
        let twolane =
            execute_block_twolane(&self.state, &txs, &ctx, &opts).expect("two-lane executor");
        assert_eq!(
            reference.receipts, twolane.receipts,
            "executors disagree on receipts"
        );
        assert_eq!(
            reference.block_events, twolane.block_events,
            "executors disagree on block events"
        );
        let mut a: Vec<_> = reference
            .delta
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut b: Vec<_> = twolane
            .delta
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        a.sort();
        b.sort();
        assert_eq!(a, b, "executors disagree on writes");
        self.state.apply_delta(&reference.delta);
        self.height += 1;
        self.ts_ms += 1_000;
        reference
    }

    pub fn run_one(&mut self, key: &SigningKey, payload: TxPayload) -> Receipt {
        let tx = self.tx(key, payload);
        self.run(vec![tx]).receipts.remove(0)
    }

    pub fn advance_secs(&mut self, secs: u64) {
        self.ts_ms += secs * 1_000;
    }
}

pub fn succeeded(r: &Receipt) -> bool {
    r.status == TxStatus::Success
}

pub fn failure(r: &Receipt) -> String {
    match &r.status {
        TxStatus::Failed(s) => s.clone(),
        TxStatus::Success => "success".into(),
    }
}

pub fn governor(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[0xB0 + i; 32])
}

pub fn submitter() -> SigningKey {
    SigningKey::from_bytes(&[0xC0; 32])
}

pub fn gov_payload(gov_nonce: u64, action: BridgeGovAction, signers: &[u8]) -> TxPayload {
    let msg = governance_signing_message(NETWORK, gov_nonce, &action);
    let approvals = signers
        .iter()
        .map(|i| {
            let k = governor(*i);
            GovernorApproval {
                public_key: k.verifying_key().to_bytes(),
                signature: sign(&k, &msg).to_vec(),
            }
        })
        .collect();
    TxPayload::BridgeGovernance {
        action,
        gov_nonce,
        approvals,
    }
}

pub fn register_action(domain: u32, vm: BridgeDomainVm, mirror: [u8; 32]) -> BridgeGovAction {
    BridgeGovAction::RegisterDomain {
        domain,
        vm,
        inbox: mirror,
        heartbeat_interval_secs: 600,
        enabled: true,
    }
}

pub fn register_evm_domain(chain: &mut Chain, domain: u32, gov_nonce: u64) {
    let r = chain.run_one(
        &submitter(),
        gov_payload(
            gov_nonce,
            register_action(domain, BridgeDomainVm::Evm, mirror32()),
            &[1, 2],
        ),
    );
    assert!(succeeded(&r), "{}", failure(&r));
}

pub struct Issuer {
    pub key: SigningKey,
    pub did: String,
}

pub fn issuer(chain: &mut Chain, seed: u8) -> Issuer {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let r = chain.run_one(
        &key,
        TxPayload::DidCreate {
            public_key: key.verifying_key().to_bytes(),
            service_endpoints: vec![],
        },
    );
    assert!(succeeded(&r), "{}", failure(&r));
    let did =
        solidus_txns::did::build_did(NETWORK, &Address::from_public_key(&key.verifying_key()));
    Issuer { key, did }
}

pub fn issue(chain: &mut Chain, issuer: &Issuer, credential_type: CredentialType) -> String {
    let subject_commitment = build_subject_commitment("did:solidus:testnet:holder", &[0x5a; 32]);
    let hash = [(chain.height % 251) as u8; 32];
    let r = chain.run_one(
        &issuer.key,
        TxPayload::CredentialIssueV2 {
            subject_commitment,
            credential_type,
            hash,
        },
    );
    assert!(succeeded(&r), "{}", failure(&r));
    r.events
        .iter()
        .find_map(|e| match e {
            Event::CredentialIssuedV2 { credential_id, .. } => Some(credential_id.clone()),
            _ => None,
        })
        .expect("CredentialIssuedV2 event")
}

/// Anvil account #1: a fixed secp256k1 key with a known address, so address
/// derivation is checked against an independent fact.
pub fn evm_holder() -> (k256::ecdsa::SigningKey, [u8; 32]) {
    let sk = k256::ecdsa::SigningKey::from_slice(
        &hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d").unwrap(),
    )
    .unwrap();
    let mut holder = [0u8; 32];
    holder[12..].copy_from_slice(&hex::decode("70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap());
    (sk, holder)
}

pub fn evm_consent(
    sk: &k256::ecdsa::SigningKey,
    credential_id: &str,
    domain: u32,
    holder: [u8; 32],
    consent_expiry: u64,
) -> Vec<u8> {
    let c = ExportConsent {
        credential_id: credential_id.into(),
        domain,
        holder,
        consent_expiry,
    };
    let digest = eip712_consent_digest(&c, u64::from(domain), &MIRROR20);
    let (sig, rid) = sk.sign_prehash_recoverable(&digest).expect("sign");
    let mut out = sig.to_bytes().to_vec();
    out.push(27 + rid.to_byte());
    out
}

pub fn export_payload(
    credential_id: &str,
    domain: u32,
    holder: [u8; 32],
    consent_sig: Vec<u8>,
    consent_expiry: u64,
) -> TxPayload {
    TxPayload::ExportCredential {
        credential_id: credential_id.into(),
        domain,
        holder,
        valid_until: 0,
        consent_sig,
        consent_expiry,
    }
}

pub fn outbox(chain: &Chain, domain: u32, seq: u64) -> BridgeMessage {
    let raw = chain
        .read(&StateKey::bridge_outbox(domain, seq))
        .expect("outbox entry");
    let entry: OutboxEntry = bincode::deserialize(&raw).expect("outbox decode");
    decode(&entry.message).expect("message decode")
}

pub fn last_seq(chain: &Chain, domain: u32) -> u64 {
    chain
        .read(&StateKey::bridge_seq(domain))
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0)
}
