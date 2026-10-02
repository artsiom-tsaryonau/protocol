#![allow(dead_code)] // shared by multiple test binaries; each uses a subset

//! Differential-parity harness: runs the same tx streams through the LIVE
//! executor (`solidus-state`, RocksDB tempdir) and the v2 serial reference
//! executor (`ExecOptions::legacy_anchor`), asserting byte-identical
//! receipts, per-namespace final state, and global state roots.
//!
//! Also home of the seeded stream generator reused by the Stage-3
//! two-lane-vs-oracle fuzz (same corpus shapes, different pair of
//! executors).

use std::collections::HashSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use solidus_crypto::bbs::BbsSecretKey;
use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_exec::{
    execute_block_reference, Account, AccountType, BlockCtx, ExecOptions, InMemoryState, StateKey,
    StateSpace,
};
use solidus_state::executor::{compute_state_root, execute_block as legacy_execute_block};
use solidus_state::store::{
    Store, CF_ACCOUNTS, CF_CREDENTIALS, CF_CRED_BY_ISSUER, CF_CRED_BY_SUBJECT, CF_DIDS,
    CF_VALIDATORS,
};
use solidus_state_tree::StateForest;
use solidus_txns::did::{DidPatch, GuardianApproval, Service};
use solidus_txns::staking::MIN_STAKE;
use solidus_txns::types::{Event, Receipt, Transaction, TxPayload};

pub const NETWORK: &str = "testnet";
pub const GENESIS_TS: u64 = 1_700_000_000_000;

// ---------------------------------------------------------------------------
// Dual-runner harness
// ---------------------------------------------------------------------------

pub struct Harness {
    pub store: Arc<Store>,
    _dir: tempfile::TempDir,
    pub baseline: InMemoryState,
    pub treasury: Address,
    pub validators: Vec<Address>,
    pub height: u64,
    seen_hashes: HashSet<[u8; 32]>,
    /// Cumulative count of transactions run through both executors.
    pub txs_executed: u64,
}

impl Harness {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store::open(dir.path()).expect("open store"));
        Self {
            store,
            _dir: dir,
            baseline: InMemoryState::new(),
            treasury: Address::from_bytes([0xAA; 20]),
            validators: vec![
                Address::from_bytes([0xB1; 20]),
                Address::from_bytes([0xB2; 20]),
                Address::from_bytes([0xB3; 20]),
            ],
            height: 1,
            seen_hashes: HashSet::new(),
            txs_executed: 0,
        }
    }

    /// Fund an account identically on both sides (also pins the v2/legacy
    /// account byte-encoding equality on every call).
    pub fn fund(&mut self, addr: Address, balance: u64) {
        let legacy = solidus_state::account::Account::with_balance(
            addr,
            balance,
            solidus_state::account::AccountType::Regular,
        );
        let v2 = Account::with_balance(addr, balance, AccountType::Regular);
        assert_eq!(
            legacy.to_bytes(),
            v2.to_bytes(),
            "v2 Account encoding must be byte-identical to the live chain's"
        );
        self.store
            .put(CF_ACCOUNTS, addr.as_bytes(), &legacy.to_bytes())
            .expect("legacy fund");
        self.baseline.set(StateKey::account(&addr), v2.to_bytes());
    }

    /// Execute one block on both executors and assert receipt parity.
    /// Returns the (identical) receipts.
    pub fn run_block(&mut self, txs: &[Transaction]) -> Vec<Receipt> {
        // The live executor's receipt-idempotency short-circuit makes a
        // repeated tx hash diverge by design (v2 dropped it); real streams
        // never repeat a hash, so the generator must not either.
        for tx in txs {
            assert!(
                self.seen_hashes.insert(tx.hash()),
                "stream generator emitted a duplicate tx hash — fix the generator"
            );
        }

        let ts = GENESIS_TS + self.height * 1_000;

        let legacy_receipts = legacy_execute_block(
            &self.store,
            txs,
            self.height,
            ts,
            &self.treasury,
            &self.validators,
            NETWORK,
        )
        .expect("legacy execute_block");

        let ctx = BlockCtx {
            height: self.height,
            timestamp_ms: ts,
            network: NETWORK,
            parent_state_root: [0u8; 32],
        };
        let opts = ExecOptions::legacy_anchor(self.treasury, self.validators.clone());
        let outcome = execute_block_reference(&self.baseline, txs, &ctx, &opts)
            .expect("reference execute_block");

        assert_eq!(
            legacy_receipts.len(),
            outcome.receipts.len(),
            "receipt count divergence at height {}",
            self.height
        );
        for (i, (l, v)) in legacy_receipts
            .iter()
            .zip(outcome.receipts.iter())
            .enumerate()
        {
            assert_eq!(
                l, v,
                "receipt divergence at height {} tx {i}:\n legacy: {l:?}\n v2:     {v:?}",
                self.height
            );
        }

        self.baseline.apply_delta(&outcome.delta);
        self.height += 1;
        self.txs_executed += txs.len() as u64;
        legacy_receipts
    }

    /// Full final-state + state-root parity assertion.
    pub fn assert_state_parity(&self) {
        // Per-namespace byte equality, both directions.
        let pairs: [(&str, StateSpace); 6] = [
            (
                CF_ACCOUNTS,
                StateSpace::Tree(solidus_state_tree::TreeId::Accounts),
            ),
            (CF_DIDS, StateSpace::Tree(solidus_state_tree::TreeId::Dids)),
            (
                CF_CREDENTIALS,
                StateSpace::Tree(solidus_state_tree::TreeId::Credentials),
            ),
            (
                CF_VALIDATORS,
                StateSpace::Tree(solidus_state_tree::TreeId::Validators),
            ),
            (CF_CRED_BY_SUBJECT, StateSpace::CredBySubject),
            (CF_CRED_BY_ISSUER, StateSpace::CredByIssuer),
        ];

        for (cf, space) in pairs {
            let legacy_entries = self.store.iter_cf(cf).expect("iter cf");
            let v2_entries: Vec<(Vec<u8>, Vec<u8>)> = self
                .baseline
                .iter()
                .filter(|(k, _)| k.space == space)
                .map(|(k, v)| (k.key.clone(), v.clone()))
                .collect();

            assert_eq!(
                legacy_entries.len(),
                v2_entries.len(),
                "entry-count divergence in {cf}: legacy {} vs v2 {}",
                legacy_entries.len(),
                v2_entries.len()
            );
            // Both iterate in ascending key order (RocksDB / BTreeMap).
            for ((lk, lv), (vk, vv)) in legacy_entries.iter().zip(v2_entries.iter()) {
                assert_eq!(lk, vk, "key divergence in {cf}");
                assert_eq!(
                    lv,
                    vv,
                    "value divergence in {cf} at key {}",
                    String::from_utf8_lossy(lk)
                );
            }
        }

        // Global state root: live full-rescan vs v2 incremental forest.
        let legacy_root = compute_state_root(&self.store).expect("legacy root");
        let mut forest = StateForest::new();
        self.baseline.seed_forest(&mut forest);
        let v2_root = forest.global_root();
        assert_eq!(
            legacy_root, v2_root,
            "GLOBAL STATE ROOT divergence after {} txs",
            self.txs_executed
        );
    }
}

// ---------------------------------------------------------------------------
// Tx builders (legacy wire — parity anchor signs like the live chain)
// ---------------------------------------------------------------------------

pub fn sign_tx(key: &SigningKey, nonce: u64, payload: TxPayload) -> Transaction {
    sign_tx_mode(key, nonce, payload, solidus_exec::WireMode::LegacyJson)
}

pub fn sign_tx_mode(
    key: &SigningKey,
    nonce: u64,
    payload: TxPayload,
    mode: solidus_exec::WireMode,
) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: key.verifying_key().to_bytes(),
        nonce,
        payload,
        signature: [0u8; 64],
    };
    let msg = solidus_exec::wire::signing_bytes(&tx, mode);
    tx.signature = sign(key, &msg);
    tx
}

// ---------------------------------------------------------------------------
// Seeded stream generator
// ---------------------------------------------------------------------------

pub struct ActorState {
    pub key: SigningKey,
    pub addr: Address,
    pub nonce: u64,
    pub balance: u64,
    pub has_did: bool,
}

pub struct StreamGen {
    rng: StdRng,
    pub actors: Vec<ActorState>,
    bbs_pubkey: [u8; 96],
    /// (issuer_did, credential_id) pairs observed in receipts.
    credentials: Vec<(String, String)>,
    service_counter: u64,
    /// Wire mode every generated tx is signed under.
    pub mode: solidus_exec::WireMode,
}

impl StreamGen {
    /// Create actors and fund a slice of them through the harness:
    /// ~55% funded value accounts (a few rich enough to stake), the rest
    /// pristine identity-key candidates.
    pub fn new(seed: u64, n_actors: usize, harness: &mut Harness) -> Self {
        Self::new_with(
            seed,
            n_actors,
            solidus_exec::WireMode::LegacyJson,
            &mut |a, b| harness.fund(a, b),
        )
    }

    /// v2-mode generator funding a bare in-memory state (no legacy store).
    pub fn new_v2(
        seed: u64,
        n_actors: usize,
        state: &mut InMemoryState,
        mode: solidus_exec::WireMode,
    ) -> Self {
        Self::new_with(seed, n_actors, mode, &mut |addr, balance| {
            let acct = Account::with_balance(addr, balance, AccountType::Regular);
            state.set(StateKey::account(&addr), acct.to_bytes());
        })
    }

    fn new_with(
        seed: u64,
        n_actors: usize,
        mode: solidus_exec::WireMode,
        fund: &mut dyn FnMut(Address, u64),
    ) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut actors = Vec::with_capacity(n_actors);
        for i in 0..n_actors {
            let key = generate_signing_key();
            let addr = Address::from_public_key(&key.verifying_key());
            let funded = i % 100 < 55;
            let balance = if funded {
                if rng.gen_bool(0.3) {
                    // Rich: can stake MIN_STAKE multiple times.
                    MIN_STAKE * 3 + 1_000_000
                } else {
                    rng.gen_range(50_000..5_000_000)
                }
            } else {
                0
            };
            if balance > 0 {
                fund(addr, balance);
            }
            actors.push(ActorState {
                key,
                addr,
                nonce: 0,
                balance,
                has_did: false,
            });
        }

        let bbs_sk =
            BbsSecretKey::from_ikm(b"parity-harness-bbs-ikm-32-bytes-or-more").expect("bbs ikm");
        let bbs_pubkey = bbs_sk.public_key().to_bytes();

        Self {
            rng,
            actors,
            bbs_pubkey,
            credentials: Vec::new(),
            service_counter: 0,
            mode,
        }
    }

    fn did_of(&self, idx: usize) -> String {
        solidus_txns::did::build_did(NETWORK, &self.actors[idx].addr)
    }

    fn pick(&mut self, pred: impl Fn(&ActorState) -> bool) -> Option<usize> {
        let candidates: Vec<usize> = self
            .actors
            .iter()
            .enumerate()
            .filter(|(_, a)| pred(a))
            .map(|(i, _)| i)
            .collect();
        if candidates.is_empty() {
            None
        } else {
            Some(candidates[self.rng.gen_range(0..candidates.len())])
        }
    }

    /// Generate one block of up to `max_txs` mixed transactions. Uses
    /// optimistic local mirrors for nonce/balance plausibility; the caller
    /// refreshes mirrors from executed state via [`StreamGen::refresh`].
    pub fn gen_block(&mut self, max_txs: usize) -> Vec<Transaction> {
        let n = self.rng.gen_range(1..=max_txs.max(1));
        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(tx) = self.gen_tx() {
                txs.push(tx);
            }
        }
        txs
    }

    fn gen_tx(&mut self) -> Option<Transaction> {
        let roll = self.rng.gen_range(0u32..100);
        match roll {
            // ---- Transfers (with deliberate failure shapes) -------------
            0..=29 => {
                let s = self.pick(|a| a.balance > 20_000 && !a.has_did)?;
                let variant = self.rng.gen_range(0u32..10);
                let (to, amount) = match variant {
                    // to a DID anchor → anchor-guard failure
                    0 => {
                        let anchor = self.pick(|a| a.has_did)?;
                        (self.actors[anchor].addr, 1_000)
                    }
                    // self-transfer → token-level failure
                    1 => (self.actors[s].addr, 1_000),
                    // zero amount → token-level failure
                    2 => {
                        let t = self.pick(|a| !a.has_did)?;
                        (self.actors[t].addr, 0)
                    }
                    // over-balance → token-level failure
                    3 => {
                        let t = self.pick(|a| !a.has_did)?;
                        (self.actors[t].addr, self.actors[s].balance * 2 + 1)
                    }
                    // honest transfer
                    _ => {
                        let t = self.pick(|a| !a.has_did)?;
                        let cap = (self.actors[s].balance - 20_000).max(1);
                        (self.actors[t].addr, self.rng.gen_range(1..=cap))
                    }
                };
                let nonce = self.actors[s].nonce;
                let tx = sign_tx_mode(
                    &self.actors[s].key,
                    nonce,
                    TxPayload::Transfer { to, amount },
                    self.mode,
                );
                // Optimistic mirror: fee always charged past step 5; amount
                // only on the honest shape.
                self.actors[s].nonce += 1;
                let fee = 10_000u64;
                let spend = if variant >= 4 { amount + fee } else { fee };
                self.actors[s].balance = self.actors[s].balance.saturating_sub(spend);
                if variant >= 4 {
                    if let Some(t) = self.actors.iter_mut().find(|a| a.addr == to) {
                        t.balance += amount;
                    }
                }
                Some(tx)
            }
            // ---- DidCreate ----------------------------------------------
            30..=39 => {
                if self.rng.gen_bool(0.15) {
                    // Non-pristine create → pristine-rule failure
                    let s = self.pick(|a| a.balance > 0 && a.nonce == 0 && !a.has_did)?;
                    let pk = self.actors[s].key.verifying_key().to_bytes();
                    let tx = sign_tx_mode(
                        &self.actors[s].key,
                        0,
                        TxPayload::DidCreate {
                            public_key: pk,
                            service_endpoints: vec![],
                        },
                        self.mode,
                    );
                    self.actors[s].nonce += 1;
                    Some(tx)
                } else {
                    let s = self.pick(|a| a.balance == 0 && a.nonce == 0 && !a.has_did)?;
                    let pk = self.actors[s].key.verifying_key().to_bytes();
                    let tx = sign_tx_mode(
                        &self.actors[s].key,
                        0,
                        TxPayload::DidCreate {
                            public_key: pk,
                            service_endpoints: vec![],
                        },
                        self.mode,
                    );
                    self.actors[s].nonce += 1;
                    self.actors[s].has_did = true;
                    Some(tx)
                }
            }
            // ---- DidUpdate ----------------------------------------------
            40..=47 => {
                let s = self.pick(|a| a.has_did)?;
                let own = self.rng.gen_bool(0.8);
                let target = if own {
                    self.did_of(s)
                } else {
                    // someone else's DID (or a missing one) → auth/not-found failure
                    match self.pick(|a| a.has_did) {
                        Some(o) if o != s => self.did_of(o),
                        _ => format!("did:solidus:{NETWORK}:missing{}", self.rng.gen::<u32>()),
                    }
                };
                self.service_counter += 1;
                let patches = if self.rng.gen_bool(0.7) {
                    vec![DidPatch::AddService(Service {
                        id: format!("svc-{}", self.service_counter),
                        service_type: "MessagingService".to_string(),
                        service_endpoint: format!("https://svc.example/{}", self.service_counter),
                    })]
                } else {
                    vec![]
                };
                let nonce = self.actors[s].nonce;
                let tx = sign_tx_mode(
                    &self.actors[s].key,
                    nonce,
                    TxPayload::DidUpdate {
                        did: target,
                        patches,
                    },
                    self.mode,
                );
                self.actors[s].nonce += 1;
                Some(tx)
            }
            // ---- DidDeactivate ------------------------------------------
            48..=51 => {
                let s = self.pick(|a| a.has_did)?;
                let nonce = self.actors[s].nonce;
                let did = self.did_of(s);
                let tx = sign_tx_mode(
                    &self.actors[s].key,
                    nonce,
                    TxPayload::DidDeactivate { did },
                    self.mode,
                );
                self.actors[s].nonce += 1;
                Some(tx)
            }
            // ---- CredentialIssue ----------------------------------------
            52..=63 => {
                let issuer = self.pick(|a| a.has_did)?;
                let subject_did = if self.rng.gen_bool(0.85) {
                    let subject = self.pick(|a| a.has_did)?;
                    self.did_of(subject)
                } else {
                    format!("did:solidus:{NETWORK}:nosubject{}", self.rng.gen::<u32>())
                };
                let mut hash = [0u8; 32];
                self.rng.fill(&mut hash);
                let nonce = self.actors[issuer].nonce;
                let tx = sign_tx_mode(
                    &self.actors[issuer].key,
                    nonce,
                    TxPayload::CredentialIssue {
                        subject_did,
                        credential_type: random_credential_type(&mut self.rng),
                        hash,
                    },
                    self.mode,
                );
                self.actors[issuer].nonce += 1;
                Some(tx)
            }
            // ---- CredentialIssueBbs -------------------------------------
            64..=69 => {
                let issuer = self.pick(|a| a.has_did)?;
                let subject = self.pick(|a| a.has_did)?;
                let subject_did = self.did_of(subject);
                let bbs_pubkey = if self.rng.gen_bool(0.85) {
                    self.bbs_pubkey
                } else {
                    [0u8; 96] // invalid G2 point → handler failure
                };
                let mut hash = [0u8; 32];
                self.rng.fill(&mut hash);
                let nonce = self.actors[issuer].nonce;
                let tx = sign_tx_mode(
                    &self.actors[issuer].key,
                    nonce,
                    TxPayload::CredentialIssueBbs {
                        subject_did,
                        credential_type: random_credential_type(&mut self.rng),
                        hash,
                        bbs_pubkey,
                        bbs_message_count: self.rng.gen_range(1..=12),
                    },
                    self.mode,
                );
                self.actors[issuer].nonce += 1;
                Some(tx)
            }
            // ---- CredentialRevoke ---------------------------------------
            70..=75 => {
                if !self.credentials.is_empty() && self.rng.gen_bool(0.8) {
                    let idx = self.rng.gen_range(0..self.credentials.len());
                    let (issuer_did, cred_id) = self.credentials[idx].clone();
                    // 75%: the true issuer revokes; 25%: someone else tries.
                    let s = if self.rng.gen_bool(0.75) {
                        self.actors.iter().position(|a| {
                            a.has_did
                                && solidus_txns::did::build_did(NETWORK, &a.addr) == issuer_did
                        })?
                    } else {
                        self.pick(|a| a.has_did)?
                    };
                    let nonce = self.actors[s].nonce;
                    let tx = sign_tx_mode(
                        &self.actors[s].key,
                        nonce,
                        TxPayload::CredentialRevoke {
                            credential_id: cred_id,
                        },
                        self.mode,
                    );
                    self.actors[s].nonce += 1;
                    Some(tx)
                } else {
                    let s = self.pick(|a| a.has_did)?;
                    let nonce = self.actors[s].nonce;
                    let tx = sign_tx_mode(
                        &self.actors[s].key,
                        nonce,
                        TxPayload::CredentialRevoke {
                            credential_id: format!(
                                "urn:solidus:credential:missing{}",
                                self.rng.gen::<u32>()
                            ),
                        },
                        self.mode,
                    );
                    self.actors[s].nonce += 1;
                    Some(tx)
                }
            }
            // ---- Stake / Unstake ----------------------------------------
            76..=83 => {
                let s = self.pick(|a| a.balance > 100_000 && !a.has_did)?;
                let amount =
                    if self.actors[s].balance > MIN_STAKE + 20_000 && self.rng.gen_bool(0.7) {
                        MIN_STAKE
                    } else {
                        // below MIN_STAKE or over-balance → staking failure
                        self.rng.gen_range(1..=100_000)
                    };
                let nonce = self.actors[s].nonce;
                let tx = sign_tx_mode(
                    &self.actors[s].key,
                    nonce,
                    TxPayload::Stake { amount },
                    self.mode,
                );
                self.actors[s].nonce += 1;
                self.actors[s].balance = self.actors[s].balance.saturating_sub(amount + 10_000);
                Some(tx)
            }
            84..=87 => {
                let s = self.pick(|a| a.balance > 20_000 && !a.has_did)?;
                let amount = if self.rng.gen_bool(0.5) {
                    MIN_STAKE // full unstake if they staked exactly MIN_STAKE
                } else {
                    self.rng.gen_range(1..MIN_STAKE) // partial-below-min or non-validator
                };
                let nonce = self.actors[s].nonce;
                let tx = sign_tx_mode(
                    &self.actors[s].key,
                    nonce,
                    TxPayload::Unstake { amount },
                    self.mode,
                );
                self.actors[s].nonce += 1;
                Some(tx)
            }
            // ---- DidRecover failure shapes ------------------------------
            88..=90 => {
                let s = self.pick(|a| a.has_did)?;
                let nonce = self.actors[s].nonce;
                let own_pk = self.actors[s].key.verifying_key().to_bytes();
                let tx = if self.rng.gen_bool(0.5) {
                    // new_public_key != sender pubkey → envelope-rule failure
                    sign_tx_mode(
                        &self.actors[s].key,
                        nonce,
                        TxPayload::DidRecover {
                            did: self.did_of(s),
                            new_public_key: [7u8; 32],
                            approvals: vec![],
                        },
                        self.mode,
                    )
                } else {
                    // matching key, no guardians configured → threshold failure
                    sign_tx_mode(
                        &self.actors[s].key,
                        nonce,
                        TxPayload::DidRecover {
                            did: self.did_of(s),
                            new_public_key: own_pk,
                            approvals: vec![GuardianApproval {
                                guardian_did: format!(
                                    "did:solidus:{NETWORK}:ghost{}",
                                    self.rng.gen::<u32>()
                                ),
                                signature: vec![0u8; 64],
                            }],
                        },
                        self.mode,
                    )
                };
                self.actors[s].nonce += 1;
                Some(tx)
            }
            // ---- Garbage: bad signature / bad nonce / drained fee -------
            _ => {
                // These shapes never advance the on-chain nonce, so the
                // uniquifier in `amount` is what keeps repeated picks of
                // the same actor from producing identical tx bytes (the
                // live executor's receipt cache would otherwise diverge
                // from v2 by design — see run_block).
                self.service_counter += 1;
                let uniq_amount = 100_000 + self.service_counter;
                let s = self.rng.gen_range(0..self.actors.len());
                let variant = self.rng.gen_range(0u32..3);
                let to = Address::from_bytes([0xEF; 20]);
                match variant {
                    0 => {
                        // Corrupt signature — no nonce consumed on-chain.
                        let nonce = self.actors[s].nonce;
                        let mut tx = sign_tx_mode(
                            &self.actors[s].key,
                            nonce,
                            TxPayload::Transfer {
                                to,
                                amount: uniq_amount,
                            },
                            self.mode,
                        );
                        tx.signature[7] ^= 0xFF;
                        Some(tx)
                    }
                    1 => {
                        // Wrong nonce — rejected before nonce bump.
                        let nonce = self.actors[s].nonce + 5;
                        Some(sign_tx_mode(
                            &self.actors[s].key,
                            nonce,
                            TxPayload::Transfer {
                                to,
                                amount: uniq_amount,
                            },
                            self.mode,
                        ))
                    }
                    _ => {
                        // Fee-poor sender (balance 0 non-DID actor).
                        let s = self.pick(|a| a.balance == 0 && a.nonce == 0 && !a.has_did)?;
                        let nonce = self.actors[s].nonce;
                        Some(sign_tx_mode(
                            &self.actors[s].key,
                            nonce,
                            TxPayload::Transfer {
                                to,
                                amount: uniq_amount,
                            },
                            self.mode,
                        ))
                    }
                }
            }
        }
    }

    /// Re-sync every actor mirror from executed v2 state and harvest
    /// credential ids from the block's receipts.
    pub fn refresh(&mut self, harness: &Harness, receipts: &[Receipt]) {
        self.refresh_v2(&harness.baseline, receipts)
    }

    /// Same, against a bare in-memory state (v2-only differentials).
    pub fn refresh_v2(&mut self, baseline: &InMemoryState, receipts: &[Receipt]) {
        use solidus_exec::StateReader;
        for actor in &mut self.actors {
            match baseline
                .get(&StateKey::account(&actor.addr))
                .expect("baseline read")
            {
                Some(bytes) => {
                    let acct = Account::from_bytes(&bytes).expect("account decode");
                    actor.nonce = acct.nonce;
                    actor.balance = acct.balance;
                }
                None => {
                    actor.nonce = 0;
                    actor.balance = 0;
                }
            }
            let did = solidus_txns::did::build_did(NETWORK, &actor.addr);
            actor.has_did = baseline
                .get(&StateKey::did(&did))
                .expect("baseline read")
                .is_some();
        }
        for receipt in receipts {
            for event in &receipt.events {
                if let Event::CredentialIssued {
                    credential_id,
                    issuer,
                    ..
                } = event
                {
                    self.credentials
                        .push((issuer.clone(), credential_id.clone()));
                }
            }
        }
    }
}

fn random_credential_type(rng: &mut StdRng) -> solidus_txns::credential::CredentialType {
    use solidus_txns::credential::CredentialType;
    match rng.gen_range(0u32..4) {
        0 => CredentialType::Email,
        1 => CredentialType::Phone,
        2 => CredentialType::KycL1,
        _ => CredentialType::KycL2,
    }
}
