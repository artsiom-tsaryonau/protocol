//! What the RPC edge needs from the node, and a Store2-backed impl.

use std::sync::{Arc, Mutex};

use solidus_crypto::keys::Address;
use solidus_exec::{Account, StateKey, StateReader};
use solidus_store2::Store2;
use solidus_txns::types::{Receipt, Transaction};

/// The node capabilities the JSON-RPC edge exposes. Reads are over
/// **committed** state (store2's persisted CFs); submit hands a
/// signature-checked-elsewhere tx into the mempool.
pub trait RpcBackend: Send + Sync + 'static {
    /// Committed balance of `addr` (0 if the account was never seen).
    fn balance(&self, addr: &Address) -> u64;
    /// Committed nonce of `addr`.
    fn nonce(&self, addr: &Address) -> u64;
    /// Newest committed block height.
    fn block_height(&self) -> u64;
    /// Global state root at the newest committed height.
    fn state_root(&self) -> [u8; 32];
    /// Receipt for a tx by (height, tx hash), if persisted.
    fn receipt(&self, height: u64, tx_hash: &[u8; 32]) -> Option<Receipt>;

    /// Height of the block a transaction was included in, if any.
    ///
    /// ⛔ WITHOUT THIS, CONFIRMING A TRANSACTION ON v2 IS IMPOSSIBLE FROM A
    /// CLIENT THAT ONLY HAS THE HASH. `receipt` needs a height, and a submitter
    /// gets back a hash — v1 let callers poll by hash alone, so an SDK ported
    /// straight across cannot confirm anything. The store has carried the index
    /// (`tx_index`: tx_hash → height) since receipts were written; only the
    /// lookup was missing.
    fn tx_height(&self, tx_hash: &[u8; 32]) -> Option<u64>;
    /// Submit a transaction to the mempool. Returns the v2 tx hash.
    fn submit(&self, tx: Transaction) -> Result<[u8; 32], String>;

    /// The canonical head as `(height, block hash)`, or `None` on a chain that
    /// has committed nothing.
    ///
    /// ⚠ THIS IS THE PERSISTED HEAD, WHICH IS NOT `block_height()`.
    /// `block_height` reads the in-memory exec anchor; this reads the store.
    /// They agree in steady state and can differ around a restart. v1 exposes
    /// both for the same reason: its own `canonHead.seq` and
    /// `chainInfo.latest_block` differed by ~1,800 when measured 2026-09-02.
    fn canon_head(&self) -> Option<(u64, [u8; 32])>;

    /// Raw state read for bridge records. Default: not served.
    fn state_value(&self, _key: &StateKey) -> Option<Vec<u8>> {
        None
    }

    fn state_proof(&self, _tree: u8, _key: &[u8]) -> Result<ProofBundle, ProofError> {
        Err(ProofError::Unavailable)
    }

    /// THIS NODE'S signature for one outbox entry, or `None` if it has not signed that sequence.
    ///
    /// ⚠ ONE NODE'S VIEW, NEVER AN AGGREGATE. A mirror needs m of n signatures over one digest and
    /// this serves exactly one of them; four validators means four calls. Nothing here knows the
    /// threshold, and a caller that treats one signature as sufficient has misread the protocol.
    fn attestation(&self, _domain: u32, _seq: u64) -> Option<[u8; 65]> {
        None
    }

    /// The address this node's attestations recover to. `None` on a node that does not attest,
    /// which is a supported configuration and not an error.
    fn attestation_signer(&self) -> Option<[u8; 20]> {
        None
    }
    fn committee_info(&self) -> Option<CommitteeInfo> {
        None
    }
    fn finality_evidence(&self, _at_or_above: u64) -> Option<EvidenceBytes> {
        None
    }

    /// Network identity: `(network name, genesis hash)`.
    ///
    /// ⚠ THE NAME, NOT THE NUMBER. v1's `chainInfo.chain_id` is a STRING -
    /// "solidus-testnet-1" - measured live on 2026-09-02. v2's `chain_id` is a
    /// u64 (50002). Returning the number under that key would satisfy a type
    /// checker and break every caller parsing it, so the network NAME is what
    /// goes out.
    fn chain_identity(&self) -> (String, [u8; 32]);

    /// Numeric chain id (the header's `chain_id`), bound into V3 signatures.
    fn chain_id_numeric(&self) -> u64;

    /// A committed block by height, if this node holds it.
    fn block_at(&self, height: u64) -> Option<RpcBlock>;

    /// The stored DID document, if this DID exists.
    ///
    /// Returns the DOMAIN type. Shaping it for the wire is the method's job,
    /// and deliberately not serde's - see `methods::did_resolve`.
    fn did_document(&self, did: &str) -> Option<solidus_txns::did::DidDocument>;

    /// The stored credential record, if this id exists.
    ///
    /// Returns the DOMAIN type. Choosing which of its fields leave the node is
    /// the method's job - see `methods::credential_verify`.
    fn credential(&self, id: &str) -> Option<solidus_txns::credential::CredentialRecord>;

    /// Every validator record in committed state.
    fn validators(&self) -> Vec<solidus_txns::staking::ValidatorInfo>;

    /// One validator by address, or `None`.
    fn validator(&self, addr: &Address) -> Option<solidus_txns::staking::ValidatorInfo>;

    /// Whether this node serves subject enumeration. **Closed by default.**
    fn subject_enumeration_allowed(&self) -> bool;

    /// Credential ids recorded against a subject DID.
    fn credential_ids_by_subject(&self, did: &str) -> Vec<String>;

    /// Seconds since this RPC edge was constructed.
    fn uptime_seconds(&self) -> u64;

    /// A committed transaction by hash, if this node still holds it.
    ///
    /// ⚠ `None` MEANS "NOT FOUND HERE", NOT "NEVER EXISTED". After pruning the
    /// index entry and the batch body are both gone, so a caller must not read
    /// this as proof of absence.
    fn transaction(&self, tx_hash: &[u8; 32]) -> Option<Transaction>;

    /// Credential ids recorded against an issuer DID.
    ///
    /// ⚠ NOT GATED, and that asymmetry is deliberate rather than an oversight.
    /// Subject enumeration is a correlation handle over a person; listing what
    /// an issuer issued is a property of a public entity. v1 gates the first
    /// and not the second, and this matches it.
    fn credential_ids_by_issuer(&self, did: &str) -> Vec<String>;
}

/// What the RPC edge serves for a block.
///
/// ⛔ THIS IS NOT v1's BLOCK SHAPE AND CANNOT BE. v1 returns
/// `transactions_root` and a `state_root` describing the block's POST-state.
/// A v2 block carries `batch_certs` - the body by digest - has no transactions
/// root, and its `exec_state_root` is the anchor the proposer had executed,
/// which TRAILS the block. Emitting that under the name `state_root` would be
/// a lie a caller cannot detect, so the v2 names are kept and the absent field
/// is absent rather than faked.
///
/// ⚠ Phase 3 parity must treat this method as a DOCUMENTED DIVERGENCE, not a
/// mismatch to fix.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcBlock {
    pub height: u64,
    pub view: u64,
    pub hash: String,
    pub parent_hash: String,
    /// The proposer's exec anchor, NOT this block's post-state root.
    pub exec_height: u64,
    pub exec_state_root: String,
    pub timestamp_ms: u64,
    pub proposer: u32,
    pub tx_count: usize,
    /// Hex tx hashes carried by this block, in order.
    ///
    /// ⛔ WITHOUT THIS NOTHING CAN INDEX A v2 BLOCK. A v2 block carries
    /// `batch_certs` — its body by DIGEST — so unlike v1 there is no
    /// transaction list in the block itself, and a consumer holding only a
    /// block has no way to enumerate what is in it. The explorer's indexer
    /// reads `block.transactions`, and against v2 that was `undefined`.
    ///
    /// Costs nothing to produce: the node already walks every batch body to
    /// compute `tx_count`, and previously threw the transactions away.
    ///
    /// ⚠ A LOWER BOUND ON A PRUNED NODE, exactly like `tx_count`. A batch body
    /// this node no longer holds contributes neither, which is honest — the
    /// alternative is a count that disagrees with the list.
    pub transactions: Vec<String>,
}

/// Node-supplied readers. Boxed closures rather than trait methods because each
/// needs types this crate deliberately does not depend on.
type BlockReader = Box<dyn Fn(u64) -> Option<RpcBlock> + Send + Sync>;
type TxReader = Box<dyn Fn(&[u8; 32]) -> Option<Transaction> + Send + Sync>;
type Submitter = Box<dyn Fn(Transaction) -> Result<[u8; 32], String> + Send + Sync>;

/// One state proof, taken atomically against the executed state at `height`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundle {
    pub height: u64,
    pub global_root: [u8; 32],
    /// accounts, dids, credentials, validators
    pub sub_roots: [[u8; 32]; 4],
    pub value: Option<Vec<u8>>,
    pub proof: Option<([u8; 32], Vec<[u8; 32]>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// The forest moved between reading the anchor and the tree; retry.
    StateAdvancing,
    BadTree,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeInfo {
    pub chain_id: u64,
    pub quorum: usize,
    pub pop_activation_view: u64,
    /// (index, 48-byte BLS public key, optional 96-byte proof of possession, optional 20-byte
    /// bridge attestation address as the node's config declares it)
    ///
    /// ⚠ THE ADDRESS IS CONFIG, NOT CHAIN STATE. `run.rs` refuses to boot when this node's own key
    /// does not match its declared address, so for this node it is proven; for the others it is
    /// what the operator wrote. Plan 11 Task 7 Step 2 expected this field and it was never emitted.
    pub validators: Vec<(u32, [u8; 48], Option<[u8; 96]>, Option<[u8; 20]>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBytes {
    pub height: u64,
    pub parent_header: Vec<u8>,
    pub child_block: Vec<u8>,
    pub child_qc: Vec<u8>,
    pub l1_height: u64,
    pub global_root: [u8; 32],
    pub sub_roots: [[u8; 32]; 4],
}

pub type Prover = Box<dyn Fn(u8, &[u8]) -> Result<ProofBundle, ProofError> + Send + Sync>;
pub type EvidenceReader = Box<dyn Fn(u64) -> Option<EvidenceBytes> + Send + Sync>;

pub struct BridgeSources {
    pub prove: Prover,
    pub finality_evidence: EvidenceReader,
    pub committee: CommitteeInfo,
}

/// Reads from a shared [`Store2`]; height/root from a shared exec anchor
/// (kept current by the node's commit path); submit through a callback
/// (the node wires this to `NodeInput::SubmitTx`).
pub struct Store2Backend {
    store: Arc<Store2>,
    /// (height, global root) of the newest executed block.
    anchor: Arc<Mutex<(u64, [u8; 32])>>,
    /// Network NAME, e.g. "v2-devnet-50002". Served as `chainInfo.chain_id`
    /// because that is what v1 puts there.
    network: String,
    /// Decodes a stored block. Supplied as a CLOSURE, mirroring `submit`,
    /// because decoding a `Block2` needs consensus types and this crate
    /// deliberately does not depend on `solidus-hotstuff2` - the backend trait
    /// exists so the RPC edge stays independent of consensus.
    read_block: BlockReader,
    /// Resolves a transaction by hash. A closure for the same reason
    /// `read_block` is: it must decode a `Block2` and its `Batch` bodies, and
    /// this crate deliberately does not depend on consensus.
    read_tx: TxReader,
    genesis_hash: [u8; 32],
    chain_id: u64,
    /// Read ONCE at construction, never per call.
    ///
    /// ⛔ ANYTHING OTHER THAN EXACTLY "1" OR "true" LEAVES IT CLOSED,
    /// including the empty string, so a blank entry in a unit file cannot
    /// silently open subject enumeration.
    allow_subject_enumeration: bool,
    /// Addresses of the LIVE CONSENSUS COMMITTEE, derived once at construction.
    ///
    /// ⛔ WITHOUT THIS `solidus_getValidators` RETURNS `[]` ON A HEALTHY CHAIN.
    /// Genesis seeds accounts only (`noded/run.rs`), and a v2 validator has no
    /// address at all: the config gives it a BLS pubkey and an index, while the
    /// genesis allocations are separate funded dev accounts. So the Validators
    /// state space is empty even while four nodes are visibly producing blocks,
    /// and the explorer honestly rendered "ACTIVE VALIDATORS 0 · 0% of 0".
    ///
    /// v1 solved this the same way and its comment states the rule: the RPC
    /// should reflect "the live voters even when no on-chain staking
    /// transactions exist". See `solidus-rpc/src/methods.rs::get_validators`.
    committee: Vec<Address>,
    /// When this edge was built, for `nodeInfo.uptime_seconds`.
    started: std::time::Instant,
    submit: Submitter,
    wire: solidus_exec::WireMode,
    /// Proofs, finality evidence and the committee (bridge plan 02). `None`
    /// until the node wires them, and then the methods answer "not served".
    bridge: Option<BridgeSources>,
    /// The address this node signs bridge attestations as, set by `solidus-noded` when a key is
    /// configured. `None` means this node does not attest.
    attestation_signer: Option<[u8; 20]>,
}

impl Store2Backend {
    // Nine constructor arguments, over clippy's threshold of seven. It was already
    // over at eight before `chain_id` was added here; the alternative is a builder or
    // a params struct for a type constructed in exactly four places, three of them
    // tests. Allowed with the count stated so the next argument is a deliberate choice.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<Store2>,
        anchor: Arc<Mutex<(u64, [u8; 32])>>,
        network: String,
        genesis_hash: [u8; 32],
        chain_id: u64,
        committee: Vec<Address>,
        read_block: impl Fn(u64) -> Option<RpcBlock> + Send + Sync + 'static,
        read_tx: impl Fn(&[u8; 32]) -> Option<Transaction> + Send + Sync + 'static,
        submit: impl Fn(Transaction) -> Result<[u8; 32], String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            store,
            anchor,
            network,
            genesis_hash,
            chain_id,
            committee,
            started: std::time::Instant::now(),
            allow_subject_enumeration: std::env::var("SOLIDUS_RPC_ALLOW_SUBJECT_ENUMERATION")
                .map(|v| {
                    let v = v.trim().to_ascii_lowercase();
                    v == "1" || v == "true"
                })
                .unwrap_or(false),
            read_block: Box::new(read_block),
            read_tx: Box::new(read_tx),
            submit: Box::new(submit),
            wire: solidus_exec::WireMode::BinaryV2,
            bridge: None,
            attestation_signer: None,
        }
    }

    /// Declare the address this node's attestations recover to.
    ///
    /// A tenth constructor argument was the alternative and the constructor's own comment already
    /// says nine is over the threshold, so this follows `with_bridge_sources`.
    pub fn with_attestation_signer(mut self, signer: [u8; 20]) -> Self {
        self.attestation_signer = Some(signer);
        self
    }

    pub fn with_bridge_sources(mut self, sources: BridgeSources) -> Self {
        self.bridge = Some(sources);
        self
    }

    fn account(&self, addr: &Address) -> Account {
        match self.store.get(&StateKey::account(addr)) {
            Ok(Some(bytes)) => Account::from_bytes(&bytes).unwrap_or_else(|_| Account::new(*addr)),
            _ => Account::new(*addr),
        }
    }
}

impl RpcBackend for Store2Backend {
    fn state_value(&self, key: &StateKey) -> Option<Vec<u8>> {
        self.store.get(key).ok().flatten()
    }

    fn attestation(&self, domain: u32, seq: u64) -> Option<[u8; 65]> {
        self.store.attestation(domain, seq).ok().flatten()
    }

    fn attestation_signer(&self) -> Option<[u8; 20]> {
        self.attestation_signer
    }

    fn state_proof(&self, tree: u8, key: &[u8]) -> Result<ProofBundle, ProofError> {
        self.bridge
            .as_ref()
            .map_or(Err(ProofError::Unavailable), |b| (b.prove)(tree, key))
    }
    fn committee_info(&self) -> Option<CommitteeInfo> {
        self.bridge.as_ref().map(|b| b.committee.clone())
    }
    fn finality_evidence(&self, at_or_above: u64) -> Option<EvidenceBytes> {
        self.bridge
            .as_ref()
            .and_then(|b| (b.finality_evidence)(at_or_above))
    }

    fn balance(&self, addr: &Address) -> u64 {
        self.account(addr).balance
    }

    fn nonce(&self, addr: &Address) -> u64 {
        self.account(addr).nonce
    }

    fn block_height(&self) -> u64 {
        #[allow(clippy::expect_used)]
        self.anchor.lock().expect("anchor poisoned").0
    }

    fn state_root(&self) -> [u8; 32] {
        #[allow(clippy::expect_used)]
        self.anchor.lock().expect("anchor poisoned").1
    }

    fn receipt(&self, height: u64, tx_hash: &[u8; 32]) -> Option<Receipt> {
        self.store.receipt(height, tx_hash).ok().flatten()
    }

    fn tx_height(&self, tx_hash: &[u8; 32]) -> Option<u64> {
        self.store.tx_height(tx_hash).ok().flatten()
    }

    fn block_at(&self, height: u64) -> Option<RpcBlock> {
        (self.read_block)(height)
    }

    fn did_document(&self, did: &str) -> Option<solidus_txns::did::DidDocument> {
        let bytes = self.store.get(&StateKey::did(did)).ok().flatten()?;
        solidus_txns::did::DidDocument::from_bytes(&bytes).ok()
    }

    fn credential(&self, id: &str) -> Option<solidus_txns::credential::CredentialRecord> {
        let bytes = self.store.get(&StateKey::credential(id)).ok().flatten()?;
        solidus_txns::credential::CredentialRecord::from_bytes(&bytes).ok()
    }

    /// On-chain validators, UNIONED with the live consensus committee.
    ///
    /// ⚠ THE UNION IS THE POINT, and it mirrors v1 exactly. On a devnet or
    /// testnet the committee runs without any on-chain staking transaction, so
    /// the state space is empty while blocks are being produced every ~116ms.
    /// Returning `[]` there is technically true about state and actively
    /// misleading about the chain. On mainnet the on-chain rows already cover
    /// every committee member and `seen` filters them, so this is a no-op.
    ///
    /// ⚠ Committee entries carry `staked: 0` and `reputation: 0` because that
    /// is the truth: they are voting, not staked. They are NOT invented numbers
    /// dressed up to look like stake.
    fn validators(&self) -> Vec<solidus_txns::staking::ValidatorInfo> {
        use std::collections::HashSet;
        let mut out: Vec<solidus_txns::staking::ValidatorInfo> = Vec::new();
        let mut seen: HashSet<Address> = HashSet::new();

        // ⚠ `iter_space` was one of six Store2 methods with zero callers in the
        // v2 stack. It is the right primitive here: validators are keyed by
        // address, so there is no range to scan without it.
        if let Ok(entries) = self.store.iter_space(solidus_exec::StateSpace::Tree(
            solidus_exec::types::TreeId::Validators,
        )) {
            for (_, v) in entries {
                // A corrupt record is skipped rather than failing the whole
                // call, as v1 does.
                let Ok(info) = solidus_txns::staking::ValidatorInfo::from_bytes(&v) else {
                    continue;
                };
                // Inactive validators are not voters; v1 filters them here too.
                if !info.active {
                    continue;
                }
                seen.insert(info.address);
                out.push(info);
            }
        }

        for addr in &self.committee {
            if seen.insert(*addr) {
                out.push(solidus_txns::staking::ValidatorInfo {
                    address: *addr,
                    staked: 0,
                    unbonding: 0,
                    unbonding_start_ms: None,
                    reputation: 0,
                    active: true,
                });
            }
        }
        out
    }

    fn transaction(&self, tx_hash: &[u8; 32]) -> Option<Transaction> {
        (self.read_tx)(tx_hash)
    }

    fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn subject_enumeration_allowed(&self) -> bool {
        self.allow_subject_enumeration
    }

    fn credential_ids_by_subject(&self, did: &str) -> Vec<String> {
        let Ok(Some(bytes)) = self.store.get(&StateKey::cred_by_subject(did)) else {
            return Vec::new();
        };
        serde_json::from_slice::<Vec<String>>(&bytes).unwrap_or_default()
    }

    fn credential_ids_by_issuer(&self, did: &str) -> Vec<String> {
        let Ok(Some(bytes)) = self.store.get(&StateKey::cred_by_issuer(did)) else {
            return Vec::new();
        };
        serde_json::from_slice::<Vec<String>>(&bytes).unwrap_or_default()
    }

    fn validator(&self, addr: &Address) -> Option<solidus_txns::staking::ValidatorInfo> {
        let bytes = self.store.get(&StateKey::validator(addr)).ok().flatten()?;
        solidus_txns::staking::ValidatorInfo::from_bytes(&bytes).ok()
    }

    fn chain_identity(&self) -> (String, [u8; 32]) {
        (self.network.clone(), self.genesis_hash)
    }

    fn chain_id_numeric(&self) -> u64 {
        self.chain_id
    }

    fn canon_head(&self) -> Option<(u64, [u8; 32])> {
        let height = self.store.canon_head().ok().flatten()?;
        let hash = self.store.canon_hash(height).ok().flatten()?;
        Some((height, hash))
    }

    fn submit(&self, tx: Transaction) -> Result<[u8; 32], String> {
        // Reject an unsigned/garbage tx at the edge (the mempool + executor
        // re-check, but a fast edge rejection saves a round trip).
        let next_height = self
            .anchor
            .lock()
            .map(|a| a.0)
            .unwrap_or(0)
            .saturating_add(1);
        let wire = solidus_exec::wire::wire_for_height(self.wire, self.chain_id, next_height);
        if !solidus_exec::wire::verify_signature(&tx, wire) {
            return Err("invalid signature".to_string());
        }
        (self.submit)(tx)
    }
}
