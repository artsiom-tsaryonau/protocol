use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use tracing::{debug, error};

use solidus_consensus::mempool::Mempool;
use solidus_consensus::types::{Block, ValidatorIdentity};
use solidus_crypto::keys::Address;
use solidus_state::executor::{
    load_committed_account, load_credential, load_credential_ids, load_validator,
};
use solidus_state::store::{
    Store, CF_BLOCKS, CF_CRED_BY_ISSUER, CF_CRED_BY_SUBJECT, CF_RECEIPTS, CF_VALIDATORS,
};
use solidus_txns::staking::ValidatorInfo;
use solidus_txns::types::{Receipt, Transaction};

use crate::types::{
    NodeInfo, RpcBlock, RpcCanonHead, RpcChainInfo, RpcCredentialProofResult, RpcCredentialRecord,
    RpcCredentialVerifyResult, RpcDidDocument, RpcDisclosedMessage, RpcNativeToken, RpcReceipt,
    RpcValidatorInfo,
};

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// JSON-RPC error code for invalid parameters.
const INVALID_PARAMS: i32 = -32602;
/// JSON-RPC error code for internal errors.
const INTERNAL_ERROR: i32 = -32603;
/// Application-defined error: the method exists and is disabled by node policy.
///
/// `-32000..=-32099` is the JSON-RPC range reserved for application errors, so this
/// does not collide with `-32601 Method not found` — and it must not, because the
/// method DOES exist. Reporting it as "not found" would be a lie a caller could
/// reasonably act on.
const POLICY_DISABLED: i32 = -32001;

fn invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS, msg.into(), None::<()>)
}

fn internal_error(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR, msg.into(), None::<()>)
}

fn policy_disabled(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(POLICY_DISABLED, msg.into(), None::<()>)
}

/// Best-effort resident set size of the current process, in bytes.
/// Reads `/proc/self/statm` on Linux; returns 0 on other platforms.
fn current_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // statm fields are in pages: size resident shared text lib data dt
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(resident_pages) = statm.split_whitespace().nth(1) {
                if let Ok(pages) = resident_pages.parse::<u64>() {
                    return pages * 4096; // standard Linux page size
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

// ---------------------------------------------------------------------------
// Trait definition (jsonrpsee proc macro generates SolidusApiServer)
// ---------------------------------------------------------------------------

#[rpc(server)]
pub trait SolidusApi {
    /// Return the balance (in smallest units) for the given base58 address.
    #[method(name = "solidus_getBalance")]
    fn get_balance(&self, address: String) -> RpcResult<u64>;

    /// Return the current nonce for the given base58 address.
    #[method(name = "solidus_getNonce")]
    fn get_nonce(&self, address: String) -> RpcResult<u64>;

    /// Submit a signed transaction (JSON-encoded). Returns the transaction
    /// hash as a hex string.
    #[method(name = "solidus_sendTransaction")]
    fn send_transaction(&self, tx_json: String) -> RpcResult<String>;

    /// Return a block by height, or `null` if it does not exist.
    #[method(name = "solidus_getBlock")]
    fn get_block(&self, height: u64) -> RpcResult<Option<RpcBlock>>;

    /// Return the latest committed block, or `null` if no blocks exist.
    #[method(name = "solidus_getLatestBlock")]
    fn get_latest_block(&self) -> RpcResult<Option<RpcBlock>>;

    /// Return a block by its contiguous canonical sequence number
    /// (`CF_CANON` index), or `null` if no block is canonized at `seq`.
    ///
    /// `seq` is the authoritative chain position. Prefer this over
    /// `solidus_getBlock`'s height-based lookup when the caller needs
    /// contiguous indexing — e.g. block explorers that iterate every block.
    #[method(name = "solidus_getBlockBySeq")]
    fn get_block_by_seq(&self, seq: u64) -> RpcResult<Option<RpcBlock>>;

    /// Return the head of the contiguous canonical ledger (max seq + hash),
    /// or `null` if no blocks have been canonized yet.
    #[method(name = "solidus_canonHead")]
    fn canon_head(&self) -> RpcResult<Option<RpcCanonHead>>;

    /// Return just the latest committed block height.
    #[method(name = "solidus_blockNumber")]
    fn block_number(&self) -> RpcResult<u64>;

    /// Return chain metadata: id, native token, genesis hash, latest height,
    /// and node version. Wallets, explorers, indexers, and listing
    /// aggregators hit this to confirm the chain self-describes correctly.
    #[method(name = "solidus_chainInfo")]
    fn chain_info(&self) -> RpcResult<RpcChainInfo>;

    /// Process-level node observability: version, uptime, resident memory.
    #[method(name = "solidus_nodeInfo")]
    fn node_info(&self) -> RpcResult<NodeInfo>;

    /// Return the receipt for a transaction identified by its hex hash.
    #[method(name = "solidus_getReceipt")]
    fn get_receipt(&self, tx_hash: String) -> RpcResult<Option<RpcReceipt>>;

    /// Return the full transaction JSON for a transaction identified by its
    /// hex hash. Scans blocks backwards from latest — acceptable for testnet.
    #[method(name = "solidus_getTransaction")]
    fn get_transaction(&self, tx_hash: String) -> RpcResult<Option<serde_json::Value>>;

    /// Resolve a DID and return its document, or `null` if not found.
    #[method(name = "solidus_didResolve")]
    fn did_resolve(&self, did: String) -> RpcResult<Option<RpcDidDocument>>;

    /// Verify a credential by ID. Returns validity status and the credential
    /// record, or `null` if the credential does not exist.
    #[method(name = "solidus_credentialVerify")]
    fn credential_verify(
        &self,
        credential_id: String,
    ) -> RpcResult<Option<RpcCredentialVerifyResult>>;

    /// Return all credentials where the given DID is the subject.
    #[method(name = "solidus_credentialsBySubject")]
    fn credentials_by_subject(&self, did: String) -> RpcResult<Vec<RpcCredentialRecord>>;

    /// Return all credentials where the given DID is the issuer.
    #[method(name = "solidus_credentialsByIssuer")]
    fn credentials_by_issuer(&self, did: String) -> RpcResult<Vec<RpcCredentialRecord>>;

    /// Return all active validators.
    #[method(name = "solidus_getValidators")]
    fn get_validators(&self) -> RpcResult<Vec<RpcValidatorInfo>>;

    /// Return validator info for a given base58 address, or `null` if not found.
    #[method(name = "solidus_getValidatorStake")]
    fn get_validator_stake(&self, address: String) -> RpcResult<Option<RpcValidatorInfo>>;

    /// Verify a BBS+ selective-disclosure proof statelessly.
    ///
    /// All hex inputs must be lowercase. `disclosed_messages` indices are
    /// the positions in the originally signed vector; `total_message_count`
    /// is the full vector length the issuer signed. Returns `true` iff the
    /// proof is cryptographically valid.
    #[method(name = "solidus_bbsVerifyProof")]
    fn bbs_verify_proof(
        &self,
        proof_hex: String,
        pubkey_hex: String,
        header_hex: String,
        ph_hex: String,
        disclosed_messages: Vec<RpcDisclosedMessage>,
        total_message_count: u32,
    ) -> RpcResult<bool>;

    /// Verify a BBS+ proof against an on-chain credential record. Looks up
    /// the credential by ID, pulls `bbs_pubkey` and `bbs_message_count` from
    /// chain state, then runs proof verification. Returns combined validity
    /// (proof + revocation status).
    #[method(name = "solidus_bbsVerifyCredentialProof")]
    fn bbs_verify_credential_proof(
        &self,
        credential_id: String,
        proof_hex: String,
        header_hex: String,
        ph_hex: String,
        disclosed_messages: Vec<RpcDisclosedMessage>,
    ) -> RpcResult<RpcCredentialProofResult>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Static chain metadata fixed at node startup. Supplied by the node binary
/// from the loaded genesis config and surfaced verbatim by `solidus_chainInfo`.
#[derive(Debug, Clone)]
pub struct ChainMeta {
    /// Chain identifier from `GenesisConfig::chain_id`.
    pub chain_id: String,
    /// Native token metadata from `GenesisConfig::native_token`.
    pub native_token: RpcNativeToken,
    /// Node software version (`CARGO_PKG_VERSION` of the node binary).
    pub version: String,
}

impl Default for ChainMeta {
    /// Sentinel default for tests and RPC servers run without a genesis
    /// config. The `TESTNET-SOLI` symbol mirrors `NativeTokenMetadata`'s
    /// sentinel so a missing-metadata chain is obvious over RPC.
    fn default() -> Self {
        Self {
            chain_id: "solidus-testnet".to_string(),
            native_token: RpcNativeToken {
                symbol: "TESTNET-SOLI".to_string(),
                name: "Solidus (testnet, no metadata)".to_string(),
                decimals: 8,
            },
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Holds shared state required by the RPC methods.
pub struct SolidusRpcImpl {
    pub store: Arc<Store>,
    pub mempool: Arc<Mutex<Mempool>>,
    pub latest_height: Arc<Mutex<u64>>,
    /// In-process consensus committee. Surfaced by `solidus_getValidators`
    /// in addition to on-chain stake records so that dev/testnet networks
    /// (which produce blocks without on-chain staking transactions) report
    /// a non-empty validator set. May be empty when the RPC server is run
    /// without an attached consensus engine (e.g. integration tests).
    pub committee: Arc<Vec<ValidatorIdentity>>,
    /// Static chain metadata surfaced by `solidus_chainInfo`.
    pub chain_meta: ChainMeta,
    /// Monotonic clock captured when this RPC impl was constructed; used for
    /// `solidus_nodeInfo.uptime_seconds`.
    pub start_time: Instant,
    /// Optional fan-out channel: when set, `solidus_sendTransaction` pushes
    /// every successfully-mempooled transaction here so the consensus loop
    /// can broadcast it on the libp2p `txs` gossipsub topic. `None` for
    /// standalone RPC tests (no networking) and the legacy single-node
    /// mode (no peers to gossip to).
    pub tx_broadcast: Option<tokio::sync::mpsc::UnboundedSender<Transaction>>,
    /// Wake signal for the event-driven proposer: fired (`notify_waiters`)
    /// the moment `solidus_sendTransaction` accepts a tx into the mempool,
    /// so an idle consensus loop proposes immediately instead of waiting
    /// for its next tick. Harmless no-op when nothing is parked on it.
    pub tx_wake: Arc<tokio::sync::Notify>,
    /// Whether `solidus_credentialsBySubject` may answer.
    ///
    /// **Defaults to `false`.** Subject enumeration is the strongest correlation
    /// handle this node exposes: `subject_did` is written to the ledger in
    /// plaintext beside a semantically loaded `credential_type` (`KycL3`, `Age`),
    /// and this method turns that into a one-request lookup of everything a given
    /// DID holds. Measured 2026-08-20: the node has **no P2P listener at all**
    /// (`dev-testnet`, single socket `127.0.0.1:9944`), so the proxied JSON-RPC is
    /// the only public door and closing it is a real mitigation rather than
    /// theatre. Same posture as `rpc_listen`: secure by default, public by opt-in.
    ///
    /// ⚠ This is a MITIGATION, not the fix. The ledger still publishes the field;
    /// the fix is removing `subject_did` from `CredentialIssue` altogether, which
    /// is consensus-breaking and gated on a founder decision (BD-7 scope).
    ///
    /// ⚠ `solidus_credentialsByIssuer` is deliberately NOT gated. Issuer plus type
    /// plus timestamp in aggregate is far weaker than a per-subject lookup, and
    /// block explorers legitimately need it.
    pub allow_subject_enumeration: bool,
}

impl SolidusRpcImpl {
    /// Create a new RPC implementation with shared state.
    ///
    /// `committee` should contain the in-process consensus committee
    /// members, or an empty `Vec` when no consensus engine is attached.
    /// `tx_broadcast` should be `None` for tests / standalone RPC and
    /// `Some(sender)` in the consensus + full-node paths where a libp2p
    /// transport will fan out submitted transactions.
    pub fn new(
        store: Arc<Store>,
        mempool: Arc<Mutex<Mempool>>,
        latest_height: Arc<Mutex<u64>>,
        committee: Arc<Vec<ValidatorIdentity>>,
        chain_meta: ChainMeta,
        tx_broadcast: Option<tokio::sync::mpsc::UnboundedSender<Transaction>>,
        tx_wake: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            store,
            mempool,
            latest_height,
            committee,
            chain_meta,
            start_time: Instant::now(),
            tx_broadcast,
            tx_wake,
            allow_subject_enumeration: false,
        }
    }

    /// Opt in to answering `solidus_credentialsBySubject`.
    ///
    /// A builder rather than an eighth positional argument to `new()`: the
    /// constructor has four call sites and every future one would have to pass
    /// the flag explicitly, which is how a secure default gets flipped by
    /// accident. Callers that do not call this get the closed behaviour.
    #[must_use]
    pub fn with_subject_enumeration(mut self, allow: bool) -> Self {
        self.allow_subject_enumeration = allow;
        self
    }

    /// Load a block from the store by height.
    fn load_block(&self, height: u64) -> RpcResult<Option<Block>> {
        let key = height.to_le_bytes();
        let bytes = self.store.get(CF_BLOCKS, &key).map_err(|e| {
            error!("failed to read block at height {height}: {e}");
            internal_error(format!("store error: {e}"))
        })?;

        match bytes {
            None => Ok(None),
            Some(data) => {
                let block: Block = serde_json::from_slice(&data).map_err(|e| {
                    error!("failed to deserialize block at height {height}: {e}");
                    internal_error(format!("deserialization error: {e}"))
                })?;
                Ok(Some(block))
            }
        }
    }
}

impl SolidusApiServer for SolidusRpcImpl {
    fn get_balance(&self, address: String) -> RpcResult<u64> {
        let addr = Address::from_base58(&address)
            .map_err(|e| invalid_params(format!("invalid address: {e}")))?;

        // Read the COMMITTED view: see only balances from blocks that have
        // reached 3-chain finality, never the speculative effects of
        // validated-but-not-yet-committed blocks that `execute_block` writes
        // into CF_ACCOUNTS. CF_COMMITTED_ACCOUNTS is mirrored by
        // `HotStuffEngine::try_commit` and seeded by `load_genesis`.
        let account = load_committed_account(&self.store, &addr).map_err(|e| {
            error!("failed to load committed account {address}: {e}");
            internal_error(format!("store error: {e}"))
        })?;

        Ok(account.balance)
    }

    fn get_nonce(&self, address: String) -> RpcResult<u64> {
        let addr = Address::from_base58(&address)
            .map_err(|e| invalid_params(format!("invalid address: {e}")))?;

        // Read the COMMITTED view — same rationale as `get_balance` above.
        // RPC callers (wallet/SDK) must use this as their next-tx nonce
        // source so they don't double-spend against in-flight blocks.
        let account = load_committed_account(&self.store, &addr).map_err(|e| {
            error!("failed to load committed account {address}: {e}");
            internal_error(format!("store error: {e}"))
        })?;

        Ok(account.nonce)
    }

    fn send_transaction(&self, tx_json: String) -> RpcResult<String> {
        let tx: Transaction = serde_json::from_str(&tx_json)
            .map_err(|e| invalid_params(format!("invalid transaction JSON: {e}")))?;

        if !tx.verify_signature() {
            return Err(invalid_params("invalid transaction signature"));
        }

        let tx_hash = tx.hash();
        let hex_hash = hex::encode(tx_hash);

        // Clone before insert: insert moves the tx into the pool, but we
        // need the tx to fan out to the broadcast channel below.
        let tx_for_broadcast = tx.clone();

        let mut pool = self.mempool.lock().map_err(|e| {
            error!("mempool lock poisoned: {e}");
            internal_error("internal error")
        })?;

        if !pool.insert(tx) {
            return Err(invalid_params(
                "transaction rejected: duplicate or mempool full",
            ));
        }

        // Drop the mempool lock BEFORE the broadcast send (the channel is
        // unbounded but the receiver might be slow; never hold the mempool
        // mutex across an await/IO point).
        drop(pool);

        // Wake any idle consensus loop so the current leader proposes NOW —
        // proposing is event-driven (2026-07-13); there is no free-running
        // block cycle to pick the tx up. If every loop is mid-iteration the
        // wake is lost, which is fine: each loop re-checks the mempool on
        // its next iteration (bounded by its 500ms backfill tick).
        self.tx_wake.notify_waiters();

        // Fan out to the libp2p `txs` gossipsub topic via the consensus
        // loop. Best-effort: a closed channel just means the node is
        // shutting down — local mempool insert already succeeded so the
        // proposer (if this node is the next leader) will still include
        // the tx in its next proposal. Any other receivers behind the
        // gossip channel pick it up on their NewTransaction handler.
        if let Some(tx_broadcast) = &self.tx_broadcast {
            if tx_broadcast.send(tx_for_broadcast).is_err() {
                debug!("tx broadcast channel closed; local mempool insert still succeeded");
            }
        }

        Ok(hex_hash)
    }

    fn get_block(&self, height: u64) -> RpcResult<Option<RpcBlock>> {
        let block = self.load_block(height)?;
        Ok(block.as_ref().map(RpcBlock::from_block))
    }

    fn get_latest_block(&self) -> RpcResult<Option<RpcBlock>> {
        let height = *self.latest_height.lock().map_err(|e| {
            error!("latest_height lock poisoned: {e}");
            internal_error("internal error")
        })?;

        if height == 0 {
            // Check if genesis block exists at height 0.
            return self.get_block(0);
        }

        self.get_block(height)
    }

    fn get_block_by_seq(&self, seq: u64) -> RpcResult<Option<RpcBlock>> {
        // Look up the canonical hash for this seq, then fetch the block by
        // hash from `CF_BLOCK_BY_HASH`. Both come from the canonical-ledger
        // store (`solidus-consensus::ledger`) populated by `try_commit` and
        // `rebuild_state_from_canon`.
        let hash = match solidus_consensus::ledger::canon_get(&self.store, seq) {
            Ok(Some(h)) => h,
            Ok(None) => return Ok(None),
            Err(e) => {
                error!("canon_get({seq}) failed: {e}");
                return Err(internal_error(format!("ledger error: {e}")));
            }
        };
        match solidus_consensus::ledger::get_block_by_hash(&self.store, &hash) {
            Ok(Some(block)) => Ok(Some(RpcBlock::from_block(&block))),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("get_block_by_hash(seq={seq}) failed: {e}");
                Err(internal_error(format!("ledger error: {e}")))
            }
        }
    }

    fn canon_head(&self) -> RpcResult<Option<RpcCanonHead>> {
        match solidus_consensus::ledger::canon_head(&self.store) {
            Ok(Some((seq, hash))) => Ok(Some(RpcCanonHead {
                seq,
                hash: hex::encode(hash),
            })),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("canon_head failed: {e}");
                Err(internal_error(format!("ledger error: {e}")))
            }
        }
    }

    fn block_number(&self) -> RpcResult<u64> {
        let height = *self.latest_height.lock().map_err(|e| {
            error!("latest_height lock poisoned: {e}");
            internal_error("internal error")
        })?;
        Ok(height)
    }

    fn chain_info(&self) -> RpcResult<RpcChainInfo> {
        let latest_block = *self.latest_height.lock().map_err(|e| {
            error!("latest_height lock poisoned: {e}");
            internal_error("internal error")
        })?;

        // Genesis hash: the hash of block 0 when present, otherwise the
        // deterministic chain_id-derived hash the node computes at genesis
        // (blake3(chain_id), see solidus-node/main.rs). Block 0 isn't always
        // persisted/loadable on the dev testnet, and returning an empty string
        // there made every SDK consumer doing due diligence flag a "missing
        // genesis" — the fallback keeps chain_info honest and non-empty.
        let genesis_hash = match self.load_block(0)? {
            Some(block) => hex::encode(block.hash()),
            None => hex::encode(solidus_crypto::hash::blake3_hash(
                self.chain_meta.chain_id.as_bytes(),
            )),
        };

        Ok(RpcChainInfo {
            chain_id: self.chain_meta.chain_id.clone(),
            native_token: self.chain_meta.native_token.clone(),
            genesis_hash,
            latest_block,
            version: self.chain_meta.version.clone(),
        })
    }

    fn node_info(&self) -> RpcResult<NodeInfo> {
        Ok(NodeInfo {
            version: self.chain_meta.version.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            rss_bytes: current_rss_bytes(),
        })
    }

    fn get_receipt(&self, tx_hash: String) -> RpcResult<Option<RpcReceipt>> {
        let hash_bytes =
            hex::decode(&tx_hash).map_err(|e| invalid_params(format!("invalid hex hash: {e}")))?;

        if hash_bytes.len() != 32 {
            return Err(invalid_params(format!(
                "invalid hash length: expected 32 bytes, got {}",
                hash_bytes.len()
            )));
        }

        let bytes = self.store.get(CF_RECEIPTS, &hash_bytes).map_err(|e| {
            error!("failed to read receipt for {tx_hash}: {e}");
            internal_error(format!("store error: {e}"))
        })?;

        match bytes {
            None => Ok(None),
            Some(data) => {
                let receipt: Receipt = serde_json::from_slice(&data).map_err(|e| {
                    error!("failed to deserialize receipt for {tx_hash}: {e}");
                    internal_error(format!("deserialization error: {e}"))
                })?;
                Ok(Some(RpcReceipt::from_receipt(&receipt)))
            }
        }
    }

    fn did_resolve(&self, did: String) -> RpcResult<Option<RpcDidDocument>> {
        use solidus_state::executor::load_did;
        match load_did(&self.store, &did) {
            Ok(Some(doc)) => Ok(Some(RpcDidDocument::from_did_document(&doc))),
            Ok(None) => Ok(None),
            Err(e) => Err(internal_error(format!("store error: {e}"))),
        }
    }

    fn credential_verify(
        &self,
        credential_id: String,
    ) -> RpcResult<Option<RpcCredentialVerifyResult>> {
        match load_credential(&self.store, &credential_id) {
            Ok(Some(cred)) => {
                let revoked = cred.revoked;
                let valid = !revoked;
                let rpc_cred = RpcCredentialRecord::from_credential(&cred);
                Ok(Some(RpcCredentialVerifyResult {
                    valid,
                    credential: Some(rpc_cred),
                    revoked,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(internal_error(format!("store error: {e}"))),
        }
    }

    fn credentials_by_subject(&self, did: String) -> RpcResult<Vec<RpcCredentialRecord>> {
        // Refuse rather than return an empty vector. `[]` would assert "this DID
        // holds no credentials" — a statement the node never computed and which is
        // false for most subjects. Same rule the BBS verify path follows: never
        // report a result you did not compute. An error is also unambiguous to a
        // caller, where an empty list silently looks like a successful query.
        if !self.allow_subject_enumeration {
            return Err(policy_disabled(concat!(
                "solidus_credentialsBySubject is disabled on this node: enumerating ",
                "every credential held by a subject DID is a correlation handle. ",
                "Query a known credential by id with solidus_credentialVerify, or ",
                "run a node with subject enumeration explicitly enabled.",
            )));
        }

        let ids = load_credential_ids(&self.store, CF_CRED_BY_SUBJECT, &did)
            .map_err(|e| internal_error(format!("store error: {e}")))?;

        let mut records = Vec::with_capacity(ids.len());
        for id in &ids {
            match load_credential(&self.store, id) {
                Ok(Some(cred)) => records.push(RpcCredentialRecord::from_credential(&cred)),
                Ok(None) => {
                    // Index references a missing record — skip (should not happen)
                    error!("credential index references missing credential: {id}");
                }
                Err(e) => return Err(internal_error(format!("store error: {e}"))),
            }
        }
        Ok(records)
    }

    fn credentials_by_issuer(&self, did: String) -> RpcResult<Vec<RpcCredentialRecord>> {
        let ids = load_credential_ids(&self.store, CF_CRED_BY_ISSUER, &did)
            .map_err(|e| internal_error(format!("store error: {e}")))?;

        let mut records = Vec::with_capacity(ids.len());
        for id in &ids {
            match load_credential(&self.store, id) {
                Ok(Some(cred)) => records.push(RpcCredentialRecord::from_credential(&cred)),
                Ok(None) => {
                    error!("credential index references missing credential: {id}");
                }
                Err(e) => return Err(internal_error(format!("store error: {e}"))),
            }
        }
        Ok(records)
    }

    fn get_transaction(&self, tx_hash: String) -> RpcResult<Option<serde_json::Value>> {
        let hash_bytes =
            hex::decode(&tx_hash).map_err(|e| invalid_params(format!("invalid hex hash: {e}")))?;

        if hash_bytes.len() != 32 {
            return Err(invalid_params(format!(
                "invalid hash length: expected 32 bytes, got {}",
                hash_bytes.len()
            )));
        }

        let mut target_hash = [0u8; 32];
        target_hash.copy_from_slice(&hash_bytes);

        let latest = *self.latest_height.lock().map_err(|e| {
            error!("latest_height lock poisoned: {e}");
            internal_error("internal error")
        })?;

        // Scan blocks backwards from latest to 0, looking for the tx.
        // This is O(blocks) which is acceptable for testnet.
        let mut height = latest;
        loop {
            if let Some(block) = self.load_block(height)? {
                for tx in &block.transactions {
                    if tx.hash() == target_hash {
                        let value = serde_json::to_value(tx).map_err(|e| {
                            error!("failed to serialize transaction: {e}");
                            internal_error(format!("serialization error: {e}"))
                        })?;
                        return Ok(Some(value));
                    }
                }
            }

            if height == 0 {
                break;
            }
            height -= 1;
        }

        Ok(None)
    }

    fn get_validator_stake(&self, address: String) -> RpcResult<Option<RpcValidatorInfo>> {
        let addr = solidus_crypto::keys::Address::from_base58(&address)
            .map_err(|e| invalid_params(format!("invalid address: {e}")))?;

        match load_validator(&self.store, &addr) {
            Ok(Some(info)) => Ok(Some(RpcValidatorInfo::from_validator(&info))),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("failed to load validator {address}: {e}");
                Err(internal_error(format!("store error: {e}")))
            }
        }
    }

    fn get_validators(&self) -> RpcResult<Vec<RpcValidatorInfo>> {
        let db = self.store.inner();
        let cf = db
            .cf_handle(CF_VALIDATORS)
            .ok_or_else(|| internal_error("CF not found: validators"))?;

        let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut validators = Vec::new();
        let mut seen: HashSet<Address> = HashSet::new();
        for item in iter {
            let (_, value) = item.map_err(|e| {
                error!("error iterating validators: {e}");
                internal_error(e.to_string())
            })?;
            match ValidatorInfo::from_bytes(&value) {
                Ok(info) if info.active => {
                    seen.insert(info.address);
                    validators.push(RpcValidatorInfo::from_validator(&info));
                }
                Ok(_) => {} // inactive validator — skip
                Err(e) => {
                    error!("failed to deserialize validator record: {e}");
                    // Skip corrupt records rather than failing the whole call.
                }
            }
        }

        // Union with the in-process consensus committee. On dev/testnet
        // networks the committee runs without on-chain staking transactions,
        // so the on-chain set is empty even though blocks are being produced.
        // Surfacing committee members here keeps `solidus_getValidators`
        // honest about who is actually voting. On mainnet, on-chain rows
        // already cover every committee member and `seen` filters duplicates,
        // so this loop is a no-op.
        for member in self.committee.iter() {
            if seen.insert(member.address) {
                validators.push(RpcValidatorInfo {
                    address: member.address.to_base58(),
                    staked: 0,
                    unbonding: 0,
                    reputation: 0,
                    active: true,
                });
            }
        }

        Ok(validators)
    }

    fn bbs_verify_proof(
        &self,
        proof_hex: String,
        pubkey_hex: String,
        header_hex: String,
        ph_hex: String,
        disclosed_messages: Vec<RpcDisclosedMessage>,
        total_message_count: u32,
    ) -> RpcResult<bool> {
        let pk = solidus_crypto::bbs::BbsPublicKey::from_hex(&pubkey_hex)
            .map_err(|e| invalid_params(format!("invalid pubkey hex: {e}")))?;
        let proof = solidus_crypto::bbs::BbsProof::from_hex(&proof_hex)
            .map_err(|e| invalid_params(format!("invalid proof hex: {e}")))?;
        let header = hex::decode(&header_hex)
            .map_err(|e| invalid_params(format!("invalid header hex: {e}")))?;
        let ph =
            hex::decode(&ph_hex).map_err(|e| invalid_params(format!("invalid ph hex: {e}")))?;

        let mut sorted = disclosed_messages.clone();
        sorted.sort_by_key(|m| m.index);
        for w in sorted.windows(2) {
            if w[0].index == w[1].index {
                return Err(invalid_params("duplicate disclosed index"));
            }
        }
        if let Some(last) = sorted.last() {
            if last.index >= total_message_count {
                return Err(invalid_params(format!(
                    "disclosed index {} >= total_message_count {}",
                    last.index, total_message_count
                )));
            }
        }

        let mut indices: Vec<usize> = Vec::with_capacity(sorted.len());
        let mut messages: Vec<Vec<u8>> = Vec::with_capacity(sorted.len());
        for dm in &sorted {
            indices.push(dm.index as usize);
            messages.push(
                hex::decode(&dm.message)
                    .map_err(|e| invalid_params(format!("invalid message hex: {e}")))?,
            );
        }
        let msg_refs: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();

        Ok(proof.is_valid(&pk, &header, &ph, &indices, &msg_refs))
    }

    fn bbs_verify_credential_proof(
        &self,
        credential_id: String,
        proof_hex: String,
        header_hex: String,
        ph_hex: String,
        disclosed_messages: Vec<RpcDisclosedMessage>,
    ) -> RpcResult<RpcCredentialProofResult> {
        let cred = match load_credential(&self.store, &credential_id) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Ok(RpcCredentialProofResult {
                    valid: false,
                    proof_valid: false,
                    is_bbs: false,
                    revoked: false,
                    credential: None,
                });
            }
            Err(e) => return Err(internal_error(format!("store error: {e}"))),
        };

        let bbs_pubkey_bytes = match cred.bbs_pubkey {
            Some(pk) => pk,
            None => {
                return Ok(RpcCredentialProofResult {
                    valid: false,
                    proof_valid: false,
                    is_bbs: false,
                    revoked: cred.revoked,
                    credential: Some(RpcCredentialRecord::from_credential(&cred)),
                });
            }
        };
        let total_message_count = cred.bbs_message_count.unwrap_or(0);

        let pk = solidus_crypto::bbs::BbsPublicKey::from_bytes(&bbs_pubkey_bytes)
            .map_err(|e| internal_error(format!("on-chain bbs_pubkey is malformed: {e}")))?;
        let proof = solidus_crypto::bbs::BbsProof::from_hex(&proof_hex)
            .map_err(|e| invalid_params(format!("invalid proof hex: {e}")))?;
        let header = hex::decode(&header_hex)
            .map_err(|e| invalid_params(format!("invalid header hex: {e}")))?;
        let ph =
            hex::decode(&ph_hex).map_err(|e| invalid_params(format!("invalid ph hex: {e}")))?;

        let mut sorted = disclosed_messages.clone();
        sorted.sort_by_key(|m| m.index);
        for w in sorted.windows(2) {
            if w[0].index == w[1].index {
                return Err(invalid_params("duplicate disclosed index"));
            }
        }
        if let Some(last) = sorted.last() {
            if last.index >= total_message_count {
                return Err(invalid_params(format!(
                    "disclosed index {} >= on-chain total_message_count {}",
                    last.index, total_message_count
                )));
            }
        }

        let mut indices: Vec<usize> = Vec::with_capacity(sorted.len());
        let mut messages: Vec<Vec<u8>> = Vec::with_capacity(sorted.len());
        for dm in &sorted {
            indices.push(dm.index as usize);
            messages.push(
                hex::decode(&dm.message)
                    .map_err(|e| invalid_params(format!("invalid message hex: {e}")))?,
            );
        }
        let msg_refs: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();

        let proof_valid = proof.is_valid(&pk, &header, &ph, &indices, &msg_refs);

        Ok(RpcCredentialProofResult {
            valid: proof_valid && !cred.revoked,
            proof_valid,
            is_bbs: true,
            revoked: cred.revoked,
            credential: Some(RpcCredentialRecord::from_credential(&cred)),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_consensus::types::{Block, BlockHeader};
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_txns::types::TxPayload;
    use tempfile::tempdir;

    /// Helper: open a store in a fresh temp directory.
    fn open_tmp() -> (Arc<Store>, tempfile::TempDir) {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Store::open(dir.path()).expect("failed to open store");
        (Arc::new(store), dir)
    }

    /// Helper: create an RPC impl with default shared state and an empty
    /// committee.
    fn make_rpc(store: Arc<Store>) -> SolidusRpcImpl {
        SolidusRpcImpl::new(
            store,
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Mutex::new(0)),
            Arc::new(Vec::new()),
            ChainMeta::default(),
            None,
            Arc::new(tokio::sync::Notify::new()),
        )
    }

    /// Helper: create an RPC impl with a committee attached.
    fn make_rpc_with_committee(
        store: Arc<Store>,
        committee: Vec<ValidatorIdentity>,
    ) -> SolidusRpcImpl {
        SolidusRpcImpl::new(
            store,
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Mutex::new(0)),
            Arc::new(committee),
            ChainMeta::default(),
            None,
            Arc::new(tokio::sync::Notify::new()),
        )
    }

    /// Helper: build a signed Transfer transaction.
    fn make_transfer_tx(
        sender_key: &ed25519_dalek::SigningKey,
        to: Address,
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::Transfer { to, amount };

        let mut tx = Transaction {
            sender_pubkey: pubkey,
            nonce,
            payload,
            signature: [0u8; 64],
        };

        let msg = tx.signing_bytes();
        tx.signature = sign(sender_key, &msg);
        tx
    }

    #[test]
    fn get_balance_default_account() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let addr = Address::from_bytes([0xAA; 20]);
        let balance = rpc.get_balance(addr.to_base58()).unwrap();
        assert_eq!(balance, 0);
    }

    #[test]
    fn get_balance_invalid_address() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = rpc.get_balance("not-valid-base58!!!".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn send_transaction_and_verify() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let sender = generate_signing_key();
        let to = Address::from_bytes([0xBB; 20]);
        let tx = make_transfer_tx(&sender, to, 100, 0);
        let expected_hash = hex::encode(tx.hash());

        let tx_json = serde_json::to_string(&tx).unwrap();
        let result = rpc.send_transaction(tx_json).unwrap();
        assert_eq!(result, expected_hash);

        // Verify it's in the mempool.
        let pool = rpc.mempool.lock().unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn send_transaction_bad_signature_rejected() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let tx = Transaction {
            sender_pubkey: [1u8; 32],
            nonce: 0,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([0xBB; 20]),
                amount: 100,
            },
            signature: [0u8; 64],
        };

        let tx_json = serde_json::to_string(&tx).unwrap();
        let result = rpc.send_transaction(tx_json);
        assert!(result.is_err());
    }

    #[test]
    fn get_block_missing() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = rpc.get_block(999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_block_after_store() {
        let (store, _dir) = open_tmp();

        // Store a block at height 1.
        let block = Block {
            header: BlockHeader {
                height: 1,
                round: 0,
                parent_hash: [0u8; 32],
                state_root: [0xAA; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 0,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
        };
        let data = serde_json::to_vec(&block).unwrap();
        store.put(CF_BLOCKS, &1u64.to_le_bytes(), &data).unwrap();

        let rpc = make_rpc(store);
        *rpc.latest_height.lock().unwrap() = 1;

        let result = rpc.get_block(1).unwrap();
        assert!(result.is_some());
        let rpc_block = result.unwrap();
        assert_eq!(rpc_block.height, 1);
        assert_eq!(rpc_block.tx_count, 0);
    }

    #[test]
    fn get_latest_block() {
        let (store, _dir) = open_tmp();

        let block = Block {
            header: BlockHeader {
                height: 5,
                round: 0,
                parent_hash: [0u8; 32],
                state_root: [0xBB; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 0,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
        };
        let data = serde_json::to_vec(&block).unwrap();
        store.put(CF_BLOCKS, &5u64.to_le_bytes(), &data).unwrap();

        let rpc = make_rpc(store);
        *rpc.latest_height.lock().unwrap() = 5;

        let result = rpc.get_latest_block().unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().height, 5);
    }

    #[test]
    fn block_number_reflects_latest_height() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        // Default height is 0.
        assert_eq!(rpc.block_number().unwrap(), 0);

        // Reflects updates to the shared latest_height.
        *rpc.latest_height.lock().unwrap() = 42;
        assert_eq!(rpc.block_number().unwrap(), 42);
    }

    #[test]
    fn node_info_returns_version_and_bounded_uptime() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let info = rpc.node_info().unwrap();

        // Version mirrors the chain metadata (same source as solidus_chainInfo).
        assert_eq!(info.version, ChainMeta::default().version);
        // Just constructed, so uptime is small but defined.
        assert!(info.uptime_seconds < 5);
        // rss_bytes is 0 on non-Linux dev hosts and >0 on Linux; just exercise it.
        let _ = info.rss_bytes;
    }

    #[test]
    fn get_receipt_missing() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let hash = hex::encode([0x11; 32]);
        let result = rpc.get_receipt(hash).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_receipt_after_store() {
        let (store, _dir) = open_tmp();

        let receipt = solidus_txns::types::Receipt {
            tx_hash: [0x33; 32],
            status: solidus_txns::types::TxStatus::Success,
            block_height: 1,
            fee_paid: 10_000,
            events: vec![],
        };
        let data = serde_json::to_vec(&receipt).unwrap();
        store.put(CF_RECEIPTS, &receipt.tx_hash, &data).unwrap();

        let rpc = make_rpc(store);
        let hash = hex::encode([0x33; 32]);
        let result = rpc.get_receipt(hash).unwrap();
        assert!(result.is_some());
        let rpc_receipt = result.unwrap();
        assert_eq!(rpc_receipt.status, "success");
        assert_eq!(rpc_receipt.fee_paid, 10_000);
    }

    #[test]
    fn get_receipt_invalid_hex() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = rpc.get_receipt("not-hex".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn did_resolve_missing() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result =
            SolidusApiServer::did_resolve(&rpc, "did:solidus:testnet:nonexistent".to_string())
                .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn did_resolve_after_store() {
        use solidus_state::store::CF_DIDS;
        use solidus_txns::did::build_did_document;

        let (store, _dir) = open_tmp();
        let did = "did:solidus:testnet:abc123";
        let doc = build_did_document(did, "aabbcc", vec![], 1000);
        store.put(CF_DIDS, did.as_bytes(), &doc.to_bytes()).unwrap();

        let rpc = make_rpc(store);
        let result = SolidusApiServer::did_resolve(&rpc, did.to_string()).unwrap();
        assert!(result.is_some());

        let rpc_doc = result.unwrap();
        assert_eq!(rpc_doc.id, did);
        assert!(rpc_doc.active);
        assert_eq!(rpc_doc.created_ms, 1000);
    }

    #[test]
    fn did_resolve_exposes_recovery_fields() {
        use solidus_state::store::CF_DIDS;
        use solidus_txns::did::{build_did_document, RecoveryPolicy};

        let (store, _dir) = open_tmp();
        let did = "did:solidus:testnet:recoverable";
        let mut doc = build_did_document(did, "aabbcc", vec![], 1000);
        doc.recovery_policy = Some(RecoveryPolicy {
            guardians: vec![
                "did:solidus:testnet:g1".to_string(),
                "did:solidus:testnet:g2".to_string(),
                "did:solidus:testnet:g3".to_string(),
            ],
            threshold: 2,
            delay_blocks: 0,
        });
        doc.recovery_nonce = 7;
        store.put(CF_DIDS, did.as_bytes(), &doc.to_bytes()).unwrap();

        let rpc = make_rpc(store);
        let result = SolidusApiServer::did_resolve(&rpc, did.to_string()).unwrap();
        let rpc_doc = result.expect("recoverable DID should resolve");

        assert_eq!(rpc_doc.recovery_nonce, 7);
        let policy = rpc_doc
            .recovery_policy
            .expect("recovery_policy should be present on resolve");
        assert_eq!(
            policy.guardians,
            vec![
                "did:solidus:testnet:g1".to_string(),
                "did:solidus:testnet:g2".to_string(),
                "did:solidus:testnet:g3".to_string(),
            ]
        );
        assert_eq!(policy.threshold, 2);
        assert_eq!(policy.delay_blocks, 0);
    }

    #[test]
    fn get_transaction_scan_blocks() {
        let (store, _dir) = open_tmp();

        let sender = generate_signing_key();
        let to = Address::from_bytes([0xCC; 20]);
        let tx = make_transfer_tx(&sender, to, 1000, 0);
        let tx_hash = tx.hash();

        // Store a block containing the transaction at height 2.
        let block = Block {
            header: BlockHeader {
                height: 2,
                round: 0,
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 1,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![tx],
            parent_qc: None,
            vrf_proof: None,
        };
        let data = serde_json::to_vec(&block).unwrap();
        store.put(CF_BLOCKS, &2u64.to_le_bytes(), &data).unwrap();

        let rpc = make_rpc(store);
        *rpc.latest_height.lock().unwrap() = 2;

        let hash_hex = hex::encode(tx_hash);
        let result = rpc.get_transaction(hash_hex).unwrap();
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // Credential RPC tests
    // -----------------------------------------------------------------------

    #[test]
    fn credential_verify_missing() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = SolidusApiServer::credential_verify(
            &rpc,
            "urn:solidus:credential:nonexistent".to_string(),
        )
        .unwrap();
        assert!(result.is_none(), "missing credential should return None");
    }

    #[test]
    fn credential_verify_after_store() {
        use solidus_state::store::CF_CREDENTIALS;
        use solidus_txns::credential::{CredentialRecord, CredentialType};

        let (store, _dir) = open_tmp();

        let cred = CredentialRecord {
            id: "urn:solidus:credential:aabbcc".to_string(),
            issuer_did: "did:solidus:testnet:issuer".to_string(),
            subject_did: "did:solidus:testnet:subject".to_string(),
            subject_commitment: None,
            credential_type: CredentialType::Email,
            hash: [0x11u8; 32],
            issued_ms: 1_700_000_000_000,
            revoked: false,
            revoked_ms: None,
            bbs_pubkey: None,
            bbs_message_count: None,
        };
        store
            .put(CF_CREDENTIALS, cred.id.as_bytes(), &cred.to_bytes())
            .unwrap();

        let rpc = make_rpc(store);
        let result =
            SolidusApiServer::credential_verify(&rpc, "urn:solidus:credential:aabbcc".to_string())
                .unwrap();

        assert!(result.is_some(), "should find stored credential");
        let verify = result.unwrap();
        assert!(verify.valid, "credential should be valid (not revoked)");
        assert!(!verify.revoked, "revoked flag should be false");
        let rpc_cred = verify
            .credential
            .expect("credential field should be present");
        assert_eq!(rpc_cred.id, "urn:solidus:credential:aabbcc");
        assert_eq!(rpc_cred.hash, hex::encode([0x11u8; 32]));
    }

    // ⚠ AN ORPHANED `#[test]` AND ITS DOC COMMENT WERE REMOVED HERE, 2026-08-23.
    //
    // A later edit inserted the doc comment and `#[test]` below BETWEEN an existing
    // `#[test]` and its function, so two attributes stacked onto one test and the first
    // annotated nothing. `cargo check --workspace` cannot see that: lib-tests are not
    // built without `--all-targets`, and CI has been dark since 2026-08-08.
    //
    // The coverage it described is NOT lost, which is why nothing was restored: the
    // refusal and its control both live below as
    // `credentials_by_subject_*`, asserting a policy refusal that names the reason
    // rather than an empty list. Checked before deleting.

    /// ⛔ A v2 credential must be READABLE, or it is write-only and useless.
    ///
    /// The holder's whole path is: receive `(subject_did, nonce)` off-chain, read the
    /// record back, recompute `BLAKE3(domain ‖ did ‖ nonce)` and compare it to what the
    /// chain served. **If the RPC does not serve `subject_commitment`, there is nothing
    /// to compare against** and the credential can never be proved. That is exactly what
    /// happened: `RpcCredentialRecord` whitelists its fields, so adding the field to the
    /// chain record did not expose it here, and the gap was silent.
    #[test]
    fn v2_record_serves_the_commitment_so_a_holder_can_verify() {
        use solidus_txns::credential::build_subject_commitment;

        let commitment = build_subject_commitment("did:solidus:testnet:alice", &[0x5a; 32]);
        let cred = solidus_txns::credential::execute_credential_issue_v2(
            "did:solidus:testnet:issuer",
            commitment,
            solidus_txns::credential::CredentialType::KycL3,
            [0x11; 32],
            true,
            42,
            1_700_000_000_000,
        )
        .expect("issue");

        let rpc_rec = RpcCredentialRecord::from_credential(&cred);

        // The holder can recompute and compare.
        assert_eq!(
            rpc_rec.subject_commitment.as_deref(),
            Some(hex::encode(commitment).as_str()),
            "the commitment must reach the caller"
        );
        // And the subject itself still does not.
        assert!(rpc_rec.subject_did.is_empty());
        let json = serde_json::to_string(&rpc_rec).expect("serialize");
        assert!(
            !json.contains("alice"),
            "the subject must not be served: {json}"
        );

        // CONTROL: a v1 record serves the DID and NO commitment, so the assertions above
        // are reading the v2 shape rather than a field that is always set or always empty.
        let v1 = solidus_txns::credential::execute_credential_issue(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:alice",
            solidus_txns::credential::CredentialType::KycL3,
            [0x11; 32],
            true,
            true,
            42,
            1_700_000_000_000,
        )
        .expect("v1 issue");
        let v1_rec = RpcCredentialRecord::from_credential(&v1);
        assert_eq!(v1_rec.subject_did, "did:solidus:testnet:alice");
        assert_eq!(v1_rec.subject_commitment, None);
    }

    #[test]
    fn credentials_by_subject_is_refused_by_default() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);
        assert!(
            !rpc.allow_subject_enumeration,
            "the secure default must be closed; if this flips, the gate is decorative"
        );

        let err = SolidusApiServer::credentials_by_subject(
            &rpc,
            "did:solidus:testnet:nobody".to_string(),
        )
        .expect_err("subject enumeration must not answer on a default node");

        assert_eq!(err.code(), POLICY_DISABLED, "must not masquerade as -32601");
        assert_ne!(
            err.code(),
            INTERNAL_ERROR,
            "a policy refusal is not a node fault"
        );
        assert!(
            err.message().contains("correlation handle"),
            "the refusal must say WHY, got: {}",
            err.message()
        );
    }

    /// CONTROL for the test above. A gate that refuses everything proves nothing;
    /// this shows the same call succeeds once the node opts in, so the refusal is
    /// attributable to the flag and not to a broken code path.
    #[test]
    fn credentials_by_subject_answers_when_explicitly_enabled() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store).with_subject_enumeration(true);

        let result = SolidusApiServer::credentials_by_subject(
            &rpc,
            "did:solidus:testnet:nobody".to_string(),
        )
        .expect("an opted-in node must answer");
        assert!(result.is_empty(), "unknown DID returns an empty list");
    }

    /// The issuer index is deliberately NOT gated, and this pins that decision.
    /// Issuer + type + timestamp in aggregate is far weaker than a per-subject
    /// lookup, and explorers need it. If someone gates it later, this test tells
    /// them it was a choice rather than an oversight.
    #[test]
    fn credentials_by_issuer_is_not_gated() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);
        assert!(!rpc.allow_subject_enumeration, "still the closed default");

        let result =
            SolidusApiServer::credentials_by_issuer(&rpc, "did:solidus:testnet:issuer".to_string())
                .expect("issuer lookup stays open on a default node");
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Validator RPC tests
    // -----------------------------------------------------------------------

    #[test]
    fn get_validator_stake_missing() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let addr = Address::from_bytes([0xAB; 20]);
        let result = SolidusApiServer::get_validator_stake(&rpc, addr.to_base58()).unwrap();
        assert!(result.is_none(), "missing validator should return None");
    }

    /// Helper: build `n` synthetic committee identities with random keys.
    fn make_committee(n: usize) -> Vec<ValidatorIdentity> {
        use solidus_crypto::bls::BlsSecretKey;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let ed_sk = generate_signing_key();
            let bls_sk = BlsSecretKey::generate();
            out.push(ValidatorIdentity {
                address: Address::from_public_key(&ed_sk.verifying_key()),
                ed25519_pubkey: ed_sk.verifying_key().to_bytes(),
                bls_pubkey: bls_sk.public_key(),
            });
        }
        out
    }

    #[test]
    fn get_validators_returns_committee_when_no_onchain_validators() {
        // Reproduces the dev-testnet case: 4 in-process consensus voters,
        // zero on-chain staking transactions. The RPC must still surface the
        // committee so the explorer's validator list is not empty.
        let (store, _dir) = open_tmp();
        let committee = make_committee(4);
        let expected_addresses: HashSet<String> =
            committee.iter().map(|v| v.address.to_base58()).collect();

        let rpc = make_rpc_with_committee(store, committee);
        let result = SolidusApiServer::get_validators(&rpc).expect("rpc call");

        assert_eq!(result.len(), 4, "should surface all 4 committee members");
        for v in &result {
            assert!(v.active, "committee fallback entries must be active=true");
            assert_eq!(v.staked, 0, "committee fallback has no on-chain stake");
            assert_eq!(v.unbonding, 0);
            assert_eq!(v.reputation, 0);
        }
        let returned: HashSet<String> = result.iter().map(|v| v.address.clone()).collect();
        assert_eq!(
            returned, expected_addresses,
            "every committee member's address must appear exactly once"
        );
    }

    #[test]
    fn get_validators_prefers_onchain_row_over_committee_duplicate() {
        // When the same address appears both on-chain (with real stake) and
        // in the in-process committee, the on-chain row must win so that
        // production behaviour is unchanged.
        use solidus_txns::staking::MIN_STAKE;

        let (store, _dir) = open_tmp();
        let committee = make_committee(2);

        // Persist the first committee member as a real on-chain validator
        // with a non-zero stake.
        let on_chain_addr = committee[0].address;
        let info = ValidatorInfo {
            address: on_chain_addr,
            staked: MIN_STAKE,
            unbonding: 0,
            unbonding_start_ms: None,
            reputation: 750,
            active: true,
        };
        store
            .put(CF_VALIDATORS, on_chain_addr.as_bytes(), &info.to_bytes())
            .unwrap();

        let rpc = make_rpc_with_committee(store, committee);
        let result = SolidusApiServer::get_validators(&rpc).expect("rpc call");

        // 2 entries: one on-chain row + one committee-only fallback.
        assert_eq!(result.len(), 2);
        let on_chain = result
            .iter()
            .find(|v| v.address == on_chain_addr.to_base58())
            .expect("on-chain validator must be present");
        assert_eq!(
            on_chain.staked, MIN_STAKE,
            "on-chain stake must not be overwritten by committee fallback"
        );
        assert_eq!(on_chain.reputation, 750);
    }

    #[test]
    fn get_validator_stake_after_store() {
        use solidus_state::store::CF_VALIDATORS;
        use solidus_txns::staking::{ValidatorInfo, MIN_STAKE};

        let (store, _dir) = open_tmp();

        let addr = Address::from_bytes([0xCD; 20]);
        let info = ValidatorInfo {
            address: addr,
            staked: MIN_STAKE,
            unbonding: 0,
            unbonding_start_ms: None,
            reputation: 1000,
            active: true,
        };
        store
            .put(CF_VALIDATORS, addr.as_bytes(), &info.to_bytes())
            .unwrap();

        let rpc = make_rpc(store);
        let result = SolidusApiServer::get_validator_stake(&rpc, addr.to_base58()).unwrap();
        assert!(result.is_some(), "should find stored validator");

        let rpc_info = result.unwrap();
        assert_eq!(rpc_info.staked, MIN_STAKE);
        assert!(rpc_info.active);
        assert_eq!(rpc_info.reputation, 1000);
        assert_eq!(rpc_info.unbonding, 0);
        assert_eq!(rpc_info.address, addr.to_base58());
    }

    // -----------------------------------------------------------------------
    // BBS+ RPC tests
    // -----------------------------------------------------------------------

    /// Helper: build a sample 8-message KYC vector + sign with a fresh BBS keypair.
    /// Returns (sk, pk_bytes, sig, messages, header).
    fn make_bbs_credential_fixtures() -> (
        solidus_crypto::bbs::BbsSecretKey,
        [u8; 96],
        solidus_crypto::bbs::BbsSignature,
        Vec<&'static [u8]>,
        &'static [u8],
    ) {
        use solidus_crypto::bbs::BbsSecretKey;
        let sk = BbsSecretKey::from_ikm(b"rpc-bbs-test-ikm-must-be-at-least-32-bytes-long")
            .expect("ikm");
        let pk_bytes = sk.public_key().to_bytes();
        let messages: Vec<&[u8]> = vec![
            b"did:solidus:testnet:alice".as_ref(),
            b"Alice Liddell".as_ref(),
            b"1990-07-04".as_ref(),
            b"GB".as_ref(),
            b"passport".as_ref(),
            b"P-12345".as_ref(),
            b"KycL2".as_ref(),
            b"2026-01-15T00:00:00Z".as_ref(),
        ];
        let header: &[u8] = b"solidus-rpc-test-credential";
        let sig = sk.sign(header, &messages).expect("sign");
        (sk, pk_bytes, sig, messages, header)
    }

    #[test]
    fn bbs_verify_proof_happy_path() {
        let (_sk, pk_bytes, sig, messages, header) = make_bbs_credential_fixtures();
        let pk = solidus_crypto::bbs::BbsPublicKey::from_bytes(&pk_bytes).expect("pk");
        let ph: &[u8] = b"verifier-presentation-header";

        // Disclose did, country, kyc_level (indices 0, 3, 6).
        let disclosed_indices = [0_usize, 3, 6];
        let proof = sig
            .create_proof(&pk, header, ph, &messages, &disclosed_indices)
            .expect("proof_gen");

        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let disclosed_messages: Vec<RpcDisclosedMessage> = disclosed_indices
            .iter()
            .map(|&i| RpcDisclosedMessage {
                index: i as u32,
                message: hex::encode(messages[i]),
            })
            .collect();

        let valid = SolidusApiServer::bbs_verify_proof(
            &rpc,
            proof.to_hex(),
            hex::encode(pk_bytes),
            hex::encode(header),
            hex::encode(ph),
            disclosed_messages,
            messages.len() as u32,
        )
        .expect("bbs_verify_proof");
        assert!(valid, "fresh proof should verify");
    }

    #[test]
    fn bbs_verify_proof_rejects_tampered_disclosed_message() {
        let (_sk, pk_bytes, sig, messages, header) = make_bbs_credential_fixtures();
        let pk = solidus_crypto::bbs::BbsPublicKey::from_bytes(&pk_bytes).expect("pk");
        let ph: &[u8] = b"verifier-presentation-header";

        let disclosed_indices = [0_usize, 3, 6];
        let proof = sig
            .create_proof(&pk, header, ph, &messages, &disclosed_indices)
            .expect("proof_gen");

        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        // Lie about the country: claim FR instead of GB.
        let lied: Vec<RpcDisclosedMessage> = vec![
            RpcDisclosedMessage {
                index: 0,
                message: hex::encode(messages[0]),
            },
            RpcDisclosedMessage {
                index: 3,
                message: hex::encode(b"FR"),
            },
            RpcDisclosedMessage {
                index: 6,
                message: hex::encode(messages[6]),
            },
        ];

        let valid = SolidusApiServer::bbs_verify_proof(
            &rpc,
            proof.to_hex(),
            hex::encode(pk_bytes),
            hex::encode(header),
            hex::encode(ph),
            lied,
            messages.len() as u32,
        )
        .expect("bbs_verify_proof");
        assert!(!valid, "tampered disclosed message must not verify");
    }

    #[test]
    fn bbs_verify_proof_rejects_invalid_pubkey_hex() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = SolidusApiServer::bbs_verify_proof(
            &rpc,
            "deadbeef".to_string(),
            "not-hex".to_string(),
            String::new(),
            String::new(),
            vec![],
            0,
        );
        assert!(result.is_err(), "invalid pubkey hex must return error");
    }

    #[test]
    fn bbs_verify_proof_rejects_index_out_of_range() {
        let (_sk, pk_bytes, _sig, messages, _header) = make_bbs_credential_fixtures();

        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let bogus = vec![RpcDisclosedMessage {
            index: 99,
            message: hex::encode(b"hi"),
        }];

        let result = SolidusApiServer::bbs_verify_proof(
            &rpc,
            "00".to_string(),
            hex::encode(pk_bytes),
            String::new(),
            String::new(),
            bogus,
            messages.len() as u32,
        );
        assert!(result.is_err(), "out-of-range index must be invalid_params");
    }

    #[test]
    fn bbs_verify_credential_proof_unknown_credential() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = SolidusApiServer::bbs_verify_credential_proof(
            &rpc,
            "urn:solidus:credential:does-not-exist".to_string(),
            "deadbeef".to_string(),
            String::new(),
            String::new(),
            vec![],
        )
        .expect("call must not error");

        assert!(!result.valid);
        assert!(!result.proof_valid);
        assert!(!result.is_bbs);
        assert!(!result.revoked);
        assert!(result.credential.is_none());
    }

    #[test]
    fn bbs_verify_credential_proof_non_bbs_credential() {
        use solidus_state::store::CF_CREDENTIALS;
        use solidus_txns::credential::{CredentialRecord, CredentialType};

        let (store, _dir) = open_tmp();
        // Store a non-BBS credential (legacy / Ed25519).
        let cred = CredentialRecord {
            id: "urn:solidus:credential:legacy".to_string(),
            issuer_did: "did:solidus:testnet:issuer".to_string(),
            subject_did: "did:solidus:testnet:subject".to_string(),
            subject_commitment: None,
            credential_type: CredentialType::Email,
            hash: [0u8; 32],
            issued_ms: 1_000,
            revoked: false,
            revoked_ms: None,
            bbs_pubkey: None,
            bbs_message_count: None,
        };
        store
            .put(CF_CREDENTIALS, cred.id.as_bytes(), &cred.to_bytes())
            .unwrap();

        let rpc = make_rpc(store);
        let result = SolidusApiServer::bbs_verify_credential_proof(
            &rpc,
            cred.id.clone(),
            "00".to_string(),
            String::new(),
            String::new(),
            vec![],
        )
        .expect("call must not error");

        assert!(!result.valid);
        assert!(!result.proof_valid);
        assert!(!result.is_bbs, "credential without bbs_pubkey is not BBS");
        assert!(!result.revoked);
        assert!(result.credential.is_some());
    }

    #[test]
    fn bbs_verify_credential_proof_happy_path() {
        use solidus_state::store::CF_CREDENTIALS;
        use solidus_txns::credential::{CredentialRecord, CredentialType};

        let (_sk, pk_bytes, sig, messages, header) = make_bbs_credential_fixtures();
        let pk = solidus_crypto::bbs::BbsPublicKey::from_bytes(&pk_bytes).expect("pk");
        let ph: &[u8] = b"happy-path-ph";
        let disclosed_indices = [0_usize, 3, 6];
        let proof = sig
            .create_proof(&pk, header, ph, &messages, &disclosed_indices)
            .expect("proof_gen");

        // Persist a matching credential record on-chain.
        let (store, _dir) = open_tmp();
        let cred = CredentialRecord {
            id: "urn:solidus:credential:bbs-test".to_string(),
            issuer_did: "did:solidus:testnet:issuer".to_string(),
            subject_did: "did:solidus:testnet:alice".to_string(),
            subject_commitment: None,
            credential_type: CredentialType::KycL2,
            hash: [0xAA; 32],
            issued_ms: 1_700_000_000_000,
            revoked: false,
            revoked_ms: None,
            bbs_pubkey: Some(pk_bytes),
            bbs_message_count: Some(messages.len() as u32),
        };
        store
            .put(CF_CREDENTIALS, cred.id.as_bytes(), &cred.to_bytes())
            .unwrap();

        let rpc = make_rpc(store);
        let disclosed_messages: Vec<RpcDisclosedMessage> = disclosed_indices
            .iter()
            .map(|&i| RpcDisclosedMessage {
                index: i as u32,
                message: hex::encode(messages[i]),
            })
            .collect();

        let result = SolidusApiServer::bbs_verify_credential_proof(
            &rpc,
            cred.id.clone(),
            proof.to_hex(),
            hex::encode(header),
            hex::encode(ph),
            disclosed_messages,
        )
        .expect("call must not error");

        assert!(result.valid, "fresh proof should be valid");
        assert!(result.proof_valid);
        assert!(result.is_bbs);
        assert!(!result.revoked);
        let rpc_cred = result.credential.expect("credential field");
        assert_eq!(rpc_cred.bbs_message_count, Some(messages.len() as u32));
        assert_eq!(rpc_cred.bbs_pubkey, Some(hex::encode(pk_bytes)));
    }

    #[test]
    fn bbs_verify_credential_proof_revoked_marks_invalid() {
        use solidus_state::store::CF_CREDENTIALS;
        use solidus_txns::credential::{CredentialRecord, CredentialType};

        let (_sk, pk_bytes, sig, messages, header) = make_bbs_credential_fixtures();
        let pk = solidus_crypto::bbs::BbsPublicKey::from_bytes(&pk_bytes).expect("pk");
        let ph: &[u8] = b"revoked-ph";
        let disclosed_indices = [0_usize];
        let proof = sig
            .create_proof(&pk, header, ph, &messages, &disclosed_indices)
            .expect("proof_gen");

        let (store, _dir) = open_tmp();
        let cred = CredentialRecord {
            id: "urn:solidus:credential:bbs-revoked".to_string(),
            issuer_did: "did:solidus:testnet:issuer".to_string(),
            subject_did: "did:solidus:testnet:alice".to_string(),
            subject_commitment: None,
            credential_type: CredentialType::KycL1,
            hash: [0; 32],
            issued_ms: 1_000,
            revoked: true, // revoked!
            revoked_ms: Some(2_000),
            bbs_pubkey: Some(pk_bytes),
            bbs_message_count: Some(messages.len() as u32),
        };
        store
            .put(CF_CREDENTIALS, cred.id.as_bytes(), &cred.to_bytes())
            .unwrap();

        let rpc = make_rpc(store);
        let result = SolidusApiServer::bbs_verify_credential_proof(
            &rpc,
            cred.id.clone(),
            proof.to_hex(),
            hex::encode(header),
            hex::encode(ph),
            vec![RpcDisclosedMessage {
                index: 0,
                message: hex::encode(messages[0]),
            }],
        )
        .expect("call must not error");

        // Proof is cryptographically valid, but the credential is revoked.
        assert!(result.proof_valid, "underlying proof is still valid crypto");
        assert!(!result.valid, "valid=false because revoked");
        assert!(result.is_bbs);
        assert!(result.revoked);
    }

    #[test]
    fn chain_info_default_metadata() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let info = rpc.chain_info().expect("chain_info should succeed");
        assert_eq!(info.chain_id, "solidus-testnet");
        assert_eq!(info.native_token.symbol, "TESTNET-SOLI");
        assert_eq!(info.native_token.decimals, 8);
        assert_eq!(info.latest_block, 0);
        // No genesis block stored → falls back to the chain_id-derived hash
        // (matches the node's genesis_hash = blake3(chain_id)). Never empty.
        assert_eq!(
            info.genesis_hash,
            hex::encode(solidus_crypto::hash::blake3_hash(b"solidus-testnet")),
        );
        assert!(!info.genesis_hash.is_empty());
        assert!(!info.version.is_empty());
    }

    #[test]
    fn chain_info_surfaces_custom_metadata_and_genesis_hash() {
        let (store, _dir) = open_tmp();

        // Store a genesis block at height 0.
        let block = Block {
            header: BlockHeader {
                height: 0,
                round: 0,
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 0,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
        };
        let expected_hash = hex::encode(block.hash());
        let data = serde_json::to_vec(&block).unwrap();
        store.put(CF_BLOCKS, &0u64.to_le_bytes(), &data).unwrap();

        let chain_meta = ChainMeta {
            chain_id: "solidus-mainnet-1".to_string(),
            native_token: RpcNativeToken {
                symbol: "SLDS".to_string(),
                name: "Solidus".to_string(),
                decimals: 8,
            },
            version: "9.9.9".to_string(),
        };
        let rpc = SolidusRpcImpl::new(
            store,
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Mutex::new(0)),
            Arc::new(Vec::new()),
            chain_meta,
            None,
            Arc::new(tokio::sync::Notify::new()),
        );

        let info = rpc.chain_info().expect("chain_info should succeed");
        assert_eq!(info.chain_id, "solidus-mainnet-1");
        assert_eq!(info.native_token.symbol, "SLDS");
        assert_eq!(info.version, "9.9.9");
        assert_eq!(info.genesis_hash, expected_hash);
    }

    // -----------------------------------------------------------------------
    // canonHead / getBlockBySeq
    // -----------------------------------------------------------------------

    /// Helper: build a minimal Block for canon-index tests. Header values are
    /// all zero except height + round, which the RPC layer surfaces.
    fn dummy_block(height: u64, round: u64) -> Block {
        Block {
            header: BlockHeader {
                height,
                round,
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 0,
                tx_count: 0,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
        }
    }

    #[test]
    fn canon_head_returns_none_when_empty() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);
        assert!(rpc.canon_head().unwrap().is_none());
    }

    #[test]
    fn canon_head_returns_max_seq_and_hash() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(Arc::clone(&store));

        let b0 = dummy_block(0, 0);
        let b1 = dummy_block(1, 1);
        solidus_consensus::ledger::put_block_by_hash(&store, &b0).unwrap();
        solidus_consensus::ledger::put_block_by_hash(&store, &b1).unwrap();
        solidus_consensus::ledger::canon_append(&store, 0, &b0.hash()).unwrap();
        solidus_consensus::ledger::canon_append(&store, 1, &b1.hash()).unwrap();

        let head = rpc.canon_head().unwrap().expect("head should be Some");
        assert_eq!(head.seq, 1);
        assert_eq!(head.hash, hex::encode(b1.hash()));
    }

    #[test]
    fn get_block_by_seq_returns_block_at_canon_position() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(Arc::clone(&store));

        let b0 = dummy_block(0, 0);
        let b1 = dummy_block(1, 5); // intentionally mismatched height vs seq
        solidus_consensus::ledger::put_block_by_hash(&store, &b0).unwrap();
        solidus_consensus::ledger::put_block_by_hash(&store, &b1).unwrap();
        solidus_consensus::ledger::canon_append(&store, 0, &b0.hash()).unwrap();
        solidus_consensus::ledger::canon_append(&store, 1, &b1.hash()).unwrap();

        let got = rpc.get_block_by_seq(1).unwrap().expect("seq 1 exists");
        assert_eq!(got.hash, hex::encode(b1.hash()));
        assert_eq!(got.round, 5);
    }

    #[test]
    fn get_block_by_seq_returns_none_for_unknown_seq() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);
        assert!(rpc.get_block_by_seq(999).unwrap().is_none());
    }
}
