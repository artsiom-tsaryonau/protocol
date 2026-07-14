use std::sync::Arc;

use solidus_crypto::keys::Address;
use solidus_txns::compute::{
    execute_compute_admit, execute_compute_anchor, execute_compute_register,
    execute_compute_remove, execute_compute_slash, ComputeAllowEntry, ComputeNodeInfo,
};
use solidus_txns::credential::{
    execute_credential_issue, execute_credential_issue_bbs, execute_credential_revoke,
    CredentialRecord,
};
use solidus_txns::did::{
    execute_did_create, execute_did_deactivate, execute_did_recover, execute_did_update,
    DidDocument,
};
use solidus_txns::staking::{execute_stake, execute_unstake, ValidatorInfo};
use solidus_txns::token::execute_transfer;
use solidus_txns::types::{Event, Receipt, Transaction, TxPayload, TxStatus};

use crate::account::Account;
use crate::store::{
    Store, StoreError, CF_ACCOUNTS, CF_COMMITTED_ACCOUNTS, CF_COMPUTE_ALLOWLIST,
    CF_COMPUTE_ANCHORS, CF_COMPUTE_NODES, CF_CREDENTIALS, CF_CRED_BY_ISSUER, CF_CRED_BY_SUBJECT,
    CF_DIDS, CF_RECEIPTS, CF_VALIDATORS,
};
use crate::tree::global_state_root;

// ---------------------------------------------------------------------------
// Fee distribution constants
// ---------------------------------------------------------------------------

/// Validators collectively receive 70% of total fees.
const VALIDATOR_SHARE_PCT: u64 = 70;
/// The protocol treasury receives 20% of total fees.
const TREASURY_SHARE_PCT: u64 = 20;
// The remaining 10% is burned (not credited to anyone).

// ---------------------------------------------------------------------------
// ExecutorError
// ---------------------------------------------------------------------------

/// Errors produced by the block executor.
#[derive(thiserror::Error, Debug)]
pub enum ExecutorError {
    /// An error originating from the key-value store.
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// Transaction signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// Transaction nonce does not match the account nonce.
    #[error("invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    /// The referenced account was not found (should not happen after
    /// load_account returns a default, but kept for completeness).
    #[error("account not found: {0}")]
    AccountNotFound(Address),
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Load an account from the store. Returns a default zero-balance account if
/// the address has no entry in `CF_ACCOUNTS`.
pub fn load_account(store: &Store, address: &Address) -> Result<Account, StoreError> {
    match store.get(CF_ACCOUNTS, address.as_bytes())? {
        Some(bytes) => Account::from_bytes(&bytes).map_err(|e| StoreError::Serde(e.to_string())),
        None => Ok(Account::new(*address)),
    }
}

/// Persist an account to the store under `CF_ACCOUNTS`.
pub fn save_account(store: &Store, account: &Account) -> Result<(), StoreError> {
    store.put(CF_ACCOUNTS, account.address.as_bytes(), &account.to_bytes())
}

/// Load an account from the COMMITTED view (`CF_COMMITTED_ACCOUNTS`).
///
/// This is the finalized state that survives 3-chain commit. RPC queries
/// (`getBalance`/`getNonce`) MUST use this rather than [`load_account`] so
/// callers never see the speculative effects of validated-but-not-yet-
/// committed blocks (which `execute_block` writes to `CF_ACCOUNTS`).
///
/// Returns a default zero-balance account if the address has no entry —
/// matches [`load_account`]'s contract.
pub fn load_committed_account(store: &Store, address: &Address) -> Result<Account, StoreError> {
    match store.get(CF_COMMITTED_ACCOUNTS, address.as_bytes())? {
        Some(bytes) => Account::from_bytes(&bytes).map_err(|e| StoreError::Serde(e.to_string())),
        None => Ok(Account::new(*address)),
    }
}

/// Persist an account to the COMMITTED view (`CF_COMMITTED_ACCOUNTS`).
///
/// Called from `HotStuffEngine::try_commit` to mirror each touched account
/// from `CF_ACCOUNTS` to `CF_COMMITTED_ACCOUNTS` when a block finalizes.
/// Also called from `load_genesis` so the genesis allocation is visible
/// to RPC before the first commit ever fires.
pub fn save_committed_account(store: &Store, account: &Account) -> Result<(), StoreError> {
    store.put(
        CF_COMMITTED_ACCOUNTS,
        account.address.as_bytes(),
        &account.to_bytes(),
    )
}

/// Mirror an account from `CF_ACCOUNTS` to `CF_COMMITTED_ACCOUNTS`.
///
/// Reads the live value and copies it byte-for-byte. If the account has
/// no entry in `CF_ACCOUNTS` (e.g. a never-touched address surfaced by
/// a noisy touched-set), the mirror is a no-op.
pub fn mirror_account_to_committed(store: &Store, address: &Address) -> Result<(), StoreError> {
    if let Some(bytes) = store.get(CF_ACCOUNTS, address.as_bytes())? {
        store.put(CF_COMMITTED_ACCOUNTS, address.as_bytes(), &bytes)?;
    }
    Ok(())
}

/// Derive the set of account addresses whose `CF_ACCOUNTS` entries may have
/// been written by `execute_block` for a given block.
///
/// This is a syntactic over-approximation derived purely from the block's
/// transactions + the fee-distribution targets — no executor knowledge is
/// needed. The set is:
///   - Every transaction sender (every tx debits its sender for the fee).
///   - Every `Transfer` recipient (`to` field).
///   - The treasury address (fee distribution: 20% to treasury).
///   - Each validator address (fee distribution: 70% split among validators).
///
/// Other transaction types (DID*, Credential*, Stake/Unstake) only touch
/// the sender's `CF_ACCOUNTS` entry; they write to other CFs (CF_DIDS /
/// CF_CREDENTIALS / CF_VALIDATORS) which are not mirrored to the committed
/// view (RPC queries against those CFs don't make a speculative/committed
/// distinction today; if that changes, extend the mirror similarly).
pub fn block_touched_accounts(
    transactions: &[Transaction],
    treasury: &Address,
    validators: &[Address],
) -> std::collections::HashSet<Address> {
    let mut touched = std::collections::HashSet::new();
    touched.insert(*treasury);
    for v in validators {
        touched.insert(*v);
    }
    for tx in transactions {
        touched.insert(tx.sender_address());
        if let TxPayload::Transfer { to, .. } = &tx.payload {
            touched.insert(*to);
        }
    }
    touched
}

/// Load a DID document from the store. Returns `Ok(None)` if not found.
pub fn load_did(store: &Store, did: &str) -> Result<Option<DidDocument>, StoreError> {
    match store.get(CF_DIDS, did.as_bytes())? {
        Some(bytes) => Ok(Some(
            DidDocument::from_bytes(&bytes).map_err(|e| StoreError::Serde(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

/// Persist a DID document to the store under `CF_DIDS`.
pub fn save_did(store: &Store, did: &str, doc: &DidDocument) -> Result<(), StoreError> {
    store.put(CF_DIDS, did.as_bytes(), &doc.to_bytes())
}

/// True if `addr` is a registered DID-anchor — a DID document exists at
/// `did:solidus:{network}:{base58(addr)}`. Anchors are forbidden from holding
/// or moving value (see the Transfer guard in `execute_block`), so this is the
/// predicate that keeps identity and value accounts disjoint. Existence —
/// active OR deactivated — makes an address an anchor; a tombstoned DID's
/// address must stay value-free too.
pub fn is_did_anchor(store: &Store, network: &str, addr: &Address) -> Result<bool, StoreError> {
    let did = solidus_txns::did::build_did(network, addr);
    Ok(load_did(store, &did)?.is_some())
}

/// Load a credential record from the store. Returns `Ok(None)` if not found.
pub fn load_credential(
    store: &Store,
    credential_id: &str,
) -> Result<Option<CredentialRecord>, StoreError> {
    match store.get(CF_CREDENTIALS, credential_id.as_bytes())? {
        Some(bytes) => Ok(Some(
            CredentialRecord::from_bytes(&bytes).map_err(|e| StoreError::Serde(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

/// Persist a credential record to the store under `CF_CREDENTIALS`.
pub fn save_credential(store: &Store, cred: &CredentialRecord) -> Result<(), StoreError> {
    store.put(CF_CREDENTIALS, cred.id.as_bytes(), &cred.to_bytes())
}

/// Load credential IDs from a secondary index (by subject or by issuer).
pub fn load_credential_ids(store: &Store, cf: &str, key: &str) -> Result<Vec<String>, StoreError> {
    match store.get(cf, key.as_bytes())? {
        Some(bytes) => {
            Ok(serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde(e.to_string()))?)
        }
        None => Ok(vec![]),
    }
}

/// Load a validator record from the store. Returns `Ok(None)` if not found.
pub fn load_validator(
    store: &Store,
    address: &Address,
) -> Result<Option<ValidatorInfo>, StoreError> {
    match store.get(CF_VALIDATORS, address.as_bytes())? {
        Some(bytes) => Ok(Some(
            ValidatorInfo::from_bytes(&bytes).map_err(|e| StoreError::Serde(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

/// Persist a validator record to the store under `CF_VALIDATORS`.
pub fn save_validator(store: &Store, info: &ValidatorInfo) -> Result<(), StoreError> {
    store.put(CF_VALIDATORS, info.address.as_bytes(), &info.to_bytes())
}

// --- Compute-network state helpers (§6.5). Auxiliary CFs, not in the state root.

/// Whether `addr` may act as compute governance. Phase-1 policy: an active
/// validator (a hand-picked testnet's validator set is its governance).
fn is_compute_governance(store: &Store, addr: &Address) -> Result<bool, StoreError> {
    Ok(load_validator(store, addr)?
        .map(|v| v.active)
        .unwrap_or(false))
}

fn load_compute_allow(
    store: &Store,
    operator: &Address,
) -> Result<Option<ComputeAllowEntry>, StoreError> {
    match store.get(CF_COMPUTE_ALLOWLIST, operator.as_bytes())? {
        Some(b) => Ok(Some(
            ComputeAllowEntry::from_bytes(&b).map_err(|e| StoreError::Serde(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

fn load_compute_node(
    store: &Store,
    operator: &Address,
) -> Result<Option<ComputeNodeInfo>, StoreError> {
    match store.get(CF_COMPUTE_NODES, operator.as_bytes())? {
        Some(b) => Ok(Some(
            ComputeNodeInfo::from_bytes(&b).map_err(|e| StoreError::Serde(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

fn compute_ok(tx_hash: [u8; 32], block_height: u64, fee: u64, event: Event) -> Receipt {
    Receipt {
        tx_hash,
        status: TxStatus::Success,
        block_height,
        fee_paid: fee,
        events: vec![event],
    }
}

fn compute_failed(tx_hash: [u8; 32], block_height: u64, fee: u64, reason: String) -> Receipt {
    Receipt {
        tx_hash,
        status: TxStatus::Failed(reason),
        block_height,
        fee_paid: fee,
        events: vec![],
    }
}

/// Meta key (inside `CF_COMPUTE_ANCHORS`) holding the next monotonic anchor seq
/// (u64 LE). `CF_COMPUTE_ANCHORS` holds three disjoint key kinds, kept distinct by
/// fixed length: 8-byte seq → `ComputeReceiptAnchor` (the append-only primary
/// record), 32-byte Merkle root → seq (the duplicate-root secondary index), and
/// this 20-byte meta key → the counter. None can collide.
const META_NEXT_ANCHOR_SEQ: &[u8] = b"meta:next_anchor_seq";

/// Read the next anchor seq (0 on a fresh chain). Read-use-increment happens
/// within `execute_block`'s single-threaded loop, so it is atomic per tx.
fn next_anchor_seq(store: &Store) -> Result<u64, StoreError> {
    match store.get(CF_COMPUTE_ANCHORS, META_NEXT_ANCHOR_SEQ)? {
        Some(b) => Ok(u64::from_le_bytes(b.as_slice().try_into().map_err(
            |_| StoreError::Serde("anchor seq counter corrupt".to_string()),
        )?)),
        None => Ok(0),
    }
}

/// Whether a Merkle root is already present in the anchor index (duplicate-root
/// guard). Keyed by the raw 32-byte root — distinct in length from seq/meta keys.
fn anchor_root_exists(store: &Store, root: &[u8; 32]) -> Result<bool, StoreError> {
    Ok(store.get(CF_COMPUTE_ANCHORS, root)?.is_some())
}

/// Append a credential ID to a secondary index.
pub fn append_credential_index(
    store: &Store,
    cf: &str,
    key: &str,
    credential_id: &str,
) -> Result<(), StoreError> {
    let mut ids = load_credential_ids(store, cf, key)?;
    ids.push(credential_id.to_string());
    let bytes = serde_json::to_vec(&ids).map_err(|e| StoreError::Serde(e.to_string()))?;
    store.put(cf, key.as_bytes(), &bytes)
}

// ---------------------------------------------------------------------------
// Block execution
// ---------------------------------------------------------------------------

/// DID and issuer-credential operations are fee-exempt: their signer is a
/// DID-anchor (or, for `DidCreate`, a fresh identity key becoming one), and
/// anchors are value-free by construction, so they cannot hold a balance to
/// pay a fee. Spam control for these free ops lives at the registration
/// relayer + (pre-mainnet) a sponsored fee_payer (Slice 4) — out of scope here.
///
/// `ComputeRegister` is exempt for the same structural reason. Registration is
/// self-certifying: the executor requires `sender == Address::from_public_key
/// (ed25519_pub)`, so a compute operator that publishes its own `did:solidus`
/// document anchors that DID at the very address it registers from — and an
/// anchor cannot be funded (`Transfer` into one is rejected). Charging a fee
/// would make registration impossible for exactly that operator, permanently.
/// The exemption opens no path to a free *registration*: `ComputeRegister`
/// fails `NotAdmitted` unless the sender is already on the on-chain allow-list,
/// and only a fee-paying governance `ComputeAdmit` puts it there — the
/// allow-list, not the fee, is the rate limit. (The fee check runs before the
/// allow-list check, so a *failing* register from a never-admitted sender is
/// free — a free-but-useless tx that writes no state. That is not new: every
/// already-exempt payload above has the same property, e.g. a `DidUpdate`
/// against a non-existent DID. Bound it for the whole exempt set at the
/// mempool, never by special-casing one payload.)
///
/// Only registration is exempt; the governance ops (`ComputeAdmit` / `Remove` /
/// `Anchor` / `Slash`) still pay `FEE_COMPUTE`.
fn is_fee_exempt(payload: &TxPayload) -> bool {
    matches!(
        payload,
        TxPayload::DidCreate { .. }
            | TxPayload::DidUpdate { .. }
            | TxPayload::DidDeactivate { .. }
            | TxPayload::DidRecover { .. }
            | TxPayload::CredentialIssue { .. }
            | TxPayload::CredentialIssueBbs { .. }
            | TxPayload::CredentialRevoke { .. }
            | TxPayload::ComputeRegister { .. }
    )
}

/// Execute a block of transactions against the state store.
///
/// For each transaction the executor:
/// 1. Verifies the signature
/// 2. Checks the nonce matches the sender account
/// 3. Checks the sender can cover the fee
/// 4. Deducts the fee, increments the nonce
/// 5. Dispatches to the appropriate handler (currently only `Transfer`)
/// 6. Stores the receipt in `CF_RECEIPTS`
///
/// After all transactions, accumulated fees are distributed:
/// - 70% split equally among `validator_addresses`
/// - 20% to `treasury_address`
/// - 10% burned
///
/// `block_timestamp_ms` is the proposing block's header timestamp. It is the
/// sole time source for every DID document (`created_ms`/`updated_ms`) and
/// credential record this block produces, so it MUST come from the agreed
/// block header — never local wall-clock. If the executor read
/// `SystemTime::now()` instead, the proposer and each re-executing validator
/// would stamp different values, diverge on the resulting state root, and
/// reject each other's blocks at the `state_root` mismatch gate in the
/// consensus loop. Determinism of state transitions is a consensus invariant.
pub fn execute_block(
    store: &Store,
    transactions: &[Transaction],
    block_height: u64,
    block_timestamp_ms: u64,
    treasury_address: &Address,
    validator_addresses: &[Address],
    network: &str,
) -> Result<Vec<Receipt>, ExecutorError> {
    let mut receipts = Vec::with_capacity(transactions.len());
    let mut total_fees: u64 = 0;

    for tx in transactions {
        let tx_hash = tx.hash();

        // -----------------------------------------------------------------
        // 0. Idempotency: if this tx_hash already has a receipt in the
        //    store, it has already been applied to this state. Return the
        //    cached receipt and skip re-execution.
        //
        // tx_hash is content-addressed over (sender_pubkey, nonce, payload,
        // signature), so two transactions with the same hash MUST yield
        // the same state effect — returning the cached receipt is sound.
        //
        // This makes execute_block safe to call multiple times against the
        // same store for the same block. Required for dev-testnet, where
        // every validator engine shares one RocksDB instance and each one
        // calls execute_block on the proposal — without this short-circuit
        // the second-through-Nth executions hit the nonce check (already
        // bumped by the first) and overwrite the success receipt with a
        // bogus "invalid nonce" failure. In production, each validator has
        // a private store, so this check is a harmless no-op (always None).
        // -----------------------------------------------------------------
        if let Some(existing) = load_receipt(store, &tx_hash)? {
            receipts.push(existing);
            continue;
        }

        // -----------------------------------------------------------------
        // 1. Verify signature
        // -----------------------------------------------------------------
        if !tx.verify_signature() {
            let receipt = Receipt {
                tx_hash,
                status: TxStatus::Failed("invalid signature".to_string()),
                block_height,
                fee_paid: 0,
                events: vec![],
            };
            store_receipt(store, &receipt)?;
            receipts.push(receipt);
            continue;
        }

        let sender_addr = tx.sender_address();

        // -----------------------------------------------------------------
        // 2. Load sender account
        // -----------------------------------------------------------------
        let mut sender = load_account(store, &sender_addr)?;

        // -----------------------------------------------------------------
        // 3. Check nonce
        // -----------------------------------------------------------------
        if sender.nonce != tx.nonce {
            let receipt = Receipt {
                tx_hash,
                status: TxStatus::Failed(format!(
                    "invalid nonce: expected {}, got {}",
                    sender.nonce, tx.nonce
                )),
                block_height,
                fee_paid: 0,
                events: vec![],
            };
            store_receipt(store, &receipt)?;
            receipts.push(receipt);
            continue;
        }

        // -----------------------------------------------------------------
        // 4. Check balance covers fee
        // -----------------------------------------------------------------
        // DID + issuer-credential ops and ComputeRegister are fee-exempt (their
        // signer may be a value-free DID-anchor — see `is_fee_exempt`). The nonce
        // is still checked above and consumed below, exactly as for a paying tx.
        // Everything else pays its scheduled fee.
        let fee = if is_fee_exempt(&tx.payload) {
            0
        } else {
            tx.payload.fee()
        };
        if sender.balance < fee {
            let receipt = Receipt {
                tx_hash,
                status: TxStatus::Failed(format!(
                    "insufficient balance for fee: have {}, need {}",
                    sender.balance, fee
                )),
                block_height,
                fee_paid: 0,
                events: vec![],
            };
            store_receipt(store, &receipt)?;
            receipts.push(receipt);
            continue;
        }

        // -----------------------------------------------------------------
        // 5. Deduct fee, increment nonce
        // -----------------------------------------------------------------
        sender.balance -= fee;
        sender.nonce += 1;

        // -----------------------------------------------------------------
        // 6. Dispatch to handler
        // -----------------------------------------------------------------
        match &tx.payload {
            TxPayload::Transfer { to, amount } => {
                let to = *to;
                let amount = *amount;

                // Identity/value separation: a DID-anchor account is forbidden
                // from holding or moving value. Reject a Transfer to OR from
                // one. The recipient guard is what keeps anchors value-free
                // (you cannot fund one); the sender guard is defense-in-depth
                // (an anchor's zero balance already fails the fee check above).
                let from_is_anchor = is_did_anchor(store, network, &sender_addr)?;
                let to_is_anchor = is_did_anchor(store, network, &to)?;
                if from_is_anchor || to_is_anchor {
                    save_account(store, &sender)?; // fee already taken, nonce bumped
                    total_fees += fee;
                    let which = if from_is_anchor {
                        "sender"
                    } else {
                        "recipient"
                    };
                    let receipt = Receipt {
                        tx_hash,
                        status: TxStatus::Failed(format!(
                            "{which} is a DID identity anchor; anchors cannot hold or move value"
                        )),
                        block_height,
                        fee_paid: fee,
                        events: vec![],
                    };
                    store_receipt(store, &receipt)?;
                    receipts.push(receipt);
                    continue;
                }

                // execute_transfer validates preconditions (zero amount, self-transfer,
                // balance). We pass fee=0 because we already deducted the fee above.
                match execute_transfer(sender_addr, sender.balance, to, amount, 0) {
                    Ok(result) => {
                        // Deduct transferred amount from sender.
                        sender.balance -= result.amount;
                        save_account(store, &sender)?;

                        // Credit recipient.
                        let mut recipient = load_account(store, &to)?;
                        recipient.balance += result.amount;
                        save_account(store, &recipient)?;

                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: result.events,
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(token_err) => {
                        // Transfer failed — sender still pays the fee and
                        // nonce is still incremented (they sent a valid tx).
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(token_err.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::DidCreate {
                ref public_key,
                ref service_endpoints,
            } => {
                // Pristine-anchor requirement: a DID may only be created on a
                // fresh identity key with no value history — otherwise a used
                // value account (balance or prior txns) could be turned into a
                // DID-anchor and re-linked to its payment history. `tx.nonce == 0`
                // means this is the account's first tx; `sender.balance == 0`
                // (DidCreate is fee-exempt, so balance is unchanged) means it
                // never received value.
                if tx.nonce != 0 || sender.balance != 0 {
                    save_account(store, &sender)?;
                    total_fees += fee; // 0 — DidCreate is fee-exempt
                    let receipt = Receipt {
                        tx_hash,
                        status: TxStatus::Failed(
                            "DidCreate requires a pristine identity key (zero balance, first transaction)"
                                .to_string(),
                        ),
                        block_height,
                        fee_paid: fee,
                        events: vec![],
                    };
                    store_receipt(store, &receipt)?;
                    receipts.push(receipt);
                    continue;
                }
                let did_str = solidus_txns::did::build_did(network, &sender_addr);
                let existing = load_did(store, &did_str).map_err(ExecutorError::Store)?;
                let timestamp_ms = block_timestamp_ms;
                match execute_did_create(
                    &sender_addr,
                    public_key,
                    service_endpoints.clone(),
                    existing.as_ref(),
                    timestamp_ms,
                    network,
                ) {
                    Ok(result) => {
                        save_did(store, &result.did, &result.document)
                            .map_err(ExecutorError::Store)?;
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: vec![Event::DidCreated {
                                did: result.did,
                                controller: sender_addr,
                            }],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(e.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::DidUpdate {
                ref did,
                ref patches,
            } => {
                let existing = load_did(store, did).map_err(ExecutorError::Store)?;
                let timestamp_ms = block_timestamp_ms;
                // Closure used by gap-6 SetController validation. Loads
                // the candidate-controller document from the same RocksDB
                // store; surfaces I/O errors as `None` so the handler
                // reports `ControllerNotFound` consistently with absent
                // records. Rare RocksDB failures are visible elsewhere
                // (e.g. when the executor itself reads/writes state).
                let lookup = |did_str: &str| load_did(store, did_str).ok().flatten();
                match execute_did_update(
                    &sender_addr,
                    did,
                    patches,
                    existing.as_ref(),
                    lookup,
                    timestamp_ms,
                    network,
                ) {
                    Ok(updated_doc) => {
                        save_did(store, did, &updated_doc).map_err(ExecutorError::Store)?;
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: vec![Event::DidUpdated { did: did.clone() }],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(e.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::CredentialIssue {
                ref subject_did,
                credential_type,
                hash,
            } => {
                let subject_did = subject_did.clone();
                let credential_type = *credential_type;
                let hash = *hash;

                let issuer_did = solidus_txns::did::build_did(network, &sender_addr);
                let timestamp_ms = block_timestamp_ms;

                let issuer_doc = load_did(store, &issuer_did).map_err(ExecutorError::Store)?;
                let subject_doc = load_did(store, &subject_did).map_err(ExecutorError::Store)?;

                let issuer_active = issuer_doc.as_ref().map(|d| d.active).unwrap_or(false);
                let subject_active = subject_doc.as_ref().map(|d| d.active).unwrap_or(false);

                match execute_credential_issue(
                    &issuer_did,
                    &subject_did,
                    credential_type,
                    hash,
                    issuer_active,
                    subject_active,
                    block_height,
                    timestamp_ms,
                ) {
                    Ok(cred) => {
                        let credential_id = cred.id.clone();
                        let issuer_did_clone = cred.issuer_did.clone();
                        let subject_did_clone = cred.subject_did.clone();

                        save_credential(store, &cred).map_err(ExecutorError::Store)?;
                        append_credential_index(
                            store,
                            CF_CRED_BY_SUBJECT,
                            &subject_did_clone,
                            &credential_id,
                        )
                        .map_err(ExecutorError::Store)?;
                        append_credential_index(
                            store,
                            CF_CRED_BY_ISSUER,
                            &issuer_did_clone,
                            &credential_id,
                        )
                        .map_err(ExecutorError::Store)?;
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: vec![Event::CredentialIssued {
                                credential_id,
                                issuer: issuer_did_clone,
                                subject: subject_did_clone,
                            }],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(e.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::CredentialIssueBbs {
                ref subject_did,
                credential_type,
                hash,
                bbs_pubkey,
                bbs_message_count,
            } => {
                let subject_did = subject_did.clone();
                let credential_type = *credential_type;
                let hash = *hash;
                let bbs_pubkey = *bbs_pubkey;
                let bbs_message_count = *bbs_message_count;

                let issuer_did = solidus_txns::did::build_did(network, &sender_addr);
                let timestamp_ms = block_timestamp_ms;

                let issuer_doc = load_did(store, &issuer_did).map_err(ExecutorError::Store)?;
                let subject_doc = load_did(store, &subject_did).map_err(ExecutorError::Store)?;

                let issuer_active = issuer_doc.as_ref().map(|d| d.active).unwrap_or(false);
                let subject_active = subject_doc.as_ref().map(|d| d.active).unwrap_or(false);

                match execute_credential_issue_bbs(
                    &issuer_did,
                    &subject_did,
                    credential_type,
                    hash,
                    bbs_pubkey,
                    bbs_message_count,
                    issuer_active,
                    subject_active,
                    block_height,
                    timestamp_ms,
                ) {
                    Ok(cred) => {
                        let credential_id = cred.id.clone();
                        let issuer_did_clone = cred.issuer_did.clone();
                        let subject_did_clone = cred.subject_did.clone();

                        save_credential(store, &cred).map_err(ExecutorError::Store)?;
                        append_credential_index(
                            store,
                            CF_CRED_BY_SUBJECT,
                            &subject_did_clone,
                            &credential_id,
                        )
                        .map_err(ExecutorError::Store)?;
                        append_credential_index(
                            store,
                            CF_CRED_BY_ISSUER,
                            &issuer_did_clone,
                            &credential_id,
                        )
                        .map_err(ExecutorError::Store)?;
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: vec![Event::CredentialIssued {
                                credential_id,
                                issuer: issuer_did_clone,
                                subject: subject_did_clone,
                            }],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(e.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::CredentialRevoke { ref credential_id } => {
                let credential_id = credential_id.clone();
                let sender_did = solidus_txns::did::build_did(network, &sender_addr);
                let timestamp_ms = block_timestamp_ms;

                let existing =
                    load_credential(store, &credential_id).map_err(ExecutorError::Store)?;

                match execute_credential_revoke(&sender_did, existing.as_ref(), timestamp_ms) {
                    Ok(revoked_cred) => {
                        let cred_id = revoked_cred.id.clone();
                        save_credential(store, &revoked_cred).map_err(ExecutorError::Store)?;
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: vec![Event::CredentialRevoked {
                                credential_id: cred_id,
                            }],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(e.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::Stake { amount } => {
                let amount = *amount;
                let existing = load_validator(store, &sender_addr).map_err(ExecutorError::Store)?;

                // Note: fee was already deducted from sender.balance above.
                // execute_stake checks balance >= amount + fee, but since we already
                // deducted the fee we pass fee=0 here.
                match execute_stake(&sender_addr, amount, sender.balance, existing.as_ref(), 0) {
                    Ok(validator_info) => {
                        // Deduct staked amount from sender balance.
                        sender.balance -= amount;
                        save_account(store, &sender)?;
                        save_validator(store, &validator_info).map_err(ExecutorError::Store)?;
                        total_fees += fee;

                        let total_stake = validator_info.staked;
                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: vec![Event::Staked {
                                validator: sender_addr,
                                amount,
                                total_stake,
                            }],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(e.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::Unstake { amount } => {
                let amount = *amount;
                let existing = load_validator(store, &sender_addr).map_err(ExecutorError::Store)?;
                let timestamp_ms = block_timestamp_ms;

                match execute_unstake(amount, existing.as_ref(), timestamp_ms) {
                    Ok(validator_info) => {
                        // For MVP: credit unstaked tokens back to sender immediately.
                        // The 21-day unbonding period is tracked in ValidatorInfo but not enforced yet.
                        sender.balance += amount;
                        save_account(store, &sender)?;
                        save_validator(store, &validator_info).map_err(ExecutorError::Store)?;
                        total_fees += fee;

                        let remaining_stake = validator_info.staked;
                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: vec![Event::Unstaked {
                                validator: sender_addr,
                                amount,
                                remaining_stake,
                            }],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(e.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::DidDeactivate { ref did } => {
                let existing = load_did(store, did).map_err(ExecutorError::Store)?;
                let timestamp_ms = block_timestamp_ms;
                match execute_did_deactivate(
                    &sender_addr,
                    did,
                    existing.as_ref(),
                    timestamp_ms,
                    network,
                ) {
                    Ok(deactivated_doc) => {
                        save_did(store, did, &deactivated_doc).map_err(ExecutorError::Store)?;
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Success,
                            block_height,
                            fee_paid: fee,
                            events: vec![Event::DidDeactivated { did: did.clone() }],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                    Err(e) => {
                        save_account(store, &sender)?;
                        total_fees += fee;

                        let receipt = Receipt {
                            tx_hash,
                            status: TxStatus::Failed(e.to_string()),
                            block_height,
                            fee_paid: fee,
                            events: vec![],
                        };
                        store_receipt(store, &receipt)?;
                        receipts.push(receipt);
                    }
                }
            }
            TxPayload::DidRecover {
                ref did,
                ref new_public_key,
                ref approvals,
            } => {
                if tx.sender_pubkey != *new_public_key {
                    save_account(store, &sender)?;
                    total_fees += fee;

                    let receipt = Receipt {
                        tx_hash,
                        status: TxStatus::Failed(
                            "recovery sender must equal new_public_key".into(),
                        ),
                        block_height,
                        fee_paid: fee,
                        events: vec![],
                    };
                    store_receipt(store, &receipt)?;
                    receipts.push(receipt);
                } else {
                    let existing = load_did(store, did).map_err(ExecutorError::Store)?;
                    let timestamp_ms = block_timestamp_ms;
                    let resolve = |g: &str| load_did(store, g).ok().flatten();
                    match execute_did_recover(
                        did,
                        existing.as_ref(),
                        new_public_key,
                        approvals,
                        resolve,
                        network,
                        timestamp_ms,
                    ) {
                        Ok(updated_doc) => {
                            save_did(store, did, &updated_doc).map_err(ExecutorError::Store)?;
                            save_account(store, &sender)?;
                            total_fees += fee;

                            let receipt = Receipt {
                                tx_hash,
                                status: TxStatus::Success,
                                block_height,
                                fee_paid: fee,
                                events: vec![Event::DidRecovered { did: did.clone() }],
                            };
                            store_receipt(store, &receipt)?;
                            receipts.push(receipt);
                        }
                        Err(e) => {
                            save_account(store, &sender)?;
                            total_fees += fee;

                            let receipt = Receipt {
                                tx_hash,
                                status: TxStatus::Failed(e.to_string()),
                                block_height,
                                fee_paid: fee,
                                events: vec![],
                            };
                            store_receipt(store, &receipt)?;
                            receipts.push(receipt);
                        }
                    }
                }
            }
            // ---- Compute network (Rebuild #5 §6.5). Governance = active validator. ----
            TxPayload::ComputeAdmit { operator, tier } => {
                let authorized = is_compute_governance(store, &sender_addr)?;
                let existing = load_compute_allow(store, operator)?;
                let result = execute_compute_admit(
                    authorized,
                    operator,
                    *tier,
                    existing.as_ref(),
                    block_timestamp_ms,
                );
                save_account(store, &sender)?;
                total_fees += fee;
                let receipt = match result {
                    Ok(entry) => match entry.to_bytes() {
                        Ok(bytes) => {
                            store.put(CF_COMPUTE_ALLOWLIST, operator.as_bytes(), &bytes)?;
                            compute_ok(
                                tx_hash,
                                block_height,
                                fee,
                                Event::ComputeAdmitted {
                                    operator: *operator,
                                    tier: *tier,
                                },
                            )
                        }
                        Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                    },
                    Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                };
                store_receipt(store, &receipt)?;
                receipts.push(receipt);
            }
            TxPayload::ComputeRemove { operator } => {
                let authorized = is_compute_governance(store, &sender_addr)?;
                let allow = load_compute_allow(store, operator)?;
                let existing = load_compute_node(store, operator)?;
                let result = execute_compute_remove(authorized, allow.as_ref(), existing.as_ref());
                save_account(store, &sender)?;
                total_fees += fee;
                let receipt = match result {
                    // Remove the operator entirely: BOTH the allow-list entry AND the
                    // node record, so the DID can re-enter only via a fresh admission.
                    Ok(()) => {
                        store.delete(CF_COMPUTE_ALLOWLIST, operator.as_bytes())?;
                        store.delete(CF_COMPUTE_NODES, operator.as_bytes())?;
                        compute_ok(
                            tx_hash,
                            block_height,
                            fee,
                            Event::ComputeRemoved {
                                operator: *operator,
                            },
                        )
                    }
                    Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                };
                store_receipt(store, &receipt)?;
                receipts.push(receipt);
            }
            TxPayload::ComputeRegister {
                ed25519_pub,
                x25519_pub,
                jurisdiction,
            } => {
                let allow = load_compute_allow(store, &sender_addr)?;
                let existing = load_compute_node(store, &sender_addr)?;
                let result = execute_compute_register(
                    &sender_addr,
                    ed25519_pub,
                    x25519_pub,
                    jurisdiction,
                    allow.as_ref(),
                    existing.as_ref(),
                    block_timestamp_ms,
                );
                save_account(store, &sender)?;
                total_fees += fee;
                let receipt = match result {
                    Ok(node) => match node.to_bytes() {
                        Ok(bytes) => {
                            store.put(CF_COMPUTE_NODES, sender_addr.as_bytes(), &bytes)?;
                            compute_ok(
                                tx_hash,
                                block_height,
                                fee,
                                Event::ComputeRegistered {
                                    operator: sender_addr,
                                    jurisdiction: node.jurisdiction.clone(),
                                    tier: node.tier,
                                },
                            )
                        }
                        Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                    },
                    Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                };
                store_receipt(store, &receipt)?;
                receipts.push(receipt);
            }
            TxPayload::ComputeAnchor {
                merkle_root,
                batch_count,
            } => {
                let authorized = is_compute_governance(store, &sender_addr)?;
                // Duplicate-root guard: reject a root already in the secondary index
                // so a repeat anchor cannot destroy the prior record.
                let already = anchor_root_exists(store, merkle_root)?;
                let result = execute_compute_anchor(
                    authorized,
                    *merkle_root,
                    *batch_count,
                    already,
                    block_timestamp_ms,
                );
                save_account(store, &sender)?;
                total_fees += fee;
                let receipt = match result {
                    Ok(anchor) => match anchor.to_bytes() {
                        Ok(bytes) => {
                            // Append-only: key the primary record by a monotonic seq,
                            // add the root→seq index entry, then bump the counter.
                            let seq = next_anchor_seq(store)?;
                            store.put(CF_COMPUTE_ANCHORS, &seq.to_le_bytes(), &bytes)?;
                            store.put(CF_COMPUTE_ANCHORS, merkle_root, &seq.to_le_bytes())?;
                            store.put(
                                CF_COMPUTE_ANCHORS,
                                META_NEXT_ANCHOR_SEQ,
                                &(seq + 1).to_le_bytes(),
                            )?;
                            compute_ok(
                                tx_hash,
                                block_height,
                                fee,
                                Event::ComputeAnchored {
                                    merkle_root: *merkle_root,
                                    batch_count: *batch_count,
                                },
                            )
                        }
                        Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                    },
                    Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                };
                store_receipt(store, &receipt)?;
                receipts.push(receipt);
            }
            TxPayload::ComputeSlash {
                operator,
                reputation_penalty,
                severe,
            } => {
                let authorized = is_compute_governance(store, &sender_addr)?;
                let existing = load_compute_node(store, operator)?;
                let result = execute_compute_slash(
                    authorized,
                    *reputation_penalty,
                    *severe,
                    existing.as_ref(),
                );
                save_account(store, &sender)?;
                total_fees += fee;
                let receipt = match result {
                    Ok(node) => match node.to_bytes() {
                        Ok(bytes) => {
                            store.put(CF_COMPUTE_NODES, operator.as_bytes(), &bytes)?;
                            compute_ok(
                                tx_hash,
                                block_height,
                                fee,
                                Event::ComputeSlashed {
                                    operator: *operator,
                                    severe: *severe,
                                    reputation: node.reputation,
                                },
                            )
                        }
                        Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                    },
                    Err(e) => compute_failed(tx_hash, block_height, fee, e.to_string()),
                };
                store_receipt(store, &receipt)?;
                receipts.push(receipt);
            }
        }
    }

    // -----------------------------------------------------------------
    // Fee distribution
    // -----------------------------------------------------------------
    distribute_fees(store, total_fees, treasury_address, validator_addresses)?;

    Ok(receipts)
}

/// Serialize and store a receipt in `CF_RECEIPTS`, keyed by `tx_hash`.
fn store_receipt(store: &Store, receipt: &Receipt) -> Result<(), ExecutorError> {
    let value = serde_json::to_vec(receipt).map_err(|e| StoreError::Serde(e.to_string()))?;
    store.put(CF_RECEIPTS, &receipt.tx_hash, &value)?;
    Ok(())
}

/// Load a receipt from `CF_RECEIPTS` by tx hash. Returns `Ok(None)` if no
/// receipt has been stored for this hash (i.e. the tx has not been executed
/// against this store yet).
fn load_receipt(store: &Store, tx_hash: &[u8; 32]) -> Result<Option<Receipt>, ExecutorError> {
    match store.get(CF_RECEIPTS, tx_hash)? {
        Some(bytes) => {
            let receipt: Receipt =
                serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde(e.to_string()))?;
            Ok(Some(receipt))
        }
        None => Ok(None),
    }
}

/// Distribute accumulated fees among validators, treasury, and burn.
///
/// - `VALIDATOR_SHARE_PCT`% split equally among validators
/// - `TREASURY_SHARE_PCT`% to the treasury
/// - Remainder is burned (not credited)
fn distribute_fees(
    store: &Store,
    total_fees: u64,
    treasury_address: &Address,
    validator_addresses: &[Address],
) -> Result<(), ExecutorError> {
    if total_fees == 0 {
        return Ok(());
    }

    // Treasury share
    let treasury_amount = total_fees * TREASURY_SHARE_PCT / 100;
    if treasury_amount > 0 {
        let mut treasury = load_account(store, treasury_address)?;
        treasury.balance += treasury_amount;
        save_account(store, &treasury)?;
    }

    // Validator share (split equally)
    if !validator_addresses.is_empty() {
        let validator_pool = total_fees * VALIDATOR_SHARE_PCT / 100;
        let per_validator = validator_pool / validator_addresses.len() as u64;

        if per_validator > 0 {
            for vaddr in validator_addresses {
                let mut validator = load_account(store, vaddr)?;
                validator.balance += per_validator;
                save_account(store, &validator)?;
            }
        }
    }

    // The remaining percentage is burned — no credit needed.
    Ok(())
}

// ---------------------------------------------------------------------------
// State root computation
// ---------------------------------------------------------------------------

/// Compute the global state root from the current store contents.
///
/// Builds four Sparse Merkle Trees (accounts, DIDs, credentials, validators)
/// by scanning the corresponding column families, then combines the four
/// tree roots into a single global root via BLAKE3.
///
/// Uses the IN-MEMORY tree (`solidus_state_tree`), which computes
/// bit-identical roots to the store-backed `crate::tree::SparseMerkleTree`
/// (guarded by `in_memory_tree_matches_store_backed_roots` below). The
/// store-backed variant persisted ~257 CF_MERKLE nodes PER INSERT, so every
/// compute_state_root call rewrote the whole tree into RocksDB — ~4 MB of
/// WAL per block × 4 engines on dev-testnet, the real bulk of the old
/// ~1.16 GB/day disk growth — and nothing ever read CF_MERKLE back.
pub fn compute_state_root(store: &Arc<Store>) -> Result<[u8; 32], ExecutorError> {
    let mut accounts_tree = solidus_state_tree::SparseMerkleTree::new();
    for (k, v) in store.iter_cf(CF_ACCOUNTS)? {
        accounts_tree.insert(&k, &v);
    }

    let mut dids_tree = solidus_state_tree::SparseMerkleTree::new();
    for (k, v) in store.iter_cf(CF_DIDS)? {
        dids_tree.insert(&k, &v);
    }

    let mut credentials_tree = solidus_state_tree::SparseMerkleTree::new();
    for (k, v) in store.iter_cf(CF_CREDENTIALS)? {
        credentials_tree.insert(&k, &v);
    }

    let mut validators_tree = solidus_state_tree::SparseMerkleTree::new();
    for (k, v) in store.iter_cf(CF_VALIDATORS)? {
        validators_tree.insert(&k, &v);
    }

    Ok(global_state_root(
        &accounts_tree.root(),
        &dids_tree.root(),
        &credentials_tree.root(),
        &validators_tree.root(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_txns::types::{TxPayload, FEE_TRANSFER};
    use tempfile::tempdir;

    /// Helper: open a store in a fresh temp directory.
    fn open_tmp() -> (Store, tempfile::TempDir) {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Store::open(dir.path()).expect("failed to open store");
        (store, dir)
    }

    /// Helper: build a signed Transfer transaction.
    fn make_transfer_tx(
        sender_key: &SigningKey,
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

    /// Helper: fund an account by directly writing to the store.
    fn fund_account(store: &Store, address: Address, balance: u64) {
        let account = Account::with_balance(address, balance, crate::account::AccountType::Regular);
        save_account(store, &account).expect("fund_account failed");
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn execute_successful_transfer() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let receiver_key = generate_signing_key();

        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_public_key(&receiver_key.verifying_key());

        let initial_balance = 1_000_000;
        let transfer_amount = 500_000;
        fund_account(&store, sender_addr, initial_balance);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);
        let validator_addr = Address::from_bytes([0xBBu8; 20]);

        let tx = make_transfer_tx(&sender_key, receiver_addr, transfer_amount, 0);
        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[validator_addr],
            "testnet",
        )
        .expect("execute_block failed");

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, TxStatus::Success);
        assert_eq!(receipts[0].fee_paid, FEE_TRANSFER);
        assert_eq!(receipts[0].block_height, 1);

        // Verify sender balance: initial - fee - amount
        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        assert_eq!(
            sender.balance,
            initial_balance - FEE_TRANSFER - transfer_amount
        );
        assert_eq!(sender.nonce, 1);

        // Verify receiver balance
        let receiver = load_account(&store, &receiver_addr).expect("load receiver failed");
        assert_eq!(receiver.balance, transfer_amount);
    }

    #[test]
    fn invalid_signature_fails() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let receiver_key = generate_signing_key();

        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_public_key(&receiver_key.verifying_key());

        fund_account(&store, sender_addr, 1_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Build a transaction with an all-zeros pubkey/signature (invalid).
        let tx = Transaction {
            sender_pubkey: [0u8; 32],
            nonce: 0,
            payload: TxPayload::Transfer {
                to: receiver_addr,
                amount: 100,
            },
            signature: [0u8; 64],
        };

        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block failed");

        assert_eq!(receipts.len(), 1);
        match &receipts[0].status {
            TxStatus::Failed(reason) => {
                assert!(
                    reason.contains("invalid signature"),
                    "unexpected reason: {reason}"
                );
            }
            TxStatus::Success => panic!("expected failure, got success"),
        }
        assert_eq!(receipts[0].fee_paid, 0);
    }

    #[test]
    fn wrong_nonce_fails() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let receiver_key = generate_signing_key();

        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_public_key(&receiver_key.verifying_key());

        fund_account(&store, sender_addr, 1_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Send with nonce=5, but account nonce is 0.
        let tx = make_transfer_tx(&sender_key, receiver_addr, 100, 5);

        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block failed");

        assert_eq!(receipts.len(), 1);
        match &receipts[0].status {
            TxStatus::Failed(reason) => {
                assert!(
                    reason.contains("invalid nonce"),
                    "unexpected reason: {reason}"
                );
            }
            TxStatus::Success => panic!("expected failure, got success"),
        }
        assert_eq!(receipts[0].fee_paid, 0);

        // Sender balance should be unchanged.
        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        assert_eq!(sender.balance, 1_000_000);
        assert_eq!(sender.nonce, 0);
    }

    #[test]
    fn fee_distribution_70_20_10() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let receiver_key = generate_signing_key();

        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_public_key(&receiver_key.verifying_key());

        fund_account(&store, sender_addr, 1_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);
        let validator_addr = Address::from_bytes([0xBBu8; 20]);

        let tx = make_transfer_tx(&sender_key, receiver_addr, 100, 0);
        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[validator_addr],
            "testnet",
        )
        .expect("execute_block failed");

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, TxStatus::Success);

        let fee = FEE_TRANSFER; // 10_000

        // 70% to validator = 7_000
        let validator = load_account(&store, &validator_addr).expect("load validator failed");
        assert_eq!(validator.balance, fee * VALIDATOR_SHARE_PCT / 100);

        // 20% to treasury = 2_000
        let treasury = load_account(&store, &treasury_addr).expect("load treasury failed");
        assert_eq!(treasury.balance, fee * TREASURY_SHARE_PCT / 100);

        // 10% burned — verify by summing all accounts: the difference should be
        // exactly 10% of fees.
        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        let receiver = load_account(&store, &receiver_addr).expect("load receiver failed");

        let total_after = sender.balance + receiver.balance + validator.balance + treasury.balance;
        let total_before = 1_000_000u64; // only the sender was funded
        let burned = total_before - total_after;
        assert_eq!(burned, fee * 10 / 100); // 10% burned = 1_000
    }

    #[test]
    fn nonce_increments_after_successful_tx() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let receiver_key = generate_signing_key();

        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_public_key(&receiver_key.verifying_key());

        // Fund enough for two transfers + fees.
        fund_account(&store, sender_addr, 1_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // First transfer (nonce=0)
        let tx1 = make_transfer_tx(&sender_key, receiver_addr, 100, 0);
        let receipts1 = execute_block(
            &store,
            &[tx1],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block 1 failed");
        assert_eq!(receipts1[0].status, TxStatus::Success);

        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        assert_eq!(sender.nonce, 1);

        // Second transfer (nonce=1)
        let tx2 = make_transfer_tx(&sender_key, receiver_addr, 200, 1);
        let receipts2 = execute_block(
            &store,
            &[tx2],
            2,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block 2 failed");
        assert_eq!(receipts2[0].status, TxStatus::Success);

        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        assert_eq!(sender.nonce, 2);
    }

    #[test]
    fn execute_block_is_idempotent_on_repeated_tx_hash() {
        // Regression test for the testnet transaction-nonce bug (2026-05-18).
        //
        // dev-testnet runs 4 validators in one process against a SHARED
        // RocksDB store. Each validator independently calls execute_block
        // on every proposal. Before the idempotency short-circuit was added,
        // the first call succeeded (nonce 0→1, success receipt) but the
        // second-through-Nth calls hit the nonce check (sender.nonce is now
        // 1, tx.nonce is still 0) and OVERWROTE the success receipt with a
        // bogus "invalid nonce: expected 1, got 0" failure — even though the
        // state effect (the transfer) had already landed correctly.
        //
        // This test simulates that shared-store double-execution: run
        // execute_block twice on the same store with the same block, and
        // assert (a) the cached success receipt is preserved, (b) the nonce
        // only advances once, and (c) the recipient is not double-credited.
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let recipient = Address::from_bytes([0xCDu8; 20]);

        fund_account(&store, sender_addr, 1_000_000);
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        let tx = make_transfer_tx(&sender_key, recipient, 100, 0);
        let block_txs = vec![tx];

        // First execution — the real one.
        let r1 = execute_block(
            &store,
            &block_txs,
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block 1 failed");
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].status, TxStatus::Success);

        let sender_after_1 = load_account(&store, &sender_addr).expect("load sender 1");
        assert_eq!(sender_after_1.nonce, 1, "first execute_block bumps nonce");
        let recipient_after_1 = load_account(&store, &recipient).expect("load recipient 1");
        assert_eq!(recipient_after_1.balance, 100);

        // Second execution — simulates a second validator on the same store.
        let r2 = execute_block(
            &store,
            &block_txs,
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block 2 failed");
        assert_eq!(r2.len(), 1);
        assert_eq!(
            r2[0].status,
            TxStatus::Success,
            "second execute_block MUST return the cached success — \
             NOT overwrite it with a nonce failure"
        );
        assert_eq!(r2[0].tx_hash, r1[0].tx_hash);

        let sender_after_2 = load_account(&store, &sender_addr).expect("load sender 2");
        assert_eq!(
            sender_after_2.nonce, 1,
            "second execute_block MUST NOT advance the nonce again"
        );
        let recipient_after_2 = load_account(&store, &recipient).expect("load recipient 2");
        assert_eq!(
            recipient_after_2.balance, 100,
            "second execute_block MUST NOT double-credit the recipient"
        );

        // Third execution for good measure — covers the 4-validator case
        // (1 proposer + 3 receivers in dev-testnet).
        let r3 = execute_block(
            &store,
            &block_txs,
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block 3 failed");
        assert_eq!(r3[0].status, TxStatus::Success);
        let sender_after_3 = load_account(&store, &sender_addr).expect("load sender 3");
        assert_eq!(sender_after_3.nonce, 1);
        let recipient_after_3 = load_account(&store, &recipient).expect("load recipient 3");
        assert_eq!(recipient_after_3.balance, 100);
    }

    // -----------------------------------------------------------------------
    // DID executor tests
    // -----------------------------------------------------------------------

    /// Helper: build a signed DidCreate transaction.
    fn make_did_create_tx(sender_key: &SigningKey, nonce: u64) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::DidCreate {
            public_key: pubkey,
            service_endpoints: vec![],
        };

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

    /// Helper: build a signed DidDeactivate transaction.
    fn make_did_deactivate_tx(sender_key: &SigningKey, did: String, nonce: u64) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::DidDeactivate { did };

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
    fn did_create_via_executor() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());

        // No funding: a DID is created on a pristine identity key (fee-exempt).
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        let tx = make_did_create_tx(&sender_key, 0);
        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block failed");

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, TxStatus::Success);
        assert_eq!(receipts[0].block_height, 1);
        assert_eq!(receipts[0].events.len(), 1);

        // Verify the DID document was stored.
        let expected_did = solidus_txns::did::build_did("testnet", &sender_addr);
        let stored = load_did(&store, &expected_did)
            .expect("load_did failed")
            .expect("DID should be stored");

        assert_eq!(stored.id, expected_did);
        assert!(stored.active);

        // Verify sender nonce was incremented.
        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        assert_eq!(sender.nonce, 1);
    }

    #[test]
    fn did_create_duplicate_fails() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();

        // No funding: DIDs are created on pristine identity keys (fee-exempt).
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // First create — should succeed.
        let tx1 = make_did_create_tx(&sender_key, 0);
        let receipts1 = execute_block(
            &store,
            &[tx1],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block 1 failed");
        assert_eq!(receipts1[0].status, TxStatus::Success);

        // Second create with nonce=1 — rejected by the pristine rule (nonce != 0)
        // before the duplicate check is reached. A used key can never become a
        // second anchor, which is what makes a DID-anchor single-DidCreate.
        let tx2 = make_did_create_tx(&sender_key, 1);
        let receipts2 = execute_block(
            &store,
            &[tx2],
            2,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block 2 failed");

        match &receipts2[0].status {
            TxStatus::Failed(reason) => {
                assert!(
                    reason.contains("pristine"),
                    "unexpected failure reason: {reason}"
                );
            }
            TxStatus::Success => panic!("expected failure for duplicate DID create"),
        }
        // DidCreate is fee-exempt; fee_paid is 0 even on failure.
        assert_eq!(receipts2[0].fee_paid, 0);
    }

    #[test]
    fn did_deactivate_via_executor() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());

        // No funding: DID create + deactivate are fee-exempt, key is pristine.
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Step 1: Create the DID.
        let tx_create = make_did_create_tx(&sender_key, 0);
        let receipts_create = execute_block(
            &store,
            &[tx_create],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block (create) failed");
        assert_eq!(receipts_create[0].status, TxStatus::Success);

        let expected_did = solidus_txns::did::build_did("testnet", &sender_addr);

        // Step 2: Deactivate the DID.
        let tx_deactivate = make_did_deactivate_tx(&sender_key, expected_did.clone(), 1);
        let receipts_deactivate = execute_block(
            &store,
            &[tx_deactivate],
            2,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block (deactivate) failed");

        assert_eq!(receipts_deactivate[0].status, TxStatus::Success);

        // Verify the stored document is now inactive.
        let stored = load_did(&store, &expected_did)
            .expect("load_did failed")
            .expect("DID should be stored");

        assert!(!stored.active, "DID should be deactivated");
    }

    // -----------------------------------------------------------------------
    // Credential executor tests
    // -----------------------------------------------------------------------

    /// Helper: build a signed CredentialIssue transaction.
    fn make_credential_issue_tx(
        sender_key: &SigningKey,
        subject_did: String,
        credential_type: solidus_txns::credential::CredentialType,
        hash: [u8; 32],
        nonce: u64,
    ) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::CredentialIssue {
            subject_did,
            credential_type,
            hash,
        };

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

    /// Helper: build a signed CredentialRevoke transaction.
    fn make_credential_revoke_tx(
        sender_key: &SigningKey,
        credential_id: String,
        nonce: u64,
    ) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::CredentialRevoke { credential_id };

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
    fn credential_issue_via_executor() {
        let (store, _dir) = open_tmp();

        let issuer_key = generate_signing_key();
        let subject_key = generate_signing_key();

        let issuer_addr = Address::from_public_key(&issuer_key.verifying_key());
        let subject_addr = Address::from_public_key(&subject_key.verifying_key());

        // No funding: issuer + subject are pristine DID anchors; ops fee-exempt.
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Step 1: Create issuer DID.
        let tx_issuer_did = make_did_create_tx(&issuer_key, 0);
        let receipts = execute_block(
            &store,
            &[tx_issuer_did],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("issuer DidCreate failed");
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "issuer DID create should succeed"
        );

        // Step 2: Create subject DID.
        let tx_subject_did = make_did_create_tx(&subject_key, 0);
        let receipts = execute_block(
            &store,
            &[tx_subject_did],
            2,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("subject DidCreate failed");
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "subject DID create should succeed"
        );

        // Step 3: Issue credential.
        let subject_did = solidus_txns::did::build_did("testnet", &subject_addr);
        let hash = [0xdeu8; 32];
        let tx_issue = make_credential_issue_tx(
            &issuer_key,
            subject_did.clone(),
            solidus_txns::credential::CredentialType::Email,
            hash,
            1, // issuer nonce=1 after DidCreate
        );
        let receipts = execute_block(
            &store,
            &[tx_issue],
            3,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("CredentialIssue execute_block failed");

        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "CredentialIssue should succeed; got: {:?}",
            receipts[0].status
        );
        assert_eq!(receipts[0].events.len(), 1);

        // Verify the credential ID from the event.
        let credential_id = match &receipts[0].events[0] {
            solidus_txns::types::Event::CredentialIssued { credential_id, .. } => {
                credential_id.clone()
            }
            other => panic!("expected CredentialIssued event, got: {:?}", other),
        };

        // Verify credential is stored.
        let stored = load_credential(&store, &credential_id)
            .expect("load_credential failed")
            .expect("credential should be stored");

        assert_eq!(stored.id, credential_id);
        assert!(!stored.revoked, "credential should not be revoked");
        assert_eq!(
            stored.credential_type,
            solidus_txns::credential::CredentialType::Email
        );
        assert_eq!(stored.hash, hash);

        // Verify secondary indexes.
        let issuer_did = solidus_txns::did::build_did("testnet", &issuer_addr);
        let by_subject = load_credential_ids(&store, CF_CRED_BY_SUBJECT, &subject_did)
            .expect("load by subject failed");
        assert!(
            by_subject.contains(&credential_id),
            "subject index should contain credential"
        );

        let by_issuer = load_credential_ids(&store, CF_CRED_BY_ISSUER, &issuer_did)
            .expect("load by issuer failed");
        assert!(
            by_issuer.contains(&credential_id),
            "issuer index should contain credential"
        );
    }

    #[test]
    fn credential_revoke_via_executor() {
        let (store, _dir) = open_tmp();

        let issuer_key = generate_signing_key();
        let subject_key = generate_signing_key();

        let subject_addr = Address::from_public_key(&subject_key.verifying_key());

        // No funding: issuer + subject are pristine DID anchors; ops fee-exempt.
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Create issuer DID.
        let tx_issuer_did = make_did_create_tx(&issuer_key, 0);
        execute_block(
            &store,
            &[tx_issuer_did],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("issuer DidCreate failed");

        // Create subject DID.
        let tx_subject_did = make_did_create_tx(&subject_key, 0);
        execute_block(
            &store,
            &[tx_subject_did],
            2,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("subject DidCreate failed");

        // Issue credential (issuer nonce=1).
        let subject_did = solidus_txns::did::build_did("testnet", &subject_addr);
        let hash = [0xabu8; 32];
        let tx_issue = make_credential_issue_tx(
            &issuer_key,
            subject_did,
            solidus_txns::credential::CredentialType::Phone,
            hash,
            1,
        );
        let receipts = execute_block(
            &store,
            &[tx_issue],
            3,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("CredentialIssue failed");
        assert_eq!(receipts[0].status, TxStatus::Success);

        let credential_id = match &receipts[0].events[0] {
            solidus_txns::types::Event::CredentialIssued { credential_id, .. } => {
                credential_id.clone()
            }
            other => panic!("expected CredentialIssued event, got: {:?}", other),
        };

        // Revoke the credential (issuer nonce=2).
        let tx_revoke = make_credential_revoke_tx(&issuer_key, credential_id.clone(), 2);
        let receipts = execute_block(
            &store,
            &[tx_revoke],
            4,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("CredentialRevoke failed");

        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "CredentialRevoke should succeed; got: {:?}",
            receipts[0].status
        );

        // Verify the stored credential is now revoked.
        let stored = load_credential(&store, &credential_id)
            .expect("load_credential failed")
            .expect("credential should still be stored");

        assert!(stored.revoked, "credential should be marked revoked");
        assert!(stored.revoked_ms.is_some(), "revoked_ms should be set");
    }

    /// Helper: build a signed CredentialIssueBbs transaction.
    fn make_credential_issue_bbs_tx(
        sender_key: &SigningKey,
        subject_did: String,
        credential_type: solidus_txns::credential::CredentialType,
        hash: [u8; 32],
        bbs_pubkey: [u8; 96],
        bbs_message_count: u32,
        nonce: u64,
    ) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::CredentialIssueBbs {
            subject_did,
            credential_type,
            hash,
            bbs_pubkey,
            bbs_message_count,
        };

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
    fn credential_issue_bbs_via_executor() {
        use solidus_crypto::bbs::BbsSecretKey;

        let (store, _dir) = open_tmp();

        let issuer_key = generate_signing_key();
        let subject_key = generate_signing_key();

        let subject_addr = Address::from_public_key(&subject_key.verifying_key());

        // No funding: issuer + subject are pristine DID anchors; BBS credential
        // ops are fee-exempt.
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        let tx_issuer_did = make_did_create_tx(&issuer_key, 0);
        execute_block(
            &store,
            &[tx_issuer_did],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("issuer DidCreate failed");

        let tx_subject_did = make_did_create_tx(&subject_key, 0);
        execute_block(
            &store,
            &[tx_subject_did],
            2,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("subject DidCreate failed");

        let bbs_sk =
            BbsSecretKey::from_ikm(b"executor-bbs-test-ikm-must-be-32-bytes-or-more").expect("ikm");
        let bbs_pubkey = bbs_sk.public_key().to_bytes();

        let subject_did = solidus_txns::did::build_did("testnet", &subject_addr);
        let hash = [0xbbu8; 32];
        let tx_issue = make_credential_issue_bbs_tx(
            &issuer_key,
            subject_did.clone(),
            solidus_txns::credential::CredentialType::KycL2,
            hash,
            bbs_pubkey,
            8,
            1, // issuer nonce=1 after DidCreate
        );

        let receipts = execute_block(
            &store,
            &[tx_issue],
            3,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("CredentialIssueBbs execute_block failed");

        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "CredentialIssueBbs should succeed; got: {:?}",
            receipts[0].status
        );
        assert_eq!(receipts[0].fee_paid, 0, "BBS credential ops are fee-exempt");

        let credential_id = match &receipts[0].events[0] {
            solidus_txns::types::Event::CredentialIssued { credential_id, .. } => {
                credential_id.clone()
            }
            other => panic!("expected CredentialIssued event, got: {:?}", other),
        };

        // Verify the stored credential carries BBS metadata.
        let stored = load_credential(&store, &credential_id)
            .expect("load_credential failed")
            .expect("credential should be stored");
        assert_eq!(stored.bbs_pubkey, Some(bbs_pubkey));
        assert_eq!(stored.bbs_message_count, Some(8));
        assert_eq!(
            stored.credential_type,
            solidus_txns::credential::CredentialType::KycL2
        );
    }

    #[test]
    fn credential_issue_bbs_invalid_pubkey_fails_at_executor() {
        let (store, _dir) = open_tmp();

        let issuer_key = generate_signing_key();
        let subject_key = generate_signing_key();
        let subject_addr = Address::from_public_key(&subject_key.verifying_key());

        // No funding: issuer + subject are pristine DID anchors; ops fee-exempt.
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        execute_block(
            &store,
            &[make_did_create_tx(&issuer_key, 0)],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("issuer DidCreate failed");
        execute_block(
            &store,
            &[make_did_create_tx(&subject_key, 0)],
            2,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("subject DidCreate failed");

        let subject_did = solidus_txns::did::build_did("testnet", &subject_addr);
        // All-zero bytes are not a valid compressed G2 point.
        let bad_pubkey = [0u8; 96];
        let tx_issue = make_credential_issue_bbs_tx(
            &issuer_key,
            subject_did,
            solidus_txns::credential::CredentialType::Email,
            [0u8; 32],
            bad_pubkey,
            3,
            1,
        );

        let receipts = execute_block(
            &store,
            &[tx_issue],
            3,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block must not error");

        assert_eq!(receipts.len(), 1);
        match &receipts[0].status {
            TxStatus::Failed(reason) => {
                assert!(
                    reason.contains("BBS"),
                    "expected BBS-related failure, got: {reason}"
                );
            }
            TxStatus::Success => panic!("expected failure for invalid BBS pubkey"),
        }
        // Credential ops are fee-exempt; fee is 0 even on failure.
        assert_eq!(receipts[0].fee_paid, 0);
    }

    // -----------------------------------------------------------------------
    // Staking executor tests
    // -----------------------------------------------------------------------

    /// Helper: build a signed Stake transaction.
    fn make_stake_tx(sender_key: &SigningKey, amount: u64, nonce: u64) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::Stake { amount };

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

    /// Helper: build a signed Unstake transaction.
    fn make_unstake_tx(sender_key: &SigningKey, amount: u64, nonce: u64) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::Unstake { amount };

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
    fn stake_via_executor() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());

        // Fund with 200_000 SLDS (in smallest units: 200_000 * ONE_SLDS).
        // MIN_STAKE = 1_000_000_000_000 = 10,000 SLDS.
        // We use MIN_STAKE directly as the stake amount, and fund with 2 * MIN_STAKE.
        use solidus_txns::staking::MIN_STAKE;
        use solidus_txns::types::FEE_STAKE;
        let initial_balance = MIN_STAKE * 2 + FEE_STAKE;
        fund_account(&store, sender_addr, initial_balance);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        let tx = make_stake_tx(&sender_key, MIN_STAKE, 0);
        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block failed");

        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "Stake should succeed; got: {:?}",
            receipts[0].status
        );
        assert_eq!(receipts[0].fee_paid, FEE_STAKE);
        assert_eq!(receipts[0].events.len(), 1);

        // Verify Staked event.
        match &receipts[0].events[0] {
            Event::Staked {
                validator,
                amount,
                total_stake,
            } => {
                assert_eq!(*validator, sender_addr);
                assert_eq!(*amount, MIN_STAKE);
                assert_eq!(*total_stake, MIN_STAKE);
            }
            other => panic!("expected Staked event, got: {:?}", other),
        }

        // Verify ValidatorInfo stored and active.
        let validator_info = load_validator(&store, &sender_addr)
            .expect("load_validator failed")
            .expect("validator should be stored");
        assert!(validator_info.active, "validator should be active");
        assert_eq!(validator_info.staked, MIN_STAKE);

        // Verify balance was reduced by (fee + staked_amount).
        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        assert_eq!(
            sender.balance,
            initial_balance - FEE_STAKE - MIN_STAKE,
            "sender balance should be reduced by fee + staked amount"
        );
    }

    #[test]
    fn unstake_via_executor() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());

        use solidus_txns::staking::MIN_STAKE;
        use solidus_txns::types::FEE_STAKE;
        use solidus_txns::types::FEE_UNSTAKE;

        // Fund with enough for fee (stake) + stake amount + fee (unstake).
        let initial_balance = MIN_STAKE * 2 + FEE_STAKE + FEE_UNSTAKE;
        fund_account(&store, sender_addr, initial_balance);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Step 1: Stake.
        let tx_stake = make_stake_tx(&sender_key, MIN_STAKE, 0);
        let receipts = execute_block(
            &store,
            &[tx_stake],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block (stake) failed");
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "Stake should succeed; got: {:?}",
            receipts[0].status
        );

        // Verify staked state.
        let info = load_validator(&store, &sender_addr)
            .expect("load_validator failed")
            .expect("should exist after stake");
        assert!(info.active);
        assert_eq!(info.staked, MIN_STAKE);

        // Step 2: Fully unstake (nonce=1).
        let tx_unstake = make_unstake_tx(&sender_key, MIN_STAKE, 1);
        let receipts = execute_block(
            &store,
            &[tx_unstake],
            2,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block (unstake) failed");

        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "Unstake should succeed; got: {:?}",
            receipts[0].status
        );
        assert_eq!(receipts[0].events.len(), 1);

        // Verify Unstaked event.
        match &receipts[0].events[0] {
            Event::Unstaked {
                validator,
                amount,
                remaining_stake,
            } => {
                assert_eq!(*validator, sender_addr);
                assert_eq!(*amount, MIN_STAKE);
                assert_eq!(*remaining_stake, 0);
            }
            other => panic!("expected Unstaked event, got: {:?}", other),
        }

        // Verify ValidatorInfo: staked=0, active=false.
        let info = load_validator(&store, &sender_addr)
            .expect("load_validator failed")
            .expect("should still exist after unstake");
        assert_eq!(info.staked, 0, "staked should be zero after full unstake");
        assert!(
            !info.active,
            "validator should be inactive after full unstake"
        );
    }

    // -----------------------------------------------------------------------
    // State root tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_root_empty_store() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));
        let root = compute_state_root(&store).expect("compute_state_root failed");
        // Empty store produces the global root of 4 empty SMTs.
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn state_root_changes_after_execution() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

        let root_before = compute_state_root(&store).expect("compute_state_root failed");

        let sender_key = generate_signing_key();
        let receiver_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_public_key(&receiver_key.verifying_key());
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        fund_account(&store, sender_addr, 1_000_000);

        let tx = make_transfer_tx(&sender_key, receiver_addr, 500, 0);
        execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block failed");

        let root_after = compute_state_root(&store).expect("compute_state_root failed");
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn state_root_deterministic() {
        // Two stores with identical state produce the same root.
        let dir1 = tempdir().expect("failed to create temp dir");
        let store1 = Arc::new(Store::open(dir1.path()).expect("failed to open store"));
        let dir2 = tempdir().expect("failed to create temp dir");
        let store2 = Arc::new(Store::open(dir2.path()).expect("failed to open store"));

        let addr = Address::from_bytes([0x11u8; 20]);
        fund_account(&store1, addr, 999);
        fund_account(&store2, addr, 999);

        let root1 = compute_state_root(&store1).expect("compute_state_root failed");
        let root2 = compute_state_root(&store2).expect("compute_state_root failed");
        assert_eq!(root1, root2);
    }

    #[test]
    fn did_state_root_uses_block_timestamp_not_wallclock() {
        // Determinism invariant (consensus-critical): two validators
        // re-executing the SAME block must derive byte-identical state —
        // including each DID document's created_ms/updated_ms — so their
        // state roots match and neither rejects the other's proposal at the
        // `state_root` mismatch gate in the consensus loop.
        //
        // Regression guard for the wall-clock bug: execute_block previously
        // stamped DID records with local SystemTime::now(), so two executions
        // a few ms apart produced different created_ms -> different CF_DIDS
        // bytes -> different state root. The block timestamp is now an
        // explicit input; this test pins it and asserts the stored document
        // reflects exactly that value, never wall-clock.
        let dir1 = tempdir().expect("temp dir 1");
        let store1 = Arc::new(Store::open(dir1.path()).expect("open store1"));
        let dir2 = tempdir().expect("temp dir 2");
        let store2 = Arc::new(Store::open(dir2.path()).expect("open store2"));

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);
        // No funding: a fresh identity key creates a DID fee-free (pristine rule).

        let block_ts: u64 = 1_700_000_123_456;

        // Validator 1 executes the block.
        let tx1 = make_did_create_tx(&sender_key, 0);
        execute_block(&store1, &[tx1], 1, block_ts, &treasury_addr, &[], "testnet")
            .expect("execute_block store1");

        // Validator 2 re-executes the same logical block a few ms later — real
        // wall-clock has advanced. With the same block-header timestamp the
        // resulting state MUST be identical.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let tx2 = make_did_create_tx(&sender_key, 0);
        execute_block(&store2, &[tx2], 1, block_ts, &treasury_addr, &[], "testnet")
            .expect("execute_block store2");

        let root1 = compute_state_root(&store1).expect("root1");
        let root2 = compute_state_root(&store2).expect("root2");
        assert_eq!(
            root1, root2,
            "state roots must match across validators re-executing the same block"
        );

        // The stored DID's timestamps equal the block timestamp exactly — not
        // wall-clock. Reintroducing now_ms() makes these assertions fail.
        let did = solidus_txns::did::build_did("testnet", &sender_addr);
        let doc = load_did(&store1, &did)
            .expect("load_did")
            .expect("did present");
        assert_eq!(
            doc.created_ms, block_ts,
            "created_ms must equal block timestamp"
        );
        assert_eq!(
            doc.updated_ms, block_ts,
            "updated_ms must equal block timestamp"
        );
    }

    // ----------------------------------------------------------------------
    // Committed-view (CF_COMMITTED_ACCOUNTS) tests
    // ----------------------------------------------------------------------

    #[test]
    fn load_committed_account_returns_default_for_unknown_address() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));
        let addr = Address::from_bytes([0x42u8; 20]);

        let acct = load_committed_account(&store, &addr).expect("load_committed_account failed");
        assert_eq!(acct.balance, 0);
        assert_eq!(acct.nonce, 0);
    }

    #[test]
    fn save_account_does_not_populate_committed_view() {
        // The whole point: speculative writes via save_account / execute_block
        // MUST NOT leak into the committed view that RPC reads.
        use crate::account::AccountType;
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

        let addr = Address::from_bytes([0x11u8; 20]);
        let acct = Account::with_balance(addr, 5_000, AccountType::Regular);
        save_account(&store, &acct).expect("save_account failed");

        // CF_ACCOUNTS sees the write.
        let live = load_account(&store, &addr).expect("load_account failed");
        assert_eq!(live.balance, 5_000);

        // CF_COMMITTED_ACCOUNTS does NOT.
        let committed =
            load_committed_account(&store, &addr).expect("load_committed_account failed");
        assert_eq!(committed.balance, 0);
    }

    #[test]
    fn mirror_account_to_committed_copies_live_to_committed() {
        use crate::account::AccountType;
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

        let addr = Address::from_bytes([0x22u8; 20]);
        let acct = Account::with_balance(addr, 12_345, AccountType::Regular);
        save_account(&store, &acct).expect("save_account failed");

        mirror_account_to_committed(&store, &addr).expect("mirror failed");

        let committed =
            load_committed_account(&store, &addr).expect("load_committed_account failed");
        assert_eq!(committed.balance, 12_345);
    }

    #[test]
    fn mirror_account_to_committed_is_noop_for_unknown_address() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

        let addr = Address::from_bytes([0x33u8; 20]);
        mirror_account_to_committed(&store, &addr).expect("mirror failed");

        // Still default (nothing to copy from CF_ACCOUNTS).
        let committed =
            load_committed_account(&store, &addr).expect("load_committed_account failed");
        assert_eq!(committed.balance, 0);
    }

    #[test]
    fn block_touched_accounts_includes_treasury_validators_senders_recipients() {
        let treasury = Address::from_bytes([0xAAu8; 20]);
        let validator_a = Address::from_bytes([0xB1u8; 20]);
        let validator_b = Address::from_bytes([0xB2u8; 20]);
        let recipient = Address::from_bytes([0xCCu8; 20]);

        let tx = make_signed_transfer(recipient, 100, 0);
        let sender = tx.sender_address();
        let touched = block_touched_accounts(&[tx], &treasury, &[validator_a, validator_b]);

        assert!(touched.contains(&treasury));
        assert!(touched.contains(&validator_a));
        assert!(touched.contains(&validator_b));
        assert!(touched.contains(&sender));
        assert!(touched.contains(&recipient));
        assert_eq!(touched.len(), 5);
    }

    #[test]
    fn block_touched_accounts_empty_block_just_returns_treasury_and_validators() {
        let treasury = Address::from_bytes([0xAAu8; 20]);
        let validator_a = Address::from_bytes([0xB1u8; 20]);

        let touched = block_touched_accounts(&[], &treasury, &[validator_a]);

        assert!(touched.contains(&treasury));
        assert!(touched.contains(&validator_a));
        assert_eq!(touched.len(), 2);
    }

    /// Helper: signed Transfer tx for committed-view tests.
    fn make_signed_transfer(to: Address, amount: u64, nonce: u64) -> Transaction {
        let sender_key = generate_signing_key();
        let pubkey = sender_key.verifying_key().to_bytes();
        let mut tx = Transaction {
            sender_pubkey: pubkey,
            nonce,
            payload: TxPayload::Transfer { to, amount },
            signature: [0u8; 64],
        };
        let msg = tx.signing_bytes();
        tx.signature = sign(&sender_key, &msg);
        tx
    }

    // -----------------------------------------------------------------------
    // DID-anchor / value-account decouple tests (Slice 1)
    // -----------------------------------------------------------------------

    #[test]
    fn is_did_anchor_true_only_for_registered_dids() {
        let (store, _dir) = open_tmp();
        let (addr, pk) = {
            let sk = generate_signing_key();
            let vk = sk.verifying_key();
            (Address::from_public_key(&vk), vk.to_bytes())
        };
        // No DID yet -> not an anchor.
        assert!(!is_did_anchor(&store, "testnet", &addr).expect("lookup"));
        // Register a DID at this address, then it IS an anchor.
        let did = solidus_txns::did::build_did("testnet", &addr);
        let doc = solidus_txns::did::build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        save_did(&store, &did, &doc).expect("save_did");
        assert!(is_did_anchor(&store, "testnet", &addr).expect("lookup"));
        // A different address is still not an anchor.
        let other = Address::from_bytes([0x77u8; 20]);
        assert!(!is_did_anchor(&store, "testnet", &other).expect("lookup"));
    }

    #[test]
    fn did_create_from_zero_balance_account_succeeds_fee_exempt() {
        let (store, _dir) = open_tmp();
        let sender_key = generate_signing_key();
        // NOTE: no funding — a fresh identity key has zero balance.
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);
        let tx = make_did_create_tx(&sender_key, 0);
        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block");
        assert_eq!(
            receipts[0].status,
            TxStatus::Success,
            "fresh-key DidCreate must succeed"
        );
        assert_eq!(receipts[0].fee_paid, 0, "DID ops are fee-exempt");
    }

    #[test]
    fn did_create_on_funded_account_is_rejected() {
        let (store, _dir) = open_tmp();
        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        fund_account(&store, sender_addr, 500); // value history -> not pristine
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);
        let tx = make_did_create_tx(&sender_key, 0);
        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block");
        match &receipts[0].status {
            TxStatus::Failed(reason) => assert!(reason.contains("pristine"), "got: {reason}"),
            TxStatus::Success => panic!("DidCreate on a funded account must be rejected"),
        }
        // And no DID was written.
        let did = solidus_txns::did::build_did("testnet", &sender_addr);
        assert!(load_did(&store, &did).expect("load_did").is_none());
    }

    #[test]
    fn transfer_to_a_did_anchor_is_rejected() {
        let (store, _dir) = open_tmp();
        // Recipient is a registered DID-anchor.
        let anchor_key = generate_signing_key();
        let anchor_addr = Address::from_public_key(&anchor_key.verifying_key());
        let anchor_did = solidus_txns::did::build_did("testnet", &anchor_addr);
        let anchor_doc = solidus_txns::did::build_did_document(
            &anchor_did,
            &hex::encode(anchor_key.verifying_key().to_bytes()),
            vec![],
            1_000,
        );
        save_did(&store, &anchor_did, &anchor_doc).expect("save_did");
        // Funded value account tries to send to the anchor.
        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        fund_account(&store, sender_addr, 1_000_000);
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);
        let tx = make_transfer_tx(&sender_key, anchor_addr, 500, 0);
        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block");
        match &receipts[0].status {
            TxStatus::Failed(r) => {
                assert!(r.contains("recipient") && r.contains("anchor"), "got: {r}")
            }
            TxStatus::Success => panic!("transfer to a DID-anchor must be rejected"),
        }
        // The anchor never received value.
        assert_eq!(load_account(&store, &anchor_addr).expect("load").balance, 0);
    }

    #[test]
    fn normal_transfer_between_value_accounts_still_succeeds() {
        let (store, _dir) = open_tmp();
        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let recipient = Address::from_bytes([0xCDu8; 20]); // not a DID-anchor
        fund_account(&store, sender_addr, 1_000_000);
        let treasury_addr = Address::from_bytes([0xAAu8; 20]);
        let tx = make_transfer_tx(&sender_key, recipient, 500, 0);
        let receipts = execute_block(
            &store,
            &[tx],
            1,
            1_700_000_000_000,
            &treasury_addr,
            &[],
            "testnet",
        )
        .expect("execute_block");
        assert_eq!(receipts[0].status, TxStatus::Success);
        assert_eq!(load_account(&store, &recipient).expect("load").balance, 500);
    }

    /// One flowing scenario against the REAL executor + store exercising the
    /// review fixes: append-only seq-keyed anchors + duplicate-root rejection
    /// (fix 1), remove-clears-node → re-register lifecycle (fix 2), remove of a
    /// never-admitted DID fails (fix 3), and non-governance senders fail every
    /// governance op while still paying fee + consuming nonce.
    #[test]
    fn compute_lifecycle_via_executor() {
        use solidus_txns::compute::{ComputeReceiptAnchor, ComputeStatus, ComputeTier};
        use solidus_txns::staking::MIN_STAKE;
        use solidus_txns::types::FEE_COMPUTE;

        let (store, _dir) = open_tmp();
        let treasury = Address::from_bytes([0xAAu8; 20]);

        // Governance sender = an ACTIVE validator (Phase-1 governance policy).
        let gov_key = generate_signing_key();
        let gov_addr = Address::from_public_key(&gov_key.verifying_key());
        fund_account(&store, gov_addr, 10_000_000);
        save_validator(
            &store,
            &ValidatorInfo {
                address: gov_addr,
                staked: MIN_STAKE,
                unbonding: 0,
                unbonding_start_ms: None,
                reputation: 1000,
                active: true,
            },
        )
        .expect("save gov validator");

        // A funded, validly-signed NON-governance stranger.
        let stranger_key = generate_signing_key();
        let stranger_addr = Address::from_public_key(&stranger_key.verifying_key());
        fund_account(&store, stranger_addr, 10_000_000);

        // The operator: self-certifying — its address derives from its ed25519 key.
        let op_key = generate_signing_key();
        let op_ed = op_key.verifying_key().to_bytes();
        let op_addr = Address::from_public_key(&op_key.verifying_key());
        fund_account(&store, op_addr, 10_000_000);

        // validator_addresses = &[] so NO fee is redistributed back to any sender;
        // each sender loses exactly FEE_COMPUTE per tx (keeps balance math clean).
        let mut height = 1u64;
        let ts = 1_700_000_000_000u64;
        let mut run = |key: &SigningKey, nonce: u64, payload: TxPayload| -> Receipt {
            let mut tx = Transaction {
                sender_pubkey: key.verifying_key().to_bytes(),
                nonce,
                payload,
                signature: [0u8; 64],
            };
            let sig = sign(key, &tx.signing_bytes());
            tx.signature = sig;
            let mut rs = execute_block(
                &store,
                std::slice::from_ref(&tx),
                height,
                ts,
                &treasury,
                &[],
                "testnet",
            )
            .expect("execute_block");
            height += 1;
            rs.pop().expect("one receipt")
        };

        let root_a = [0x01u8; 32];
        let root_b = [0x02u8; 32];

        // 1. admit(op, Trusted) — governance succeeds.
        let r = run(
            &gov_key,
            0,
            TxPayload::ComputeAdmit {
                operator: op_addr,
                tier: ComputeTier::Trusted,
            },
        );
        assert_eq!(r.status, TxStatus::Success);
        assert!(load_compute_allow(&store, &op_addr).unwrap().is_some());

        // 2. register(op) — self-certifying, succeeds.
        let r = run(
            &op_key,
            0,
            TxPayload::ComputeRegister {
                ed25519_pub: op_ed,
                x25519_pub: [9u8; 32],
                jurisdiction: "TR".into(),
            },
        );
        assert_eq!(r.status, TxStatus::Success);
        let node = load_compute_node(&store, &op_addr)
            .unwrap()
            .expect("node record");
        assert_eq!(node.status, ComputeStatus::Active);
        assert_eq!(node.reputation, 700);
        assert_eq!(node.tier, ComputeTier::Trusted);

        // 3. anchor(root_a, 5) — succeeds, stored append-only at seq 0.
        let r = run(
            &gov_key,
            1,
            TxPayload::ComputeAnchor {
                merkle_root: root_a,
                batch_count: 5,
            },
        );
        assert_eq!(r.status, TxStatus::Success);
        let seq0 = store
            .get(CF_COMPUTE_ANCHORS, &0u64.to_le_bytes())
            .unwrap()
            .expect("seq-0 record");
        let a0 = ComputeReceiptAnchor::from_bytes(&seq0).unwrap();
        assert_eq!(a0.merkle_root, root_a);
        assert_eq!(a0.batch_count, 5);
        // Secondary index root_a -> seq 0.
        assert_eq!(
            store.get(CF_COMPUTE_ANCHORS, &root_a).unwrap().unwrap(),
            0u64.to_le_bytes().to_vec()
        );

        // 4. anchor(root_a, 9) again — duplicate root REJECTED; fee + nonce consumed;
        //    the original seq-0 record is NOT overwritten and no seq-1 record appears.
        let r = run(
            &gov_key,
            2,
            TxPayload::ComputeAnchor {
                merkle_root: root_a,
                batch_count: 9,
            },
        );
        assert!(
            matches!(r.status, TxStatus::Failed(_)),
            "duplicate-root anchor must fail"
        );
        assert_eq!(r.fee_paid, FEE_COMPUTE, "failed tx still pays fee");
        assert!(r.events.is_empty(), "rejected anchor emits no event");
        let seq0_after = ComputeReceiptAnchor::from_bytes(
            &store
                .get(CF_COMPUTE_ANCHORS, &0u64.to_le_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            seq0_after.batch_count, 5,
            "original anchor MUST NOT be overwritten"
        );
        assert!(
            store
                .get(CF_COMPUTE_ANCHORS, &1u64.to_le_bytes())
                .unwrap()
                .is_none(),
            "rejected anchor MUST NOT consume a seq slot"
        );

        // 5. anchor(root_b, 7) — distinct root, next seq (1).
        let r = run(
            &gov_key,
            3,
            TxPayload::ComputeAnchor {
                merkle_root: root_b,
                batch_count: 7,
            },
        );
        assert_eq!(r.status, TxStatus::Success);
        let a1 = ComputeReceiptAnchor::from_bytes(
            &store
                .get(CF_COMPUTE_ANCHORS, &1u64.to_le_bytes())
                .unwrap()
                .expect("seq-1 record"),
        )
        .unwrap();
        assert_eq!(a1.merkle_root, root_b);
        assert_eq!(a1.batch_count, 7);
        assert_eq!(
            store.get(CF_COMPUTE_ANCHORS, &root_b).unwrap().unwrap(),
            1u64.to_le_bytes().to_vec()
        );

        // 6. slash(op, severe) — record kept, marked Slashed.
        let r = run(
            &gov_key,
            4,
            TxPayload::ComputeSlash {
                operator: op_addr,
                reputation_penalty: 0,
                severe: true,
            },
        );
        assert_eq!(r.status, TxStatus::Success);
        let node = load_compute_node(&store, &op_addr)
            .unwrap()
            .expect("record still present");
        assert_eq!(node.status, ComputeStatus::Slashed);
        assert_eq!(node.reputation, 0);

        // 6b. A slashed-but-NOT-removed node still cannot re-register (record persists).
        let r = run(
            &op_key,
            1,
            TxPayload::ComputeRegister {
                ed25519_pub: op_ed,
                x25519_pub: [9u8; 32],
                jurisdiction: "TR".into(),
            },
        );
        assert!(
            matches!(r.status, TxStatus::Failed(_)),
            "slashed node cannot re-register"
        );

        // 7. remove(op) — deletes BOTH the allow-list entry AND the node record.
        let r = run(&gov_key, 5, TxPayload::ComputeRemove { operator: op_addr });
        assert_eq!(r.status, TxStatus::Success);
        assert!(
            load_compute_allow(&store, &op_addr).unwrap().is_none(),
            "allow-list entry removed"
        );
        assert!(
            load_compute_node(&store, &op_addr).unwrap().is_none(),
            "node record removed"
        );

        // 8. re-admit(op, Attested) — fresh admission after removal.
        let r = run(
            &gov_key,
            6,
            TxPayload::ComputeAdmit {
                operator: op_addr,
                tier: ComputeTier::Attested,
            },
        );
        assert_eq!(r.status, TxStatus::Success);

        // 9. re-register(op) — now SUCCEEDS (record was cleared by removal).
        let r = run(
            &op_key,
            2,
            TxPayload::ComputeRegister {
                ed25519_pub: op_ed,
                x25519_pub: [9u8; 32],
                jurisdiction: "US".into(),
            },
        );
        assert_eq!(
            r.status,
            TxStatus::Success,
            "re-admitted DID must be able to re-register"
        );
        let node = load_compute_node(&store, &op_addr)
            .unwrap()
            .expect("re-registered node");
        assert_eq!(node.status, ComputeStatus::Active);
        assert_eq!(node.reputation, 700);
        assert_eq!(
            node.tier,
            ComputeTier::Attested,
            "tier comes from the fresh admission"
        );

        // 10. remove of a never-admitted DID — fails NotAdmitted, no event, fee consumed.
        let never = Address::from_bytes([0x33u8; 20]);
        let r = run(&gov_key, 7, TxPayload::ComputeRemove { operator: never });
        assert!(
            matches!(r.status, TxStatus::Failed(_)),
            "remove of never-admitted DID must fail"
        );
        assert!(
            r.events.is_empty(),
            "no ComputeRemoved event for a never-admitted DID"
        );
        assert_eq!(r.fee_paid, FEE_COMPUTE);

        // 11. A non-governance stranger fails EVERY governance op, still pays fee + nonce.
        for (n, payload) in [
            TxPayload::ComputeAdmit {
                operator: op_addr,
                tier: ComputeTier::Trusted,
            },
            TxPayload::ComputeAnchor {
                merkle_root: [0x07u8; 32],
                batch_count: 3,
            },
            TxPayload::ComputeSlash {
                operator: op_addr,
                reputation_penalty: 100,
                severe: false,
            },
            TxPayload::ComputeRemove { operator: op_addr },
        ]
        .into_iter()
        .enumerate()
        {
            let r = run(&stranger_key, n as u64, payload);
            assert!(
                matches!(r.status, TxStatus::Failed(_)),
                "non-governance op must fail"
            );
            assert_eq!(
                r.fee_paid, FEE_COMPUTE,
                "failed governance op still pays fee"
            );
        }

        // Nonces + balances: every validly-signed tx consumed a nonce slot and its fee.
        assert_eq!(load_account(&store, &gov_addr).unwrap().nonce, 8);
        assert_eq!(
            load_account(&store, &gov_addr).unwrap().balance,
            10_000_000 - 8 * FEE_COMPUTE
        );
        assert_eq!(load_account(&store, &op_addr).unwrap().nonce, 3);
        assert_eq!(load_account(&store, &stranger_addr).unwrap().nonce, 4);
        assert_eq!(
            load_account(&store, &stranger_addr).unwrap().balance,
            10_000_000 - 4 * FEE_COMPUTE
        );
    }

    /// An operator whose chain account IS its own `did:solidus` anchor holds zero
    /// balance by construction — anchors are value-free, a `Transfer` into one is
    /// rejected. `ComputeRegister` is therefore fee-exempt; without the exemption
    /// such an operator could never register (permanent "insufficient balance for
    /// fee"). The exemption is scoped: the nonce is still checked and consumed,
    /// and every NON-exempt payload from that same account still fails the fee
    /// check.
    #[test]
    fn compute_register_from_did_anchored_zero_balance_operator_succeeds() {
        use solidus_txns::compute::{ComputeStatus, ComputeTier};
        use solidus_txns::staking::MIN_STAKE;

        let (store, _dir) = open_tmp();
        let treasury = Address::from_bytes([0xAAu8; 20]);

        // Governance sender = an ACTIVE validator (Phase-1 governance policy).
        let gov_key = generate_signing_key();
        let gov_addr = Address::from_public_key(&gov_key.verifying_key());
        fund_account(&store, gov_addr, 10_000_000);
        save_validator(
            &store,
            &ValidatorInfo {
                address: gov_addr,
                staked: MIN_STAKE,
                unbonding: 0,
                unbonding_start_ms: None,
                reputation: 1000,
                active: true,
            },
        )
        .expect("save gov validator");

        // The operator publishes its OWN DID document on-chain, so its account
        // becomes a DID anchor. NOTE: never funded — an anchor cannot be funded.
        let op_key = generate_signing_key();
        let op_ed = op_key.verifying_key().to_bytes();
        let op_addr = Address::from_public_key(&op_key.verifying_key());

        let mut height = 1u64;
        let ts = 1_700_000_000_000u64;
        let mut run = |key: &SigningKey, nonce: u64, payload: TxPayload| -> Receipt {
            let mut tx = Transaction {
                sender_pubkey: key.verifying_key().to_bytes(),
                nonce,
                payload,
                signature: [0u8; 64],
            };
            let sig = sign(key, &tx.signing_bytes());
            tx.signature = sig;
            let mut rs = execute_block(
                &store,
                std::slice::from_ref(&tx),
                height,
                ts,
                &treasury,
                &[],
                "testnet",
            )
            .expect("execute_block");
            height += 1;
            rs.pop().expect("one receipt")
        };

        // 1. The operator anchors its own DID via the REAL DidCreate path.
        let r = run(
            &op_key,
            0,
            TxPayload::DidCreate {
                public_key: op_ed,
                service_endpoints: vec![],
            },
        );
        assert_eq!(
            r.status,
            TxStatus::Success,
            "DidCreate on a pristine key must succeed"
        );
        assert!(
            is_did_anchor(&store, "testnet", &op_addr).expect("lookup"),
            "the operator account is now a genuine DID anchor"
        );
        let acct = load_account(&store, &op_addr).unwrap();
        assert_eq!(acct.balance, 0, "an anchor account can never hold value");
        assert_eq!(acct.nonce, 1);

        // 2. Governance admits it to the compute allow-list.
        let r = run(
            &gov_key,
            0,
            TxPayload::ComputeAdmit {
                operator: op_addr,
                tier: ComputeTier::Trusted,
            },
        );
        assert_eq!(r.status, TxStatus::Success);

        // 3. ComputeRegister from the zero-balance anchor — fee-exempt, succeeds.
        let r = run(
            &op_key,
            1,
            TxPayload::ComputeRegister {
                ed25519_pub: op_ed,
                x25519_pub: [9u8; 32],
                jurisdiction: "TR".into(),
            },
        );
        assert_eq!(
            r.status,
            TxStatus::Success,
            "a DID-anchored operator with zero balance must still be able to register"
        );
        assert_eq!(r.fee_paid, 0, "ComputeRegister is fee-exempt");
        let node = load_compute_node(&store, &op_addr)
            .unwrap()
            .expect("node record");
        assert_eq!(node.status, ComputeStatus::Active);
        assert_eq!(node.tier, ComputeTier::Trusted);

        // The nonce is still consumed on the fee-exempt path; the balance is not touched.
        let acct = load_account(&store, &op_addr).unwrap();
        assert_eq!(
            acct.nonce, 2,
            "a fee-exempt tx still checks and consumes its nonce"
        );
        assert_eq!(acct.balance, 0);

        // 3b. A fresh tx at the now-stale nonce is rejected by the nonce check —
        //     the exemption did not weaken nonce handling. (A byte-identical replay
        //     would instead hit the tx_hash idempotency cache, so vary the payload.)
        let r = run(
            &op_key,
            1,
            TxPayload::ComputeRegister {
                ed25519_pub: op_ed,
                x25519_pub: [8u8; 32],
                jurisdiction: "TR".into(),
            },
        );
        match &r.status {
            TxStatus::Failed(reason) => assert!(reason.contains("invalid nonce"), "got: {reason}"),
            TxStatus::Success => panic!("a stale-nonce ComputeRegister must be rejected"),
        }

        // 4. A NON-exempt payload from the same account still fails the fee check —
        //    the exemption did not turn this account into a free-tx account.
        let r = run(
            &op_key,
            2,
            TxPayload::Transfer {
                to: Address::from_bytes([0xCDu8; 20]),
                amount: 1,
            },
        );
        match &r.status {
            TxStatus::Failed(reason) => assert!(
                reason.contains("insufficient balance for fee"),
                "got: {reason}"
            ),
            TxStatus::Success => panic!("a zero-balance account must not be able to Transfer"),
        }
        assert_eq!(
            load_account(&store, &op_addr).unwrap().nonce,
            2,
            "a tx rejected at the fee check consumes no nonce"
        );
    }

    /// compute_state_root switched to the IN-MEMORY tree (2026-07-13) to
    /// stop rewriting the whole Merkle tree into RocksDB on every call.
    /// The switch is only sound if the in-memory tree computes BIT-IDENTICAL
    /// roots to the store-backed one: state roots live in committed block
    /// headers, and a full-node re-executing history compares recomputed
    /// roots against them (SyncError::StateRootMismatch). This test is that
    /// guard — varied keys/values, overwrites included.
    #[test]
    fn in_memory_tree_matches_store_backed_roots() {
        let (store, _dir) = open_tmp();
        let store = Arc::new(store);

        let mut persisted =
            crate::tree::SparseMerkleTree::new(Arc::clone(&store), crate::tree::TreeId::Accounts);
        let mut in_memory = solidus_state_tree::SparseMerkleTree::new();

        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0u32..64)
            .map(|i| {
                (
                    format!("key-{i}").into_bytes(),
                    vec![i as u8; (i as usize % 40) + 1],
                )
            })
            // Overwrite a third of the keys with new values — insertion
            // order and updates must not diverge the roots.
            .chain((0u32..64).step_by(3).map(|i| {
                (
                    format!("key-{i}").into_bytes(),
                    format!("updated-{i}").into_bytes(),
                )
            }))
            .collect();

        for (k, v) in &entries {
            persisted.insert(k, v).expect("store-backed insert");
            in_memory.insert(k, v);
        }

        assert_eq!(
            persisted.root(),
            in_memory.root(),
            "in-memory and store-backed trees must agree bit-for-bit"
        );

        // Empty trees must agree too (the genesis / empty-CF case).
        assert_eq!(
            crate::tree::SparseMerkleTree::new(store, crate::tree::TreeId::Dids).root(),
            solidus_state_tree::SparseMerkleTree::new().root(),
            "empty-tree roots must agree"
        );
    }
}
