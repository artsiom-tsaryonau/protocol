use std::sync::Arc;

use solidus_crypto::keys::Address;
use solidus_txns::credential::{CredentialRecord, execute_credential_issue, execute_credential_revoke};
use solidus_txns::did::{DidDocument, execute_did_create, execute_did_update, execute_did_deactivate};
use solidus_txns::staking::{ValidatorInfo, execute_stake, execute_unstake};
use solidus_txns::token::execute_transfer;
use solidus_txns::types::{Event, Receipt, Transaction, TxPayload, TxStatus};

use crate::account::Account;
use crate::store::{Store, StoreError, CF_ACCOUNTS, CF_CREDENTIALS, CF_CRED_BY_ISSUER, CF_CRED_BY_SUBJECT, CF_DIDS, CF_RECEIPTS, CF_VALIDATORS};
use crate::tree::{SparseMerkleTree, TreeId, global_state_root};

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

/// Load a credential record from the store. Returns `Ok(None)` if not found.
pub fn load_credential(store: &Store, credential_id: &str) -> Result<Option<CredentialRecord>, StoreError> {
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
        Some(bytes) => Ok(serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde(e.to_string()))?),
        None => Ok(vec![]),
    }
}

/// Load a validator record from the store. Returns `Ok(None)` if not found.
pub fn load_validator(store: &Store, address: &Address) -> Result<Option<ValidatorInfo>, StoreError> {
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

/// Append a credential ID to a secondary index.
pub fn append_credential_index(store: &Store, cf: &str, key: &str, credential_id: &str) -> Result<(), StoreError> {
    let mut ids = load_credential_ids(store, cf, key)?;
    ids.push(credential_id.to_string());
    let bytes = serde_json::to_vec(&ids).map_err(|e| StoreError::Serde(e.to_string()))?;
    store.put(cf, key.as_bytes(), &bytes)
}

// ---------------------------------------------------------------------------
// Block execution
// ---------------------------------------------------------------------------

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
pub fn execute_block(
    store: &Store,
    transactions: &[Transaction],
    block_height: u64,
    treasury_address: &Address,
    validator_addresses: &[Address],
) -> Result<Vec<Receipt>, ExecutorError> {
    let mut receipts = Vec::with_capacity(transactions.len());
    let mut total_fees: u64 = 0;

    for tx in transactions {
        let tx_hash = tx.hash();

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
        let fee = tx.payload.fee();
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
            TxPayload::DidCreate { ref public_key, ref service_endpoints } => {
                let did_str = solidus_txns::did::build_did("testnet", &sender_addr);
                let existing = load_did(store, &did_str).map_err(ExecutorError::Store)?;
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                match execute_did_create(
                    &sender_addr,
                    public_key,
                    service_endpoints.clone(),
                    existing.as_ref(),
                    timestamp_ms,
                    "testnet",
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
            TxPayload::DidUpdate { ref did, ref patches } => {
                let existing = load_did(store, did).map_err(ExecutorError::Store)?;
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                match execute_did_update(
                    &sender_addr,
                    did,
                    patches,
                    existing.as_ref(),
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
            TxPayload::CredentialIssue { ref subject_did, credential_type, hash } => {
                let subject_did = subject_did.clone();
                let credential_type = *credential_type;
                let hash = *hash;

                let issuer_did = solidus_txns::did::build_did("testnet", &sender_addr);
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;

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
                        append_credential_index(store, CF_CRED_BY_SUBJECT, &subject_did_clone, &credential_id)
                            .map_err(ExecutorError::Store)?;
                        append_credential_index(store, CF_CRED_BY_ISSUER, &issuer_did_clone, &credential_id)
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
                let sender_did = solidus_txns::did::build_did("testnet", &sender_addr);
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;

                let existing = load_credential(store, &credential_id).map_err(ExecutorError::Store)?;

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
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let _ = timestamp_ms; // not needed for stake, but available for consistency

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
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;

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
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                match execute_did_deactivate(
                    &sender_addr,
                    did,
                    existing.as_ref(),
                    timestamp_ms,
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
    let value =
        serde_json::to_vec(receipt).map_err(|e| StoreError::Serde(e.to_string()))?;
    store.put(CF_RECEIPTS, &receipt.tx_hash, &value)?;
    Ok(())
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
pub fn compute_state_root(store: &Arc<Store>) -> Result<[u8; 32], ExecutorError> {
    let mut accounts_tree = SparseMerkleTree::new(Arc::clone(store), TreeId::Accounts);
    for (k, v) in store.iter_cf(CF_ACCOUNTS)? {
        accounts_tree.insert(&k, &v)?;
    }

    let mut dids_tree = SparseMerkleTree::new(Arc::clone(store), TreeId::Dids);
    for (k, v) in store.iter_cf(CF_DIDS)? {
        dids_tree.insert(&k, &v)?;
    }

    let mut credentials_tree = SparseMerkleTree::new(Arc::clone(store), TreeId::Credentials);
    for (k, v) in store.iter_cf(CF_CREDENTIALS)? {
        credentials_tree.insert(&k, &v)?;
    }

    let mut validators_tree = SparseMerkleTree::new(Arc::clone(store), TreeId::Validators);
    for (k, v) in store.iter_cf(CF_VALIDATORS)? {
        validators_tree.insert(&k, &v)?;
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
    use solidus_txns::types::{FEE_TRANSFER, TxPayload};
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
            &treasury_addr,
            &[validator_addr],
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

        let receipts = execute_block(&store, &[tx], 1, &treasury_addr, &[])
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

        let receipts = execute_block(&store, &[tx], 1, &treasury_addr, &[])
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
            &treasury_addr,
            &[validator_addr],
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

        let total_after =
            sender.balance + receiver.balance + validator.balance + treasury.balance;
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
        let receipts1 = execute_block(&store, &[tx1], 1, &treasury_addr, &[])
            .expect("execute_block 1 failed");
        assert_eq!(receipts1[0].status, TxStatus::Success);

        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        assert_eq!(sender.nonce, 1);

        // Second transfer (nonce=1)
        let tx2 = make_transfer_tx(&sender_key, receiver_addr, 200, 1);
        let receipts2 = execute_block(&store, &[tx2], 2, &treasury_addr, &[])
            .expect("execute_block 2 failed");
        assert_eq!(receipts2[0].status, TxStatus::Success);

        let sender = load_account(&store, &sender_addr).expect("load sender failed");
        assert_eq!(sender.nonce, 2);
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

        // Fund enough for DID create fee (100_000) plus some headroom.
        fund_account(&store, sender_addr, 1_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        let tx = make_did_create_tx(&sender_key, 0);
        let receipts = execute_block(&store, &[tx], 1, &treasury_addr, &[])
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
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());

        // Fund enough for two DID create fees.
        fund_account(&store, sender_addr, 2_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // First create — should succeed.
        let tx1 = make_did_create_tx(&sender_key, 0);
        let receipts1 = execute_block(&store, &[tx1], 1, &treasury_addr, &[])
            .expect("execute_block 1 failed");
        assert_eq!(receipts1[0].status, TxStatus::Success);

        // Second create with nonce=1 — should fail (DID already exists).
        let tx2 = make_did_create_tx(&sender_key, 1);
        let receipts2 = execute_block(&store, &[tx2], 2, &treasury_addr, &[])
            .expect("execute_block 2 failed");

        match &receipts2[0].status {
            TxStatus::Failed(reason) => {
                assert!(
                    reason.contains("already exists"),
                    "unexpected failure reason: {reason}"
                );
            }
            TxStatus::Success => panic!("expected failure for duplicate DID create"),
        }
        // Fee is still paid even on failure.
        assert!(receipts2[0].fee_paid > 0);
    }

    #[test]
    fn did_deactivate_via_executor() {
        let (store, _dir) = open_tmp();

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());

        // Fund enough for create + deactivate fees.
        fund_account(&store, sender_addr, 2_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Step 1: Create the DID.
        let tx_create = make_did_create_tx(&sender_key, 0);
        let receipts_create = execute_block(&store, &[tx_create], 1, &treasury_addr, &[])
            .expect("execute_block (create) failed");
        assert_eq!(receipts_create[0].status, TxStatus::Success);

        let expected_did = solidus_txns::did::build_did("testnet", &sender_addr);

        // Step 2: Deactivate the DID.
        let tx_deactivate = make_did_deactivate_tx(&sender_key, expected_did.clone(), 1);
        let receipts_deactivate =
            execute_block(&store, &[tx_deactivate], 2, &treasury_addr, &[])
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

        // Fund issuer with enough for DID create + credential issue fees.
        fund_account(&store, issuer_addr, 100_000_000);
        // Fund subject with enough for DID create fee.
        fund_account(&store, subject_addr, 1_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Step 1: Create issuer DID.
        let tx_issuer_did = make_did_create_tx(&issuer_key, 0);
        let receipts = execute_block(&store, &[tx_issuer_did], 1, &treasury_addr, &[])
            .expect("issuer DidCreate failed");
        assert_eq!(receipts[0].status, TxStatus::Success, "issuer DID create should succeed");

        // Step 2: Create subject DID.
        let tx_subject_did = make_did_create_tx(&subject_key, 0);
        let receipts = execute_block(&store, &[tx_subject_did], 2, &treasury_addr, &[])
            .expect("subject DidCreate failed");
        assert_eq!(receipts[0].status, TxStatus::Success, "subject DID create should succeed");

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
        let receipts = execute_block(&store, &[tx_issue], 3, &treasury_addr, &[])
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
            solidus_txns::types::Event::CredentialIssued { credential_id, .. } => credential_id.clone(),
            other => panic!("expected CredentialIssued event, got: {:?}", other),
        };

        // Verify credential is stored.
        let stored = load_credential(&store, &credential_id)
            .expect("load_credential failed")
            .expect("credential should be stored");

        assert_eq!(stored.id, credential_id);
        assert!(!stored.revoked, "credential should not be revoked");
        assert_eq!(stored.credential_type, solidus_txns::credential::CredentialType::Email);
        assert_eq!(stored.hash, hash);

        // Verify secondary indexes.
        let issuer_did = solidus_txns::did::build_did("testnet", &issuer_addr);
        let by_subject = load_credential_ids(&store, CF_CRED_BY_SUBJECT, &subject_did)
            .expect("load by subject failed");
        assert!(by_subject.contains(&credential_id), "subject index should contain credential");

        let by_issuer = load_credential_ids(&store, CF_CRED_BY_ISSUER, &issuer_did)
            .expect("load by issuer failed");
        assert!(by_issuer.contains(&credential_id), "issuer index should contain credential");
    }

    #[test]
    fn credential_revoke_via_executor() {
        let (store, _dir) = open_tmp();

        let issuer_key = generate_signing_key();
        let subject_key = generate_signing_key();

        let issuer_addr = Address::from_public_key(&issuer_key.verifying_key());
        let subject_addr = Address::from_public_key(&subject_key.verifying_key());

        // Fund accounts.
        fund_account(&store, issuer_addr, 100_000_000);
        fund_account(&store, subject_addr, 1_000_000);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        // Create issuer DID.
        let tx_issuer_did = make_did_create_tx(&issuer_key, 0);
        execute_block(&store, &[tx_issuer_did], 1, &treasury_addr, &[])
            .expect("issuer DidCreate failed");

        // Create subject DID.
        let tx_subject_did = make_did_create_tx(&subject_key, 0);
        execute_block(&store, &[tx_subject_did], 2, &treasury_addr, &[])
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
        let receipts = execute_block(&store, &[tx_issue], 3, &treasury_addr, &[])
            .expect("CredentialIssue failed");
        assert_eq!(receipts[0].status, TxStatus::Success);

        let credential_id = match &receipts[0].events[0] {
            solidus_txns::types::Event::CredentialIssued { credential_id, .. } => credential_id.clone(),
            other => panic!("expected CredentialIssued event, got: {:?}", other),
        };

        // Revoke the credential (issuer nonce=2).
        let tx_revoke = make_credential_revoke_tx(&issuer_key, credential_id.clone(), 2);
        let receipts = execute_block(&store, &[tx_revoke], 4, &treasury_addr, &[])
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

        // Fund with 200_000 SOLID (in smallest units: 200_000 * ONE_SOLID).
        // MIN_STAKE = 100_000_000_000 = 1000 SOLID.
        // We use MIN_STAKE directly as the stake amount, and fund with 2 * MIN_STAKE.
        use solidus_txns::staking::MIN_STAKE;
        use solidus_txns::types::FEE_STAKE;
        let initial_balance = MIN_STAKE * 2 + FEE_STAKE;
        fund_account(&store, sender_addr, initial_balance);

        let treasury_addr = Address::from_bytes([0xAAu8; 20]);

        let tx = make_stake_tx(&sender_key, MIN_STAKE, 0);
        let receipts = execute_block(&store, &[tx], 1, &treasury_addr, &[])
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
            Event::Staked { validator, amount, total_stake } => {
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
        let receipts = execute_block(&store, &[tx_stake], 1, &treasury_addr, &[])
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
        let receipts = execute_block(&store, &[tx_unstake], 2, &treasury_addr, &[])
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
            Event::Unstaked { validator, amount, remaining_stake } => {
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
        assert!(!info.active, "validator should be inactive after full unstake");
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
        execute_block(&store, &[tx], 1, &treasury_addr, &[])
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
}
