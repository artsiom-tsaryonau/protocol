use solidus_crypto::keys::Address;
use solidus_txns::token::execute_transfer;
use solidus_txns::types::{Receipt, Transaction, TxPayload, TxStatus};

use crate::account::Account;
use crate::store::{Store, StoreError, CF_ACCOUNTS, CF_RECEIPTS};

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
}
