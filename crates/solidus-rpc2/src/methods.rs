//! Pure JSON-RPC method handlers — parse params, call the backend, shape
//! JSON. No transport, no async: directly unit-testable.
//!
//! Wire conventions at the JSON boundary:
//! - addresses: base58 string (matches `Address::to_base58`)
//! - hashes / roots: lowercase hex string
//! - a submitted transaction: hex of its **bincode** encoding (R-WIRE —
//!   the v2 binary format; the client SDK bincodes and hex-wraps).

use serde_json::{json, Value};
use solidus_crypto::keys::Address;
use solidus_txns::types::{Receipt, Transaction, TxStatus};

use crate::backend::RpcBackend;

/// A JSON-RPC-level error (bad params / not found / rejected submit).
#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("not found")]
    NotFound,
    #[error("submit rejected: {0}")]
    SubmitRejected(String),
}

fn param_str(params: &Value, idx: usize, name: &str) -> Result<String, RpcError> {
    // Accept both positional [..] and by-name {..} params.
    let v = if let Some(arr) = params.as_array() {
        arr.get(idx).cloned()
    } else if let Some(obj) = params.as_object() {
        obj.get(name).cloned()
    } else {
        None
    };
    match v {
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(RpcError::InvalidParams(format!("{name} must be a string"))),
        None => Err(RpcError::InvalidParams(format!("missing param {name}"))),
    }
}

fn param_u64(params: &Value, idx: usize, name: &str) -> Result<u64, RpcError> {
    let v = if let Some(arr) = params.as_array() {
        arr.get(idx).cloned()
    } else if let Some(obj) = params.as_object() {
        obj.get(name).cloned()
    } else {
        None
    };
    match v {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| RpcError::InvalidParams(format!("{name} must be a u64"))),
        Some(Value::String(s)) => s
            .parse()
            .map_err(|_| RpcError::InvalidParams(format!("{name} must be a u64"))),
        _ => Err(RpcError::InvalidParams(format!("missing param {name}"))),
    }
}

fn parse_address(s: &str) -> Result<Address, RpcError> {
    Address::from_base58(s).map_err(|_| RpcError::InvalidParams(format!("bad address: {s}")))
}

fn parse_hash(s: &str) -> Result<[u8; 32], RpcError> {
    let bytes = hex::decode(s).map_err(|_| RpcError::InvalidParams("bad hex hash".into()))?;
    bytes
        .try_into()
        .map_err(|_| RpcError::InvalidParams("hash must be 32 bytes".into()))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub fn get_balance(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let addr = parse_address(&param_str(params, 0, "address")?)?;
    Ok(json!(backend.balance(&addr).to_string()))
}

pub fn get_nonce(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let addr = parse_address(&param_str(params, 0, "address")?)?;
    Ok(json!(backend.nonce(&addr)))
}

pub fn get_block_height(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    Ok(json!(backend.block_height()))
}

pub fn get_state_root(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    Ok(json!(hex::encode(backend.state_root())))
}

pub fn get_receipt(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let height = param_u64(params, 0, "height")?;
    let tx_hash = parse_hash(&param_str(params, 1, "txHash")?)?;
    let receipt = backend
        .receipt(height, &tx_hash)
        .ok_or(RpcError::NotFound)?;
    Ok(receipt_to_json(&receipt))
}

pub fn submit_transaction(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let hex_tx = param_str(params, 0, "transaction")?;
    let bytes = hex::decode(&hex_tx)
        .map_err(|_| RpcError::InvalidParams("transaction must be hex".into()))?;
    let tx: Transaction = bincode::deserialize(&bytes)
        .map_err(|e| RpcError::InvalidParams(format!("undecodable transaction: {e}")))?;
    let tx_hash = backend.submit(tx).map_err(RpcError::SubmitRejected)?;
    Ok(json!(hex::encode(tx_hash)))
}

fn receipt_to_json(receipt: &Receipt) -> Value {
    let (status, reason) = match &receipt.status {
        TxStatus::Success => ("success", Value::Null),
        TxStatus::Failed(r) => ("failed", json!(r)),
    };
    json!({
        "txHash": hex::encode(receipt.tx_hash),
        "status": status,
        "failureReason": reason,
        "blockHeight": receipt.block_height,
        "feePaid": receipt.fee_paid.to_string(),
        "eventCount": receipt.events.len(),
    })
}

#[cfg(test)]
mod tests {
    use solidus_txns::types::Event;

    use super::*;

    struct StubBackend {
        balance: u64,
        nonce: u64,
        height: u64,
        root: [u8; 32],
        receipt: Option<Receipt>,
        submit_ok: bool,
    }

    impl RpcBackend for StubBackend {
        fn balance(&self, _a: &Address) -> u64 {
            self.balance
        }
        fn nonce(&self, _a: &Address) -> u64 {
            self.nonce
        }
        fn block_height(&self) -> u64 {
            self.height
        }
        fn state_root(&self) -> [u8; 32] {
            self.root
        }
        fn receipt(&self, _h: u64, _t: &[u8; 32]) -> Option<Receipt> {
            self.receipt.clone()
        }
        fn submit(&self, tx: Transaction) -> Result<[u8; 32], String> {
            if self.submit_ok {
                Ok(solidus_exec::wire::tx_hash(
                    &tx,
                    solidus_exec::WireMode::BinaryV2,
                ))
            } else {
                Err("mempool full".into())
            }
        }
    }

    fn stub() -> StubBackend {
        StubBackend {
            balance: 12_345,
            nonce: 7,
            height: 99,
            root: [0xAB; 32],
            receipt: Some(Receipt {
                tx_hash: [0x11; 32],
                status: TxStatus::Success,
                block_height: 42,
                fee_paid: 10_000,
                events: vec![Event::Transfer {
                    from: Address::from_bytes([1; 20]),
                    to: Address::from_bytes([2; 20]),
                    amount: 5,
                }],
            }),
            submit_ok: true,
        }
    }

    #[test]
    fn balance_nonce_height_root() {
        let b = stub();
        let addr = Address::from_bytes([9; 20]).to_base58();
        assert_eq!(
            get_balance(&b, &json!([addr])).unwrap(),
            json!("12345"),
            "balance is a decimal string (u64-safe for JS clients)"
        );
        assert_eq!(get_nonce(&b, &json!([addr])).unwrap(), json!(7));
        assert_eq!(get_block_height(&b, &json!([])).unwrap(), json!(99));
        assert_eq!(
            get_state_root(&b, &json!([])).unwrap(),
            json!(hex::encode([0xAB; 32]))
        );
    }

    #[test]
    fn by_name_params_also_work() {
        let b = stub();
        let addr = Address::from_bytes([9; 20]).to_base58();
        assert_eq!(
            get_balance(&b, &json!({ "address": addr })).unwrap(),
            json!("12345")
        );
    }

    #[test]
    fn bad_address_is_invalid_params() {
        let b = stub();
        assert!(matches!(
            get_balance(&b, &json!(["not-base58-!!!"])),
            Err(RpcError::InvalidParams(_))
        ));
        assert!(matches!(
            get_balance(&b, &json!([])),
            Err(RpcError::InvalidParams(_))
        ));
    }

    #[test]
    fn receipt_shape_and_not_found() {
        let b = stub();
        let out = get_receipt(&b, &json!([42, hex::encode([0x11; 32])])).unwrap();
        assert_eq!(out["status"], json!("success"));
        assert_eq!(out["feePaid"], json!("10000"));
        assert_eq!(out["eventCount"], json!(1));

        let mut missing = stub();
        missing.receipt = None;
        assert!(matches!(
            get_receipt(&missing, &json!([1, hex::encode([0; 32])])),
            Err(RpcError::NotFound)
        ));
    }

    #[test]
    fn submit_roundtrips_bincode_and_returns_hash() {
        use solidus_crypto::ed25519::{generate_signing_key, sign};
        use solidus_txns::types::TxPayload;

        let key = generate_signing_key();
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce: 0,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([3; 20]),
                amount: 100,
            },
            signature: [0u8; 64],
        };
        let msg = solidus_exec::wire::signing_bytes(&tx, solidus_exec::WireMode::BinaryV2);
        tx.signature = sign(&key, &msg);
        let hex_tx = hex::encode(bincode::serialize(&tx).unwrap());

        let b = stub();
        let out = submit_transaction(&b, &json!([hex_tx])).unwrap();
        let expected = hex::encode(solidus_exec::wire::tx_hash(
            &tx,
            solidus_exec::WireMode::BinaryV2,
        ));
        assert_eq!(out, json!(expected));

        let mut rejecting = stub();
        rejecting.submit_ok = false;
        assert!(matches!(
            submit_transaction(&rejecting, &json!([hex_tx])),
            Err(RpcError::SubmitRejected(_))
        ));

        // Garbage hex → invalid params.
        assert!(matches!(
            submit_transaction(&b, &json!(["zzzz"])),
            Err(RpcError::InvalidParams(_))
        ));
    }
}
