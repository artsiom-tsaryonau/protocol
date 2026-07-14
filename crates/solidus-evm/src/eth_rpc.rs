//! Minimal ETH-style JSON-RPC edge over the EVM subnet (§4.8 — "ETH-style
//! hashes + JSON-RPC for MetaMask/ethers/hardhat/foundry").
//!
//! **Scope (honest):** this ships the **read + `eth_call`** surface — the
//! path a dApp / verifier uses to query the identity precompiles as *view*
//! calls (`isDidActive` / `verifyCredential` / `verifyBbsDisclosure`), the
//! chain-metadata methods MetaMask/ethers probe on connect, **and
//! `eth_sendRawTransaction`**: a raw legacy (EIP-155) or EIP-1559 tx is
//! RLP-decoded, its sender is secp256k1-recovered ([`crate::raw_tx`]), and it
//! is executed against the subnet under revm with nonce + chain-id checks,
//! returning the ETH tx hash. Decode + recovery are validated against
//! `cast`-generated known-answer vectors, and a foundry-signed ERC-20
//! `transfer` moves balance end-to-end (see tests). **Not yet modelled** (a
//! founder follow-up, and it does NOT gate the L1): a persistent mempool +
//! receipt store + block production — `submit_raw` executes immediately
//! against the current bridged state rather than sequencing into blocks; and
//! a real gas/fee market (gas is metered but priced 0).
//!
//! Methods: `eth_chainId` · `net_version` · `web3_clientVersion` ·
//! `eth_blockNumber` · `eth_call` · `eth_sendRawTransaction`.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::codec::InputBuilder;
use crate::subnet::EvmSubnet;
use revm::primitives::Address as EvmAddress;

/// The subnet, shared behind a lock for the RPC handlers.
pub type SharedSubnet = Arc<Mutex<EvmSubnet>>;

/// An ETH-RPC-level error.
#[derive(thiserror::Error, Debug)]
pub enum EthRpcError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("execution reverted: {0}")]
    Reverted(String),
    #[error("not supported: {0}")]
    Unsupported(String),
}

fn hex_quantity(n: u64) -> Value {
    json!(format!("0x{n:x}"))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, EthRpcError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|_| EthRpcError::InvalidParams(format!("bad hex: {s}")))
}

fn parse_address_20(s: &str) -> Result<EvmAddress, EthRpcError> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 20 {
        return Err(EthRpcError::InvalidParams(
            "address must be 20 bytes".into(),
        ));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&bytes);
    Ok(EvmAddress::from(a))
}

// ---------------------------------------------------------------------------
// Handlers (pure over the shared subnet)
// ---------------------------------------------------------------------------

/// `eth_chainId` → `0x<hex chain id>`.
pub fn eth_chain_id(subnet: &SharedSubnet) -> Value {
    #[allow(clippy::expect_used)]
    let id = subnet.lock().expect("subnet lock").chain_id_or_default();
    hex_quantity(id)
}

/// `net_version` → decimal chain-id string.
pub fn net_version(subnet: &SharedSubnet) -> Value {
    #[allow(clippy::expect_used)]
    let id = subnet.lock().expect("subnet lock").chain_id_or_default();
    json!(id.to_string())
}

/// `web3_clientVersion`.
pub fn web3_client_version() -> Value {
    json!("solidus-evm/v2")
}

/// `eth_blockNumber` → the latest L1 height bridged to the subnet (the
/// subnet's identity view advances with L1), or 0 if none delivered yet.
pub fn eth_block_number(subnet: &SharedSubnet) -> Value {
    #[allow(clippy::expect_used)]
    let h = subnet
        .lock()
        .expect("subnet lock")
        .latest_l1_height_or_zero();
    hex_quantity(h)
}

/// `eth_call` — a view call. Params: `[{to, data}, block]`. Routes to the
/// subnet's EVM execution (which includes the identity precompiles), so a
/// contract's `STATICCALL` to a precompile address returns its 32-byte
/// bool word as `0x`-hex.
pub fn eth_call(subnet: &SharedSubnet, params: &Value) -> Result<Value, EthRpcError> {
    let call = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_object())
        .ok_or_else(|| EthRpcError::InvalidParams("expected [{to,data}, block]".into()))?;

    let to = call
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or_else(|| EthRpcError::InvalidParams("missing 'to'".into()))?;
    let to = parse_address_20(to)?;
    let data = match call.get("data").or_else(|| call.get("input")) {
        Some(Value::String(s)) => parse_hex_bytes(s)?,
        _ => Vec::new(),
    };

    #[allow(clippy::expect_used)]
    let result = subnet.lock().expect("subnet lock").call(to, data);
    match result {
        Ok(bytes) => Ok(json!(format!("0x{}", hex::encode(bytes)))),
        Err(e) => Err(EthRpcError::Reverted(format!("{e:?}"))),
    }
}

/// `eth_sendRawTransaction` — decode a raw signed tx (legacy or EIP-1559),
/// recover its sender, execute it against the subnet, and return the ETH tx
/// hash (`0x…`). Params: `["0x<rlp bytes>"]`.
pub fn eth_send_raw_transaction(
    subnet: &SharedSubnet,
    params: &Value,
) -> Result<Value, EthRpcError> {
    let raw_hex = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| EthRpcError::InvalidParams("expected [\"0x<raw tx>\"]".into()))?;
    let raw = parse_hex_bytes(raw_hex)?;

    let tx = crate::raw_tx::decode(&raw)
        .map_err(|e| EthRpcError::InvalidParams(format!("decode: {e}")))?;

    #[allow(clippy::expect_used)]
    let result = subnet.lock().expect("subnet lock").submit_raw(&tx);
    match result {
        Ok(tx_hash) => Ok(json!(format!("0x{}", hex::encode(tx_hash)))),
        Err(e) => Err(EthRpcError::Reverted(format!("{e:?}"))),
    }
}

/// Build an `eth_call` input for one of the identity precompiles the way a
/// client SDK would (helper for tests + the SDK).
pub fn encode_precompile_call(claimed_root: &[u8; 32], fields: &[&[u8]]) -> Vec<u8> {
    let mut b = InputBuilder::new(claimed_root);
    for f in fields {
        b = b.field(f);
    }
    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::ADDR_IS_DID_ACTIVE;
    use crate::subnet::precompile_address;
    use solidus_state_tree::{StateForest, TreeId};
    use solidus_subnet::{L1FinalizedRoots, Subnet};

    fn did_doc(active: bool) -> Vec<u8> {
        let mut doc = solidus_txns::did::build_did_document(
            "did:solidus:v2:rpc",
            &hex::encode([5u8; 32]),
            vec![],
            1_000,
        );
        doc.active = active;
        doc.to_bytes()
    }

    fn subnet_with_did(active: bool) -> (SharedSubnet, [u8; 32], Vec<u8>, Vec<u8>) {
        let mut forest = StateForest::new();
        let did = b"did:solidus:v2:rpc".to_vec();
        let doc = did_doc(active);
        forest.apply(TreeId::Dids, &did, &doc);
        let dids_root = forest.subtree_root(TreeId::Dids);
        let proof = forest.prove(TreeId::Dids, &did).expect("leaf");

        let mut subnet = EvmSubnet::new(7);
        subnet
            .on_l1_finalized(L1FinalizedRoots {
                l1_height: 42,
                global_root: forest.global_root(),
                accounts_root: forest.subtree_root(TreeId::Accounts),
                dids_root,
                credentials_root: forest.subtree_root(TreeId::Credentials),
                validators_root: forest.subtree_root(TreeId::Validators),
                commit_qc: vec![],
            })
            .expect("roots");

        let input = encode_precompile_call(
            &dids_root,
            &[&did, &doc, &bincode::serialize(&proof).expect("proof")],
        );
        (Arc::new(Mutex::new(subnet)), dids_root, did, input)
    }

    #[test]
    fn metadata_methods() {
        let (subnet, ..) = subnet_with_did(true);
        assert_eq!(eth_chain_id(&subnet), json!("0x7"));
        assert_eq!(net_version(&subnet), json!("7"));
        assert_eq!(web3_client_version(), json!("solidus-evm/v2"));
        assert_eq!(eth_block_number(&subnet), json!("0x2a")); // 42
    }

    #[test]
    fn eth_call_isdidactive_returns_true_word() {
        let (subnet, _root, _did, input) = subnet_with_did(true);
        let params = json!([{
            "to": format!("0x{}", hex::encode(precompile_address(ADDR_IS_DID_ACTIVE))),
            "data": format!("0x{}", hex::encode(&input)),
        }, "latest"]);
        let out = eth_call(&subnet, &params).expect("eth_call");
        // 32-byte EVM bool word = true.
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(out, json!(format!("0x{}", hex::encode(expected))));
    }

    #[test]
    fn eth_call_isdidactive_returns_false_for_inactive() {
        let (subnet, _root, _did, input) = subnet_with_did(false);
        let params = json!([{
            "to": format!("0x{}", hex::encode(precompile_address(ADDR_IS_DID_ACTIVE))),
            "data": format!("0x{}", hex::encode(&input)),
        }]);
        let out = eth_call(&subnet, &params).expect("eth_call");
        assert_eq!(out, json!(format!("0x{}", hex::encode([0u8; 32]))));
    }

    #[test]
    fn eth_call_and_sendraw_bad_params_rejected() {
        let (subnet, ..) = subnet_with_did(true);
        assert!(matches!(
            eth_call(&subnet, &json!([])),
            Err(EthRpcError::InvalidParams(_))
        ));
        // Missing param.
        assert!(matches!(
            eth_send_raw_transaction(&subnet, &json!([])),
            Err(EthRpcError::InvalidParams(_))
        ));
        // Undecodable raw tx → InvalidParams (not a wrong result / panic).
        assert!(matches!(
            eth_send_raw_transaction(&subnet, &json!(["0xdeadbeef"])),
            Err(EthRpcError::InvalidParams(_))
        ));
    }

    // ------- eth_sendRawTransaction end-to-end (foundry-signed ERC-20) -------

    const ERC20_CREATION_HEX: &str = include_str!("../tests/fixtures/erc20_token.creation.hex");

    /// `cast`-signed legacy tx (foundry 1.7.1): from 0x9d8A…, to the token at
    /// 0x8620…13E9 (= CREATE from the 0xC0… deployer at nonce 0), nonce 0,
    /// `transfer(0xB0*20, 250000)`, chain 7.
    const SIGNED_TRANSFER_HEX: &str = "f8a980843b9aca00830186a0948620d3253c8741eff5b5c9e5b181bb14845b13e980b844a9059cbb000000000000000000000000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000000000000000000000000000000000000000000000000003d09032a00ad6c679cda9bc2ea362a1500317e7ae2974bb6ba96c07f92cdcf173072cfdc5a07ab5836015bfe6f950d47dfee08824d906fefab68d508bb24a636f744e68aab0";

    fn u256_word(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }
    fn addr_word(a: [u8; 20]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    }
    fn balance_of_calldata(who: [u8; 20]) -> Vec<u8> {
        let mut c = vec![0x70, 0xa0, 0x82, 0x31];
        c.extend_from_slice(&addr_word(who));
        c
    }
    fn transfer_calldata(to: [u8; 20], amt: u128) -> Vec<u8> {
        let mut c = vec![0xa9, 0x05, 0x9c, 0xbb];
        c.extend_from_slice(&addr_word(to));
        c.extend_from_slice(&u256_word(amt));
        c
    }
    fn read_u128(w: &[u8]) -> u128 {
        let mut b = [0u8; 16];
        b.copy_from_slice(&w[16..]);
        u128::from_be_bytes(b)
    }

    #[test]
    fn eth_send_raw_transaction_runs_signed_erc20_transfer() {
        // subnet_with_did builds EvmSubnet::new(7) — chain id 7 matches the
        // signed vector's chain, so revm's chain-id check passes.
        let (subnet, ..) = subnet_with_did(true);
        let sender: [u8; 20] = [
            0x9d, 0x8A, 0x62, 0xf6, 0x56, 0xa8, 0xd1, 0x61, 0x5C, 0x12, 0x94, 0xfd, 0x71, 0xe9,
            0xCF, 0xb3, 0xE4, 0x85, 0x5A, 0x4F,
        ];
        let bob: [u8; 20] = [0xB0; 20];

        let raw = hex::decode(SIGNED_TRANSFER_HEX).unwrap();
        let decoded = crate::raw_tx::decode(&raw).unwrap();
        let token_target = EvmAddress::from(decoded.to.unwrap());

        // Deploy the ERC-20 (deployer = internal caller at nonce 0) and prove
        // its CREATE address equals the address the signed tx targets.
        let creation = hex::decode(ERC20_CREATION_HEX.trim()).unwrap();
        let mut init = creation;
        init.extend_from_slice(&u256_word(1_000_000_000));
        let token = subnet.lock().unwrap().deploy(init).expect("deploy erc20");
        assert_eq!(
            token, token_target,
            "deterministic CREATE address matches the signed tx's `to`"
        );

        // Seed the signer with tokens (internal caller holds total supply).
        subnet
            .lock()
            .unwrap()
            .execute(token, transfer_calldata(sender, 1_000_000))
            .expect("seed signer");

        // Submit the foundry-signed transfer through the RPC handler.
        let out = eth_send_raw_transaction(&subnet, &json!([format!("0x{SIGNED_TRANSFER_HEX}")]))
            .expect("sendRawTransaction");
        assert_eq!(
            out,
            json!(format!("0x{}", hex::encode(decoded.tx_hash))),
            "returns the ETH tx hash"
        );

        // Balances moved by the SIGNED tx: bob credited, signer debited.
        let bal = |who: [u8; 20]| -> u128 {
            read_u128(
                &subnet
                    .lock()
                    .unwrap()
                    .call(token, balance_of_calldata(who))
                    .unwrap(),
            )
        };
        assert_eq!(bal(bob), 250_000, "bob credited by the signed transfer");
        assert_eq!(
            bal(sender),
            750_000,
            "signer debited by the signed transfer"
        );
    }
}
