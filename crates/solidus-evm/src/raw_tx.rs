//! Raw Ethereum transaction decode + secp256k1 sender recovery — the front
//! half of `eth_sendRawTransaction`. Supports **legacy (EIP-155)** and
//! **EIP-1559 (type-0x02)** envelopes, the two ethers/MetaMask emit by
//! default. Type-1 (2930), type-3 (4844 blob) and type-4 (7702) return a
//! clear "unsupported type" error rather than a wrong result.
//!
//! Design: RLP framing is decoded with `alloy-rlp` and each top-level field's
//! *raw encoded bytes* are captured, so the signing-hash preimage is rebuilt
//! by concatenating original field bytes (for 1559 the access-list is copied
//! verbatim — never semantically re-encoded) under a fresh list header. ECDSA
//! recovery is delegated to `alloy-primitives` (k256), which is the audited
//! part; only the RLP framing is ours, and the cast-generated known-answer
//! tests pin it to real-Ethereum behaviour.

use alloy_primitives::{keccak256, PrimitiveSignature, B256, U256};
use alloy_rlp::{Decodable, Encodable, Header};

/// A decoded, sender-recovered transaction — the minimum the subnet needs to
/// re-execute it under revm.
#[derive(Clone, Debug)]
pub struct DecodedTx {
    /// Recovered signer (the `msg.sender` / gas payer).
    pub sender: [u8; 20],
    /// Call target, or `None` for a contract-creation tx.
    pub to: Option<[u8; 20]>,
    /// Native value moved.
    pub value: U256,
    /// Calldata / init code.
    pub data: Vec<u8>,
    /// Sender nonce (revm checks this against the account).
    pub nonce: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// EIP-155 chain id (`None` only for pre-155 legacy txs).
    pub chain_id: Option<u64>,
    /// keccak256 of the full raw tx bytes — the ETH tx hash.
    pub tx_hash: [u8; 32],
}

/// Errors decoding or recovering a raw transaction.
#[derive(thiserror::Error, Debug)]
pub enum RawTxError {
    #[error("empty transaction")]
    Empty,
    #[error("unsupported transaction type 0x{0:02x}")]
    UnsupportedType(u8),
    #[error("rlp decode error: {0}")]
    Rlp(String),
    #[error("malformed field: {0}")]
    Field(&'static str),
    #[error("signature recovery failed")]
    Recovery,
}

fn rlp_err(e: alloy_rlp::Error) -> RawTxError {
    RawTxError::Rlp(e.to_string())
}

/// Read exactly `n` top-level RLP items from `buf`, returning each item's
/// **full raw encoding** (header + payload). A nested list (e.g. the 1559
/// access-list) is returned as one opaque slice — exactly the bytes needed to
/// reproduce the signing preimage without re-encoding it.
fn read_raw_items<'a>(buf: &mut &'a [u8], n: usize) -> Result<Vec<&'a [u8]>, RawTxError> {
    let mut items = Vec::with_capacity(n);
    for _ in 0..n {
        let start: &[u8] = buf;
        let header = Header::decode(buf).map_err(rlp_err)?;
        if buf.len() < header.payload_length {
            return Err(RawTxError::Field("item payload runs past end"));
        }
        *buf = &buf[header.payload_length..];
        let consumed = start.len() - buf.len();
        items.push(&start[..consumed]);
    }
    Ok(items)
}

fn decode_u64(item: &[u8]) -> Result<u64, RawTxError> {
    let mut s = item;
    u64::decode(&mut s).map_err(rlp_err)
}

fn decode_u256(item: &[u8]) -> Result<U256, RawTxError> {
    let mut s = item;
    U256::decode(&mut s).map_err(rlp_err)
}

fn decode_bytes(item: &[u8]) -> Result<Vec<u8>, RawTxError> {
    let mut s = item;
    let b = alloy_primitives::Bytes::decode(&mut s).map_err(rlp_err)?;
    Ok(b.to_vec())
}

/// Decode a `to` field: empty RLP string ⇒ contract creation (`None`);
/// 20-byte string ⇒ the address.
fn decode_to(item: &[u8]) -> Result<Option<[u8; 20]>, RawTxError> {
    let b = decode_bytes(item)?;
    match b.len() {
        0 => Ok(None),
        20 => {
            let mut a = [0u8; 20];
            a.copy_from_slice(&b);
            Ok(Some(a))
        }
        _ => Err(RawTxError::Field("to must be 0 or 20 bytes")),
    }
}

/// keccak256 over a freshly-framed RLP list whose payload is `payload`.
fn list_hash(prefix: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(prefix.len() + 9 + payload.len());
    preimage.extend_from_slice(prefix);
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut preimage);
    preimage.extend_from_slice(payload);
    keccak256(&preimage).into()
}

fn recover(sighash: [u8; 32], r: U256, s: U256, y_parity: bool) -> Result<[u8; 20], RawTxError> {
    // Raw y-parity (the recovery id already extracted from v / yParity) — no
    // EIP-155 chain adjustment here, the prehash is the final signing hash.
    let sig = PrimitiveSignature::new(r, s, y_parity);
    let addr = sig
        .recover_address_from_prehash(&B256::from(sighash))
        .map_err(|_| RawTxError::Recovery)?;
    Ok(addr.into())
}

/// Decode a raw signed transaction and recover its sender.
pub fn decode(raw: &[u8]) -> Result<DecodedTx, RawTxError> {
    match raw.first().copied() {
        None => Err(RawTxError::Empty),
        // A list header (>= 0xc0) ⇒ legacy (untyped) transaction.
        Some(b) if b >= 0xc0 => decode_legacy(raw),
        Some(0x02) => decode_1559(raw),
        Some(t) => Err(RawTxError::UnsupportedType(t)),
    }
}

/// Legacy EIP-155: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`.
/// Signing preimage = `rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])`.
fn decode_legacy(raw: &[u8]) -> Result<DecodedTx, RawTxError> {
    let mut buf: &[u8] = raw;
    let outer = Header::decode(&mut buf).map_err(rlp_err)?;
    if !outer.list {
        return Err(RawTxError::Field("legacy tx is not an RLP list"));
    }
    let items = read_raw_items(&mut buf, 9)?;

    let nonce = decode_u64(items[0])?;
    let gas_limit = decode_u64(items[2])?;
    let to = decode_to(items[3])?;
    let value = decode_u256(items[4])?;
    let data = decode_bytes(items[5])?;
    let v = decode_u64(items[6])?;
    let r = decode_u256(items[7])?;
    let s = decode_u256(items[8])?;

    // EIP-155: v = recid + 35 + 2*chainId. Pre-155: v ∈ {27, 28}.
    let (chain_id, recid) = if v >= 35 {
        let cid = (v - 35) / 2;
        (Some(cid), ((v - 35) % 2) as u8)
    } else if v == 27 || v == 28 {
        (None, (v - 27) as u8)
    } else {
        return Err(RawTxError::Field("invalid legacy v"));
    };

    // Signing preimage: first 6 raw fields ++ chainId ++ 0x80 ++ 0x80.
    let sighash = if let Some(cid) = chain_id {
        let mut payload = Vec::new();
        for it in &items[0..6] {
            payload.extend_from_slice(it);
        }
        cid.encode(&mut payload);
        payload.push(0x80); // RLP(0) = empty string
        payload.push(0x80);
        list_hash(&[], &payload)
    } else {
        let mut payload = Vec::new();
        for it in &items[0..6] {
            payload.extend_from_slice(it);
        }
        list_hash(&[], &payload)
    };

    let sender = recover(sighash, r, s, recid == 1)?;
    Ok(DecodedTx {
        sender,
        to,
        value,
        data,
        nonce,
        gas_limit,
        chain_id,
        tx_hash: keccak256(raw).into(),
    })
}

/// EIP-1559 (type 0x02): `0x02 || rlp([chainId, nonce, maxPrio, maxFee,
/// gasLimit, to, value, data, accessList, yParity, r, s])`. Signing preimage =
/// `0x02 || rlp([chainId … accessList])` (the first 9 fields).
fn decode_1559(raw: &[u8]) -> Result<DecodedTx, RawTxError> {
    let mut buf: &[u8] = &raw[1..];
    let outer = Header::decode(&mut buf).map_err(rlp_err)?;
    if !outer.list {
        return Err(RawTxError::Field("1559 body is not an RLP list"));
    }
    let items = read_raw_items(&mut buf, 12)?;

    let chain_id = decode_u64(items[0])?;
    let nonce = decode_u64(items[1])?;
    let gas_limit = decode_u64(items[4])?;
    let to = decode_to(items[5])?;
    let value = decode_u256(items[6])?;
    let data = decode_bytes(items[7])?;
    let y_parity = decode_u64(items[9])?;
    let r = decode_u256(items[10])?;
    let s = decode_u256(items[11])?;

    // Preimage: 0x02 ++ rlp(items[0..9]) — access-list bytes copied verbatim.
    let mut payload = Vec::new();
    for it in &items[0..9] {
        payload.extend_from_slice(it);
    }
    let sighash = list_hash(&[0x02], &payload);

    let sender = recover(sighash, r, s, y_parity == 1)?;
    Ok(DecodedTx {
        sender,
        to,
        value,
        data,
        nonce,
        gas_limit,
        chain_id: Some(chain_id),
        tx_hash: keccak256(raw).into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sender of every vector below — private key 0x46…46, per `cast wallet
    // address` (= the canonical EIP-155 example address).
    const SENDER: [u8; 20] = [
        0x9d, 0x8A, 0x62, 0xf6, 0x56, 0xa8, 0xd1, 0x61, 0x5C, 0x12, 0x94, 0xfd, 0x71, 0xe9, 0xCF,
        0xb3, 0xE4, 0x85, 0x5A, 0x4F,
    ];

    fn addr20(hex_str: &str) -> [u8; 20] {
        let b = hex::decode(hex_str).unwrap();
        let mut a = [0u8; 20];
        a.copy_from_slice(&b);
        a
    }

    // Known-answer vectors produced offline by `cast mktx` (foundry 1.7.1),
    // chain id 7. If the RLP framing / signing-hash / recovery is wrong, the
    // recovered sender will not equal SENDER and these fail loudly.

    #[test]
    fn legacy_eip155_recovers_cast_sender() {
        // nonce 0, gasPrice 1 gwei, gas 21000, to 0x35*20, value 0, no data.
        let raw = hex::decode(
            "f86380843b9aca00825208943535353535353535353535353535353535353535808032a0\
             dfba5ce6d46fc859ae28a5036bd84d10ac7290c4b11d48f3111eeda4069c3238a0412f55\
             67bc5de9d4eac006e05ce6041766630d0daa30fdc78167e91a7b175da0",
        )
        .unwrap();
        let tx = decode(&raw).expect("decode legacy");
        assert_eq!(tx.sender, SENDER, "recovered sender matches cast");
        assert_eq!(
            tx.to,
            Some(addr20("3535353535353535353535353535353535353535"))
        );
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.value, U256::ZERO);
        assert_eq!(tx.chain_id, Some(7));
        assert!(tx.data.is_empty());
    }

    #[test]
    fn eip1559_recovers_cast_sender() {
        // type 2, nonce 5, gas 50000, to 0x35*20, value 100, data =
        // transfer(0xB0*20, 100), non-empty access list absent.
        let raw = hex::decode(
            "02f8af0705843b9aca00847735940082c350943535353535353535353535353535353535\
             35353564b844a9059cbb000000000000000000000000b0b0b0b0b0b0b0b0b0b0b0b0b0b0\
             b0b0b0b0b0b00000000000000000000000000000000000000000000000000000000000000\
             064c001a0233a216e12a1157b89ceb29c2ff692bbd03214b1d3a4e00734867dad0558733\
             4a07b483f71b394d02809e33da65807c5f1c901f95c371ecc718003f1559e5e218c",
        )
        .unwrap();
        let tx = decode(&raw).expect("decode 1559");
        assert_eq!(tx.sender, SENDER, "recovered sender matches cast");
        assert_eq!(
            tx.to,
            Some(addr20("3535353535353535353535353535353535353535"))
        );
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.value, U256::from(100));
        assert_eq!(tx.chain_id, Some(7));
        assert_eq!(&tx.data[0..4], &[0xa9, 0x05, 0x9c, 0xbb]); // transfer selector
    }

    #[test]
    fn unsupported_type_rejected() {
        // type 0x03 (blob) — not supported.
        let raw = vec![0x03, 0xc0];
        assert!(matches!(
            decode(&raw),
            Err(RawTxError::UnsupportedType(0x03))
        ));
        assert!(matches!(decode(&[]), Err(RawTxError::Empty)));
    }

    #[test]
    fn garbage_does_not_panic() {
        for len in 0..40usize {
            let junk: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let _ = decode(&junk); // must return Err, never panic
        }
    }
}
