//! Length-prefixed input layout for the identity precompiles.
//!
//! Solidity callers assemble inputs with `abi.encodePacked(...)` — every
//! field is `[u32 big-endian length][bytes]` after a fixed 32-byte
//! claimed-root prefix. No Solidity-side bincode is ever required: the
//! SMT proof and BBS proof travel as opaque `bytes` blobs produced
//! off-chain by the SDK.

use crate::PrecompileFailure;

pub struct InputReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> InputReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_root(&mut self) -> Result<[u8; 32], PrecompileFailure> {
        let bytes = self.take(32)?;
        let mut root = [0u8; 32];
        root.copy_from_slice(bytes);
        Ok(root)
    }

    /// Read a `[u32 BE length][bytes]` field with a sanity cap.
    pub fn read_field(&mut self, max_len: usize) -> Result<&'a [u8], PrecompileFailure> {
        let len_bytes = self.take(4)?;
        #[allow(clippy::expect_used)]
        let len = u32::from_be_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
        if len > max_len {
            return Err(PrecompileFailure::Malformed(format!(
                "field length {len} exceeds cap {max_len}"
            )));
        }
        self.take(len)
    }

    pub fn read_u32(&mut self) -> Result<u32, PrecompileFailure> {
        let bytes = self.take(4)?;
        #[allow(clippy::expect_used)]
        Ok(u32::from_be_bytes(bytes.try_into().expect("4 bytes")))
    }

    /// All input must be consumed — trailing garbage is malformed.
    pub fn finish(&self) -> Result<(), PrecompileFailure> {
        if self.pos != self.data.len() {
            return Err(PrecompileFailure::Malformed(format!(
                "{} trailing bytes",
                self.data.len() - self.pos
            )));
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PrecompileFailure> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| PrecompileFailure::Malformed("length overflow".into()))?;
        if end > self.data.len() {
            return Err(PrecompileFailure::Malformed("input truncated".into()));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}

/// EVM-ABI boolean word: 31 zero bytes + 0/1.
pub fn bool_word(value: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = value as u8;
    word
}

/// Builder used by tests and the SDK to assemble precompile inputs.
#[derive(Default)]
pub struct InputBuilder {
    buf: Vec<u8>,
}

impl InputBuilder {
    pub fn new(claimed_root: &[u8; 32]) -> Self {
        Self {
            buf: claimed_root.to_vec(),
        }
    }

    pub fn field(mut self, bytes: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    pub fn u32(mut self, v: u32) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}
