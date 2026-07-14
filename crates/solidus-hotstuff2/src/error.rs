/// Errors produced by the HotStuff-2 core. Anything reachable from
/// network input returns an error (or is silently ignored where the
/// protocol says so) — never panics.
#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
    #[error("message from unknown validator index {0}")]
    UnknownValidator(u32),

    #[error("invalid signature from validator {0}")]
    InvalidSignature(u32),

    #[error("quorum cert invalid: {0}")]
    InvalidQc(String),

    #[error("timeout cert invalid: {0}")]
    InvalidTc(String),

    #[error("proposal invalid: {0}")]
    InvalidProposal(String),

    #[error("bls error: {0}")]
    Bls(#[from] solidus_crypto::bls::BlsError),
}
