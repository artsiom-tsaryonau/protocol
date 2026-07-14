/// Errors produced by v2 block execution.
///
/// Note the deliberate split: a *transaction* that fails validation
/// (bad signature, wrong nonce, insufficient balance, handler rejection)
/// is **not** an error — it produces a `Failed` receipt, exactly like the
/// live chain. `ExecError` is reserved for infrastructure faults (store
/// read failure, corrupt record bytes) and protocol-invariant violations
/// (over-cap identity lane), where the block as a whole cannot execute.
#[derive(thiserror::Error, Debug)]
pub enum ExecError {
    /// Reading a key from the baseline state failed (I/O or backend fault).
    #[error("state read error: {0}")]
    StateRead(String),

    /// A stored record failed to deserialize (corrupt state).
    #[error("state decode error: {0}")]
    StateDecode(String),

    /// A write was attempted against a frozen delta (two-lane invariant
    /// violation — the identity delta is immutable once the payment lane
    /// starts).
    #[error("write to frozen delta ({0})")]
    FrozenDelta(String),

    /// The committed block carries more identity-lane transactions than
    /// the protocol cap allows. Such a block is invalid by construction
    /// (the proposer must defer overflow to the next block).
    #[error("identity lane cap exceeded: {count} > {cap}")]
    IdentityCapExceeded { count: usize, cap: usize },
}
