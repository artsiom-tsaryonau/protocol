//! Block delta accumulation and baseline state access.

use std::collections::BTreeMap;

use solidus_state_tree::StateForest;

use crate::error::ExecError;
use crate::types::{StateKey, StateSpace};

// ---------------------------------------------------------------------------
// StateReader — the baseline (pre-block, committed) state
// ---------------------------------------------------------------------------

/// Read-only access to the state a block executes on top of. Implemented by
/// the in-memory harness state today and by `solidus-store2` in Stage 4.
pub trait StateReader {
    /// Fetch the current value at `key`, or `None` if absent.
    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, ExecError>;
}

/// Simple in-memory baseline used by the reference executor's harnesses and
/// unit tests: a plain map, seeded at genesis, advanced by applying block
/// deltas.
#[derive(Default, Clone)]
pub struct InMemoryState {
    map: BTreeMap<StateKey, Vec<u8>>,
}

impl InMemoryState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Directly set a key (genesis seeding).
    pub fn set(&mut self, key: StateKey, value: Vec<u8>) {
        self.map.insert(key, value);
    }

    /// Fold a finalized block delta into the state (block commit).
    pub fn apply_delta(&mut self, delta: &DeltaSet) {
        for (k, v) in delta.iter() {
            self.map.insert(k.clone(), v.clone());
        }
    }

    /// Iterate every entry (harness comparisons).
    pub fn iter(&self) -> impl Iterator<Item = (&StateKey, &Vec<u8>)> {
        self.map.iter()
    }

    /// Seed a [`StateForest`] with every root-bearing entry, so incremental
    /// root computation can proceed from this baseline.
    pub fn seed_forest(&self, forest: &mut StateForest) {
        for (k, v) in &self.map {
            if let StateSpace::Tree(tree) = k.space {
                forest.apply(tree, &k.key, v);
            }
        }
    }
}

impl StateReader for InMemoryState {
    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, ExecError> {
        Ok(self.map.get(key).cloned())
    }
}

// ---------------------------------------------------------------------------
// DeltaSet — the block's write set
// ---------------------------------------------------------------------------

/// Accumulates every state write a block produces: `(space, key) → value`,
/// final-value semantics (later writes overwrite earlier ones). The
/// identity lane writes here directly; after [`DeltaSet::freeze`] it
/// becomes the immutable read baseline for the payment lane (Hazard-B
/// rule), and payment-lane writes are merged in afterwards.
#[derive(Debug, Default)]
pub struct DeltaSet {
    map: BTreeMap<StateKey, Vec<u8>>,
    frozen: bool,
}

impl DeltaSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a write. Fails if the delta is frozen — a two-lane invariant
    /// violation the executor treats as a hard error, never a receipt.
    pub fn insert(&mut self, key: StateKey, value: Vec<u8>) -> Result<(), ExecError> {
        if self.frozen {
            return Err(ExecError::FrozenDelta(format!("{:?}", key.space)));
        }
        self.map.insert(key, value);
        Ok(())
    }

    /// Read a value previously written this block.
    pub fn get(&self, key: &StateKey) -> Option<&Vec<u8>> {
        self.map.get(key)
    }

    /// Freeze the delta: no further writes may land (identity → payment
    /// lane handoff).
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Thaw after the payment lane finalizes so its writes can merge in.
    /// Only the executor pipeline calls this.
    #[allow(dead_code)] // wired by the Stage-3 two-lane pipeline; unit-tested below
    pub(crate) fn thaw(&mut self) {
        self.frozen = false;
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&StateKey, &Vec<u8>)> {
        self.map.iter()
    }

    /// Consume into the raw final map.
    pub fn into_map(self) -> BTreeMap<StateKey, Vec<u8>> {
        self.map
    }

    /// Apply every root-bearing entry to a [`StateForest`] (incremental
    /// O(touched · depth) root update — §5.5).
    pub fn apply_to_forest(&self, forest: &mut StateForest) {
        for (k, v) in &self.map {
            if let StateSpace::Tree(tree) = k.space {
                forest.apply(tree, &k.key, v);
            }
        }
    }
}

/// Read through the delta first, then the baseline — the visibility rule
/// for serial execution (a tx sees every earlier write in the block).
pub fn read_through<R: StateReader + ?Sized>(
    delta: &DeltaSet,
    baseline: &R,
    key: &StateKey,
) -> Result<Option<Vec<u8>>, ExecError> {
    if let Some(v) = delta.get(key) {
        return Ok(Some(v.clone()));
    }
    baseline.get(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> StateKey {
        StateKey::meta(&[n])
    }

    #[test]
    fn frozen_delta_rejects_writes() {
        let mut d = DeltaSet::new();
        d.insert(k(1), vec![1]).expect("write");
        d.freeze();
        assert!(matches!(
            d.insert(k(2), vec![2]),
            Err(ExecError::FrozenDelta(_))
        ));
        d.thaw();
        d.insert(k(2), vec![2]).expect("write after thaw");
    }

    #[test]
    fn read_through_prefers_delta() {
        let mut base = InMemoryState::new();
        base.set(k(1), vec![10]);
        let mut d = DeltaSet::new();
        assert_eq!(
            read_through(&d, &base, &k(1)).expect("read"),
            Some(vec![10])
        );
        d.insert(k(1), vec![20]).expect("write");
        assert_eq!(
            read_through(&d, &base, &k(1)).expect("read"),
            Some(vec![20])
        );
        assert_eq!(read_through(&d, &base, &k(9)).expect("read"), None);
    }

    #[test]
    fn final_value_semantics() {
        let mut d = DeltaSet::new();
        d.insert(k(1), vec![1]).expect("write");
        d.insert(k(1), vec![2]).expect("write");
        assert_eq!(d.get(&k(1)), Some(&vec![2]));
        assert_eq!(d.len(), 1);
    }
}
