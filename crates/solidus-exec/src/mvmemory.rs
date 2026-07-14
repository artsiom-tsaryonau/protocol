//! Multi-version memory for the payment-lane scheduler.
//!
//! Versioned map: `StateKey → { tx_index → (incarnation, value) }`. A
//! reader at index `i` resolves to the value written by the **highest
//! writer index < i**, else falls through to the frozen-identity-delta +
//! store baseline. Bespoke implementation using Aptos's MVMemory as the
//! *reference*, not a fork (BD-7).
//!
//! Concurrency model (deliberately simple — see `payment.rs`): waves of
//! transactions execute in parallel against an **immutable** `&MvMemory`
//! snapshot; writes are applied by a serial validate-and-apply pass
//! between waves. The table itself therefore needs no interior
//! synchronization — shared reads are plain `&self` calls.

use std::collections::BTreeMap;

use crate::types::StateKey;

/// Position of a transaction in the payment lane's canonical order.
pub type TxIndex = usize;
/// Re-execution counter for a tx after aborts.
pub type Incarnation = u32;

/// Outcome of a versioned read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    /// A lower-indexed tx wrote this value.
    Versioned {
        writer: TxIndex,
        incarnation: Incarnation,
        value: Vec<u8>,
    },
    /// No lower-indexed writer — resolve from the frozen baseline.
    Baseline,
}

/// Version-only fingerprint of a read — what the read-set records and what
/// validation compares. Two resolutions are equivalent iff they came from
/// the same writer incarnation (or both fell through to the immutable
/// baseline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOrigin {
    Baseline,
    Version {
        writer: TxIndex,
        incarnation: Incarnation,
    },
}

#[derive(Debug, Clone)]
struct Entry {
    incarnation: Incarnation,
    value: Vec<u8>,
}

/// The multi-version write table.
#[derive(Debug, Default)]
pub struct MvMemory {
    versions: BTreeMap<StateKey, BTreeMap<TxIndex, Entry>>,
}

impl MvMemory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `tx_index`'s write of `key` at `incarnation`.
    pub fn write(
        &mut self,
        tx_index: TxIndex,
        incarnation: Incarnation,
        key: StateKey,
        value: Vec<u8>,
    ) {
        self.versions
            .entry(key)
            .or_default()
            .insert(tx_index, Entry { incarnation, value });
    }

    /// Apply a whole write-set for `tx_index` at `incarnation`.
    pub fn apply_write_set(
        &mut self,
        tx_index: TxIndex,
        incarnation: Incarnation,
        writes: &BTreeMap<StateKey, Vec<u8>>,
    ) {
        for (key, value) in writes {
            self.write(tx_index, incarnation, key.clone(), value.clone());
        }
    }

    /// Remove `tx_index`'s write of `key` (abort cleanup).
    pub fn delete(&mut self, tx_index: TxIndex, key: &StateKey) {
        if let Some(m) = self.versions.get_mut(key) {
            m.remove(&tx_index);
        }
    }

    /// Read `key` as `reader` would: highest writer index strictly below
    /// `reader`, else baseline.
    pub fn read(&self, key: &StateKey, reader: TxIndex) -> ReadOutcome {
        let Some(writers) = self.versions.get(key) else {
            return ReadOutcome::Baseline;
        };
        match writers.range(..reader).next_back() {
            Some((&writer, entry)) => ReadOutcome::Versioned {
                writer,
                incarnation: entry.incarnation,
                value: entry.value.clone(),
            },
            None => ReadOutcome::Baseline,
        }
    }

    /// Version-only resolution (no value clone) — validation's workhorse.
    pub fn origin_of(&self, key: &StateKey, reader: TxIndex) -> ReadOrigin {
        let Some(writers) = self.versions.get(key) else {
            return ReadOrigin::Baseline;
        };
        match writers.range(..reader).next_back() {
            Some((&writer, entry)) => ReadOrigin::Version {
                writer,
                incarnation: entry.incarnation,
            },
            None => ReadOrigin::Baseline,
        }
    }

    /// Fold into the final `key → value` map: the highest-index write wins
    /// per key (commit order = index order).
    pub fn into_finalized(self) -> BTreeMap<StateKey, Vec<u8>> {
        self.versions
            .into_iter()
            .filter_map(|(key, writers)| {
                writers
                    .into_iter()
                    .next_back()
                    .map(|(_, entry)| (key, entry.value))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> StateKey {
        StateKey::meta(&[n])
    }

    #[test]
    fn read_resolves_highest_lower_writer() {
        let mut mv = MvMemory::new();
        mv.write(1, 0, k(1), vec![1]);
        mv.write(5, 0, k(1), vec![5]);

        assert_eq!(mv.read(&k(1), 0), ReadOutcome::Baseline);
        assert!(matches!(
            mv.read(&k(1), 3),
            ReadOutcome::Versioned { writer: 1, .. }
        ));
        assert!(matches!(
            mv.read(&k(1), 9),
            ReadOutcome::Versioned { writer: 5, .. }
        ));
        // A tx never reads its own index's write via this path.
        assert!(matches!(
            mv.read(&k(1), 5),
            ReadOutcome::Versioned { writer: 1, .. }
        ));
    }

    #[test]
    fn origin_matches_read_resolution() {
        let mut mv = MvMemory::new();
        mv.write(2, 3, k(1), vec![2]);
        assert_eq!(mv.origin_of(&k(1), 1), ReadOrigin::Baseline);
        assert_eq!(
            mv.origin_of(&k(1), 5),
            ReadOrigin::Version {
                writer: 2,
                incarnation: 3
            }
        );
    }

    #[test]
    fn finalized_takes_highest_index_per_key() {
        let mut mv = MvMemory::new();
        mv.write(2, 0, k(1), vec![2]);
        mv.write(7, 1, k(1), vec![7]);
        mv.write(3, 0, k(2), vec![3]);

        let m = mv.into_finalized();
        assert_eq!(m.get(&k(1)), Some(&vec![7]));
        assert_eq!(m.get(&k(2)), Some(&vec![3]));
    }

    #[test]
    fn delete_removes_a_writers_entry() {
        let mut mv = MvMemory::new();
        mv.write(2, 0, k(1), vec![2]);
        mv.delete(2, &k(1));
        assert_eq!(mv.read(&k(1), 9), ReadOutcome::Baseline);
    }

    #[test]
    fn apply_write_set_writes_all_keys() {
        let mut mv = MvMemory::new();
        let mut ws = BTreeMap::new();
        ws.insert(k(1), vec![1]);
        ws.insert(k(2), vec![2]);
        mv.apply_write_set(4, 1, &ws);
        assert!(matches!(
            mv.read(&k(1), 9),
            ReadOutcome::Versioned {
                writer: 4,
                incarnation: 1,
                ..
            }
        ));
        assert!(matches!(
            mv.read(&k(2), 9),
            ReadOutcome::Versioned { writer: 4, .. }
        ));
    }
}
