//! `TxView` — the only way a handler touches state (frozen Stage-0
//! interface, §5.2). No handler ever calls a store or column family
//! directly; reads and writes route through a view whose backing differs
//! by lane:
//!
//! - **Serial view** (identity lane + reference executor): reads
//!   `delta → baseline`, writes into the [`DeltaSet`].
//! - **MV view** (payment lane, Stage 3): reads
//!   `MVMemory → frozen identity delta → baseline` recording a read-set,
//!   writes into `MVMemory` under the tx's index.

use crate::delta::{read_through, DeltaSet, StateReader};
use crate::error::ExecError;
use crate::fee::FeeAccumulator;
use crate::types::StateKey;

/// Handler-facing state interface (frozen).
pub trait TxView {
    /// Read the current value at `key` (block-visibility rules apply).
    fn read(&mut self, key: &StateKey) -> Result<Option<Vec<u8>>, ExecError>;

    /// Record a state write.
    fn write(&mut self, key: StateKey, value: Vec<u8>) -> Result<(), ExecError>;

    /// Charge a fee into the block's commutative accumulator — never a
    /// per-tx write to any fee-destination account (Hazard-C rule).
    fn charge_fee(&mut self, amount: u64);
}

/// Serial-lane view over `(DeltaSet, baseline)`.
pub struct SerialView<'a, R: StateReader + ?Sized> {
    delta: &'a mut DeltaSet,
    baseline: &'a R,
    fees: &'a mut FeeAccumulator,
}

impl<'a, R: StateReader + ?Sized> SerialView<'a, R> {
    pub fn new(delta: &'a mut DeltaSet, baseline: &'a R, fees: &'a mut FeeAccumulator) -> Self {
        Self {
            delta,
            baseline,
            fees,
        }
    }
}

impl<R: StateReader + ?Sized> TxView for SerialView<'_, R> {
    fn read(&mut self, key: &StateKey) -> Result<Option<Vec<u8>>, ExecError> {
        read_through(self.delta, self.baseline, key)
    }

    fn write(&mut self, key: StateKey, value: Vec<u8>) -> Result<(), ExecError> {
        self.delta.insert(key, value)
    }

    fn charge_fee(&mut self, amount: u64) {
        self.fees.charge(amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::InMemoryState;

    #[test]
    fn serial_view_reads_delta_over_baseline_and_writes_delta() {
        let mut base = InMemoryState::new();
        let key = StateKey::meta(b"x");
        base.set(key.clone(), vec![1]);

        let mut delta = DeltaSet::new();
        let mut fees = FeeAccumulator::new();
        let mut view = SerialView::new(&mut delta, &base, &mut fees);

        assert_eq!(view.read(&key).expect("read"), Some(vec![1]));
        view.write(key.clone(), vec![2]).expect("write");
        assert_eq!(view.read(&key).expect("read"), Some(vec![2]));
        view.charge_fee(10_000);

        assert_eq!(fees.total(), 10_000);
        assert_eq!(delta.get(&key), Some(&vec![2]));
    }
}
