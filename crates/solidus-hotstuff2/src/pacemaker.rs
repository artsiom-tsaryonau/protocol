//! Sub-second pacemaker (§4.4): 400ms base view timeout with capped
//! exponential backoff — replaces the live chain's 2000→16000ms ladder.
//! Pure timeout *policy*; the node layer owns actual timers.

use std::time::Duration;

/// Default base view timeout (ms).
pub const BASE_TIMEOUT_MS: u64 = 400;
/// Default backoff cap (ms): 400 → 800 → 1600 → 3200, then flat.
pub const MAX_TIMEOUT_MS: u64 = 3_200;

#[derive(Debug, Clone)]
pub struct Pacemaker {
    base_ms: u64,
    cap_ms: u64,
    consecutive_timeouts: u32,
}

impl Default for Pacemaker {
    fn default() -> Self {
        Self::new(BASE_TIMEOUT_MS, MAX_TIMEOUT_MS)
    }
}

impl Pacemaker {
    pub fn new(base_ms: u64, cap_ms: u64) -> Self {
        Self {
            base_ms,
            cap_ms,
            consecutive_timeouts: 0,
        }
    }

    /// Timeout to arm for the view being entered now.
    pub fn current_timeout(&self) -> Duration {
        let shift = self.consecutive_timeouts.min(16);
        let ms = self.base_ms.saturating_mul(1u64 << shift).min(self.cap_ms);
        Duration::from_millis(ms)
    }

    /// A local view timeout fired (backoff grows).
    pub fn on_local_timeout(&mut self) {
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
    }

    /// The chain made progress via a QC (backoff resets).
    pub fn on_qc_progress(&mut self) {
        self.consecutive_timeouts = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let mut p = Pacemaker::default();
        assert_eq!(p.current_timeout(), Duration::from_millis(400));
        p.on_local_timeout();
        assert_eq!(p.current_timeout(), Duration::from_millis(800));
        p.on_local_timeout();
        assert_eq!(p.current_timeout(), Duration::from_millis(1600));
        p.on_local_timeout();
        assert_eq!(p.current_timeout(), Duration::from_millis(3200));
        p.on_local_timeout();
        assert_eq!(p.current_timeout(), Duration::from_millis(3200), "capped");
    }

    #[test]
    fn qc_progress_resets_backoff() {
        let mut p = Pacemaker::default();
        p.on_local_timeout();
        p.on_local_timeout();
        p.on_qc_progress();
        assert_eq!(p.current_timeout(), Duration::from_millis(400));
    }
}
