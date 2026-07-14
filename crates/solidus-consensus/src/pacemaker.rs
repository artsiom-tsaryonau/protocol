use std::time::Duration;
use tokio::time::Instant;

const MIN_TIMEOUT_MS: u64 = 2000;
const MAX_TIMEOUT_MS: u64 = 16_000;

/// Pacemaker manages round timeouts and view synchronization.
pub struct Pacemaker {
    current_round: u64,
    timeout_duration: Duration,
    deadline: Instant,
    consecutive_timeouts: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacemakerEvent {
    Timeout { round: u64 },
    NewRound { round: u64 },
}

impl Pacemaker {
    pub fn new(starting_round: u64) -> Self {
        let timeout = Duration::from_millis(MIN_TIMEOUT_MS);
        Self {
            current_round: starting_round,
            timeout_duration: timeout,
            deadline: Instant::now() + timeout,
            consecutive_timeouts: 0,
        }
    }

    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn timeout_duration(&self) -> Duration {
        self.timeout_duration
    }

    /// Advance on successful QC. Resets timeout to 2s and consecutive_timeouts to 0.
    pub fn advance_round_on_qc(&mut self, new_round: u64) -> PacemakerEvent {
        self.current_round = new_round;
        self.consecutive_timeouts = 0;
        self.timeout_duration = Duration::from_millis(MIN_TIMEOUT_MS);
        self.deadline = Instant::now() + self.timeout_duration;
        PacemakerEvent::NewRound { round: new_round }
    }

    /// Advance on timeout certificate. Applies exponential backoff.
    pub fn advance_round_on_tc(&mut self, new_round: u64) -> PacemakerEvent {
        self.current_round = new_round;
        self.consecutive_timeouts += 1;
        let backoff_ms = MIN_TIMEOUT_MS * 2u64.pow(self.consecutive_timeouts);
        self.timeout_duration = Duration::from_millis(backoff_ms.min(MAX_TIMEOUT_MS));
        self.deadline = Instant::now() + self.timeout_duration;
        PacemakerEvent::NewRound { round: new_round }
    }

    /// Called when round timer expires.
    pub fn on_timeout(&self) -> PacemakerEvent {
        PacemakerEvent::Timeout {
            round: self.current_round,
        }
    }

    /// Push the deadline forward by `timeout_duration` without changing the
    /// round. Call after broadcasting a timeout vote so the consensus loop
    /// does not busy-spin on an already-expired deadline while waiting for
    /// either a TC (which advances the round) or a late proposal/QC.
    pub fn bump_deadline_after_timeout(&mut self) {
        self.deadline = Instant::now() + self.timeout_duration;
    }

    /// Fast-forward to a higher round if we see a QC/TC for it.
    pub fn try_fast_forward(&mut self, round: u64) -> Option<PacemakerEvent> {
        if round > self.current_round {
            Some(self.advance_round_on_qc(round))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let pm = Pacemaker::new(0);
        assert_eq!(pm.current_round(), 0);
        assert_eq!(pm.timeout_duration(), Duration::from_millis(2000));
    }

    #[test]
    fn advance_on_qc_resets_timeout() {
        let mut pm = Pacemaker::new(0);
        // First apply a TC to get backoff to 4s
        pm.advance_round_on_tc(1);
        assert_eq!(pm.timeout_duration(), Duration::from_millis(4000));
        // Then apply a QC — should reset to 2s
        pm.advance_round_on_qc(2);
        assert_eq!(pm.timeout_duration(), Duration::from_millis(2000));
    }

    #[test]
    fn advance_on_tc_applies_backoff() {
        let mut pm = Pacemaker::new(0);
        // 1st TC: 2000 * 2^1 = 4000
        pm.advance_round_on_tc(1);
        assert_eq!(pm.timeout_duration(), Duration::from_millis(4000));
        // 2nd TC: 2000 * 2^2 = 8000
        pm.advance_round_on_tc(2);
        assert_eq!(pm.timeout_duration(), Duration::from_millis(8000));
        // 3rd TC: 2000 * 2^3 = 16000
        pm.advance_round_on_tc(3);
        assert_eq!(pm.timeout_duration(), Duration::from_millis(16000));
        // 4th TC: 2000 * 2^4 = 32000 — caps at 16000
        pm.advance_round_on_tc(4);
        assert_eq!(pm.timeout_duration(), Duration::from_millis(16000));
    }

    #[test]
    fn on_timeout_returns_current_round() {
        let mut pm = Pacemaker::new(0);
        pm.advance_round_on_qc(5);
        assert_eq!(pm.on_timeout(), PacemakerEvent::Timeout { round: 5 });
    }

    #[test]
    fn fast_forward_advances() {
        let mut pm = Pacemaker::new(0);
        pm.advance_round_on_qc(3);
        let event = pm.try_fast_forward(7);
        assert_eq!(event, Some(PacemakerEvent::NewRound { round: 7 }));
        assert_eq!(pm.current_round(), 7);
    }

    #[test]
    fn fast_forward_ignores_lower_round() {
        let mut pm = Pacemaker::new(0);
        pm.advance_round_on_qc(5);
        let event = pm.try_fast_forward(3);
        assert_eq!(event, None);
        assert_eq!(pm.current_round(), 5);
    }

    #[test]
    fn fast_forward_ignores_same_round() {
        let mut pm = Pacemaker::new(0);
        pm.advance_round_on_qc(5);
        let event = pm.try_fast_forward(5);
        assert_eq!(event, None);
        assert_eq!(pm.current_round(), 5);
    }

    #[test]
    fn bump_deadline_after_timeout_pushes_forward_without_advancing_round() {
        let mut pm = Pacemaker::new(0);
        pm.deadline = Instant::now() - Duration::from_millis(50);
        let before = Instant::now();
        pm.bump_deadline_after_timeout();
        assert!(pm.deadline() > before);
        assert_eq!(pm.current_round(), 0);
    }
}
