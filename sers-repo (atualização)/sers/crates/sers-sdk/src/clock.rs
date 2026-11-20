use sers_core::SersError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Largest backwards jump of the system clock that is tolerated, in seconds.
pub const MAX_CLOCK_REGRESSION_SECS: u64 = 5;

/// Source of Unix time in seconds.
pub trait Clock {
    fn now(&self) -> u64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Keeps the highest time ever observed so that trusted time never decreases.
/// A clock moved back by more than [`MAX_CLOCK_REGRESSION_SECS`] is an error.
/// This only protects a running process; it does not survive restarts.
#[derive(Debug, Default)]
pub(crate) struct MonotonicGuard {
    high_water: AtomicU64,
}

impl MonotonicGuard {
    pub(crate) fn observe(&self, now: u64) -> Result<u64, SersError> {
        let previous = self.high_water.fetch_max(now, Ordering::SeqCst);
        if now.saturating_add(MAX_CLOCK_REGRESSION_SECS) < previous {
            return Err(SersError::PolicyDenied("system clock moved backwards"));
        }
        Ok(now.max(previous))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_never_goes_backwards_within_tolerance() {
        let g = MonotonicGuard::default();
        assert_eq!(g.observe(1_000).unwrap(), 1_000);
        assert_eq!(g.observe(1_010).unwrap(), 1_010);
        assert_eq!(g.observe(1_008).unwrap(), 1_010);
    }

    #[test]
    fn large_regression_is_rejected() {
        let g = MonotonicGuard::default();
        g.observe(1_000).unwrap();
        assert!(matches!(
            g.observe(1_000 - MAX_CLOCK_REGRESSION_SECS - 1),
            Err(SersError::PolicyDenied(_))
        ));
        assert!(g.observe(1_000 - MAX_CLOCK_REGRESSION_SECS).is_ok());
    }

    #[test]
    fn system_clock_is_plausible() {
        assert!(SystemClock.now() > 1_600_000_000);
    }
}
