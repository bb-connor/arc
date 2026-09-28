//! Checked signed claim windows. Retries keep their persisted original deadline.
use super::FINDING_POOL_CLAIM_WINDOW_MS;
use crate::finding_pool_error::FindingPoolLedgerError;
use chio_security_types::clock::UnixMillis;

pub(super) fn claim_deadline(
    now: u64,
    allocation_expires: u64,
) -> Result<u64, FindingPoolLedgerError> {
    if now >= allocation_expires {
        return Err(FindingPoolLedgerError::AllocationNotLive);
    }
    Ok(UnixMillis::new(now)
        .checked_add(FINDING_POOL_CLAIM_WINDOW_MS)?
        .get()
        .min(allocation_expires))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_security_types::clock::ClockError;
    #[test]
    fn signed_allocation_caps_the_checked_claim_window() {
        assert_eq!(claim_deadline(1_000, 20_000), Ok(20_000));
        assert_eq!(claim_deadline(1_000, 100_000), Ok(31_000));
        assert_eq!(
            claim_deadline(1_000, 1_000),
            Err(FindingPoolLedgerError::AllocationNotLive)
        );
        assert_eq!(
            claim_deadline(u64::MAX - 1, u64::MAX),
            Err(FindingPoolLedgerError::Clock(ClockError::Overflow))
        );
    }
}
