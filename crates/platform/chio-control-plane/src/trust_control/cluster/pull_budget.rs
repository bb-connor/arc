use super::*;
use std::time::{Duration, Instant};

pub(crate) const MAX_PULL_PAGES_PER_PEER_PER_ROUND: u32 = 64;
pub(crate) const MAX_PULL_RECORDS_PER_PEER_PER_ROUND: u64 = 200_000;
pub(crate) const PEER_ROUND_WALL_CLOCK_BUDGET: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub(crate) enum PeerProtocolError {
    NonAdvancingPage { after_seq: u64, page_max_seq: u64 },
    PageBudgetExhausted { pages: u32 },
    RecordBudgetExhausted { records: u64 },
    RoundDeadlineExceeded,
}

impl std::fmt::Display for PeerProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonAdvancingPage { after_seq, page_max_seq } => write!(
                f,
                "peer returned a non-empty page whose max seq {page_max_seq} did not advance past cursor {after_seq}"
            ),
            Self::PageBudgetExhausted { pages } => {
                write!(f, "peer exceeded per-round page budget after {pages} pages")
            }
            Self::RecordBudgetExhausted { records } => {
                write!(f, "peer exceeded per-round record budget after {records} records")
            }
            Self::RoundDeadlineExceeded => write!(f, "peer exceeded per-round wall-clock budget"),
        }
    }
}

pub(crate) struct PullRoundBudget {
    pages_left: u32,
    records_left: u64,
    deadline: Instant,
}

impl PullRoundBudget {
    pub(crate) fn new() -> Self {
        Self {
            pages_left: MAX_PULL_PAGES_PER_PEER_PER_ROUND,
            records_left: MAX_PULL_RECORDS_PER_PEER_PER_ROUND,
            deadline: Instant::now() + PEER_ROUND_WALL_CLOCK_BUDGET,
        }
    }

    /// Charge one page of `records`. Fail-closed: any exhaustion is a peer
    /// protocol error, not a silent stop.
    pub(crate) fn charge_page(&mut self, records: u64) -> Result<(), PeerProtocolError> {
        if Instant::now() >= self.deadline {
            return Err(PeerProtocolError::RoundDeadlineExceeded);
        }
        self.pages_left =
            self.pages_left
                .checked_sub(1)
                .ok_or(PeerProtocolError::PageBudgetExhausted {
                    pages: MAX_PULL_PAGES_PER_PEER_PER_ROUND,
                })?;
        self.records_left = self.records_left.checked_sub(records).ok_or(
            PeerProtocolError::RecordBudgetExhausted {
                records: MAX_PULL_RECORDS_PER_PEER_PER_ROUND,
            },
        )?;
        Ok(())
    }
}

/// Strict monotonicity for a `u64` cursor puller. `page_max_seq` MUST be the
/// maximum seq in a non-empty page.
pub(crate) fn ensure_seq_advanced(
    after_seq: u64,
    page_max_seq: u64,
) -> Result<(), PeerProtocolError> {
    if page_max_seq > after_seq {
        Ok(())
    } else {
        Err(PeerProtocolError::NonAdvancingPage {
            after_seq,
            page_max_seq,
        })
    }
}

/// Strict monotonicity for the composite `(revoked_at, capability_id)`
/// revocation cursor.
pub(crate) fn ensure_revocation_advanced(
    after: Option<&RevocationCursor>,
    page_max: &RevocationCursor,
) -> Result<(), PeerProtocolError> {
    let advanced = match after {
        None => true,
        Some(prev) => {
            (page_max.revoked_at, page_max.capability_id.as_str())
                > (prev.revoked_at, prev.capability_id.as_str())
        }
    };
    if advanced {
        Ok(())
    } else {
        Err(PeerProtocolError::NonAdvancingPage {
            after_seq: after.map(|cursor| cursor.revoked_at as u64).unwrap_or(0),
            page_max_seq: page_max.revoked_at as u64,
        })
    }
}

/// Carries the protocol-violation distinction out of the pullers so `sync_peer`
/// can demote a misbehaving peer while leaving a transient failure retryable.
#[derive(Debug)]
pub(crate) enum PullError {
    /// The peer violated the pull wire contract; demote it (fail-closed).
    Protocol(PeerProtocolError),
    /// Transport or store failure; retryable, peer keeps its standing.
    Transient(CliError),
}

impl From<PeerProtocolError> for PullError {
    fn from(error: PeerProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<CliError> for PullError {
    fn from(error: CliError) -> Self {
        Self::Transient(error)
    }
}

#[cfg(test)]
mod pull_budget_tests {
    use super::*;

    #[test]
    fn charge_page_exhausts_pages_records_and_reports_typed_errors() {
        let mut budget = PullRoundBudget::new();
        // Records budget: one page that overruns the record budget is a typed error.
        let mut records_budget = PullRoundBudget::new();
        assert!(matches!(
            records_budget.charge_page(MAX_PULL_RECORDS_PER_PEER_PER_ROUND + 1),
            Err(PeerProtocolError::RecordBudgetExhausted { .. })
        ));

        // Page budget: charging one more page than allowed is a typed error.
        for _ in 0..MAX_PULL_PAGES_PER_PEER_PER_ROUND {
            assert!(budget.charge_page(1).is_ok(), "page within budget");
        }
        assert!(matches!(
            budget.charge_page(1),
            Err(PeerProtocolError::PageBudgetExhausted { .. })
        ));
    }

    #[test]
    fn non_advancing_page_is_peer_protocol_error() {
        // Strict advance: equal or lower page max is a violation.
        assert!(ensure_seq_advanced(10, 11).is_ok());
        assert!(matches!(
            ensure_seq_advanced(10, 10),
            Err(PeerProtocolError::NonAdvancingPage {
                after_seq: 10,
                page_max_seq: 10
            })
        ));
        assert!(matches!(
            ensure_seq_advanced(10, 9),
            Err(PeerProtocolError::NonAdvancingPage { .. })
        ));

        // Composite revocation cursor: strict (revoked_at, capability_id) advance.
        let prev = RevocationCursor {
            revoked_at: 5,
            capability_id: "cap-b".to_string(),
        };
        let same = RevocationCursor {
            revoked_at: 5,
            capability_id: "cap-b".to_string(),
        };
        let higher = RevocationCursor {
            revoked_at: 5,
            capability_id: "cap-c".to_string(),
        };
        assert!(ensure_revocation_advanced(None, &same).is_ok());
        assert!(ensure_revocation_advanced(Some(&prev), &higher).is_ok());
        assert!(matches!(
            ensure_revocation_advanced(Some(&prev), &same),
            Err(PeerProtocolError::NonAdvancingPage { .. })
        ));
    }
}
