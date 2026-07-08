use super::*;
use std::time::{Duration, Instant};

pub(crate) const MAX_PULL_PAGES_PER_PEER_PER_ROUND: u32 = 64;
pub(crate) const MAX_PULL_RECORDS_PER_PEER_PER_ROUND: u64 = 200_000;
pub(crate) const PEER_ROUND_WALL_CLOCK_BUDGET: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub(crate) enum PeerProtocolError {
    NonAdvancingPage {
        after_seq: u64,
        page_max_seq: u64,
    },
    /// A dense append-only page was not cursor-anchored or had an interior gap:
    /// the sorted seqs did not run consecutively from the expected next seq.
    /// `expected_seq` is the seq the puller required next; `found_seq` is the
    /// out-of-order seq that broke contiguity (either a forward cursor-jump that
    /// would skip unreplicated rows, or an internal hole).
    NonContiguousPage {
        expected_seq: u64,
        found_seq: u64,
    },
    PageBudgetExhausted {
        pages: u32,
    },
    RecordBudgetExhausted {
        records: u64,
    },
    RoundDeadlineExceeded,
}

impl std::fmt::Display for PeerProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonAdvancingPage { after_seq, page_max_seq } => write!(
                f,
                "peer returned a non-empty page whose max seq {page_max_seq} did not advance past cursor {after_seq}"
            ),
            Self::NonContiguousPage { expected_seq, found_seq } => write!(
                f,
                "peer returned a page that is not cursor-anchored or has a gap: expected next seq {expected_seq}, found {found_seq}"
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

/// Soundness guard for a dense append-only `u64` sequence puller (tool
/// receipts, child receipts, lineage, and the budget mutation-event stream).
///
/// A max-advance-only check (page max seq > cursor) is NOT enough: a peer at
/// cursor 10 that returns the page {110, 111} would pass it, get imported, and
/// advance the cursor to 111, permanently omitting the append-only rows 11..109
/// (a replication-soundness hole). This requires the returned page to be BOTH
/// cursor-anchored and gap-free: the sorted seqs must run consecutively
/// starting at `expected_next_seq`. Any forward cursor-jump (page starts past
/// the expected next row) or interior hole is a `NonContiguousPage` protocol
/// violation, which demotes the peer via the existing `update_peer_failure`
/// path and does NOT advance the cursor past the gap. An empty slice is
/// vacuously contiguous (the callers treat an empty page as "caught up" and do
/// not advance).
pub(crate) fn require_contiguous_page(
    expected_next_seq: u64,
    seqs: &[u64],
) -> Result<(), PeerProtocolError> {
    if seqs.is_empty() {
        return Ok(());
    }
    // The delta endpoints order ascending, but do not trust the peer's ordering:
    // sort locally so an out-of-order page cannot mask a skip.
    let mut sorted = seqs.to_vec();
    sorted.sort_unstable();
    let mut expected = expected_next_seq;
    for &seq in &sorted {
        if seq != expected {
            return Err(PeerProtocolError::NonContiguousPage {
                expected_seq: expected,
                found_seq: seq,
            });
        }
        expected = expected.saturating_add(1);
    }
    Ok(())
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
    fn require_contiguous_page_rejects_cursor_jump_and_interior_gap() {
        // Cursor-anchored, gap-free page from cursor 10 (expected next 11).
        assert!(require_contiguous_page(11, &[11, 12, 13]).is_ok());
        // An empty page is vacuously contiguous ("caught up").
        assert!(require_contiguous_page(11, &[]).is_ok());
        // Out-of-order but still contiguous once sorted.
        assert!(require_contiguous_page(11, &[13, 11, 12]).is_ok());

        // Forward cursor-jump: {110, 111} from cursor 10 would skip 11..109.
        // A max-advance-only check (110 > 10) would wrongly ACCEPT this; the
        // contiguity guard rejects it, anchored at the expected next seq.
        assert!(matches!(
            require_contiguous_page(11, &[110, 111]),
            Err(PeerProtocolError::NonContiguousPage {
                expected_seq: 11,
                found_seq: 110
            })
        ));
        // Interior hole: {11, 12, 14} skips 13.
        assert!(matches!(
            require_contiguous_page(11, &[11, 12, 14]),
            Err(PeerProtocolError::NonContiguousPage {
                expected_seq: 13,
                found_seq: 14
            })
        ));
        // A duplicate seq breaks contiguity (second 12 lands below expected 13).
        assert!(matches!(
            require_contiguous_page(11, &[11, 12, 12]),
            Err(PeerProtocolError::NonContiguousPage { .. })
        ));
    }

    #[test]
    fn non_advancing_revocation_cursor_is_peer_protocol_error() {
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
