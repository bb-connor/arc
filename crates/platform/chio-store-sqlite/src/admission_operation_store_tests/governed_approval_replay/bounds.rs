use super::*;
use chio_kernel::admission_operation::governed_approval_replay::{
    GovernedApprovalReplaySourceFileIdentity, GovernedApprovalReplaySourceInventory,
    GovernedApprovalReplaySourceMarker, MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_MARKERS,
};

/// Data-only source double for destination capacity and identity refusal. No
/// successful sealing through this implementation is possible or qualified.
struct CandidateSource {
    identity: GovernedApprovalReplaySourceFileIdentity,
    marker_count: usize,
}

impl GovernedApprovalReplaySourcePort for CandidateSource {
    fn preview_unsealed(
        &self,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
        let markers = (0..self.marker_count)
            .map(|index| GovernedApprovalReplaySourceMarker {
                subject_id: identifier("subject", "subject"),
                request_id: identifier("request", &format!("request-{index:05}")),
                intent_hash: identifier("intent", "intent"),
                expires_at: "100".into(),
                dispatch_reservation_id: None,
            })
            .collect();
        GovernedApprovalReplaySourceSnapshot::from_inventory(
            binding.clone(),
            self.identity,
            "a".repeat(64),
            GovernedApprovalReplaySourceInventory {
                wall_clock_high_water: "100".into(),
                pruned_through: "50".into(),
                capacity: MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_MARKERS.to_string(),
                markers,
            },
        )
    }
    fn seal_exact(
        &self,
        _: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        panic!("capacity checks must never seal this source")
    }
    fn verify_exact(
        &self,
        _: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        panic!("capacity checks must never verify this source")
    }
}

#[test]
fn destination_database_cannot_be_its_own_replay_source() -> AnchoredTestResult {
    let fixture = fixture();
    let identity =
        chio_sqlite_file_identity::main_database_file_identity(&*fixture.store.connection()?)?;
    let source = CandidateSource {
        identity: GovernedApprovalReplaySourceFileIdentity {
            device: identity.device,
            inode: identity.inode,
            link_count: identity.link_count,
        },
        marker_count: 0,
    };
    let error = pin(&fixture, &source).expect_err("source/destination identity collision");
    assert!(
        error.to_string().contains("different physical database"),
        "{error}"
    );
    assert_eq!(counts(&fixture), [0, 0, 0]);
    Ok(())
}

#[test]
fn pending_pins_reserve_complete_marker_budget_before_any_source_is_sealed() -> AnchoredTestResult {
    let fixture = fixture();
    let before = global_count(&fixture);
    for index in 0..5 {
        let source = CandidateSource {
            identity: GovernedApprovalReplaySourceFileIdentity {
                device: u64::MAX,
                inode: index,
                link_count: 1,
            },
            marker_count: if index == 4 {
                1
            } else {
                MAX_GOVERNED_APPROVAL_REPLAY_SOURCE_MARKERS
            },
        };
        let result = fixture.store.expect_governed_approval_replay_source(
            &identifier("source", &format!("source-{index}")),
            &identifier("authority", &format!("authority-{index}")),
            &source,
            &fixture.fence,
            now_ms(),
        );
        if index < 4 {
            assert!(!result?.is_imported());
        } else {
            let error = result.expect_err("pending pins exhausted marker budget");
            assert!(
                error.to_string().contains("complete-inventory capacity"),
                "{error}"
            );
        }
    }
    assert_eq!(counts(&fixture), [0, 4, 4]);
    assert_eq!(global_count(&fixture), before + 4);
    Ok(())
}
