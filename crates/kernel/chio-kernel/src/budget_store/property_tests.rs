#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_test_support::prelude::*;
use proptest::prelude::*;

use super::*;

const CAPABILITY_ID: &str = "cap-property";
const GRANT_INDEX: usize = 0;

fn property_operation_binding(hold_index: u8) -> BudgetAdmissionOperationBinding {
    BudgetAdmissionOperationBinding::new(
        format!("property-operation-{hold_index}"),
        "44".repeat(32),
    )
    .expect("valid property admission operation")
}

fn composite_property_request(hold_index: u8, maxima: [u32; 3]) -> BudgetAuthorizeHoldRequest {
    let quotas = vec![
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::GrantInvocation,
                owner_id: CAPABILITY_ID.to_string(),
                grant_index: Some(0),
            },
            max_invocations: maxima[0],
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::AggregateCapabilityInvocation,
                owner_id: CAPABILITY_ID.to_string(),
                grant_index: None,
            },
            max_invocations: maxima[1],
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::SupplementalBrokerExecution,
                owner_id: "77".repeat(32),
                grant_index: None,
            },
            max_invocations: maxima[2],
        },
    ];
    BudgetAuthorizeHoldRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        max_invocations: None,
        requested_exposure_units: 5,
        max_cost_per_invocation: Some(5),
        max_total_cost_units: Some(100),
        hold_id: Some(format!("property-hold-{hold_index}")),
        event_id: Some(format!("property-event-{hold_index}-authorize")),
        authority: None,
        admission_operation: Some(property_operation_binding(hold_index)),
        invocation_admission: Some(VerifiedInvocationAdmission {
            quotas,
            revocation_set: CanonicalRevocationSet::new(CAPABILITY_ID, &[], &[])
                .expect("canonical revocation set"),
            aggregate_root_capability_id: None,
            aggregate_binding_digest: None,
            supplemental_binding: Some(SupplementalQuotaBinding {
                artifact_digest: "11".repeat(32),
                verifier_id: "property-verifier".to_string(),
                request_binding_hash: "22".repeat(32),
                negotiated_features_digest: "33".repeat(32),
                issuer: chio_core::crypto::Keypair::from_seed(&[71; 32]).public_key(),
                not_before: 90,
                expires_at: 300,
                request_constraint_digest: "34".repeat(32),
                broker_capability_id: "property-broker-capability".to_string(),
                claim_binding_digest: "35".repeat(32),
                verified_at: 100,
            }),
            partition_escrow_evidence: None,
        }),
        authorization_policy: BudgetAuthorizationPolicy::FreshOrReplay,
        payment_journal: None,
    }
}

proptest! {
    #[test]
    fn composite_exhaustion_and_reversal_conserve_every_quota(
        exhausted_index in 0usize..3,
    ) {
        let store = InMemoryBudgetStore::new();
        let mut maxima = [2, 2, 2];
        maxima[exhausted_index] = 1;

        let first = store
            .authorize_budget_hold(composite_property_request(1, maxima))
            .expect("authorize first composite hold");
        let BudgetAuthorizeHoldDecision::Authorized(first) = first else {
            return Err(TestCaseError::fail("first composite hold was denied"));
        };
        prop_assert!(first
            .invocation_counts_after
            .iter()
            .all(|usage| usage.invocation_count_after().expect("count") == 1));

        let denied = store
            .authorize_budget_hold(composite_property_request(2, maxima))
            .expect("authorize exhausted composite hold");
        let BudgetAuthorizeHoldDecision::Denied(denied) = denied else {
            return Err(TestCaseError::fail("exhausted composite hold was authorized"));
        };
        let denial_seq = denied
            .metadata
            .budget_commit_index
            .ok_or_else(|| TestCaseError::fail("denial omitted its decision event sequence"))?;
        prop_assert!(denied
            .invocation_counts_after
            .iter()
            .all(|usage| usage.invocation_count_after().expect("count") == 1));
        let denial_event = store
            .list_mutation_events(10, Some(CAPABILITY_ID), Some(GRANT_INDEX))
            .test_expect("list denial event")
            .into_iter()
            .find(|event| event.event_id == "property-event-2-authorize")
            .test_expect("denial event");
        prop_assert_eq!(denial_event.event_seq, denial_seq);
        prop_assert_eq!(denial_event.usage_seq, None);
        let usage = store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("read usage")
            .expect("usage row");
        prop_assert_eq!(usage.invocation_count, 1);
        prop_assert_eq!(usage.total_cost_exposed, 5);

        let reversed = store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: CAPABILITY_ID.to_string(),
                grant_index: GRANT_INDEX,
                reversed_exposure_units: 5,
                hold_id: Some("property-hold-1".to_string()),
                event_id: Some("property-event-1-reverse".to_string()),
                authority: None,
                admission_operation: Some(property_operation_binding(1)),
            })
            .expect("reverse composite hold");
        prop_assert!(reversed
            .invocation_counts_after
            .iter()
            .all(|usage| usage.invocation_count_after().expect("count") == 0));
        let usage = store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("read usage")
            .expect("usage row");
        prop_assert_eq!(usage.invocation_count, 0);
        prop_assert_eq!(usage.total_cost_exposed, 0);
    }
}

#[cfg(all(test, feature = "loom-tests"))]
#[test]
fn loom_production_composite_quota_authorization_is_all_or_none() {
    loom::model(|| {
        use loom::sync::Arc;
        use loom::thread;

        let store = Arc::new(InMemoryBudgetStore::new_loom());
        let first_store = Arc::clone(&store);
        let first = thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                first_store
                    .authorize_budget_hold(composite_property_request(1, [2, 1, 2]))
                    .expect("first composite authorization")
            })
            .expect("spawn first authorization");
        let second_store = Arc::clone(&store);
        let second = thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                second_store
                    .authorize_budget_hold(composite_property_request(2, [2, 1, 2]))
                    .expect("second composite authorization")
            })
            .expect("spawn second authorization");

        let decisions = [
            first.join().expect("join first authorization"),
            second.join().expect("join second authorization"),
        ];
        assert_eq!(
            decisions
                .iter()
                .filter(|decision| decision.is_authorized())
                .count(),
            1
        );
        for decision in decisions {
            let counts = match decision {
                BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                    authorized.invocation_counts_after
                }
                BudgetAuthorizeHoldDecision::Denied(denied) => denied.invocation_counts_after,
            };
            assert!(counts
                .iter()
                .all(|usage| usage.invocation_count_after().expect("count") == 1));
        }
        let usage = store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("read usage")
            .expect("usage row");
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 5);
    });
}
