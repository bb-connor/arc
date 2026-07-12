use super::*;

/// Closed wire vocabulary for structured invocation quota ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum BudgetQuotaProfileView {
    #[serde(rename = "chio.grant-invocation.v1")]
    GrantInvocation,
    #[serde(rename = "chio.aggregate-capability-invocation.v1")]
    AggregateCapabilityInvocation,
    #[serde(rename = "chio.aggregate-family-invocation.v1")]
    AggregateFamilyInvocation,
    #[serde(rename = "chio.broker-capability-execution.v1")]
    SupplementalBrokerExecution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetQuotaKeyView {
    pub(crate) profile: BudgetQuotaProfileView,
    pub(crate) owner_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetInvocationQuotaView {
    pub(crate) key: BudgetQuotaKeyView,
    pub(crate) max_invocations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetInvocationQuotaUsageView {
    pub(crate) quota: BudgetInvocationQuotaView,
    pub(crate) reserved_invocations_after: u32,
    pub(crate) captured_invocations_after: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CanonicalRevocationSetView {
    pub(crate) ids: Vec<String>,
    pub(crate) digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetSupplementalQuotaBindingView {
    pub(crate) artifact_digest: String,
    pub(crate) verifier_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) negotiated_features_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetInvocationAdmissionEvidenceView {
    pub(crate) invocation_quotas: Vec<BudgetInvocationQuotaView>,
    pub(crate) revocation_set: CanonicalRevocationSetView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aggregate_binding_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) supplemental_binding: Option<BudgetSupplementalQuotaBindingView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetInvocationReservationStateView {
    Absent,
    Authorized,
    Captured,
    Reversed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetMonetaryHoldStateView {
    None,
    Exposed,
    Released,
    Reconciled,
    Captured,
    Reversed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompositeBudgetAuthorizeRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) requested_exposure_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_exposure_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_total_exposure_units: Option<u64>,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) admission_evidence: BudgetInvocationAdmissionEvidenceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompositeBudgetAuthorizeResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authorized_exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) attempted_exposure_units: Option<u64>,
    pub(crate) committed_cost_units_after: u64,
    pub(crate) invocation_count_after: u32,
    pub(crate) invocation_counts_after: Vec<BudgetInvocationQuotaUsageView>,
    pub(crate) invocation_state: BudgetInvocationReservationStateView,
    pub(crate) monetary_state: BudgetMonetaryHoldStateView,
    pub(crate) admission_evidence: BudgetInvocationAdmissionEvidenceView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureInvocationReservationsRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetMutationAuthorityView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureInvocationReservationsResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) exposure_units: u64,
    pub(crate) realized_spend_units: u64,
    pub(crate) committed_cost_units_after: u64,
    pub(crate) invocation_count_after: u32,
    pub(crate) invocation_counts_after: Vec<BudgetInvocationQuotaUsageView>,
    pub(crate) invocation_state: BudgetInvocationReservationStateView,
    pub(crate) monetary_state: BudgetMonetaryHoldStateView,
    pub(crate) revocation_set: CanonicalRevocationSetView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CombinedAdmissionCaptureRequest {
    pub(crate) operation_id: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetMutationAuthorityView>,
    pub(crate) revocation_set: CanonicalRevocationSetView,
    pub(crate) bound_revocation_set_digest: String,
    pub(crate) authorization_artifact_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_observed_revocation_index: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdmissionCaptureOutcomeView {
    Captured,
    DeniedRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetGuaranteeLevelView {
    SingleNodeAtomic,
    HaLinearizable,
    PartitionEscrowed,
    AdvisoryPosthoc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionCaptureMetadataView {
    pub(crate) operation_id: String,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) checked_revocation_set_digest: String,
    pub(crate) invocation_quotas: Vec<BudgetInvocationQuotaView>,
    pub(crate) authorization_artifact_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit_index: Option<u64>,
    pub(crate) revocation_commit_index: u64,
    pub(crate) authority_commit_index: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) leader_epoch: Option<u64>,
    pub(crate) guarantee_level: BudgetGuaranteeLevelView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority: Option<BudgetMutationAuthorityView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CombinedAdmissionCaptureResponse {
    pub(crate) operation_id: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) outcome: AdmissionCaptureOutcomeView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget: Option<CaptureInvocationReservationsResponse>,
    pub(crate) revocation_set: CanonicalRevocationSetView,
    pub(crate) revoked_capability_ids: Vec<String>,
    pub(crate) metadata: AdmissionCaptureMetadataView,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn quota(profile: BudgetQuotaProfileView, owner_id: &str) -> BudgetInvocationQuotaView {
        BudgetInvocationQuotaView {
            key: BudgetQuotaKeyView {
                profile,
                owner_id: owner_id.to_string(),
                grant_index: matches!(profile, BudgetQuotaProfileView::GrantInvocation)
                    .then_some(2),
            },
            max_invocations: 9,
        }
    }

    fn usage(profile: BudgetQuotaProfileView, owner_id: &str) -> BudgetInvocationQuotaUsageView {
        BudgetInvocationQuotaUsageView {
            quota: quota(profile, owner_id),
            reserved_invocations_after: 1,
            captured_invocations_after: 2,
        }
    }

    fn revocation_set() -> CanonicalRevocationSetView {
        CanonicalRevocationSetView {
            ids: vec!["cap-leaf".to_string(), "cap-root".to_string()],
            digest: "11".repeat(32),
        }
    }

    fn admission_evidence() -> BudgetInvocationAdmissionEvidenceView {
        BudgetInvocationAdmissionEvidenceView {
            invocation_quotas: vec![
                quota(BudgetQuotaProfileView::GrantInvocation, "cap-leaf"),
                quota(
                    BudgetQuotaProfileView::AggregateFamilyInvocation,
                    &"22".repeat(32),
                ),
                quota(
                    BudgetQuotaProfileView::SupplementalBrokerExecution,
                    &"33".repeat(32),
                ),
            ],
            revocation_set: revocation_set(),
            aggregate_binding_digest: Some("44".repeat(32)),
            supplemental_binding: Some(BudgetSupplementalQuotaBindingView {
                artifact_digest: "55".repeat(32),
                verifier_id: "broker-capability-verifier-v1".to_string(),
                request_binding_hash: "66".repeat(32),
                negotiated_features_digest: "77".repeat(32),
            }),
        }
    }

    fn mutation_authority() -> BudgetMutationAuthorityView {
        BudgetMutationAuthorityView {
            authority_id: "https://leader-a.example".to_string(),
            lease_id: "https://leader-a.example#term-7".to_string(),
            lease_epoch: 7,
        }
    }

    fn authority_metadata() -> BudgetAuthorityMetadataView {
        BudgetAuthorityMetadataView {
            authority_id: "https://leader-a.example".to_string(),
            leader_url: "https://leader-a.example".to_string(),
            budget_term: 7,
            lease_id: "https://leader-a.example#term-7".to_string(),
            lease_epoch: 7,
            lease_expires_at: 9_000,
            lease_ttl_ms: 750,
            guarantee_level: "ha_linearizable".to_string(),
            budget_commit_index: Some(42),
        }
    }

    fn budget_commit() -> BudgetWriteCommitView {
        BudgetWriteCommitView {
            budget_seq: 42,
            commit_index: 42,
            quorum_committed: true,
            quorum_size: 2,
            committed_nodes: 2,
            witness_urls: vec![
                "https://leader-a.example".to_string(),
                "https://follower-b.example".to_string(),
            ],
            authority_id: "https://leader-a.example".to_string(),
            budget_term: 7,
            lease_id: "https://leader-a.example#term-7".to_string(),
            lease_epoch: 7,
        }
    }

    fn assert_round_trip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let encoded = serde_json::to_value(value).test_unwrap();
        let decoded: T = serde_json::from_value(encoded.clone()).test_unwrap();
        let reencoded = serde_json::to_value(decoded).test_unwrap();
        assert_eq!(reencoded, encoded);
    }

    fn assert_unknown_field_rejected<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let mut encoded = serde_json::to_value(value).test_unwrap();
        encoded
            .as_object_mut()
            .test_unwrap()
            .insert("rogueField".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<T>(encoded).is_err());
    }

    #[test]
    fn structured_quota_and_admission_evidence_round_trip_exactly() {
        let evidence = admission_evidence();
        let encoded = serde_json::to_value(&evidence).test_unwrap();

        assert_eq!(
            encoded["invocationQuotas"][0]["key"]["profile"],
            "chio.grant-invocation.v1"
        );
        assert_eq!(encoded["invocationQuotas"][0]["key"]["grantIndex"], 2);
        assert!(encoded["invocationQuotas"][1]["key"]
            .get("grantIndex")
            .is_none());
        assert_eq!(
            encoded["supplementalBinding"]["requestBindingHash"],
            "66".repeat(32)
        );

        assert_round_trip(&evidence);
        assert_unknown_field_rejected(&evidence);
        assert_unknown_field_rejected(&evidence.invocation_quotas[0].key);
        assert_unknown_field_rejected(&evidence.invocation_quotas[0]);
        assert_unknown_field_rejected(&usage(BudgetQuotaProfileView::GrantInvocation, "cap-leaf"));
        assert_unknown_field_rejected(&evidence.revocation_set);
        assert_unknown_field_rejected(evidence.supplemental_binding.as_ref().test_unwrap());

        let mut key = encoded["invocationQuotas"][0]["key"].clone();
        key.as_object_mut()
            .test_unwrap()
            .insert("unknown".to_string(), serde_json::json!(1));
        assert!(serde_json::from_value::<BudgetQuotaKeyView>(key).is_err());
        assert!(
            serde_json::from_value::<BudgetQuotaProfileView>(serde_json::json!("chio.unknown.v1"))
                .is_err()
        );
    }

    #[test]
    fn composite_authorize_contract_round_trips_without_caller_authority() {
        let request = CompositeBudgetAuthorizeRequest {
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            requested_exposure_units: 120,
            max_exposure_per_invocation: Some(150),
            max_total_exposure_units: Some(900),
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:authorize".to_string(),
            admission_evidence: admission_evidence(),
        };
        let encoded = serde_json::to_value(&request).test_unwrap();
        assert_eq!(encoded["requestedExposureUnits"], 120);
        assert_eq!(encoded["maxExposurePerInvocation"], 150);
        assert_eq!(encoded["maxTotalExposureUnits"], 900);
        assert!(encoded.get("budgetAuthority").is_none());
        assert_round_trip(&request);
        assert_unknown_field_rejected(&request);

        let response = CompositeBudgetAuthorizeResponse {
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:authorize".to_string(),
            allowed: true,
            authorized_exposure_units: Some(120),
            attempted_exposure_units: None,
            committed_cost_units_after: 120,
            invocation_count_after: 3,
            invocation_counts_after: vec![usage(
                BudgetQuotaProfileView::GrantInvocation,
                "cap-leaf",
            )],
            invocation_state: BudgetInvocationReservationStateView::Authorized,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            admission_evidence: admission_evidence(),
            budget_authority: Some(authority_metadata()),
            budget_commit: Some(budget_commit()),
        };
        assert_round_trip(&response);
        assert_unknown_field_rejected(&response);
    }

    #[test]
    fn invocation_capture_contract_is_distinct_from_monetary_capture() {
        let request = CaptureInvocationReservationsRequest {
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:capture-invocations".to_string(),
            budget_authority: Some(mutation_authority()),
        };
        let encoded = serde_json::to_value(&request).test_unwrap();
        assert_eq!(encoded["eventId"], "hold-42:capture-invocations");
        assert!(encoded.get("authorizedExposureUnits").is_none());
        assert!(encoded.get("realizedSpendUnits").is_none());
        assert_round_trip(&request);
        assert_unknown_field_rejected(&request);

        let response = CaptureInvocationReservationsResponse {
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:capture-invocations".to_string(),
            exposure_units: 120,
            realized_spend_units: 0,
            committed_cost_units_after: 120,
            invocation_count_after: 3,
            invocation_counts_after: vec![usage(
                BudgetQuotaProfileView::GrantInvocation,
                "cap-leaf",
            )],
            invocation_state: BudgetInvocationReservationStateView::Captured,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            revocation_set: revocation_set(),
            budget_authority: Some(authority_metadata()),
            budget_commit: Some(budget_commit()),
        };
        let encoded = serde_json::to_value(&response).test_unwrap();
        assert_eq!(encoded["exposureUnits"], 120);
        assert_eq!(encoded["realizedSpendUnits"], 0);
        assert_round_trip(&response);
        assert_unknown_field_rejected(&response);
    }

    #[test]
    fn combined_admission_capture_contract_round_trips_all_commit_evidence() {
        let request = CombinedAdmissionCaptureRequest {
            operation_id: "operation-42".to_string(),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:combined-capture".to_string(),
            budget_authority: Some(mutation_authority()),
            revocation_set: revocation_set(),
            bound_revocation_set_digest: "11".repeat(32),
            authorization_artifact_digests: vec!["55".repeat(32)],
            last_observed_revocation_index: Some(40),
        };
        let encoded = serde_json::to_value(&request).test_unwrap();
        assert_eq!(encoded["lastObservedRevocationIndex"], 40);
        assert_eq!(encoded["authorizationArtifactDigests"][0], "55".repeat(32));
        assert_round_trip(&request);
        assert_unknown_field_rejected(&request);

        let metadata = AdmissionCaptureMetadataView {
            operation_id: "operation-42".to_string(),
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:combined-capture".to_string(),
            checked_revocation_set_digest: "11".repeat(32),
            invocation_quotas: admission_evidence().invocation_quotas,
            authorization_artifact_digests: vec!["55".repeat(32)],
            budget_commit_index: Some(42),
            revocation_commit_index: 42,
            authority_commit_index: 42,
            leader_epoch: Some(7),
            guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
            authority: Some(mutation_authority()),
        };
        assert_round_trip(&metadata);
        assert_unknown_field_rejected(&metadata);
        let response = CombinedAdmissionCaptureResponse {
            operation_id: "operation-42".to_string(),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:combined-capture".to_string(),
            outcome: AdmissionCaptureOutcomeView::Captured,
            budget: Some(CaptureInvocationReservationsResponse {
                capability_id: "cap-leaf".to_string(),
                grant_index: 2,
                hold_id: "hold-42".to_string(),
                event_id: "hold-42:combined-capture".to_string(),
                exposure_units: 120,
                realized_spend_units: 0,
                committed_cost_units_after: 120,
                invocation_count_after: 3,
                invocation_counts_after: vec![usage(
                    BudgetQuotaProfileView::GrantInvocation,
                    "cap-leaf",
                )],
                invocation_state: BudgetInvocationReservationStateView::Captured,
                monetary_state: BudgetMonetaryHoldStateView::Exposed,
                revocation_set: revocation_set(),
                budget_authority: Some(authority_metadata()),
                budget_commit: Some(budget_commit()),
            }),
            revocation_set: revocation_set(),
            revoked_capability_ids: Vec::new(),
            metadata,
        };
        let encoded = serde_json::to_value(&response).test_unwrap();
        assert_eq!(encoded["outcome"], "captured");
        assert_eq!(encoded["metadata"]["budgetCommitIndex"], 42);
        assert_eq!(encoded["metadata"]["revocationCommitIndex"], 42);
        assert_eq!(encoded["metadata"]["authorityCommitIndex"], 42);
        assert_eq!(encoded["metadata"]["leaderEpoch"], 7);
        assert_eq!(encoded["budget"]["invocationState"], "captured");
        assert_round_trip(&response);
        assert_unknown_field_rejected(&response);

        let denied = CombinedAdmissionCaptureResponse {
            operation_id: "operation-43".to_string(),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-43".to_string(),
            event_id: "hold-43:combined-capture".to_string(),
            outcome: AdmissionCaptureOutcomeView::DeniedRevoked,
            budget: None,
            revocation_set: revocation_set(),
            revoked_capability_ids: vec!["cap-root".to_string()],
            metadata: AdmissionCaptureMetadataView {
                operation_id: "operation-43".to_string(),
                hold_id: "hold-43".to_string(),
                event_id: "hold-43:combined-capture".to_string(),
                checked_revocation_set_digest: "11".repeat(32),
                invocation_quotas: admission_evidence().invocation_quotas,
                authorization_artifact_digests: vec!["55".repeat(32)],
                budget_commit_index: None,
                revocation_commit_index: 43,
                authority_commit_index: 43,
                leader_epoch: Some(7),
                guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
                authority: Some(mutation_authority()),
            },
        };
        let encoded = serde_json::to_value(&denied).test_unwrap();
        assert_eq!(encoded["outcome"], "denied_revoked");
        assert!(encoded.get("budget").is_none());
        assert_eq!(encoded["revokedCapabilityIds"][0], "cap-root");
        assert_round_trip(&denied);
        assert_unknown_field_rejected(&denied);
    }

    #[test]
    fn dedicated_admission_paths_are_stable() {
        assert_eq!(BUDGET_AUTHORIZE_HOLD_PATH, "/v1/budgets/authorize-hold");
        assert_eq!(
            BUDGET_CAPTURE_INVOCATIONS_PATH,
            "/v1/budgets/capture-invocations"
        );
        assert_eq!(ADMISSION_CAPTURE_PATH, "/v1/admissions/capture");
    }
}
