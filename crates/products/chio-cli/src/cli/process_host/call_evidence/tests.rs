use super::*;
use chio_core::{
    capability::token::CapabilityTokenBody,
    crypto::Keypair,
    receipt::{body::ChioReceiptBody, decision::ToolCallAction},
};
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantClaimIntentInput,
    RuntimeParticipantClaimIntentV1, RuntimeParticipantResourceV1,
};
use chio_kernel::admission_operation::RuntimeParticipantKind;
use chio_kernel::admission_operation::{
    expected_dispatch_committed_version, AdmissionCompensationStatus, AdmissionIdentifier,
    AdmissionOperationBindingInputV1, AdmissionOperationV1, AdmissionParticipantRequirements,
    AdmissionReceiptSchema, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
    SideEffectClass, StoreMutationFence,
};

const RUNTIME: &str = "714d3643-e7f7-42f9-95b5-6a3a0d734ce8";
const OBSERVED_AT: u64 = 1_700_000_000_000;
const UNKNOWN_ERROR: &str = "unknown operation must retain uncertainty without a terminal result";
const COMPENSATED_ERROR: &str =
    "compensated operation must be denied without retained dispatch custody";
const PROJECTION_ERROR: &str =
    "operation readback differs from original signed admission projection";
const REFUSAL_STATES: [AdmissionOperationState; 2] = [
    AdmissionOperationState::OutcomeUnknownAfterDispatch,
    AdmissionOperationState::CompensatedBeforeDispatch,
];

fn refusal_error(state: AdmissionOperationState) -> &'static str {
    match state {
        AdmissionOperationState::OutcomeUnknownAfterDispatch => UNKNOWN_ERROR,
        _ => COMPENSATED_ERROR,
    }
}

fn assert_signed_dispatch_commit_without_launch_is_refused(
    decision: Decision,
) -> Result<(), CliError> {
    let mut fixture = SemanticRefusal::new(
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        decision,
    )?;
    receipt(&fixture.call, &fixture.key.public_key())?;
    let mut operation = serde_json::to_value(&fixture.operation).map_err(error)?;
    let _: Operation = serde_json::from_value(operation.clone()).map_err(error)?;
    let commit = operation["dispatch_commit"]
        .as_object_mut()
        .ok_or_else(|| error("missing synthetic dispatch commit"))?;
    assert_eq!(
        commit.remove("dispatch_launch"),
        Some(json!({"native_launch": null, "worker_profile": null})),
    );
    let mut body = fixture.call.body();
    body.action = ToolCallAction::from_parameters(operation).map_err(error)?;
    body.content_hash = hash(&body.action.parameters)?;
    let signed = ChioReceipt::sign(body, &fixture.key).map_err(error)?;
    let signed = crate::receipt_verify::verify_original_receipt(
        &serde_json::to_string(&signed).map_err(error)?,
        &fixture.key.public_key(),
    )?;
    assert_eq!(
        serde_json::from_value::<Operation>(signed.action.parameters)
            .err()
            .map(|failure| failure.to_string()),
        Some("missing field `dispatch_launch`".to_owned()),
    );

    let _: AdmissionReceiptMetadataV1 =
        serde_json::from_value(fixture.metadata()?["admission_operation"].clone())
            .map_err(error)?;
    let commit = fixture.metadata()?["admission_operation"]["retained_dispatch_commit"]
        .as_object_mut()
        .ok_or_else(|| error("missing synthetic signed dispatch commit"))?;
    assert_eq!(
        commit.remove("dispatch_launch"),
        Some(json!({"native_launch": null, "worker_profile": null})),
    );
    fixture.resign()?;
    assert_eq!(
        serde_json::from_value::<AdmissionReceiptMetadataV1>(
            fixture.metadata()?["admission_operation"].clone(),
        )
        .err()
        .map(|failure| failure.to_string()),
        Some("missing field `dispatch_launch`".to_owned()),
    );
    Ok(())
}

#[test]
fn interrupted_incident_dispatch_commit_without_its_launch_is_refused() -> Result<(), CliError> {
    assert_signed_dispatch_commit_without_launch_is_refused(Decision::Incomplete {
        reason: "upstream process exited before responding".into(),
    })
}

#[test]
fn unknown_incident_dispatch_commit_without_its_launch_is_refused() -> Result<(), CliError> {
    assert_signed_dispatch_commit_without_launch_is_refused(kernel_denial())
}

struct SemanticRefusal {
    operation: Operation,
    call: ChioReceipt,
    cap: CapabilityToken,
    key: Keypair,
}

impl SemanticRefusal {
    fn new(state: AdmissionOperationState, decision: Decision) -> Result<Self, CliError> {
        let key = Keypair::generate();
        let cap = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "semantic-refusal-capability".into(),
                issuer: key.public_key(),
                subject: key.public_key(),
                scope: Default::default(),
                issued_at: OBSERVED_AT / 1_000,
                expires_at: OBSERVED_AT / 1_000 + 60,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &key,
        )
        .map_err(error)?;
        let action =
            ToolCallAction::from_parameters(json!({"message": "refused"})).map_err(error)?;
        let requirements = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        };
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::ToolDispatch,
            namespace: AuthenticatedRequestNamespace::for_local_system(
                AdmissionIdentifier::try_new("coordinator_authority_id", "semantic-authority")
                    .map_err(error)?,
            )
            .map_err(error)?,
            request_id: AdmissionIdentifier::try_new("request_id", "semantic-refusal-request")
                .map_err(error)?,
            capability_id: AdmissionIdentifier::try_new("capability_id", cap.id.clone())
                .map_err(error)?,
            authorization_capability_hash: AdmissionDigest::try_new(
                "authorization_capability_hash",
                hash(&cap)?,
            )
            .map_err(error)?,
            request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
                AdmissionDigest::try_new("immutable_request_hash", hash(&action)?)
                    .map_err(error)?,
                AdmissionDigest::try_new("action_parameter_hash", action.parameter_hash.clone())
                    .map_err(error)?,
                requirements,
            )
            .map_err(error)?,
            policy_hash: AdmissionDigest::try_new("policy_hash", "a".repeat(64)).map_err(error)?,
            effect_class: SideEffectClass::SideEffecting,
        })
        .map_err(error)?;
        let fence = StoreMutationFence {
            store_uuid: "semantic-store".into(),
            lease_id: "semantic-store-lease".into(),
            owner_epoch: 1,
        };
        let coordinator_lease_id =
            AdmissionIdentifier::try_new("coordinator_lease_id", "semantic-coordinator-lease")
                .map_err(error)?;
        let dispatch_commit = if state == AdmissionOperationState::OutcomeUnknownAfterDispatch {
            Some(AdmissionDispatchCommitBindingV1 {
                dispatch_launch: Default::default(),
                committed_version: expected_dispatch_committed_version(
                    AdmissionOperationKind::ToolDispatch,
                    requirements,
                    1,
                )
                .map_err(error)?,
                coordinator_lease_id: coordinator_lease_id.clone(),
                coordinator_lease_epoch: 1,
                store_fence: fence.clone(),
                provider_attempt: Some(
                    chio_core_types::provider_attempt::ProviderAttemptBindingV1 {
                        operation_id: binding.operation_id().as_str().into(),
                        attempt_id: "semantic-attempt".into(),
                        transport_id: "kernel-tool-server:semantic-server".into(),
                        transport_key_epoch: 1,
                    },
                ),
            })
        } else {
            None
        };
        let version = dispatch_commit
            .as_ref()
            .map_or(2, |commit| commit.committed_version + 1);
        let projection = AdmissionReceiptMetadataV1 {
            schema: AdmissionReceiptSchema::V1,
            operation_id: binding.operation_id().clone(),
            request_id: binding.request_id().clone(),
            request_namespace_digest: binding.request_namespace_digest().clone(),
            request_binding_hash: binding.request_binding_hash().clone(),
            projected_operation_version: version,
            projected_state: state,
            projected_dispatch_state: AdmissionDispatchState::Terminal,
            trusted_time_unix_ms: OBSERVED_AT,
            coordinator_lease_id,
            coordinator_lease_epoch: 1,
            store_fence: fence,
            retained_dispatch_commit: dispatch_commit.clone(),
            compensation_status: if state == AdmissionOperationState::OutcomeUnknownAfterDispatch {
                AdmissionCompensationStatus::NotCompensated
            } else {
                AdmissionCompensationStatus::CompensatedBeforeDispatch
            },
            tool_outcome_id: None,
            tool_outcome_version: None,
        };
        let call = ChioReceipt::sign(
            ChioReceiptBody {
                id: String::new(),
                timestamp: OBSERVED_AT / 1_000,
                capability_id: cap.id.clone(),
                tool_server: "semantic-server".into(),
                tool_name: "semantic-tool".into(),
                action,
                decision: Some(decision),
                receipt_kind: ReceiptKind::default(),
                boundary_class: BoundaryClass::default(),
                observation_outcome: None,
                tool_origin: ToolOrigin::default(),
                redaction_mode: RedactionMode::default(),
                actor_chain: Vec::new(),
                content_hash: hash(&Value::Null)?,
                policy_hash: binding.policy_hash().as_str().into(),
                evidence: Vec::new(),
                metadata: Some(json!({
                    "receipt_context": {
                        "request_id": binding.request_id().as_str(),
                        "request_namespace_digest": binding.request_namespace_digest().as_str(),
                    },
                    "admission_operation": projection,
                })),
                trust_level: TrustLevel::default(),
                tenant_id: None,
                kernel_key: key.public_key(),
                bbs_projection_version: None,
            },
            &key,
        )
        .map_err(error)?;
        let operation = Operation {
            binding: binding.to_persisted(),
            state,
            version,
            dispatch_state: AdmissionDispatchState::Terminal,
            dispatch_commit,
            terminal_replay: Some(AdmissionTerminalReplay::Receipt {
                receipt_id: AdmissionIdentifier::try_new("receipt_id", call.id.clone())
                    .map_err(error)?,
                projection_digest: AdmissionDigest::try_new(
                    "projection_digest",
                    hash(&projection)?,
                )
                .map_err(error)?,
            }),
            execution_nonce_issuance_digest: None,
            history: Vec::new(),
        };
        Ok(Self {
            operation,
            call,
            cap,
            key,
        })
    }

    fn resign(&mut self) -> Result<(), CliError> {
        self.call = ChioReceipt::sign(self.call.body(), &self.key).map_err(error)?;
        self.operation.terminal_replay = Some(AdmissionTerminalReplay::Receipt {
            receipt_id: AdmissionIdentifier::try_new("receipt_id", self.call.id.clone())
                .map_err(error)?,
            projection_digest: AdmissionDigest::try_new("projection_digest", "b".repeat(64))
                .map_err(error)?,
        });
        receipt(&self.call, &self.key.public_key())
    }

    fn metadata(&mut self) -> Result<&mut Value, CliError> {
        self.call
            .metadata
            .as_mut()
            .ok_or_else(|| error("missing semantic refusal metadata"))
    }

    fn verify(&self) -> Result<(), CliError> {
        verify_operation_with_runtime(
            Some(&self.operation),
            &self.call,
            &self.cap,
            RUNTIME,
            OBSERVED_AT,
            false,
        )
    }

    fn assert_rejected(&self, expected: &str) {
        assert_eq!(
            self.verify().map_err(|failure| failure.to_string()),
            Err(error(expected).to_string()),
        );
    }
}

fn kernel_denial() -> Decision {
    Decision::Deny {
        guard: "kernel".into(),
        reason: "operation refused".into(),
    }
}

#[test]
fn semantic_refusals_accept_bound_signed_denials_and_cancellations() -> Result<(), CliError> {
    for state in REFUSAL_STATES {
        for decision in [
            kernel_denial(),
            Decision::Cancelled {
                reason: "caller cancelled".into(),
            },
        ] {
            let fixture = SemanticRefusal::new(state, decision)?;
            receipt(&fixture.call, &fixture.key.public_key())?;
            assert!(fixture.cap.verify_signature().map_err(error)?);
            fixture.verify()?;
        }
    }
    Ok(())
}

#[test]
fn semantic_refusals_require_the_exact_terminal_receipt() -> Result<(), CliError> {
    for state in REFUSAL_STATES {
        let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
        fixture.operation.terminal_replay = Some(AdmissionTerminalReplay::Receipt {
            receipt_id: AdmissionIdentifier::try_new("receipt_id", "another-receipt")
                .map_err(error)?,
            projection_digest: AdmissionDigest::try_new("projection_digest", "b".repeat(64))
                .map_err(error)?,
        });
        fixture.assert_rejected(refusal_error(state));
        fixture.operation.terminal_replay = Some(AdmissionTerminalReplay::Incident {
            incident_id: AdmissionIdentifier::try_new("incident_id", "retained-incident")
                .map_err(error)?,
            projection_digest: AdmissionDigest::try_new("projection_digest", "b".repeat(64))
                .map_err(error)?,
        });
        fixture.assert_rejected(refusal_error(state));
        fixture.operation.terminal_replay = None;
        fixture.assert_rejected(refusal_error(state));
    }
    Ok(())
}

#[test]
fn semantic_refusals_reject_foreign_signed_namespaces() -> Result<(), CliError> {
    for state in REFUSAL_STATES {
        for field in ["admission_operation", "receipt_context"] {
            let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
            fixture.metadata()?[field]["request_namespace_digest"] = json!("0".repeat(64));
            fixture.resign()?;
            fixture.assert_rejected(PROJECTION_ERROR);
        }
    }
    Ok(())
}

#[test]
fn semantic_refusals_reject_tool_outcomes_and_non_null_content() -> Result<(), CliError> {
    for state in REFUSAL_STATES {
        for (field, value) in [
            ("tool_outcome_id", json!("c".repeat(64))),
            ("tool_outcome_version", json!(1)),
        ] {
            let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
            fixture.metadata()?["admission_operation"][field] = value;
            fixture.resign()?;
            fixture.assert_rejected(refusal_error(state));
        }
        let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
        fixture.call.content_hash = hash(&json!({"output": "unexpected"}))?;
        fixture.resign()?;
        fixture.assert_rejected(refusal_error(state));
    }
    Ok(())
}

#[test]
fn semantic_refusals_require_projection_status_and_receipt_time() -> Result<(), CliError> {
    for state in REFUSAL_STATES {
        let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
        fixture.metadata()?["admission_operation"]["compensation_status"] =
            json!("not_accepted_after_dispatch_commit");
        fixture.resign()?;
        fixture.assert_rejected(refusal_error(state));

        let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
        fixture.call.timestamp += 1;
        fixture.resign()?;
        fixture.assert_rejected(refusal_error(state));

        let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
        fixture
            .metadata()?
            .as_object_mut()
            .ok_or_else(|| error("semantic refusal metadata is not an object"))?
            .remove("admission_operation");
        fixture.resign()?;
        fixture.assert_rejected(refusal_error(state));
    }
    Ok(())
}

#[test]
fn semantic_refusals_reject_allow_incomplete_and_foreign_guard_decisions() -> Result<(), CliError> {
    for state in REFUSAL_STATES {
        for decision in [
            Decision::Allow,
            Decision::Incomplete {
                reason: "interrupted".into(),
            },
            Decision::Deny {
                guard: "another-guard".into(),
                reason: "unrelated denial".into(),
            },
        ] {
            let fixture = SemanticRefusal::new(state, decision)?;
            fixture.assert_rejected(refusal_error(state));
        }
    }
    Ok(())
}

#[test]
fn semantic_refusals_reject_foreign_tenants_and_operation_projections() -> Result<(), CliError> {
    for state in REFUSAL_STATES {
        let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
        fixture.call.tenant_id = Some("foreign-tenant".into());
        fixture.resign()?;
        fixture.assert_rejected(PROJECTION_ERROR);
        for field in ["projected_operation_version", "request_binding_hash"] {
            let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
            fixture.metadata()?["admission_operation"][field] =
                if field == "projected_operation_version" {
                    json!(999)
                } else {
                    json!("0".repeat(64))
                };
            fixture.resign()?;
            fixture.assert_rejected(PROJECTION_ERROR);
        }
        let mut fixture = SemanticRefusal::new(state, kernel_denial())?;
        fixture.call.capability_id = "foreign-capability".into();
        fixture.resign()?;
        fixture.assert_rejected("retained operation differs from call binding");
    }
    Ok(())
}

impl SemanticRefusal {
    fn with_runtime(reference_in_receipt: bool) -> Result<Self, CliError> {
        let mut fixture = Self::new(
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
            kernel_denial(),
        )?;
        let binding =
            AdmissionOperationBindingV1::from_persisted(fixture.operation.binding.clone())
                .map_err(error)?;
        let operation = AdmissionOperationV1::prepare(binding.clone(), 1)
            .map_err(error)?
            .to_persisted();
        let intent = RuntimeParticipantClaimIntentV1::new(RuntimeParticipantClaimIntentInput {
            episode_id: AdmissionIdentifier::try_new("episode_id", "semantic-episode")
                .map_err(error)?,
            runtime_authority_id: AdmissionIdentifier::try_new("runtime_authority_id", RUNTIME)
                .map_err(error)?,
            qualification_id: AdmissionIdentifier::try_new(
                "qualification_id",
                "semantic-qualification",
            )
            .map_err(error)?,
            request_binding_hash: binding.request_binding_hash().clone(),
            grant_index: 0,
            phase: RuntimeParticipantPhase::Dispatch,
            plan_digest: AdmissionDigest::try_new("plan_digest", "c".repeat(64)).map_err(error)?,
            resources: vec![RuntimeParticipantResourceV1::new(
                RuntimeParticipantKind::SwarmContinuation,
                AdmissionIdentifier::try_new("resource_id", "semantic-continuation")
                    .map_err(error)?,
                AdmissionDigest::try_new("artifact_digest", "d".repeat(64)).map_err(error)?,
            )],
        })
        .map_err(error)?;
        let claim = json!({
            "schema": "chio.runtime-participant-claim.v1",
            "operationId": binding.operation_id(),
            "intent": intent,
            "ledgerDigest": "e".repeat(64),
            "recordedAtUnixMs": OBSERVED_AT,
        });
        let reference = RuntimeParticipantClaimReferenceV1::new(
            binding.operation_id().clone(),
            intent.episode_id().clone(),
            AdmissionDigest::try_new(
                "claim_digest",
                hash(&(
                    "chio.runtime-participant-claim-commit.v1",
                    (&claim, &operation),
                ))?,
            )
            .map_err(error)?,
        );
        if reference_in_receipt {
            fixture.metadata()?["chio_runtime"] = json!({"operation_owned_replay": {
                "reference": reference,
                "plan_sha256": intent.plan_digest(),
                "resources_sha256": hash(&intent.resources())?,
            }});
            fixture.resign()?;
        }
        let evidence = RuntimeParticipantClaimEvidenceV1 {
            history: RuntimeParticipantClaimHistoryV1 {
                reference,
                intent,
                disposition: RuntimeParticipantDisposition::RetainedAfterDispatchCommit,
            },
            claim,
            operation,
        };
        evidence.verify().map_err(error)?;
        fixture.operation.history.push(evidence);
        Ok(fixture)
    }

    fn verify_runtime(&self) -> Result<(), CliError> {
        verify_operation(
            Some(&self.operation),
            &self.call,
            &self.cap,
            RUNTIME,
            OBSERVED_AT,
        )
    }

    fn assert_runtime_rejected(&self, expected: &str) {
        assert_eq!(
            self.verify_runtime().map_err(|failure| failure.to_string()),
            Err(error(expected).to_string())
        );
    }
}

#[test]
fn canonical_unknown_receipts_retain_live_and_recovery_custody() -> Result<(), CliError> {
    for reference_in_receipt in [false, true] {
        let fixture = SemanticRefusal::with_runtime(reference_in_receipt)?;
        receipt(&fixture.call, &fixture.key.public_key())?;
        fixture.verify_runtime()?;
    }
    Ok(())
}

#[test]
fn canonical_unknown_receipts_reject_missing_duplicate_and_substituted_history(
) -> Result<(), CliError> {
    for reference_in_receipt in [false, true] {
        let mut fixture = SemanticRefusal::with_runtime(reference_in_receipt)?;
        fixture.operation.history.clear();
        fixture.assert_runtime_rejected(
            "call continuation custody is missing or contradicts dispatch",
        );
        let mut fixture = SemanticRefusal::with_runtime(reference_in_receipt)?;
        fixture
            .operation
            .history
            .push(fixture.operation.history[0].clone());
        fixture.assert_runtime_rejected("substituted or duplicate continuation episode");
        let mut fixture = SemanticRefusal::with_runtime(reference_in_receipt)?;
        fixture.operation.history[0].claim["intent"]["expectationId"] = json!("foreign-generation");
        fixture.assert_runtime_rejected("admission operation invariant failed: runtime claim commitment differs from its history");
    }
    let mut fixture = SemanticRefusal::with_runtime(true)?;
    fixture.operation.history[0].history.disposition =
        RuntimeParticipantDisposition::ReleasedBeforeDispatch;
    fixture.assert_runtime_rejected("retained continuation contradicts dispatch custody");
    Ok(())
}

#[test]
fn canonical_unknown_receipts_reject_substituted_signed_custody_references() -> Result<(), CliError>
{
    for field in ["plan_sha256", "resources_sha256"] {
        let mut fixture = SemanticRefusal::with_runtime(true)?;
        fixture.metadata()?["chio_runtime"]["operation_owned_replay"][field] =
            json!("0".repeat(64));
        fixture.resign()?;
        fixture
            .assert_runtime_rejected("retained continuation differs from original signed receipt");
    }
    let mut fixture = SemanticRefusal::with_runtime(true)?;
    fixture.metadata()?["chio_runtime"]["operation_owned_replay"]["reference"]["claimDigest"] =
        json!("0".repeat(64));
    fixture.resign()?;
    fixture.assert_runtime_rejected("unreferenced continuation episode remains live");
    Ok(())
}

#[test]
fn signed_evidence_refuses_a_repeated_parameter_key_before_projection() -> Result<(), CliError> {
    let fixture = SemanticRefusal::new(
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        kernel_denial(),
    )?;
    let mut body = fixture.call.body();
    body.action =
        ToolCallAction::from_parameters(json!({"capabilities": {"root": "cap"}})).map_err(error)?;
    body.content_hash = hash(&body.action.parameters)?;
    let text = serde_json::to_string(&ChioReceipt::sign(body, &fixture.key).map_err(error)?)
        .map_err(error)?;
    let key = fixture.key.public_key();
    crate::receipt_verify::verify_original_receipt(&text, &key)?;

    let member = r#""root":"cap""#;
    assert_eq!(text.matches(member).count(), 1);
    let repeated = text.replacen(member, &format!("{member},{member}"), 1);
    assert!(matches!(
        crate::receipt_verify::verify_original_receipt(&repeated, &key),
        Err(CliError::SignedJson(
            chio_core::canonical::UntrustedJsonError::Canonicalization(
                chio_core::Error::CanonicalJson(message)
            )
        )) if message.starts_with(r#"invalid I-JSON input: duplicate object key: "root""#)
    ));
    Ok(())
}
