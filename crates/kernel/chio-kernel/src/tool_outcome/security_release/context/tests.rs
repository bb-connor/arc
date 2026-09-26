//! Check the private context boundary independently of caller-side preparation.
use super::*;
use crate::tool_outcome::{test_support, tests as fixtures};
use crate::{ToolCallChunk, ToolCallOutput, ToolCallStream};
use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    operation: AdmissionOperationV1,
    raw: RawInvocationOutcomeV1,
    outcome: ToolOutcomeRecordV1,
    evaluation: PostReturnEvaluationRecordV1,
    output: ToolCallOutput,
    preimage: Vec<u8>,
    record: SecurityReleaseRecordV1,
}

impl Fixture {
    fn new(stream: bool) -> TestResult<Self> {
        let operation = fixtures::committed_operation("release-output-binding");
        let signer = Keypair::generate();
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "capability-1".into(),
                issuer: signer.public_key(),
                subject: signer.public_key(),
                scope: ChioScope::default(),
                issued_at: 1,
                expires_at: 2,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &signer,
        )?;
        let request: ToolCallRequest = serde_json::from_value(json!({
            "request_id": "release-output-binding", "capability": capability,
            "agent_id": signer.public_key().to_hex(), "arguments": {},
            "server_id": "tool-outcome-test-server", "tool_name": "tool-outcome-test-tool"
        }))?;
        let (raw, _) = test_support::returned_value(
            &operation,
            fixtures::fence(),
            900,
            json!({"raw": true}),
            None,
        )?;
        let mut raw = RawInvocationOutcomeV1::from_canonical_bytes(raw.bytes())?.to_persisted();
        raw.schema = RAW_INVOCATION_OUTCOME_WITH_SECURITY_RELEASE_SCHEMA.into();
        raw.request_canonical_json = Some(String::from_utf8(canonical(&request)?)?);
        raw.security_invocation_context = Some(crate::SecurityInvocationContext::v1(
            crate::SecurityInvocationContextV1::new(
                TenantId::new("tenant")?,
                SessionId::new("session")?,
                PrincipalId::new(request.agent_id.clone())?,
                IsolationEpochId::new("epoch")?,
                LineageId::new(request.capability.id.clone())?,
                1,
            ),
        ));
        raw.security_release_required = Some(true);
        let raw = RawInvocationOutcomeV1::from_persisted(raw)?;
        let outcome = ToolOutcomeRecordV1::record_tool_returned(
            &operation,
            &raw,
            &raw.canonical_blob()?,
            fixtures::fence(),
            900,
        )?;
        let operation = fixtures::advance(
            &operation,
            AdmissionOperationState::Finalizing,
            vec![AdmissionAttachment::ToolOutcomeId(
                outcome.outcome_id().clone(),
            )],
        );
        let evaluation = test_support::prepared_evaluation(&operation, &outcome, 1_000)?;
        let evaluation = test_support::record_pure_step(&evaluation)?;
        let evaluation = test_support::record_external_step(&evaluation, 1_000)?;
        let output = if stream {
            ToolCallOutput::Stream(ToolCallStream {
                chunks: vec![
                    ToolCallChunk {
                        data: json!({"part": 1}),
                    },
                    ToolCallChunk {
                        data: json!({"part": 2}),
                    },
                ],
            })
        } else {
            ToolCallOutput::Value(json!({"allowed": true}))
        };
        let preimage = crate::receipt_support::receipt_content_for_output(Some(&output), None)?
            .canonical_content;
        let (resolution, _) = PostReturnResolutionV1::from_signing_preimage(
            &evaluation,
            preimage.clone(),
            fixtures::admission_digest("guard"),
            fixtures::admission_digest("pricing"),
            SettlementDispositionV1::NotApplicable,
        )?;
        let evaluation = evaluation.transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::Resolve(resolution),
        )?;
        let outcome = outcome.transition(
            outcome.version(),
            ToolOutcomeTransitionV1::Resolve(evaluation.terminal_evidence()?),
        )?;
        let record = SecurityReleaseRecordV1 {
            schema: SCHEMA.into(),
            operation_id: operation.binding().operation_id().clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            dispatch_commitment_id: raw.security_dispatch_commitment_id()?,
            outcome_id: outcome.outcome_id().clone(),
            raw_output_digest: outcome.raw_output_digest().clone(),
            evaluation_id: evaluation.evaluation_id().clone(),
            evaluation_lifecycle_digest: evaluation.lifecycle_digest.clone(),
            resolved_output_digest: AdmissionDigest::try_new("output", sha256_hex(&preimage))?,
            acknowledged_at_unix_ms: 1_001,
            store_fence: fixtures::fence(),
        };
        Ok(Self {
            operation,
            raw,
            outcome,
            evaluation,
            output,
            preimage,
            record,
        })
    }

    fn artifacts(&self) -> SecurityReleaseArtifacts<'_> {
        SecurityReleaseArtifacts {
            operation: &self.operation,
            raw: &self.raw,
            outcome: &self.outcome,
            evaluation: &self.evaluation,
            output: &self.output,
            resolved_output: &self.preimage,
        }
    }
}

#[test]
fn context_rejects_substituted_preimages_and_value_or_stream_payloads() -> TestResult {
    for stream in [false, true] {
        let fixture = Fixture::new(stream)?;
        let context = DurableSecurityReleaseContext::new(&fixture.record, &fixture.artifacts())?;
        assert_eq!(context.output(), &fixture.output);
        let mut wrong_preimage = fixture.preimage.clone();
        wrong_preimage[0] ^= 1;
        assert!(matches!(
            DurableSecurityReleaseContext::new(
                &fixture.record,
                &SecurityReleaseArtifacts {
                    resolved_output: &wrong_preimage,
                    ..fixture.artifacts()
                }
            ),
            Err(ToolOutcomeError::Binding(
                "security_release.output_preimage"
            ))
        ));
        let wrong_output = match fixture.output.clone() {
            ToolCallOutput::Value(_) => ToolCallOutput::Value(json!({"allowed": false})),
            ToolCallOutput::Stream(mut stream) => {
                stream.chunks.reverse();
                ToolCallOutput::Stream(stream)
            }
        };
        assert!(matches!(
            DurableSecurityReleaseContext::new(
                &fixture.record,
                &SecurityReleaseArtifacts {
                    output: &wrong_output,
                    ..fixture.artifacts()
                }
            ),
            Err(ToolOutcomeError::Binding("security_release.output_payload"))
        ));
    }
    Ok(())
}

#[test]
fn context_rejects_other_dispatch_and_evaluation_records() -> TestResult {
    let fixture = Fixture::new(false)?;
    DurableSecurityReleaseContext::new(&fixture.record, &fixture.artifacts())?;
    let mut record = fixture.record.clone();
    record.dispatch_commitment_id = chio_security_types::ports::RecordId::new("another-dispatch")?;
    assert!(matches!(
        DurableSecurityReleaseContext::new(&record, &fixture.artifacts()),
        Err(ToolOutcomeError::Binding("security_release.dispatch"))
    ));
    let mut record = fixture.record.clone();
    record.evaluation_lifecycle_digest = fixtures::admission_digest("another-evaluation");
    assert!(matches!(
        DurableSecurityReleaseContext::new(&record, &fixture.artifacts()),
        Err(ToolOutcomeError::Binding("security_release.records"))
    ));
    Ok(())
}
