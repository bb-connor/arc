use super::*;

pub(super) fn emit_threat_matrix_code(code: &str) {
    if std::env::var_os("CHIO_THREAT_MATRIX_EMIT_CODE").is_some() {
        println!("CHIO_THREAT_MATRIX_CODE={code}");
    }
}

pub(super) fn unanimous_deny_policy_evaluation_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        server_b_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        joint_disposition: Some("deny".to_string()),
    }
}

pub(super) fn treaty_runtime_fixture() -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    treaty_runtime_fixture_with_policy(allow_policy_evaluation_summary())
}

pub(super) fn treaty_runtime_fixture_with_policy(
    policy_evaluation_summary: PolicyEvaluationSummary,
) -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    treaty_runtime_fixture_with_signers(
        policy_evaluation_summary,
        Keypair::generate(),
        Keypair::generate(),
    )
}

pub(super) fn insert_in_memory_treaty_runtime_fixture(
    store: &InMemoryRuntimeAdmissionStore,
    fixture: &TreatyRuntimeFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        &fixture.bilateral_dsse_id,
        &fixture.bilateral_dsse,
    )?;
    Ok(())
}

pub(super) fn deny_policy_bilateral_dsse(
    envelope: &DsseEnvelope,
) -> Result<DsseEnvelope, Box<dyn std::error::Error>> {
    let (mut statement, _) = envelope.decode_statement()?;
    let summary = statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .ok_or_else(|| io::Error::other("fixture DSSE missing policy summary"))?;
    summary.server_b_verdict.verdict = "deny".to_string();
    summary.joint_disposition = Some("deny".to_string());
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            statement.canonical_bytes()?,
        ),
        signatures: envelope.signatures.clone(),
    })
}

#[derive(Debug)]
pub(super) struct RetainedSwarmGraphs(Vec<SwarmAuthorityBundle>);

impl runtime_api::SwarmGraphSource for RetainedSwarmGraphs {
    fn swarm_graph(
        &self,
        graph_id: &str,
        graph_sha256: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        for bundle in &self.0 {
            if bundle.task_graph.graph_id == graph_id
                && canonical_test_hash(&bundle.task_graph)
                    .map_err(|error| ChioRuntimeError::Store(error.to_string()))?
                    == graph_sha256
            {
                return Ok(Some(bundle.clone()));
            }
        }
        Ok(None)
    }
}

pub(super) fn retained_swarm_graphs(
    bundle: &SwarmAuthorityBundle,
) -> std::sync::Arc<RetainedSwarmGraphs> {
    std::sync::Arc::new(RetainedSwarmGraphs(vec![bundle.clone()]))
}
