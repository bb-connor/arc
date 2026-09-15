// Signed, enforced runtime inputs and an independently sealed replay source.
use super::*;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use chio_runtime_core::*;

pub(super) fn install(fixture: &mut Fixture) -> TestResult {
    let now = now_ms()?;
    let expires = now.checked_add(600_000).ok_or("fixture expiry overflow")?;
    let local_kernel = "native-combined-runtime-kernel";
    fixture.kernel.set_federation_local_kernel_id(local_kernel);
    let path = fixture._directory.path().join("native-runtime.db");
    let source = SqliteRuntimeOrchestrationStore::open(&path)?;
    let bundle = RuntimeAdmissionBundle {
        schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.into(),
        admission_id: "native-runtime-admission".into(),
        binding: RuntimeRequestBinding::from_tool_call_request(&fixture.request, local_kernel)?,
        workflow_id: "native-workflow".into(),
        workflow_grant_id: "native-workflow-grant".into(),
        step_index: 1,
        destructive: true,
        lease_id: Some("native-runtime-lease".into()),
        governance_receipt_id: Some("native-runtime-governance".into()),
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
    };
    fixture.request.governed_intent = Some(GovernedTransactionIntent {
        id: fixture.request.request_id.clone(),
        server_id: fixture.request.server_id.clone(),
        tool_name: fixture.request.tool_name.clone(),
        purpose: "native combined security invocation".into(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({"chioAdmission": {
            "admissionId": bundle.admission_id,
            "bundleSha256": runtime_admission_bundle_sha256(&bundle)?,
        }})),
        body: Default::default(),
    });
    source.insert_bundle(bundle)?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let authority = AdmissionIdentifier::try_new("authority", "native-combined-runtime")?;
    let expected = store.expect_runtime_replay_source(
        &AdmissionIdentifier::try_new("source", "native-combined-runtime-source")?,
        &authority,
        &source,
        &fence,
        now_ms()?,
    )?;
    store.import_runtime_replay_source(
        &authority,
        expected.expectation_id(),
        &source,
        &fence,
        now_ms()?,
    )?;
    let binding =
        RuntimeParticipantAuthorityBindingV1::new(authority, expected.expectation_id().clone());
    store.activate_runtime_replay_source(&binding, &source, &fence, now_ms()?)?;
    let verifier = Keypair::generate();
    let verifier_id = "native-runtime-verifier";
    let key_id = "native-runtime-key";
    let weights = RuntimePeerWeights {
        schema: CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.into(),
        verifier_id: verifier_id.into(),
        key_id: key_id.into(),
        reputation_epoch: 1,
        issued_at_unix_ms: now,
        expires_at_unix_ms: expires,
        weights: vec![RuntimePeerWeight {
            peer_kernel_id: local_kernel.into(),
            weight: 1.0,
        }],
    };
    let policy = RuntimePheromonePolicy {
        schema: CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.into(),
        policy_id: "native-runtime-policy".into(),
        verifier_id: verifier_id.into(),
        key_id: key_id.into(),
        policy_version: 1,
        mode: "enforce".into(),
        issued_at_unix_ms: now,
        expires_at_unix_ms: expires,
        allowed_reputation_epochs: vec![1],
        max_query_report_age_ms: 60_000,
        min_distinct_origin_pairs: 1,
        runtime_trust_bundle_sha256: "b".repeat(64),
        peer_weights_sha256: runtime_peer_weights_sha256(&weights)?,
        rules: vec![RuntimePheromonePolicyRule {
            rule_id: "deny-high-risk".into(),
            subject_class: "native-execution".into(),
            subject_class_namespace: "chio.runtime".into(),
            action_class_id: "*".into(),
            direction: "deny_if_at_or_above".into(),
            threshold_total_strength: 0.75,
            effect: "deny".into(),
        }],
    };
    let hook = ChioRuntimeAdmissionHook::new(RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.into(), profile_id: "native-runtime-profile".into(),
        local_kernel_id: local_kernel.into(), verifier_id: verifier_id.into(),
        issued_at_unix_ms: now, expires_at_unix_ms: expires,
    }, source)
        .with_runtime_trust_input(SignedExportEnvelope::sign(RuntimeVerifierTrustBundleV4 {
            schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.into(), verifier_id: verifier_id.into(),
            key_id: key_id.into(), version: 1, previous_hash_sha256: None,
            trust_bundle_sha256: "b".repeat(64), verification_context_sha256: "c".repeat(64),
            revocation_checkpoint_sha256: "d".repeat(64), revocation_authority_roots: vec!["native-revocation-root".into()],
            issued_at_unix_ms: now, expires_at_unix_ms: expires,
        }, &verifier)?, vec![RuntimeTrustedVerifierKey {
            verifier_id: verifier_id.into(), key_id: key_id.into(), public_key: verifier.public_key(),
            valid_from_unix_ms: now, valid_until_unix_ms: expires, status: "active".into(),
        }])
        .with_pheromone_query_report(SignedExportEnvelope::sign(serde_json::json!({
            "schema": "chio.pheromone.query-report.v1", "accepted": true,
            "concentration": { "subjectClass": "native-execution", "subjectClassNamespace": "chio.runtime",
                "totalStrength": 0.1, "distinctOriginPairs": 1, "reputationEpoch": 1, "evaluatedAtUnixMs": now },
        }), &verifier)?)
        .with_runtime_pheromone_policy(SignedExportEnvelope::sign(policy, &verifier)?, SignedExportEnvelope::sign(weights, &verifier)?)
        .with_operation_owned_runtime_replay(binding);
    fixture.kernel.set_runtime_admission_hook(Arc::new(hook));
    Ok(())
}
