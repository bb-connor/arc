//! Real signed runtime artifacts and physical claims exercise the native
//! revalidation contract. A retained claim used here is test input, not a permit:
//! production capture additionally requires the kernel's live credential borrow.

use super::*;
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeDispatchValidity, RuntimeParticipantClaimIntentV1,
};
use chio_kernel::admission_operation::{AdmissionOperationStore, RuntimeReplaySourceSnapshotV1};
use chio_kernel::{KernelError, RuntimeAdmissionDecision, RuntimeParticipantClaimAuthority};

type Hook = ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>;

#[test]
fn native_swarm_evolution_preserves_treaty_and_original_physical_claim() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let (prior, next) = crate::swarm_evolution::treaty_versions()?;
    let fixture = CombinedFixture::with_swarm_input(None, |_, _, _| Ok(()), prior.clone())?;
    // A restart must retain the owner's verifier configuration, not generate a
    // fresh trust root as the default independent-test fixture does.
    let policy_inputs = signed_policy_inputs(0.1)?;
    let hook = Arc::new(
        fixture
            .inner
            .hook_with_inputs(policy_inputs.clone())?
            .with_swarm_witness_keys(trusted_swarm_witness_keys()),
    );
    let kernel = fixture.kernel(SharedHook(hook.clone()))?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:#?}");
    assert!(kernel.dual_signed_receipt(&response.receipt.id).is_some());
    let (source, intent) = physical_input(&fixture.inner)?;
    assert_eq!(intent.resources().len(), 3);
    let before = faults::history(&fixture.inner)?;
    crate::swarm_evolution::open(&fixture.inner._directory.path().join("runtime.sqlite3"))?
        .extend_swarm_authority_bundle(
            &canonical_test_hash(&prior)?,
            next,
            &trusted_swarm_witness_keys(),
        )?;
    // This explicitly exercises historical artifact resolution; a completed
    // request's fast receipt replay alone would not test the changed resolver.
    hook.revalidate_operation_owned_for_native_capture(
        &revalidation_input(&fixture.inner, &response),
        &source,
        &intent,
    )?
    .validate_at(NOW)?;
    drop(kernel);
    drop(hook);
    let fixture = fixture.reopen()?;
    let hook = fixture
        .inner
        .hook_with_inputs(policy_inputs)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys());
    let (source, intent) = physical_input(&fixture.inner)?;
    hook.revalidate_operation_owned_for_native_capture(
        &revalidation_input(&fixture.inner, &response),
        &source,
        &intent,
    )?
    .validate_at(NOW)?;
    let mut stripped = fixture.inner.request.clone();
    stripped
        .governed_intent
        .as_mut()
        .and_then(|i| i.context.as_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("context")?
        .remove("chioTreaty");
    let mut context = revalidation_input(&fixture.inner, &response);
    context.request = &stripped;
    assert!(hook
        .revalidate_operation_owned_for_native_capture(&context, &source, &intent)
        .is_err());
    let kernel = fixture.kernel(hook)?;
    let replay = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(
        canonical_json_bytes(&response.receipt)?,
        canonical_json_bytes(&replay.receipt)?
    );
    assert_eq!(faults::history(&fixture.inner)?, before);
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn native_runtime_deadline_includes_the_verified_bilateral_capability_lease() -> TestResult {
    use base64::Engine;
    use chio_federation::bilateral_dsse::{pae, DsseSignature};
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    const UNTIL: u64 = NOW + 5_000;
    let fixture = CombinedFixture::with_treaty_input(None, |treaty, origin, local| {
        let (mut statement, _) = treaty.bilateral_dsse.decode_statement()?;
        statement
            .predicate
            .capability_lease_ref
            .as_mut()
            .ok_or("bilateral lease")?
            .expires_at_unix_ms = UNTIL;
        let bytes = statement.canonical_bytes()?;
        let preimage = pae(PAYLOAD_TYPE_IN_TOTO, &bytes);
        let encoding = base64::engine::general_purpose::STANDARD;
        treaty.bilateral_dsse.payload = encoding.encode(&bytes);
        treaty.bilateral_dsse.signatures = [origin, local]
            .into_iter()
            .map(|key| DsseSignature {
                keyid: chio_federation::bilateral_dsse::Keyid::from_public_key(&key.public_key()).0,
                sig: encoding.encode(key.sign(&preimage).to_bytes()),
            })
            .collect();
        chio_federation::bilateral_dsse::verify_chio_bilateral_dsse_envelope(
            &treaty.bilateral_dsse,
            &origin.public_key(),
            &local.public_key(),
        )?;
        treaty.bilateral_dsse_sha256 = sha256_hex(&canonical_json_bytes(&treaty.bilateral_dsse)?);
        Ok(())
    })?;
    let hook = Arc::new(fixture.hook()?);
    let kernel = fixture.kernel(SharedHook(hook.clone()))?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let (source, intent) = physical_input(&fixture.inner)?;
    let context = revalidation_input(&fixture.inner, &response);
    let validity =
        hook.revalidate_operation_owned_for_native_capture(&context, &source, &intent)?;
    assert_eq!(validity.valid_until_unix_ms(), UNTIL);
    validity.validate_at(UNTIL - 1)?;
    assert!(validity.validate_at(UNTIL).is_err());
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

struct SharedHook(Arc<Hook>);

#[test]
fn native_runtime_deadline_includes_other_participants_governance() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    const UNTIL: u64 = NOW + 5_000;
    let fixture = CombinedFixture::new()?;
    let mut governance = fixture
        .inner
        .source
        .treaty_governance_receipt("gov-live-1")?
        .ok_or("governance receipt")?;
    governance.valid_until_unix_ms = UNTIL;
    // Provision a shorter receiver-owned governance window before any admission.
    // The signed receipt identity stays fixed; this is the owner's local validity.
    let connection =
        rusqlite::Connection::open(fixture.inner._directory.path().join("runtime.sqlite3"))?;
    assert_eq!(connection.execute(
        "UPDATE runtime_treaty_artifacts SET raw_json=?1, artifact_sha256=?2 WHERE evidence_kind='governance_receipt' AND evidence_id='gov-live-1'",
        rusqlite::params![serde_json::to_string(&governance)?, canonical_test_hash(&governance)?],
    )?, 1);
    let hook = Arc::new(fixture.hook()?);
    let kernel = fixture.kernel(SharedHook(hook.clone()))?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let (source, intent) = physical_input(&fixture.inner)?;
    let validity = hook.revalidate_operation_owned_for_native_capture(
        &revalidation_input(&fixture.inner, &response),
        &source,
        &intent,
    )?;
    assert_eq!(validity.valid_until_unix_ms(), UNTIL);
    validity.validate_at(UNTIL - 1)?;
    assert!(validity.validate_at(UNTIL).is_err());
    Ok(())
}

impl RuntimeAdmissionHook for SharedHook {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn runtime_participant_binding(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
        self.0.runtime_participant_binding()
    }
    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }
    fn enforces_swarm_authority(&self) -> bool {
        self.0.enforces_swarm_authority()
    }
    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        panic!("native validity fixture cannot use legacy admission")
    }
    fn evaluate_operation_owned(
        &self,
        context: &RuntimeAdmissionContext<'_>,
        authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.0.evaluate_operation_owned(context, authority)
    }
    fn revalidate_operation_owned_before_dispatch(
        &self,
        context: &RuntimeAdmissionRevalidationContext<'_>,
        source: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), KernelError> {
        self.0
            .revalidate_operation_owned_before_dispatch(context, source)
    }
}

fn revalidation_input<'a>(
    fixture: &'a Fixture,
    response: &'a chio_kernel::ToolCallResponse,
) -> RuntimeAdmissionRevalidationContext<'a> {
    RuntimeAdmissionRevalidationContext {
        request: &fixture.request,
        admission_metadata: response.receipt.metadata.as_ref(),
        now_unix_ms: NOW,
        now_unix_secs: NOW / 1000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".into(),
    }
}

fn physical_input(
    fixture: &Fixture,
) -> TestResult<(
    RuntimeReplaySourceSnapshotV1,
    RuntimeParticipantClaimIntentV1,
)> {
    let history = super::super::faults::history(fixture)?;
    assert_eq!(history.len(), 1);
    assert!(!history[0].intent.resources().is_empty());
    let source = fixture
        .authority
        .admission_operation_store()
        .load_runtime_participant_activation(
            &fixture.binding,
            &fixture.authority.mutation_fence(),
            NOW,
        )?;
    Ok((source, history[0].intent.clone()))
}

#[test]
fn native_runtime_revalidation_binds_nonempty_signed_treaty_swarm_and_original_plan() -> TestResult
{
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = CombinedFixture::new()?;
    let hook = Arc::new(fixture.hook()?);
    let kernel = fixture.kernel(SharedHook(hook.clone()))?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(response.receipt.verify_signature()?);
    let (source, intent) = physical_input(&fixture.inner)?;
    assert_eq!(intent.resources().len(), 3);
    let context = revalidation_input(&fixture.inner, &response);
    let validity =
        hook.revalidate_operation_owned_for_native_capture(&context, &source, &intent)?;
    validity.validate_at(NOW)?;
    assert!(validity
        .validate_at(validity.valid_until_unix_ms())
        .is_err());

    for (field, replacement) in [
        ("planDigest", serde_json::json!("e".repeat(64))),
        ("requestBindingHash", serde_json::json!("f".repeat(64))),
        ("grantIndex", serde_json::json!(1)),
        ("expectationId", serde_json::json!("wrong-expectation")),
        ("phase", serde_json::json!("nonce_preflight")),
        ("resources", serde_json::json!([])),
    ] {
        let mut changed = serde_json::to_value(&intent)?;
        changed[field] = replacement;
        let changed: RuntimeParticipantClaimIntentV1 = serde_json::from_value(changed)?;
        assert!(
            hook.revalidate_operation_owned_for_native_capture(&context, &source, &changed)
                .is_err(),
            "{field}"
        );
    }
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(physical_input(&fixture.inner)?.1, intent);
    Ok(())
}

#[test]
fn native_runtime_deadline_includes_every_selected_signed_time_bound() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    const UNTIL: u64 = NOW + 10_000;
    for selected in ["profile", "trust", "key", "policy", "weights", "report"] {
        let fixture = Fixture::new(true)?;
        let verifier = Keypair::generate();
        let mut profile = profile();
        let mut trust = trust_body(1, None);
        let mut keys = trusted_keys(&verifier);
        let mut weights = peer_weights();
        if selected == "weights" {
            weights.expires_at_unix_ms = UNTIL;
        }
        let mut policy = policy(runtime_peer_weights_sha256(&weights)?);
        match selected {
            "profile" => profile.expires_at_unix_ms = UNTIL,
            "trust" => trust.expires_at_unix_ms = UNTIL,
            "key" => keys[0].valid_until_unix_ms = UNTIL,
            "policy" => policy.expires_at_unix_ms = UNTIL,
            "report" => policy.max_query_report_age_ms = UNTIL - NOW - 1,
            "weights" => {}
            _ => unreachable!(),
        }
        let mut unrelated = keys[0].clone();
        unrelated.key_id = "unrelated-expired-key".into();
        unrelated.valid_until_unix_ms = NOW - 1;
        keys.push(unrelated);
        let hook = Arc::new(
            Hook::new(
                profile,
                SqliteRuntimeOrchestrationStore::open(
                    fixture._directory.path().join("runtime.sqlite3"),
                )?,
            )
            .with_runtime_trust_input(SignedExportEnvelope::sign(trust, &verifier)?, keys)
            .with_pheromone_query_report(signed_query_report(advisory(0.1), &verifier)?)
            .with_runtime_pheromone_policy(
                SignedExportEnvelope::sign(policy, &verifier)?,
                SignedExportEnvelope::sign(weights, &verifier)?,
            )
            .with_operation_owned_runtime_replay(fixture.binding.clone()),
        );
        let kernel = fixture.kernel(SharedHook(hook.clone()), true, false)?;
        let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "{selected}: {:?}",
            response.reason
        );
        let (source, intent) = physical_input(&fixture)?;
        let context = revalidation_input(&fixture, &response);
        let validity: RuntimeDispatchValidity =
            hook.revalidate_operation_owned_for_native_capture(&context, &source, &intent)?;
        assert_eq!(validity.valid_until_unix_ms(), UNTIL, "{selected}");
        validity.validate_at(UNTIL - 1)?;
        assert!(validity.validate_at(UNTIL).is_err(), "{selected}");
        let expired = RuntimeAdmissionRevalidationContext {
            now_unix_ms: UNTIL,
            now_unix_secs: UNTIL / 1000,
            ..context
        };
        assert!(
            hook.revalidate_operation_owned_for_native_capture(&expired, &source, &intent)
                .is_err(),
            "{selected}"
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
