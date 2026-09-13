use super::super::{NativeFlowCustody, NativeFlowError, NativeFlowResolver};
use super::*;
use chio_flow::FlowDenial;

mod support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_test_support.rs"
    ));
}
use support::*;

mod input {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_input_tests.rs"
    ));
}

mod policy {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_policy_tests.rs"
    ));
}

mod ledger {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_ledger_tests.rs"
    ));
}

fn public_fixture() -> TestResult<Fixture> {
    Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))
}

fn resolver(
    fixture: &Fixture,
    clock: Arc<dyn SecurityClock>,
) -> TestResult<Arc<NativeFlowResolver>> {
    Ok(Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        flow_registry(),
        Arc::new(CountingEmptyClassifier::new()),
        clock,
        flow_config(),
    )?))
}

fn registry(
    egress: bool,
    clearance: InformationLabel,
) -> TestResult<Arc<VerifiedManifestRegistry>> {
    registry_with_description(egress, clearance, None)
}

fn registry_with_description(
    egress: bool,
    clearance: InformationLabel,
    description: Option<String>,
) -> TestResult<Arc<VerifiedManifestRegistry>> {
    let signer = Keypair::from_seed(&[73; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.into(),
        server_id: "server-a".into(),
        name: "Native policy tool".into(),
        description,
        version: "1.0.0".into(),
        tools: vec![ToolDefinition {
            name: "send".into(),
            description: "Send".into(),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations::default(),
            latency_hint: None,
            flow: Some(ToolFlowDeclaration::new(
                Some(InformationLabel::bottom()),
                Some(clearance.clone()),
                egress,
                BTreeSet::new(),
            )?),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let policy =
        AuthoritativeToolPolicy::new(vec![clearance], InformationLabel::bottom(), BTreeSet::new())?;
    let mut registry = VerifiedManifestRegistry::default();
    registry.register(
        sign_manifest(&manifest, &signer)?,
        &signer.public_key(),
        &BTreeMap::from([("send".into(), policy)]),
        &BTreeMap::from([(
            "send".into(),
            if egress {
                RuntimeToolTopology::remote()
            } else {
                RuntimeToolTopology::local()
            },
        )]),
    )?;
    Ok(Arc::new(registry))
}

#[test]
fn native_policy_commits_real_egress_custody_without_activating_dispatch() -> TestResult {
    let mut fixture = public_fixture()?;
    let classifier = Arc::new(CountingEmptyClassifier::new());
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        flow_registry(),
        classifier.clone(),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    let custody = fixture.run(resolver, || {})??;
    let history = custody.egress_history().ok_or("egress history")?;
    assert!(history.commitment.is_some());
    assert!(custody.admission().egress_fence_plan.is_some());
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(format!("{custody:?}"), "NativeFlowCustody { .. }");
    Ok(())
}

#[test]
fn native_local_policy_does_not_manufacture_an_egress_fence() -> TestResult {
    let mut fixture = public_fixture()?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(false, InformationLabel::bottom())?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    let custody = fixture.run(resolver, || {})??;
    assert!(custody.egress_history().is_none());
    assert!(custody.admission().egress_fence_plan.is_none());
    Ok(())
}

#[test]
fn native_policy_rejects_unrecorded_operator_floor_without_rejoining() -> TestResult {
    let mut fixture = public_fixture()?;
    let mut config = flow_config();
    config.operator_input_floor = restricted_label();
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(true, restricted_label())?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        config,
    )?);
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::UnrecordedInputTaint)
    ));
    Ok(())
}

#[test]
fn native_policy_requires_taint_propagation_in_each_recorded_label() -> TestResult {
    // The session inherits principal taint, but the lineage was not joined with
    // it. Checking only the effective session label would miss the required join.
    let mut fixture = Fixture::new([
        restricted_label(),
        InformationLabel::bottom(),
        InformationLabel::bottom(),
    ])?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(true, restricted_label())?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::UnrecordedInputTaint)
    ));
    Ok(())
}

#[test]
fn native_policy_accepts_recorded_restricted_labels_with_matching_clearance() -> TestResult {
    let mut fixture = Fixture::new(std::array::from_fn(|_| restricted_label()))?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(true, restricted_label())?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    let custody = fixture.run(resolver, || {})??;
    assert!(custody.egress_history().is_some());
    assert_eq!(
        custody
            .observation()
            .snapshot()
            .ok_or("snapshot")?
            .session_label,
        restricted_label()
    );
    Ok(())
}

#[test]
fn native_policy_rejects_public_destination_for_recorded_restricted_input() -> TestResult {
    let mut fixture = Fixture::new(std::array::from_fn(|_| restricted_label()))?;
    let resolver = resolver(&fixture, Arc::new(Clock::default()))?;
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::Policy(FlowDenial::PolicyFlowViolation))
    ));
    Ok(())
}

#[test]
fn native_policy_requires_admitted_manifest_before_classification() -> TestResult {
    let mut fixture = public_fixture()?;
    let classifier = Arc::new(CountingEmptyClassifier::new());
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        Arc::new(VerifiedManifestRegistry::default()),
        classifier.clone(),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::Policy(FlowDenial::InvalidManifest))
    ));
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_policy_rejects_other_initialized_authority_before_classification() -> TestResult {
    let mut fixture = public_fixture()?;
    let other = public_fixture()?;
    assert_ne!(fixture.binding, other.binding);
    let resolver = resolver(&other, Arc::new(Clock::default()))?;
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::AuthorityMismatch)
    ));
    Ok(())
}

#[test]
fn native_policy_rejects_legacy_evidence_configuration() -> TestResult {
    let fixture = public_fixture()?;
    let config =
        flow_config().with_receipt_evidence(Arc::new(RejectingSecurityReceipts), receipt_policy());
    assert!(matches!(
        NativeFlowResolver::new(
            fixture.binding,
            flow_registry(),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            config
        ),
        Err(NativeFlowError::LegacyEvidenceConfigured)
    ));
    Ok(())
}

#[test]
fn native_policy_rejects_regressing_clock_before_egress_acquisition() -> TestResult {
    let mut fixture = public_fixture()?;
    let clock = Arc::new(Clock::default());
    let resolver = resolver(&fixture, clock.clone())?;
    assert!(matches!(
        fixture.run(resolver, move || {
            clock.mode.store(1, Ordering::SeqCst);
        })?,
        Err(NativeFlowError::ClockChanged)
    ));
    Ok(())
}

#[test]
fn native_policy_rejects_future_clock_before_preparation() -> TestResult {
    let mut fixture = public_fixture()?;
    let clock = Arc::new(Clock::default());
    clock.mode.store(2, Ordering::SeqCst);
    let resolver = resolver(&fixture, clock)?;
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::ClockChanged)
    ));
    Ok(())
}

#[test]
fn native_policy_contains_clock_panic_before_egress_acquisition() -> TestResult {
    let mut fixture = public_fixture()?;
    let clock = Arc::new(Clock::default());
    let resolver = resolver(&fixture, clock.clone())?;
    assert!(matches!(
        fixture.run(resolver, move || {
            clock.mode.store(3, Ordering::SeqCst);
        })?,
        Err(NativeFlowError::CallbackPanicked)
    ));
    Ok(())
}

struct InvalidClassifier(bool);
impl ClassificationPort for InvalidClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        if self.0 {
            panic!("native policy classifier panic");
        }
        let mut result = CountingEmptyClassifier::new().classify(request)?;
        result.payload_digest = Digest32::new([42; 32]);
        Ok(result)
    }
}

#[test]
fn native_policy_rejects_classifier_payload_substitution() -> TestResult {
    let mut fixture = public_fixture()?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        flow_registry(),
        Arc::new(InvalidClassifier(false)),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::Policy(FlowDenial::ClassifierFailure))
    ));
    Ok(())
}

#[test]
fn native_policy_contains_classifier_panic_without_egress_writes() -> TestResult {
    let mut fixture = public_fixture()?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        flow_registry(),
        Arc::new(InvalidClassifier(true)),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::CallbackPanicked)
    ));
    Ok(())
}

#[test]
fn native_policy_rejects_untrusted_declassification_before_classification() -> TestResult {
    let mut fixture = public_fixture()?;
    let authority = Keypair::from_seed(&[31; 32]);
    fixture.request.declassification_grant = declassifying_flow_request(
        &authority,
        &DeclassificationPurpose::new("native-unsupported")?,
    )
    .declassification_grant;
    let classifier = Arc::new(CountingEmptyClassifier::new());
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        flow_registry(),
        classifier.clone(),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::Policy(
            FlowDenial::DeclassificationUntrustedAuthority
        ))
    ));
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

struct RestrictedClassifier;
impl ClassificationPort for RestrictedClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        let mut result = CountingEmptyClassifier::new().classify(request)?;
        result.findings = chio_security_types::ports::BoundedVec::new(vec![
            chio_security_types::ports::ClassificationFinding {
                category: RecordId::new("restricted").map_err(PortError::from)?,
                confidence_basis_points: 10_000,
                byte_range: None,
                field_path: Some(RecordId::new("/safe").map_err(PortError::from)?),
            },
        ])
        .map_err(|_| PortError::invalid_data())?;
        Ok(result)
    }
}

#[test]
fn native_policy_rejects_classifier_taint_not_in_original_join() -> TestResult {
    let mut fixture = public_fixture()?;
    let mut config = flow_config();
    config.category_labels = CategoryLabelMap::new(
        ClassifierId::new("classifier.empty")?,
        ClassifierVersion::new("1")?,
        BTreeMap::from([(RecordId::new("restricted")?, restricted_label())]),
    )?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(true, restricted_label())?,
        Arc::new(RestrictedClassifier),
        Arc::new(Clock::default()),
        config,
    )?);
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::UnrecordedInputTaint)
    ));
    Ok(())
}

#[test]
fn native_local_policy_revalidates_clock_without_fence_writes() -> TestResult {
    let mut fixture = public_fixture()?;
    let clock = Arc::new(Clock::default());
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(false, InformationLabel::bottom())?,
        Arc::new(CountingEmptyClassifier::new()),
        clock.clone(),
        flow_config(),
    )?);
    assert!(matches!(
        fixture.run(resolver, move || {
            clock.mode.store(1, Ordering::SeqCst);
        })?,
        Err(NativeFlowError::ClockChanged)
    ));
    Ok(())
}

#[test]
fn native_policy_rejects_clock_failure_before_egress_acquisition() -> TestResult {
    let mut fixture = public_fixture()?;
    let clock = Arc::new(Clock::default());
    let resolver = resolver(&fixture, clock.clone())?;
    assert!(matches!(
        fixture.run(resolver, move || {
            clock.mode.store(4, Ordering::SeqCst);
        })?,
        Err(NativeFlowError::ClockChanged)
    ));
    Ok(())
}
