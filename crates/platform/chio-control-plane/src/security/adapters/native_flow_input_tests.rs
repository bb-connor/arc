use super::*;

fn seed(key: &FlowStateKey) -> TestResult<FlowJoinRequest> {
    Ok(FlowJoinRequest {
        key: key.clone(),
        principal_join: InformationLabel::bottom(),
        lineage_join: InformationLabel::bottom(),
        session_join: InformationLabel::bottom(),
        transition_id: RecordId::new("inherited-input-source")?,
    })
}

fn require_complete_source(custody: &NativeFlowCustody, label: &InformationLabel) -> TestResult {
    let snapshot = custody
        .observation()
        .snapshot()
        .ok_or("native full source")?;
    assert_eq!(&snapshot.principal_label, label);
    assert_eq!(&snapshot.lineage_label, label);
    assert_eq!(&snapshot.session_label, label);
    assert!(snapshot.context_generation > 0);
    assert!(custody.egress_history().is_some());
    Ok(())
}

fn restricted_resolver(fixture: &Fixture) -> TestResult<Arc<NativeFlowResolver>> {
    Ok(Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(true, restricted_label())?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        flow_config(),
    )?))
}

#[test]
fn native_input_inherits_global_lineage_before_the_exact_epoch_exists() -> TestResult {
    let mut fixture =
        Fixture::new_with_seed(std::array::from_fn(|_| InformationLabel::bottom()), |key| {
            let mut source = seed(key)?;
            source.key.principal_id = PrincipalId::new("other-principal")?;
            source.key.session_id = SessionId::new("other-session")?;
            source.key.isolation_epoch_id =
                chio_security_types::ports::IsolationEpochId::new("other-epoch")?;
            source.lineage_join = restricted_label();
            Ok(Some(source))
        })?;
    let resolver = restricted_resolver(&fixture)?;
    require_complete_source(&fixture.run_native(resolver)??, &restricted_label())
}

#[test]
fn native_input_inherits_principal_epoch_from_another_lineage() -> TestResult {
    let mut fixture =
        Fixture::new_with_seed(std::array::from_fn(|_| InformationLabel::bottom()), |key| {
            let mut source = seed(key)?;
            source.key.lineage_id = LineageId::new("other-lineage")?;
            source.key.session_id = SessionId::new("other-session")?;
            source.principal_join = restricted_label();
            Ok(Some(source))
        })?;
    let resolver = restricted_resolver(&fixture)?;
    require_complete_source(&fixture.run_native(resolver)??, &restricted_label())
}

#[test]
fn native_input_propagates_inherited_session_only_taint() -> TestResult {
    let mut fixture =
        Fixture::new_with_seed(std::array::from_fn(|_| InformationLabel::bottom()), |key| {
            let mut source = seed(key)?;
            source.session_join = restricted_label();
            Ok(Some(source))
        })?;
    let resolver = restricted_resolver(&fixture)?;
    require_complete_source(&fixture.run_native(resolver)??, &restricted_label())
}

struct BudgetClassifier {
    calls: AtomicUsize,
    observe: Arc<dyn Fn() -> PortResult<u64> + Send + Sync>,
    expected_payload: Vec<u8>,
    expected_request: String,
}
impl ClassificationPort for BudgetClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(call < 2, "native policy must not retry classification");
        // This also proves classification is outside the store write lock.
        assert_eq!((self.observe)()?, u64::from(call == 1));
        assert_eq!(request.payload.as_bytes(), self.expected_payload);
        assert_eq!(request.request_id.as_str(), self.expected_request);
        assert_eq!(request.tenant_id.as_str(), "native-tenant");
        assert_eq!(
            request.payload_digest,
            crate::security::adapters::digest(request.payload.as_bytes())
        );
        RestrictedClassifier.classify(request)
    }
}

fn restricted_config() -> TestResult<FlowResolverConfig> {
    let mut config = flow_config();
    config.category_labels = CategoryLabelMap::new(
        ClassifierId::new("classifier.empty")?,
        ClassifierVersion::new("1")?,
        BTreeMap::from([(RecordId::new("restricted")?, restricted_label())]),
    )?;
    Ok(config)
}

#[test]
fn native_input_classifies_before_budget_and_rechecks_after_the_single_join() -> TestResult {
    let mut fixture = public_fixture()?;
    let classifier = Arc::new(BudgetClassifier {
        calls: AtomicUsize::new(0),
        observe: fixture.budget_observer(),
        expected_payload: chio_core::canonical::canonical_json_bytes(&fixture.request.arguments)?,
        expected_request: fixture.request.request_id.clone(),
    });
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(true, restricted_label())?,
        classifier.clone(),
        Arc::new(Clock::default()),
        restricted_config()?,
    )?);
    require_complete_source(&fixture.run_native(resolver)??, &restricted_label())?;
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn native_input_operator_floor_is_in_the_original_join() -> TestResult {
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
    require_complete_source(&fixture.run_native(resolver)??, &restricted_label())
}

#[test]
fn native_input_local_policy_does_not_acquire_egress_custody() -> TestResult {
    let mut fixture = public_fixture()?;
    let classifier = Arc::new(CountingEmptyClassifier::new());
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(false, InformationLabel::bottom())?,
        classifier.clone(),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    let custody = fixture.run_native(resolver)??;
    assert!(custody.egress_history().is_none());
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

struct DriftingClassifier(AtomicUsize);
impl ClassificationPort for DriftingClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            CountingEmptyClassifier::new().classify(request)
        } else {
            RestrictedClassifier.classify(request)
        }
    }
}

#[test]
fn native_input_stronger_post_join_classification_denies_without_rejoining() -> TestResult {
    let mut fixture = public_fixture()?;
    let classifier = Arc::new(DriftingClassifier(AtomicUsize::new(0)));
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(true, restricted_label())?,
        classifier.clone(),
        Arc::new(Clock::default()),
        restricted_config()?,
    )?);
    assert!(matches!(
        fixture.run_native(resolver)?,
        Err(NativeFlowError::UnrecordedInputTaint)
    ));
    assert_eq!(classifier.0.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn native_input_missing_manifest_denies_before_classification_or_join() -> TestResult {
    let mut fixture = public_fixture()?;
    let classifier = Arc::new(CountingEmptyClassifier::new());
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        Arc::new(VerifiedManifestRegistry::default()),
        classifier.clone(),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    fixture.deny_native(resolver, &FlowDenial::InvalidManifest.to_string())?;
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_input_classifier_substitution_denies_without_taint_or_budget() -> TestResult {
    let mut fixture = public_fixture()?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        flow_registry(),
        Arc::new(InvalidClassifier(false)),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    fixture.deny_native(resolver, "classifier")
}

#[test]
fn native_input_classifier_panic_denies_without_taint_or_budget() -> TestResult {
    let mut fixture = public_fixture()?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        flow_registry(),
        Arc::new(InvalidClassifier(true)),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    fixture.deny_native(resolver, "panicked")
}

#[test]
fn native_input_untrusted_declassification_denies_before_classification_or_join() -> TestResult {
    let mut fixture = public_fixture()?;
    fixture.request.declassification_grant = declassifying_flow_request(
        &Keypair::from_seed(&[31; 32]),
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
    fixture.deny_native(
        resolver,
        "declassification authority is not currently trusted",
    )?;
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
