use super::*;

#[test]
fn native_policy_evidence_binds_exact_inputs_and_decision_without_payload() -> TestResult {
    for egress in [false, true] {
        let mut fixture = public_fixture()?;
        fixture.request.arguments = serde_json::json!({"message": "private-policy-payload"});
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let manifests = registry(egress, InformationLabel::bottom())?;
        let manifest = manifests
            .verified_manifest(&fixture.request.server_id)
            .ok_or("manifest")?;
        let expected_manifest = serde_json::json!({
            "manifest_digest": chio_core::sha256_hex(&chio_core::canonical_json_bytes(&manifest.manifest)?),
            "signer_key": manifest.signer_key,
            "signature": manifest.signature,
        });
        let resolver = Arc::new(NativeFlowResolver::new(
            fixture.binding.clone(),
            manifests,
            classifier.clone(),
            Arc::new(Clock::default()),
            flow_config(),
        )?);
        let custody = fixture.run(resolver, || {})??;
        let evidence = custody.policy_evidence();
        let bytes = evidence.canonical_bytes();
        let record: serde_json::Value = serde_json::from_slice(bytes)?;
        assert_eq!(chio_core::canonical_json_bytes(&record)?, bytes);
        assert_eq!(evidence.digest(), super::super::super::digest(bytes));
        assert_eq!(record["schema"], "chio.native-flow-dispatch-policy.v1");
        let inputs = &record["inputs"];
        assert_eq!(inputs["operation_id"], custody.operation_id().as_str());
        assert!(inputs["operation_version"]
            .as_u64()
            .is_some_and(|version| version > 0));
        assert_eq!(
            inputs["native_authority"],
            serde_json::to_value(&fixture.binding)?
        );
        assert_eq!(
            inputs["live_request_digest"],
            serde_json::to_value(custody.live_request_digest())?
        );
        assert_eq!(inputs["manifest_attestation"], expected_manifest);
        assert_eq!(
            inputs["observation"],
            serde_json::to_value(custody.observation().snapshot())?
        );
        assert_eq!(
            inputs["observed_at_unix_ms"],
            custody.observation().observed_at_unix_ms()
        );
        assert_eq!(
            inputs["classification"]["classifier_id"],
            "classifier.empty"
        );
        assert_eq!(inputs["classification"]["classifier_version"], "1");
        assert_eq!(
            inputs["classification"]["request_id"],
            fixture.request.request_id
        );
        assert_eq!(inputs["classification"]["findings"], serde_json::json!([]));
        assert_eq!(inputs["runtime_egress"], egress);
        assert_eq!(record["decision"]["effective_egress"], egress);
        assert_eq!(record["decision"]["declassification"], false);
        assert_eq!(
            record["decision"]["request_hash"],
            serde_json::to_value(custody.admission().request_hash)?
        );
        assert_ne!(
            inputs["live_request_digest"],
            record["decision"]["request_hash"]
        );
        assert_eq!(
            record["decision"]["taint_transition"],
            serde_json::to_value(&custody.admission().taint_transition)?
        );
        assert_eq!(
            record["decision"]["egress_expires_at_unix_ms"].is_null(),
            !egress
        );
        assert!(!std::str::from_utf8(bytes)?.contains("private-policy-payload"));
        assert!(!format!("{evidence:?}").contains("classifier.empty"));
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn native_policy_evidence_commits_large_manifest_without_retaining_its_payload() -> TestResult {
    let mut fixture = public_fixture()?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry_with_description(true, InformationLabel::bottom(), Some("x".repeat(300_000)))?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    let custody = fixture.run(resolver, || {})??;
    assert!(custody.egress_history().is_some());
    assert!(custody.policy_evidence().canonical_bytes().len() < 16_384);
    Ok(())
}

#[test]
fn native_policy_evidence_retains_unused_category_policy_and_admitted_clearance() -> TestResult {
    let mut fixture = public_fixture()?;
    let mut config = flow_config();
    let category = RecordId::new("unused-category")?;
    let labels = BTreeMap::from([(category, restricted_label())]);
    config.category_labels = CategoryLabelMap::new(
        ClassifierId::new("classifier.empty")?,
        ClassifierVersion::new("1")?,
        labels.clone(),
    )?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        registry(true, restricted_label())?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        config,
    )?);
    let custody = fixture.run(resolver, || {})??;
    let record: serde_json::Value =
        serde_json::from_slice(custody.policy_evidence().canonical_bytes())?;
    assert_eq!(
        record["inputs"]["category_bindings"],
        serde_json::to_value(labels)?
    );
    assert_eq!(
        record["inputs"]["policy_clearances"],
        serde_json::json!([restricted_label()])
    );
    assert_eq!(
        record["inputs"]["classified_label"],
        serde_json::to_value(InformationLabel::bottom())?
    );
    assert_eq!(
        record["inputs"]["admitted_security"]["effective_egress"],
        true
    );
    Ok(())
}

#[test]
fn oversized_native_policy_evidence_denies_before_any_egress_custody() -> TestResult {
    let mut fixture = public_fixture()?;
    // Each label is valid and the map is within its 256-category bound. The
    // complete policy still exceeds the separate retained-evidence byte limit.
    let owner = PrincipalId::new("policy-owner")?;
    let readers = (0..64)
        .map(|index| PrincipalId::new(format!("reader-{index}-{}", "x".repeat(200))))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut readers = readers;
    readers.insert(owner.clone());
    let label = InformationLabel::try_known(BTreeMap::from([(owner, readers)]), BTreeSet::new())?;
    let labels = (0..32)
        .map(|index| RecordId::new(format!("category-{index}")).map(|id| (id, label.clone())))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut config = flow_config();
    config.category_labels = CategoryLabelMap::new(
        ClassifierId::new("classifier.empty")?,
        ClassifierVersion::new("1")?,
        labels,
    )?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        flow_registry(),
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        config,
    )?);
    assert!(matches!(
        fixture.run(resolver, || {})?,
        Err(NativeFlowError::PolicyEvidence)
    ));
    Ok(())
}
