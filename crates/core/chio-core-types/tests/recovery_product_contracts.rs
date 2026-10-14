use chio_core_types::{canonical_json_bytes, recovery::*};
use chio_security_types::{knowledge::ArtifactVersionRefV1, recovery::*};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn report() -> Result<DecisionReportV1, Box<dyn std::error::Error>> {
    Ok(DecisionReportV1 {
        domain_version: VersionV1,
        scope: RecoveryScopeV1 {
            tenant_id: RecoveryTenantId::new("product-tenant")?,
            authority_domain: AuthorityDomainId::new("product-authority")?,
            process_id: ProcessId::new("product-process")?,
        },
        workflow_id: WorkflowId::new("product-workflow")?,
        expected_revision: SafeInteger::new(1)?,
        decision: RecoveryReportedDecision::NeedsReview,
        reporter_text: ProtectedText::new("feedback-secret-canary")?,
        desired_outcome: ProtectedText::new("permit the reviewed benign task")?,
        attachments: BoundedList::<ArtifactVersionRefV1, 8>::new(vec![])?,
    })
}
#[test]
fn product_report_bounds_closed_fields_and_redacted_debug() -> TestResult {
    let report = report()?;
    report.validate()?;
    let bytes = canonical_json_bytes(&report)?;
    let decoded: DecisionReportV1 = decode_contract(&bytes)?;
    assert_eq!(decoded, report);
    assert!(!format!("{report:?}").contains("feedback-secret-canary"));
    let mut body = serde_json::to_value(&report)?;
    body["reporter_text"] = "x".repeat(4097).into();
    assert!(decode_contract::<DecisionReportV1>(&canonical_json_bytes(&body)?).is_err());
    body = serde_json::to_value(&report)?;
    body["desired_outcome"] = "x".repeat(1025).into();
    assert!(decode_contract::<DecisionReportV1>(&canonical_json_bytes(&body)?).is_err());
    body = serde_json::to_value(&report)?;
    body["approval"] = "complaint-is-not-approval".into();
    assert!(decode_contract::<DecisionReportV1>(&canonical_json_bytes(&body)?).is_err());
    body = serde_json::to_value(&report)?;
    body["expected_revision"] = serde_json::json!(9007199254740992u64);
    assert!(decode_contract::<DecisionReportV1>(&canonical_json_bytes(&body)?).is_err());
    let duplicate = String::from_utf8(bytes)?.replacen("{", "{\"domain_version\":1,", 1);
    assert!(decode_contract::<DecisionReportV1>(duplicate.as_bytes()).is_err());
    let empty = DecisionReportV1 {
        reporter_text: ProtectedText::new(" ")?,
        ..report
    };
    assert!(empty.validate().is_err());
    Ok(())
}

fn proposal() -> Result<PolicyMaintenanceProposalV1, Box<dyn std::error::Error>> {
    let scope = report()?.scope;
    let trajectory = PolicyTrajectoryRefV1 {
        artifact: ArtifactVersionRefV1 {
            scope: scope.clone(),
            artifact: ArtifactId::new("qualification-evidence")?,
            version: ArtifactRevisionId::new("evidence-v1")?,
            provenance: ProvenanceDigest::from_bytes([7; 32]),
        },
        case_id: EvidenceRef::new("benign-case")?,
    };
    Ok(PolicyMaintenanceProposalV1 {
        domain_version: VersionV1,
        scope,
        proposal_id: ReviewId::new("proposal-1")?,
        report_id: EvidenceRef::new("report-1")?,
        base_deployment: DeploymentDigest::from_bytes([1; 32]),
        base_policy: PolicyDigest::from_bytes([2; 32]),
        target_policy: PolicyDigest::from_bytes([3; 32]),
        rationale: ProtectedText::new("feedback-secret-canary")?,
        affected_contracts: NonEmptyBoundedList::new(vec![SemanticPackageDigest::from_bytes(
            [4; 32],
        )])?,
        benign_trajectories: NonEmptyBoundedList::new(vec![trajectory.clone()])?,
        adversarial_trajectories: NonEmptyBoundedList::new(vec![PolicyTrajectoryRefV1 {
            case_id: EvidenceRef::new("adversarial-case")?,
            ..trajectory
        }])?,
        expected_effects: ProtectedText::new("allow scoped public projections")?,
        rollback_policy: PolicyDigest::from_bytes([2; 32]),
        rollback_plan: ProtectedText::new("new proposal and signature restore prior rules")?,
    })
}

fn change() -> Result<PolicyDeploymentChangeV1, Box<dyn std::error::Error>> {
    Ok(PolicyDeploymentChangeV1 {
        domain_version: VersionV1,
        scope: report()?.scope,
        proposal_id: ReviewId::new("proposal-1")?,
        proposal_digest: CanonicalPayloadDigest::from_bytes([5; 32]),
        base_deployment: DeploymentDigest::from_bytes([1; 32]),
        base_policy: PolicyDigest::from_bytes([2; 32]),
        target_deployment: DeploymentDigest::from_bytes([6; 32]),
        target_policy: PolicyDigest::from_bytes([3; 32]),
        base_generation: PolicyGeneration::new(1)?,
        target_generation: PolicyGeneration::new(2)?,
        writer_fence: SourceDigest::from_bytes([8; 32]),
    })
}

fn probe() -> Result<RecoverySetupProbeV1, Box<dyn std::error::Error>> {
    Ok(RecoverySetupProbeV1 {
        domain_version: VersionV1,
        scope: report()?.scope,
        probe_id: ChallengeId::new("setup-probe-1")?,
        native_authority: SourceDigest::from_bytes([9; 32]),
        deployment: DeploymentDigest::from_bytes([1; 32]),
        source_profile: SourceDigest::from_bytes([10; 32]),
        required_coverage: CoverageDigest::from_bytes([11; 32]),
        benign_workflow: WorkflowId::new("benign-workflow")?,
        denied_command: CommandId::new("denied-command")?,
        issued_at_unix_ms: SafeInteger::new(1_000)?,
        expires_at_unix_ms: SafeInteger::new(901_000)?,
    })
}

#[test]
fn proposal_requires_both_trajectory_classes_and_an_actual_policy_change() -> TestResult {
    let proposal = proposal()?;
    proposal.validate()?;
    assert!(!format!("{proposal:?}").contains("feedback-secret-canary"));
    let mut body = serde_json::to_value(&proposal)?;
    body["benign_trajectories"] = serde_json::json!([]);
    assert!(decode_contract::<PolicyMaintenanceProposalV1>(&canonical_json_bytes(&body)?).is_err());
    body = serde_json::to_value(&proposal)?;
    body["adversarial_trajectories"] = serde_json::json!([]);
    assert!(decode_contract::<PolicyMaintenanceProposalV1>(&canonical_json_bytes(&body)?).is_err());
    let unchanged = PolicyMaintenanceProposalV1 {
        target_policy: proposal.base_policy,
        ..proposal
    };
    assert!(unchanged.validate().is_err());
    Ok(())
}

#[test]
fn operator_signatures_bind_every_base_target_proposal_and_fence() -> TestResult {
    let key = chio_core_types::Keypair::from_seed(&[226; 32]);
    let signed = SignedPolicyDeploymentChangeV1::sign(change()?, &key)?;
    assert!(signed.verify_signature()?);
    for field in [
        "base_deployment",
        "base_policy",
        "target_deployment",
        "target_policy",
        "proposal_digest",
        "writer_fence",
    ] {
        let mut body = serde_json::to_value(&signed)?;
        body["body"][field] = serde_json::to_value([99u8; 32])?;
        let decoded: SignedPolicyDeploymentChangeV1 =
            decode_contract(&canonical_json_bytes(&body)?)?;
        assert!(
            !decoded.verify_signature().is_ok_and(|valid| valid),
            "{field}"
        );
    }
    let mut body = serde_json::to_value(&signed)?;
    body["body"]["proposal_id"] = "proposal-2".into();
    let decoded: SignedPolicyDeploymentChangeV1 = decode_contract(&canonical_json_bytes(&body)?)?;
    assert!(!decoded.verify_signature()?);
    let setup = SignedRecoverySetupProbeV1::sign(probe()?, &key)?;
    assert!(setup.verify_signature()?);
    assert_ne!(signed.signing_bytes()?, setup.signing_bytes()?);
    assert!(signed
        .signing_bytes()?
        .starts_with(b"chio:recovery-policy-deployment-change:v1\0"));
    assert!(setup
        .signing_bytes()?
        .starts_with(b"chio:recovery-setup-probe:v1\0"));
    Ok(())
}

#[test]
fn setup_report_requires_a_distinct_reopened_writer_and_bounded_probe_lifetime() -> TestResult {
    let key = chio_core_types::Keypair::from_seed(&[226; 32]);
    let report = RecoverySetupReportV1 {
        domain_version: VersionV1,
        probe: probe()?,
        benign_operation: OperationId::new("benign-operation")?,
        benign_receipt: SourceDigest::from_bytes([12; 32]),
        denied_command_digest: CommandDigest::from_bytes([13; 32]),
        previous_serving_fence: SourceDigest::from_bytes([14; 32]),
        current_serving_fence: SourceDigest::from_bytes([15; 32]),
        qualified_at_unix_ms: SafeInteger::new(2_000)?,
    };
    let signed = SignedRecoverySetupReportV1::sign(report.clone(), &key)?;
    assert!(signed.verify_signature()?);
    assert!(signed
        .signing_bytes()?
        .starts_with(b"chio:recovery-setup-report:v1\0"));
    let same_writer = RecoverySetupReportV1 {
        current_serving_fence: report.previous_serving_fence,
        ..report
    };
    assert!(SignedRecoverySetupReportV1::sign(same_writer, &key).is_err());
    let expired = RecoverySetupProbeV1 {
        expires_at_unix_ms: SafeInteger::new(901_001)?,
        ..probe()?
    };
    assert!(expired.validate().is_err());
    Ok(())
}

fn contracts() -> Result<Vec<(&'static str, serde_json::Value)>, Box<dyn std::error::Error>> {
    let key = chio_core_types::Keypair::from_seed(&[226; 32]);
    let report = RecoverySetupReportV1 {
        domain_version: VersionV1,
        probe: probe()?,
        benign_operation: OperationId::new("benign-operation")?,
        benign_receipt: SourceDigest::from_bytes([12; 32]),
        denied_command_digest: CommandDigest::from_bytes([13; 32]),
        previous_serving_fence: SourceDigest::from_bytes([14; 32]),
        current_serving_fence: SourceDigest::from_bytes([15; 32]),
        qualified_at_unix_ms: SafeInteger::new(2_000)?,
    };
    Ok(vec![
        (
            "decision-report.schema.json",
            serde_json::to_value(self::report()?)?,
        ),
        (
            "decision-report-view.schema.json",
            serde_json::json!({"domain_version":1,"id":"retained-report","digest":vec![7u8;32],"report":self::report()?,
                "label":{"kind":"top"},"influence":{"commitment":vec![8u8;32],"externally_influenced":true,"unknown":true}}),
        ),
        (
            "policy-maintenance-view.schema.json",
            serde_json::json!({"domain_version":1,"digest":vec![9u8;32],"proposal":proposal()?,
                "label":{"kind":"top"},"influence":{"commitment":vec![10u8;32],"externally_influenced":true,"unknown":true}}),
        ),
        (
            "policy-trajectory-ref.schema.json",
            serde_json::to_value(&proposal()?.benign_trajectories.as_slice()[0])?,
        ),
        (
            "policy-maintenance-proposal.schema.json",
            serde_json::to_value(proposal()?)?,
        ),
        (
            "policy-deployment-change.schema.json",
            serde_json::to_value(change()?)?,
        ),
        (
            "recovery-setup-probe.schema.json",
            serde_json::to_value(probe()?)?,
        ),
        (
            "recovery-setup-report.schema.json",
            serde_json::to_value(&report)?,
        ),
        (
            "signed-policy-deployment-change.schema.json",
            serde_json::to_value(SignedPolicyDeploymentChangeV1::sign(change()?, &key)?)?,
        ),
        (
            "signed-recovery-setup-probe.schema.json",
            serde_json::to_value(SignedRecoverySetupProbeV1::sign(probe()?, &key)?)?,
        ),
        (
            "signed-recovery-setup-report.schema.json",
            serde_json::to_value(SignedRecoverySetupReportV1::sign(report, &key)?)?,
        ),
    ])
}
fn vectors() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for (schema, body) in contracts()? {
        out.push(serde_json::json!({"name":schema,"schema":schema,"body":body,"valid":true,"schema_valid":true}));
        let mut unknown = body.clone();
        unknown
            .as_object_mut()
            .ok_or("object")?
            .insert("untrusted_approval".into(), true.into());
        out.push(serde_json::json!({"name":format!("{schema}:unknown"),"schema":schema,"body":unknown,"valid":false,"schema_valid":false}));
        let mut missing = body.clone();
        let key = missing
            .as_object()
            .ok_or("object")?
            .keys()
            .next()
            .ok_or("key")?
            .clone();
        missing.as_object_mut().ok_or("object")?.remove(&key);
        out.push(serde_json::json!({"name":format!("{schema}:missing"),"schema":schema,"body":missing,"valid":false,"schema_valid":false}));
        if schema.starts_with("signed-") {
            let mut changed = body;
            if schema == "signed-policy-deployment-change.schema.json" {
                changed["body"]["writer_fence"] = serde_json::to_value([99u8; 32])?;
            } else if schema == "signed-recovery-setup-probe.schema.json" {
                changed["body"]["source_profile"] = serde_json::to_value([99u8; 32])?;
            } else {
                changed["body"]["probe"]["source_profile"] = serde_json::to_value([99u8; 32])?;
            }
            out.push(serde_json::json!({"name":format!("{schema}:substitution"),"schema":schema,"body":changed,"valid":false,"schema_valid":true}));
        }
    }
    let report = serde_json::to_value(report()?)?;
    for (field, value, schema_valid) in [
        (
            "reporter_text",
            serde_json::Value::from("x".repeat(4097)),
            false,
        ),
        (
            "desired_outcome",
            serde_json::Value::from("x".repeat(1025)),
            false,
        ),
        (
            "expected_revision",
            serde_json::json!(9007199254740992u64),
            false,
        ),
        (
            "reporter_text",
            serde_json::Value::from("é".repeat(2049)),
            true,
        ),
        ("reporter_text", serde_json::Value::from(" "), true),
    ] {
        let mut body = report.clone();
        body[field] = value;
        out.push(serde_json::json!({"name":format!("decision-report:{field}:{}", out.len()),"schema":"decision-report.schema.json","body":body,"valid":false,"schema_valid":schema_valid}));
    }
    let trajectory = proposal()?.benign_trajectories.as_slice()[0]
        .artifact
        .clone();
    let mut body = report;
    let attachments = (0..9)
        .map(|index| {
            Ok(ArtifactVersionRefV1 {
                artifact: ArtifactId::new(&format!("attachment-{index}"))?,
                ..trajectory.clone()
            })
        })
        .collect::<Result<Vec<_>, ContractError>>()?;
    let mut boundary = body.clone();
    boundary["attachments"] = serde_json::to_value(&attachments[..8])?;
    out.push(serde_json::json!({"name":"decision-report:eight-distinct-attachments","schema":"decision-report.schema.json","body":boundary,"valid":true,"schema_valid":true}));
    body["attachments"] = serde_json::to_value(attachments)?;
    out.push(serde_json::json!({"name":"decision-report:ninth-attachment","schema":"decision-report.schema.json","body":body,"valid":false,"schema_valid":false}));
    for field in ["benign_trajectories", "adversarial_trajectories"] {
        let mut body = serde_json::to_value(proposal()?)?;
        body[field] = serde_json::json!([]);
        out.push(serde_json::json!({"name":format!("policy-maintenance-proposal:empty-{field}"),"schema":"policy-maintenance-proposal.schema.json","body":body,"valid":false,"schema_valid":false}));
    }
    let mut body = serde_json::to_value(proposal()?)?;
    body["target_policy"] = body["base_policy"].clone();
    out.push(serde_json::json!({"name":"policy-maintenance-proposal:unchanged-policy","schema":"policy-maintenance-proposal.schema.json","body":body,"valid":false,"schema_valid":true}));
    Ok(out)
}
fn typed(schema: &str, bytes: &[u8]) -> bool {
    macro_rules! check {
        ($t:ty) => {
            decode_contract::<$t>(bytes).is_ok_and(|v| v.validate().is_ok())
        };
    }
    macro_rules! signed {
        ($t:ty) => {
            decode_contract::<$t>(bytes)
                .is_ok_and(|v| v.verify_signature().is_ok_and(|valid| valid))
        };
    }
    match schema {
        "decision-report.schema.json" => check!(DecisionReportV1),
        "decision-report-view.schema.json" => check!(DecisionReportViewV1),
        "policy-maintenance-view.schema.json" => check!(PolicyMaintenanceViewV1),
        "policy-trajectory-ref.schema.json" => {
            decode_contract::<PolicyTrajectoryRefV1>(bytes).is_ok()
        }
        "policy-maintenance-proposal.schema.json" => check!(PolicyMaintenanceProposalV1),
        "policy-deployment-change.schema.json" => check!(PolicyDeploymentChangeV1),
        "recovery-setup-probe.schema.json" => check!(RecoverySetupProbeV1),
        "recovery-setup-report.schema.json" => check!(RecoverySetupReportV1),
        "signed-policy-deployment-change.schema.json" => signed!(SignedPolicyDeploymentChangeV1),
        "signed-recovery-setup-probe.schema.json" => signed!(SignedRecoverySetupProbeV1),
        "signed-recovery-setup-report.schema.json" => signed!(SignedRecoverySetupReportV1),
        _ => false,
    }
}
#[test]
fn product_shared_vectors_recompute_and_match_closed_schemas() -> TestResult {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let schema_root = root.join("spec/schemas/chio-wire/v1");
    let mut registry = jsonschema::Registry::new();
    for group in std::fs::read_dir(&schema_root)? {
        let group = group?;
        if !group.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(group.path())? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let schema: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            if let Some(id) = schema.get("$id").and_then(|v| v.as_str()) {
                registry = registry.add(id, schema.clone())?;
                let alias = format!(
                    "https://chio.computer/schemas/chio-wire/v1/{}",
                    path.strip_prefix(&schema_root)?.to_string_lossy()
                );
                if id != alias {
                    registry = registry.add(&alias, schema)?;
                }
            }
        }
    }
    let registry = registry.prepare()?;
    let cases = vectors()?;
    for case in &cases {
        let schema = case["schema"].as_str().ok_or("schema")?;
        let body = &case["body"];
        let validator =
            jsonschema::options()
                .with_registry(&registry)
                .build(&serde_json::from_slice::<serde_json::Value>(
                    &std::fs::read(schema_root.join("recovery").join(schema))?,
                )?)?;
        assert_eq!(
            validator.is_valid(body),
            case["schema_valid"].as_bool().ok_or("schema valid")?,
            "{}",
            case["name"]
        );
        assert_eq!(
            typed(schema, &canonical_json_bytes(body)?),
            case["valid"].as_bool().ok_or("valid")?,
            "{}",
            case["name"]
        );
    }
    let path = root.join("spec/vectors/recovery/v1/product-contracts.json");
    let document =
        serde_json::json!({"schema":"chio.recovery-product-contract-vectors.v1","cases":cases});
    if std::env::var_os("CHIO_REGENERATE_RECOVERY_PRODUCT_VECTORS").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&document)? + "\n")?;
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(path)?)?,
        document
    );
    Ok(())
}
