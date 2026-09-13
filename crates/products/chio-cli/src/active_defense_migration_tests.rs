use std::collections::BTreeSet;

use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::{sha256_hex, Keypair};
use chio_manifest::{
    sign_manifest, DeclassificationPurpose, LatencyHint, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, TOOL_MANIFEST_SCHEMA,
};
use chio_security_types::InformationLabel;
use chio_test_support::prelude::*;

use super::*;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn tool(name: &str, flow: Option<ToolFlowDeclaration>) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: format!("{name} fixture"),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: Some(serde_json::json!({"type": "object"})),
        pricing: None,
        annotations: ToolAnnotations {
            read_only: true,
            destructive: false,
            idempotent: true,
            requires_approval: false,
            estimated_duration_ms: None,
        },
        latency_hint: Some(LatencyHint::Fast),
        flow,
    }
}

fn signed_v2_registration(
    signer: &Keypair,
    registry_id: &str,
    flow: Option<ToolFlowDeclaration>,
) -> ManifestRegistration {
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "server.one".to_string(),
        name: "Server One".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![tool("send", flow)],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, signer).test_expect("sign v2 manifest");
    ManifestRegistration {
        registry_id: registry_id.to_string(),
        registered_key_id: "manifest-key".to_string(),
        signed_envelope: ManifestEnvelope {
            manifest: serde_json::to_value(signed.manifest).test_expect("manifest value"),
            signature: signed.signature,
            signer_key: signed.signer_key,
        },
        legacy_permission_amendment: None,
        tools: vec![ToolDeploymentInventory {
            tool_name: "send".to_string(),
            runtime_egress: true,
            policy_clearances: vec![InformationLabel::bottom()],
            policy_declassification_purposes: Vec::new(),
            adapters: vec![AdapterInventory {
                adapter_id: "mcp".to_string(),
                preserves_exact_flow_declaration: true,
                preserves_authenticated_extensions: true,
            }],
            direct_credential_grants: Vec::new(),
        }],
        server_runtime: ServerRuntimeInventory::Managed,
    }
}

fn base_input(signer: &Keypair) -> ShadowMigrationInput {
    ShadowMigrationInput {
        schema: SHADOW_MIGRATION_INPUT_SCHEMA.to_string(),
        manifest_public_keys: vec![RegisteredPublicKey {
            key_id: "manifest-key".to_string(),
            public_key: signer.public_key(),
        }],
        receipt_public_keys: Vec::new(),
        manifests: vec![signed_v2_registration(
            signer,
            "registry.one",
            Some(ToolFlowDeclaration::public_egress()),
        )],
        backfill_targets: Vec::new(),
        backfill_receipts: Vec::new(),
        shadow_observations: Vec::new(),
    }
}

fn backfill_evidence(
    manifest_digest: String,
    session_id: &str,
    legacy_session_closed: bool,
) -> BackfillEvidence {
    BackfillEvidence {
        schema: BACKFILL_EVIDENCE_SCHEMA.to_string(),
        manifest_registry_id: "registry.one".to_string(),
        manifest_digest,
        tenant_id: "tenant.one".to_string(),
        principal_id: "principal.one".to_string(),
        lineage_id: "lineage.one".to_string(),
        session_id: session_id.to_string(),
        isolation_epoch_id: "epoch.one".to_string(),
        principal_label: InformationLabel::bottom(),
        lineage_label: InformationLabel::bottom(),
        session_label: InformationLabel::bottom(),
        context_generation: 7,
        legacy_session_closed,
    }
}

fn signed_backfill_receipt(
    signer: &Keypair,
    evidence: BackfillEvidence,
) -> RegisteredBackfillReceipt {
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        BACKFILL_METADATA_KEY.to_string(),
        serde_json::to_value(evidence).test_expect("backfill evidence value"),
    );
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp: 1_720_000_000,
        capability_id: "cap.one".to_string(),
        tool_server: "server.one".to_string(),
        tool_name: "send".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"value": 1})).test_expect("action"),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"fixture-output"),
        policy_hash: sha256_hex(b"fixture-policy"),
        evidence: Vec::new(),
        metadata: Some(serde_json::Value::Object(metadata)),
        trust_level: TrustLevel::Mediated,
        tenant_id: Some("tenant.one".to_string()),
        kernel_key: signer.public_key(),
        bbs_projection_version: None,
    };
    let receipt = ChioReceipt::sign(body, signer).test_expect("sign receipt");
    RegisteredBackfillReceipt {
        registered_key_id: "receipt-key".to_string(),
        receipt: serde_json::to_value(receipt).test_expect("receipt value"),
    }
}

#[test]
fn verifies_v2_against_the_registered_key_and_rejects_a_tampered_body() {
    let signer = key(1);
    let input = base_input(&signer);
    let report = build_shadow_migration_report(input.clone()).test_expect("verified report");
    assert_eq!(report.manifests.len(), 1);
    assert_eq!(report.manifests[0].outcome, ManifestOutcome::VerifiedV2);

    let mut tampered = input;
    tampered.manifests[0].signed_envelope.manifest["name"] =
        serde_json::Value::String("Tampered".to_string());
    assert!(build_shadow_migration_report(tampered).is_err());
}

#[test]
fn verifies_the_original_v1_body_before_emitting_an_unsigned_v2_artifact() {
    let signer = key(2);
    let v1 = serde_json::json!({
        "schema": "chio.manifest.v1",
        "server_id": "server.legacy",
        "name": "Legacy Server",
        "description": "legacy",
        "version": "1.0.0",
        "tools": [{
            "name": "read",
            "description": "read fixture",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "annotations": {
                "read_only": true,
                "destructive": false,
                "idempotent": true,
                "requires_approval": false,
                "estimated_duration_ms": 999
            }
        }],
        "server_tools": [],
        "required_permissions": null,
        "public_key": signer.public_key().to_hex()
    });
    let (signature, _) = signer.sign_canonical(&v1).test_expect("sign v1");
    let input = ShadowMigrationInput {
        schema: SHADOW_MIGRATION_INPUT_SCHEMA.to_string(),
        manifest_public_keys: vec![RegisteredPublicKey {
            key_id: "manifest-key".to_string(),
            public_key: signer.public_key(),
        }],
        receipt_public_keys: Vec::new(),
        manifests: vec![ManifestRegistration {
            registry_id: "registry.legacy".to_string(),
            registered_key_id: "manifest-key".to_string(),
            signed_envelope: ManifestEnvelope {
                manifest: v1,
                signature,
                signer_key: signer.public_key(),
            },
            legacy_permission_amendment: None,
            tools: vec![ToolDeploymentInventory {
                tool_name: "read".to_string(),
                runtime_egress: false,
                policy_clearances: Vec::new(),
                policy_declassification_purposes: Vec::new(),
                adapters: Vec::new(),
                direct_credential_grants: Vec::new(),
            }],
            server_runtime: ServerRuntimeInventory::Managed,
        }],
        backfill_targets: Vec::new(),
        backfill_receipts: Vec::new(),
        shadow_observations: Vec::new(),
    };

    let report = build_shadow_migration_report(input.clone()).test_expect("v1 migration");
    assert_eq!(report.unsigned_v2_artifacts.len(), 1);
    assert!(report.unsigned_v2_artifacts[0].operator_resigning_required);
    assert_eq!(
        report.unsigned_v2_artifacts[0].manifest.schema,
        TOOL_MANIFEST_SCHEMA
    );
    assert_eq!(
        report.unsigned_v2_artifacts[0].manifest.tools[0].latency_hint,
        Some(LatencyHint::Fast)
    );

    let mut forged = input;
    forged.manifests[0].signed_envelope.manifest["version"] =
        serde_json::Value::String("9.9.9".to_string());
    assert!(build_shadow_migration_report(forged).is_err());
}

#[test]
fn reports_egress_adapter_purpose_credential_and_cage_findings() {
    let signer = key(3);
    let mut purposes = BTreeSet::new();
    purposes.insert(DeclassificationPurpose::new("support").test_expect("purpose"));
    let flow = ToolFlowDeclaration::new(None, Some(InformationLabel::bottom()), true, purposes)
        .test_expect("flow");
    let mut input = base_input(&signer);
    input.manifests[0] = signed_v2_registration(&signer, "registry.one", Some(flow));
    let deployment = &mut input.manifests[0].tools[0];
    deployment.policy_clearances.clear();
    deployment.adapters[0].preserves_exact_flow_declaration = false;
    deployment.direct_credential_grants = vec![DirectCredentialGrant::EnvironmentVariable {
        name: "PROVIDER_TOKEN".to_string(),
    }];
    input.manifests[0].server_runtime = ServerRuntimeInventory::Native {
        selected_for_cage: true,
        operator_ceiling: NativeCageCeiling {
            read_paths: vec!["/srv/data".to_string()],
            write_paths: Vec::new(),
            network_destinations: Vec::new(),
            environment_variables: Vec::new(),
            native_syscall_profile: chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        },
    };

    let report = build_shadow_migration_report(input).test_expect("inventory report");
    assert_eq!(report.egress_clearance_findings.len(), 1);
    assert_eq!(report.unknown_output_declarations.len(), 1);
    assert_eq!(report.invalid_purpose_sets.len(), 1);
    assert_eq!(report.unsupported_adapters.len(), 1);
    assert_eq!(report.direct_credential_grants.len(), 1);
    assert_eq!(report.native_cage_inventory.len(), 1);
    assert!(report.native_cage_inventory[0].selected_for_cage);
}

#[test]
fn backfill_requires_pinned_receipts_and_verified_v2_manifest_evidence() {
    let manifest_signer = key(4);
    let receipt_signer = key(5);
    let mut input = base_input(&manifest_signer);
    let source_digest = chio_core::sha256_hex(
        &chio_core::canonical_json_bytes(&input.manifests[0].signed_envelope.manifest)
            .test_expect("manifest canonical bytes"),
    );
    input.receipt_public_keys.push(RegisteredPublicKey {
        key_id: "receipt-key".to_string(),
        public_key: receipt_signer.public_key(),
    });
    input.backfill_targets = vec![BackfillTarget {
        tenant_id: "tenant.one".to_string(),
        principal_id: "principal.one".to_string(),
        lineage_id: "lineage.one".to_string(),
        session_id: "session.legacy".to_string(),
        isolation_epoch_id: "epoch.one".to_string(),
    }];
    input.backfill_receipts.push(signed_backfill_receipt(
        &receipt_signer,
        backfill_evidence(source_digest, "session.legacy", true),
    ));

    let report = build_shadow_migration_report(input.clone()).test_expect("verified backfill");
    assert_eq!(report.backfill.principal_records_from_verified_evidence, 1);
    assert_eq!(report.backfill.principal_records_assigned_top, 0);
    assert!(report.backfill.sessions[0].legacy_session_closed);

    let mut wrong_key = input;
    wrong_key.receipt_public_keys[0].public_key = key(6).public_key();
    assert!(build_shadow_migration_report(wrong_key).is_err());
}

#[test]
fn absent_legacy_session_evidence_assigns_top_and_preserves_principal_knowledge() {
    let manifest_signer = key(7);
    let receipt_signer = key(8);
    let mut input = base_input(&manifest_signer);
    let source_digest = chio_core::sha256_hex(
        &chio_core::canonical_json_bytes(&input.manifests[0].signed_envelope.manifest)
            .test_expect("manifest canonical bytes"),
    );
    input.receipt_public_keys.push(RegisteredPublicKey {
        key_id: "receipt-key".to_string(),
        public_key: receipt_signer.public_key(),
    });
    input.backfill_targets = vec![
        BackfillTarget {
            tenant_id: "tenant.one".to_string(),
            principal_id: "principal.one".to_string(),
            lineage_id: "lineage.one".to_string(),
            session_id: "session.verified".to_string(),
            isolation_epoch_id: "epoch.one".to_string(),
        },
        BackfillTarget {
            tenant_id: "tenant.one".to_string(),
            principal_id: "principal.one".to_string(),
            lineage_id: "lineage.one".to_string(),
            session_id: "session.unknown".to_string(),
            isolation_epoch_id: "epoch.one".to_string(),
        },
    ];
    input.backfill_receipts.push(signed_backfill_receipt(
        &receipt_signer,
        backfill_evidence(source_digest, "session.verified", true),
    ));

    let report = build_shadow_migration_report(input).test_expect("conservative backfill");
    assert_eq!(report.backfill.principals.len(), 1);
    assert_eq!(report.backfill.principals[0].label, InformationLabel::Top);
    assert!(report.backfill.principals[0].assigned_top_due_to_missing_evidence);
    assert_eq!(report.backfill.sessions.len(), 2);
    assert_eq!(report.backfill.session_records_assigned_top, 1);
}

#[test]
fn emits_all_shadow_metrics_without_embedding_promotion_thresholds() {
    let signer = key(9);
    let mut input = base_input(&signer);
    input.shadow_observations = vec![
        ShadowObservation {
            metric: ShadowMetric::UnknownLabels,
            count: 2,
        },
        ShadowObservation {
            metric: ShadowMetric::UnknownLabels,
            count: 3,
        },
    ];

    let report = build_shadow_migration_report(input).test_expect("metric report");
    assert_eq!(report.shadow_metrics.len(), ShadowMetric::ALL.len());
    assert_eq!(report.shadow_metrics[0].count, 5);
    let encoded = serde_json::to_value(report).test_expect("report value");
    let encoded = serde_json::to_string(&encoded).test_expect("report JSON");
    assert!(!encoded.contains("threshold"));
}

#[test]
fn strict_input_rejects_unknown_fields_and_atomic_failure_preserves_output() {
    let directory = tempfile::tempdir().test_expect("temp directory");
    let input_path = directory.path().join("input.json");
    let output_path = directory.path().join("report.json");
    std::fs::write(
        &input_path,
        br#"{"schema":"chio.active-defense.shadow-migration-input.v1","unknown":true}"#,
    )
    .test_expect("write input");
    std::fs::write(&output_path, b"existing-report").test_expect("write prior output");

    assert!(cmd_shadow_migrate(&input_path, &output_path).is_err());
    assert_eq!(
        std::fs::read(&output_path).test_expect("read prior output"),
        b"existing-report"
    );
}

#[test]
fn migration_command_writes_one_canonical_report_after_full_verification() {
    let directory = tempfile::tempdir().test_expect("temp directory");
    let input_path = directory.path().join("input.json");
    let output_path = directory.path().join("report.json");
    let input = base_input(&key(10));
    std::fs::write(
        &input_path,
        chio_core::canonical_json_bytes(&input).test_expect("canonical input"),
    )
    .test_expect("write input");

    cmd_shadow_migrate(&input_path, &output_path).test_expect("write migration report");

    let bytes = std::fs::read(&output_path).test_expect("read report");
    let value: serde_json::Value = serde_json::from_slice(&bytes).test_expect("parse report");
    assert_eq!(
        bytes,
        chio_core::canonical_json_bytes(&value).test_expect("canonical report")
    );
    assert_eq!(value["schema"], SHADOW_MIGRATION_REPORT_SCHEMA);
    assert_eq!(value["shadow_metrics"].as_array().map(Vec::len), Some(9));
}
