use std::collections::BTreeSet;

use chio_core::Keypair;
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
        },
        latency_hint: Some(LatencyHint::Fast),
        flow,
    }
}

fn signed_registration(
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
    let signed = sign_manifest(&manifest, signer).test_expect("sign manifest");
    ManifestRegistration {
        registry_id: registry_id.to_string(),
        registered_key_id: "manifest-key".to_string(),
        signed_envelope: ManifestEnvelope {
            manifest: serde_json::to_value(signed.manifest).test_expect("manifest value"),
            signature: signed.signature,
            signer_key: signed.signer_key,
        },

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
        manifests: vec![signed_registration(
            signer,
            "registry.one",
            Some(ToolFlowDeclaration::public_egress()),
        )],
        backfill_targets: Vec::new(),
        shadow_observations: Vec::new(),
    }
}

#[test]
fn verifies_manifest_against_the_registered_key_and_rejects_a_tampered_body() {
    let signer = key(1);
    let input = base_input(&signer);
    let report = build_shadow_migration_report(input.clone()).test_expect("verified report");
    assert_eq!(report.manifests.len(), 1);
    assert_eq!(report.manifests[0].outcome, ManifestOutcome::Verified);

    let mut tampered = input;
    tampered.manifests[0].signed_envelope.manifest["name"] =
        serde_json::Value::String("Tampered".to_string());
    assert!(build_shadow_migration_report(tampered).is_err());
}

#[test]
fn rejects_the_old_manifest_shape_under_the_current_id_even_when_signed() {
    let signer = key(2);
    let old_shape = serde_json::json!({
        "schema": TOOL_MANIFEST_SCHEMA,
        "server_id": "server.old-shape",
        "name": "Old Shape Server",
        "version": "1.0.0",
        "tools": [{
            "name": "read",
            "description": "read fixture",
            "input_schema": {"type": "object"},
            "has_side_effects": false
        }],
        "public_key": signer.public_key().to_hex()
    });
    let (signature, _) = signer
        .sign_canonical(&old_shape)
        .test_expect("sign old-shape manifest");
    let input = ShadowMigrationInput {
        schema: SHADOW_MIGRATION_INPUT_SCHEMA.to_string(),
        manifest_public_keys: vec![RegisteredPublicKey {
            key_id: "manifest-key".to_string(),
            public_key: signer.public_key(),
        }],
        manifests: vec![ManifestRegistration {
            registry_id: "registry.old-shape".to_string(),
            registered_key_id: "manifest-key".to_string(),
            signed_envelope: ManifestEnvelope {
                manifest: old_shape,
                signature,
                signer_key: signer.public_key(),
            },

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
        shadow_observations: Vec::new(),
    };

    assert!(matches!(build_shadow_migration_report(input.clone()),
        Err(ShadowMigrationError::Input(chio_core::canonical::UntrustedJsonError::Decode(error)))
            if error.to_string() == "unknown field `has_side_effects`, expected one of `name`, `description`, `input_schema`, `output_schema`, `pricing`, `annotations`, `latency_hint`, `flow`"));

    let mut forged = input;
    forged.manifests[0].signed_envelope.manifest["version"] =
        serde_json::Value::String("9.9.9".to_string());
    assert!(build_shadow_migration_report(forged).is_err());
}

#[test]
fn rejects_the_retired_manifest_id_even_when_signed() {
    let signer = key(2);
    let mut input = base_input(&signer);
    input.manifests[0].signed_envelope.manifest["schema"] =
        serde_json::Value::String("chio.manifest.v2".to_string());
    let (signature, _) = signer
        .sign_canonical(&input.manifests[0].signed_envelope.manifest)
        .test_expect("re-sign retired-id manifest");
    input.manifests[0].signed_envelope.signature = signature;
    assert!(matches!(build_shadow_migration_report(input),
        Err(ShadowMigrationError::Invalid(message))
            if message == "manifest schema is unsupported: chio.manifest.v2"));
}

#[test]
fn reports_egress_adapter_purpose_credential_and_cage_findings() {
    let signer = key(3);
    let mut purposes = BTreeSet::new();
    purposes.insert(DeclassificationPurpose::new("support").test_expect("purpose"));
    let flow = ToolFlowDeclaration::new(None, Some(InformationLabel::bottom()), true, purposes)
        .test_expect("flow");
    let mut input = base_input(&signer);
    input.manifests[0] = signed_registration(&signer, "registry.one", Some(flow));
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

fn input_bytes_with(signer: &Keypair, field: &str) -> Vec<u8> {
    let mut value = serde_json::to_value(base_input(signer)).test_expect("input value");
    value
        .as_object_mut()
        .test_expect("input object")
        .insert(field.to_string(), serde_json::json!([]));
    chio_core::canonical_json_bytes(&value).test_expect("canonical input")
}

#[test]
fn input_refuses_backfill_receipts_and_receipt_keys() {
    let signer = key(11);
    for field in ["backfill_receipts", "receipt_public_keys"] {
        let expected = format!(
            "unknown field `{field}`, expected one of `schema`, `manifest_public_keys`, `manifests`, `backfill_targets`, `shadow_observations`"
        );
        let result = parse_shadow_migration_input(&input_bytes_with(&signer, field));
        assert!(
            matches!(&result,
                Err(ShadowMigrationError::Input(chio_core::canonical::UntrustedJsonError::Decode(error)))
                    if error.to_string() == expected),
            "{field}: {result:?}"
        );
    }
}

#[test]
fn every_backfill_target_is_assigned_top_with_no_evidence_fields() {
    let mut input = base_input(&key(12));
    input.backfill_targets = vec![BackfillTarget {
        tenant_id: "tenant.one".to_string(),
        principal_id: "principal.one".to_string(),
        lineage_id: "lineage.one".to_string(),
        session_id: "session.pre-enablement".to_string(),
        isolation_epoch_id: "epoch.one".to_string(),
    }];

    let report = build_shadow_migration_report(input).test_expect("backfill report");
    let value = serde_json::to_value(&report).test_expect("report value");
    assert!(value.get("verified_receipts").is_none(), "{value}");
    let top = serde_json::to_value(InformationLabel::Top).test_expect("top label");
    assert_eq!(
        value["backfill"],
        serde_json::json!({
            "principals": [{
                "tenant_id": "tenant.one",
                "principal_id": "principal.one",
                "label": top,
            }],
            "lineages": [{
                "tenant_id": "tenant.one",
                "lineage_id": "lineage.one",
                "label": top,
            }],
            "sessions": [{
                "tenant_id": "tenant.one",
                "principal_id": "principal.one",
                "lineage_id": "lineage.one",
                "session_id": "session.pre-enablement",
                "isolation_epoch_id": "epoch.one",
                "label": top,
            }],
        })
    );
}

#[test]
fn sessions_of_one_principal_and_lineage_share_one_record_each() {
    let mut input = base_input(&key(13));
    input.backfill_targets = ["session.one", "session.two"]
        .into_iter()
        .map(|session_id| BackfillTarget {
            tenant_id: "tenant.one".to_string(),
            principal_id: "principal.one".to_string(),
            lineage_id: "lineage.one".to_string(),
            session_id: session_id.to_string(),
            isolation_epoch_id: "epoch.one".to_string(),
        })
        .collect();

    let report = build_shadow_migration_report(input).test_expect("backfill report");
    assert_eq!(report.backfill.principals.len(), 1);
    assert_eq!(report.backfill.principals[0].label, InformationLabel::Top);
    assert_eq!(report.backfill.sessions.len(), 2);
    assert!(report
        .backfill
        .sessions
        .iter()
        .all(|session| session.label == InformationLabel::Top));
}
