use chio_core::crypto::Keypair;
use chio_manifest::{
    load_existing_verified_manifest_registry, migrate_legacy_manifest_v1, sign_manifest,
    verify_manifest, AuthoritativeToolPolicy, DeclassificationPurpose, EnvironmentVariableName,
    LatencyHint, NativeSyscallProfile, NetworkDestination, RequiredPermissions,
    RuntimeToolTopology, ServerTool, ToolAnnotations, ToolDefinition, ToolManifest,
    VerifiedManifestAdmissionError, VerifiedManifestInvocationError, VerifiedManifestRegistry,
    TOOL_MANIFEST_SCHEMA,
};
use chio_security_types::{Compartment, InformationLabel};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn v2_manifest(public_key: String) -> ToolManifest {
    ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "srv-v2".to_string(),
        name: "V2 server".to_string(),
        description: None,
        version: "2.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "read".to_string(),
            description: "Read".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: Some(LatencyHint::Instant),
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: Some(RequiredPermissions {
            read_paths: Some(vec!["/srv/data".to_string()]),
            write_paths: None,
            network_destinations: Some(vec![NetworkDestination::new("api.example.com", 443)
                .unwrap_or_else(|error| panic!("destination: {error}"))]),
            environment_variables: Some(vec![EnvironmentVariableName::new("CHIO_MODE")
                .unwrap_or_else(|error| panic!("environment name: {error}"))]),
            native_syscall_profile: NativeSyscallProfile::BrokeredNativeV1,
        }),
        public_key,
    }
}

fn unique_manifest_path(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("system clock: {error}"))
        .as_nanos();
    std::env::temp_dir().join(format!(
        "chio-manifest-{name}-{}-{nonce}.json",
        std::process::id()
    ))
}

fn write_signed_manifest_fixture(name: &str) -> (PathBuf, Keypair) {
    let keypair = Keypair::generate();
    let signed = sign_manifest(&v2_manifest(keypair.public_key().to_hex()), &keypair)
        .unwrap_or_else(|error| panic!("sign fixture: {error}"));
    let path = unique_manifest_path(name);
    std::fs::write(
        &path,
        serde_json::to_vec(&signed).unwrap_or_else(|error| panic!("serialize fixture: {error}")),
    )
    .unwrap_or_else(|error| panic!("write fixture: {error}"));
    (path, keypair)
}

#[test]
fn existing_signed_manifest_loader_requires_out_of_band_key_and_server_identity() {
    let (path, keypair) = write_signed_manifest_fixture("load-positive");
    let registry = load_existing_verified_manifest_registry(
        &path,
        &keypair.public_key().to_hex(),
        "srv-v2",
        RuntimeToolTopology::remote(),
    )
    .unwrap_or_else(|error| panic!("load registry: {error}"));
    let security = registry
        .bridge_security("srv-v2", "read")
        .unwrap_or_else(|| panic!("admitted bridge security"));
    assert!(security.has_registry_coordinates());
    assert!(security.effective_egress());

    let wrong_key = Keypair::generate();
    assert!(load_existing_verified_manifest_registry(
        &path,
        &wrong_key.public_key().to_hex(),
        "srv-v2",
        RuntimeToolTopology::remote(),
    )
    .is_err());
    assert!(load_existing_verified_manifest_registry(
        &path,
        &keypair.public_key().to_hex(),
        "different-server",
        RuntimeToolTopology::remote(),
    )
    .is_err());
    std::fs::remove_file(path).unwrap_or_else(|error| panic!("remove fixture: {error}"));
}

#[test]
fn existing_signed_manifest_loader_never_creates_missing_paths() {
    let path = unique_manifest_path("missing");
    let keypair = Keypair::generate();
    assert!(load_existing_verified_manifest_registry(
        &path,
        &keypair.public_key().to_hex(),
        "srv-v2",
        RuntimeToolTopology::remote(),
    )
    .is_err());
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn existing_signed_manifest_loader_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let (target, keypair) = write_signed_manifest_fixture("symlink-target");
    let link = unique_manifest_path("symlink-link");
    symlink(&target, &link).unwrap_or_else(|error| panic!("create symlink: {error}"));
    assert!(load_existing_verified_manifest_registry(
        &link,
        &keypair.public_key().to_hex(),
        "srv-v2",
        RuntimeToolTopology::remote(),
    )
    .is_err());
    std::fs::remove_file(link).unwrap_or_else(|error| panic!("remove symlink: {error}"));
    std::fs::remove_file(target).unwrap_or_else(|error| panic!("remove target: {error}"));
}

#[test]
fn verified_registry_admits_provider_server_tools_only_as_remote_egress() {
    let signer = Keypair::from_seed(&[30; 32]);
    let mut manifest = v2_manifest(signer.public_key().to_hex());
    manifest.server_tools = vec![ServerTool::Bash];
    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign server-tool manifest: {error}"));
    let policies = [
        ("read".to_string(), AuthoritativeToolPolicy::public_only()),
        ("bash".to_string(), AuthoritativeToolPolicy::public_only()),
    ]
    .into_iter()
    .collect();
    let topologies = [
        ("read".to_string(), RuntimeToolTopology::local()),
        ("bash".to_string(), RuntimeToolTopology::remote()),
    ]
    .into_iter()
    .collect();
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(signed.clone(), &signer.public_key(), &policies, &topologies)
        .unwrap_or_else(|error| panic!("admit server-tool manifest: {error}"));
    assert!(registry.requires_flow_runtime());
    let security = registry
        .bridge_security_for_server_tool("srv-v2", "bash_20241022")
        .unwrap_or_else(|| panic!("server-tool bridge security"));
    assert!(security.has_registry_coordinates());
    assert!(security.effective_egress());
    assert_eq!(security.tool_name(), Some("bash"));
    assert_eq!(
        registry
            .tool_security_for_server_tool("srv-v2", "bash_20241022")
            .unwrap_or_else(|| panic!("server-tool admitted security")),
        registry
            .tool_security_for_server_tool("srv-v2", "bash")
            .unwrap_or_else(|| panic!("stable server-tool admitted security"))
    );
    registry
        .validate_bridge_security("srv-v2", "bash_20241022", &security)
        .unwrap_or_else(|error| panic!("validate server-tool sidecar: {error}"));
    registry
        .validate_invocation_arguments(
            "srv-v2",
            "bash_20241022",
            &security,
            &serde_json::json!({"command": "pwd"}),
        )
        .unwrap_or_else(|error| panic!("validate trusted server-tool arguments: {error}"));
    registry
        .validate_invocation_arguments(
            "srv-v2",
            "bash_20250124",
            &security,
            &serde_json::json!({"restart": true}),
        )
        .unwrap_or_else(|error| panic!("validate date-suffixed server-tool family: {error}"));
    assert!(matches!(
        registry.validate_invocation_arguments(
            "srv-v2",
            "bash_20241022",
            &security,
            &serde_json::json!({"command": 7}),
        ),
        Err(VerifiedManifestInvocationError::TrustedServerToolSchemaMismatch {
            server_id,
            tool_name,
        }) if server_id == "srv-v2" && tool_name == "bash_20241022"
    ));

    let mut local_registry = VerifiedManifestRegistry::default();
    assert!(local_registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::local(),)
        .is_err());

    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign broker-confused server-tool manifest: {error}"));
    let mut broker_registry = VerifiedManifestRegistry::default();
    assert!(broker_registry
        .register_public_only(
            signed,
            &signer.public_key(),
            RuntimeToolTopology::brokered(),
        )
        .is_err());
}

#[test]
fn verified_registry_runtime_requirement_includes_derived_remote_topology() {
    let signer = Keypair::from_seed(&[32; 32]);
    let manifest = v2_manifest(signer.public_key().to_hex());
    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign topology manifest: {error}"));

    let mut local_registry = VerifiedManifestRegistry::default();
    local_registry
        .register_public_only(
            signed.clone(),
            &signer.public_key(),
            RuntimeToolTopology::local(),
        )
        .unwrap_or_else(|error| panic!("admit local manifest: {error}"));
    assert!(!local_registry.requires_flow_runtime());

    let mut remote_registry = VerifiedManifestRegistry::default();
    remote_registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .unwrap_or_else(|error| panic!("admit remote manifest: {error}"));
    assert!(remote_registry.requires_flow_runtime());
}

#[test]
fn cage_authorization_requires_profile_matched_runtime_topology() {
    let signer = Keypair::from_seed(&[36; 32]);
    let mut local_manifest = v2_manifest(signer.public_key().to_hex());
    local_manifest.required_permissions =
        local_manifest.required_permissions.map(|mut permissions| {
            permissions.native_syscall_profile = NativeSyscallProfile::NativeMinimalV1;
            permissions
        });
    let local_signed = sign_manifest(&local_manifest, &signer)
        .unwrap_or_else(|error| panic!("sign local cage manifest: {error}"));

    let mut local_registry = VerifiedManifestRegistry::default();
    local_registry
        .register_public_only(
            local_signed.clone(),
            &signer.public_key(),
            RuntimeToolTopology::local(),
        )
        .unwrap_or_else(|error| panic!("register local cage manifest: {error}"));
    let local = local_registry
        .authorize_cage_manifest("srv-v2")
        .unwrap_or_else(|error| panic!("authorize local cage manifest: {error}"));
    assert_eq!(local.topology(), RuntimeToolTopology::local());
    assert_eq!(local.server_id(), "srv-v2");
    assert_eq!(local.manifest_digest().len(), 64);
    assert_eq!(local.signed_manifest_digest().len(), 64);
    assert_eq!(local.registry_digest().len(), 64);
    assert_eq!(local.authorization_digest().len(), 64);

    let mut remote_registry = VerifiedManifestRegistry::default();
    remote_registry
        .register_public_only(
            local_signed,
            &signer.public_key(),
            RuntimeToolTopology::remote(),
        )
        .unwrap_or_else(|error| panic!("register remote manifest: {error}"));
    assert!(matches!(
        remote_registry.authorize_cage_manifest("srv-v2"),
        Err(VerifiedManifestAdmissionError::CageTopologyMismatch { .. })
    ));

    let broker_signer = Keypair::from_seed(&[37; 32]);
    let broker_manifest = v2_manifest(broker_signer.public_key().to_hex());
    let broker_signed = sign_manifest(&broker_manifest, &broker_signer)
        .unwrap_or_else(|error| panic!("sign broker cage manifest: {error}"));
    let mut broker_registry = VerifiedManifestRegistry::default();
    broker_registry
        .register_public_only(
            broker_signed.clone(),
            &broker_signer.public_key(),
            RuntimeToolTopology::brokered(),
        )
        .unwrap_or_else(|error| panic!("register broker cage manifest: {error}"));
    let broker = broker_registry
        .authorize_cage_manifest("srv-v2")
        .unwrap_or_else(|error| panic!("authorize broker cage manifest: {error}"));
    assert_eq!(broker.topology(), RuntimeToolTopology::brokered());

    let mut wrong_local_registry = VerifiedManifestRegistry::default();
    wrong_local_registry
        .register_public_only(
            broker_signed,
            &broker_signer.public_key(),
            RuntimeToolTopology::local(),
        )
        .unwrap_or_else(|error| panic!("register profile-confused manifest: {error}"));
    assert!(matches!(
        wrong_local_registry.authorize_cage_manifest("srv-v2"),
        Err(VerifiedManifestAdmissionError::CageTopologyMismatch { .. })
    ));
}

#[test]
fn cage_authorization_binds_registry_manifest_and_every_tool_topology() {
    let signer = Keypair::from_seed(&[38; 32]);
    let mut manifest = v2_manifest(signer.public_key().to_hex());
    manifest.required_permissions = manifest.required_permissions.map(|mut permissions| {
        permissions.native_syscall_profile = NativeSyscallProfile::NativeStandardV1;
        permissions
    });
    let mut second_tool = manifest.tools[0].clone();
    second_tool.name = "write".to_string();
    second_tool.description = "Write".to_string();
    manifest.tools.push(second_tool);
    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign multi-tool cage manifest: {error}"));
    let policies = [
        ("read".to_string(), AuthoritativeToolPolicy::public_only()),
        ("write".to_string(), AuthoritativeToolPolicy::public_only()),
    ]
    .into_iter()
    .collect();

    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(
            signed.clone(),
            &signer.public_key(),
            &policies,
            &[
                ("read".to_string(), RuntimeToolTopology::local()),
                ("write".to_string(), RuntimeToolTopology::local()),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap_or_else(|error| panic!("register exact local topology: {error}"));
    let exact = registry
        .authorize_cage_manifest("srv-v2")
        .unwrap_or_else(|error| panic!("authorize exact local topology: {error}"));

    let mut mixed_registry = VerifiedManifestRegistry::default();
    mixed_registry
        .register(
            signed,
            &signer.public_key(),
            &policies,
            &[
                ("read".to_string(), RuntimeToolTopology::local()),
                ("write".to_string(), RuntimeToolTopology::remote()),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap_or_else(|error| panic!("register mixed topology: {error}"));
    assert!(matches!(
        mixed_registry.authorize_cage_manifest("srv-v2"),
        Err(VerifiedManifestAdmissionError::CageTopologyMismatch { .. })
    ));

    let other_signer = Keypair::from_seed(&[39; 32]);
    let mut other_manifest = v2_manifest(other_signer.public_key().to_hex());
    other_manifest.server_id = "other-server".to_string();
    other_manifest.required_permissions =
        other_manifest.required_permissions.map(|mut permissions| {
            permissions.native_syscall_profile = NativeSyscallProfile::NativeMinimalV1;
            permissions
        });
    let other_signed = sign_manifest(&other_manifest, &other_signer)
        .unwrap_or_else(|error| panic!("sign other registry manifest: {error}"));
    let mut expanded_registry = registry.clone();
    expanded_registry
        .register_public_only(
            other_signed,
            &other_signer.public_key(),
            RuntimeToolTopology::local(),
        )
        .unwrap_or_else(|error| panic!("expand registry snapshot: {error}"));
    let expanded = expanded_registry
        .authorize_cage_manifest("srv-v2")
        .unwrap_or_else(|error| panic!("authorize expanded registry: {error}"));
    assert_eq!(exact.manifest_digest(), expanded.manifest_digest());
    assert_eq!(
        exact.signed_manifest_digest(),
        expanded.signed_manifest_digest()
    );
    assert_ne!(exact.registry_digest(), expanded.registry_digest());
    assert_ne!(
        exact.authorization_digest(),
        expanded.authorization_digest()
    );
}

#[test]
fn v2_manifest_signs_and_verifies_with_normalized_permissions() {
    let keypair = Keypair::generate();
    let manifest = v2_manifest(keypair.public_key().to_hex());
    assert_eq!(
        manifest
            .required_permissions
            .as_ref()
            .unwrap_or_else(|| panic!("permissions"))
            .network_destinations
            .as_ref()
            .unwrap_or_else(|| panic!("destinations"))[0]
            .host()
            .as_str(),
        "api.example.com"
    );
    let signed =
        sign_manifest(&manifest, &keypair).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    verify_manifest(&signed, &keypair.public_key())
        .unwrap_or_else(|error| panic!("verify manifest: {error}"));
}

#[test]
fn changing_flow_metadata_invalidates_manifest_signature() {
    let keypair = Keypair::generate();
    let mut manifest = v2_manifest(keypair.public_key().to_hex());
    manifest.tools[0].flow = Some(chio_manifest::ToolFlowDeclaration::public_egress());
    let mut signed = sign_manifest(&manifest, &keypair)
        .unwrap_or_else(|error| panic!("sign flow manifest: {error}"));
    signed.manifest.tools[0].flow = None;
    assert!(verify_manifest(&signed, &keypair.public_key()).is_err());
}

#[test]
fn v2_rejects_alternate_json_spellings_of_signed_fields() {
    let keypair = Keypair::from_seed(&[23; 32]);
    let manifest = v2_manifest(keypair.public_key().to_hex());
    let canonical = serde_json::to_value(&manifest)
        .unwrap_or_else(|error| panic!("serialize manifest: {error}"));

    let mut explicit_description_null = canonical.clone();
    explicit_description_null["description"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ToolManifest>(explicit_description_null).is_err());

    let mut explicit_server_tools_empty = canonical.clone();
    explicit_server_tools_empty["server_tools"] = serde_json::json!([]);
    assert!(serde_json::from_value::<ToolManifest>(explicit_server_tools_empty).is_err());

    let mut explicit_output_schema_null = canonical.clone();
    explicit_output_schema_null["tools"][0]["output_schema"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ToolManifest>(explicit_output_schema_null).is_err());

    let mut missing_annotation = canonical;
    missing_annotation["tools"][0]["annotations"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("annotations object"))
        .remove("destructive");
    assert!(serde_json::from_value::<ToolManifest>(missing_annotation).is_err());
}

#[test]
fn v2_rejects_noncanonical_permission_spellings() {
    let keypair = Keypair::from_seed(&[29; 32]);
    let manifest = v2_manifest(keypair.public_key().to_hex());
    let canonical = serde_json::to_value(&manifest)
        .unwrap_or_else(|error| panic!("serialize manifest: {error}"));

    let mut uppercase_host = canonical.clone();
    uppercase_host["required_permissions"]["network_destinations"][0]["host"] =
        serde_json::json!("API.Example.COM");
    assert!(serde_json::from_value::<ToolManifest>(uppercase_host).is_err());

    for path in ["/workspace/./data", "/workspace//data", "/workspace/"] {
        let mut aliased_path = canonical.clone();
        aliased_path["required_permissions"]["read_paths"] = serde_json::json!([path]);
        let parsed = serde_json::from_value::<ToolManifest>(aliased_path)
            .unwrap_or_else(|error| panic!("parse aliased path {path}: {error}"));
        assert!(chio_manifest::validate_manifest(&parsed).is_err(), "{path}");
    }

    for field in [
        "read_paths",
        "write_paths",
        "network_destinations",
        "environment_variables",
    ] {
        let mut empty_permission = canonical.clone();
        empty_permission["required_permissions"][field] = serde_json::json!([]);
        let parsed = serde_json::from_value::<ToolManifest>(empty_permission)
            .unwrap_or_else(|error| panic!("parse empty permission {field}: {error}"));
        assert!(
            chio_manifest::validate_manifest(&parsed).is_err(),
            "{field}"
        );
    }
}

#[test]
fn flow_rejects_null_and_explicit_empty_aliases() {
    assert!(
        serde_json::from_value::<chio_manifest::ToolFlowDeclaration>(serde_json::json!({
            "egress": false,
            "output_label": null
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<chio_manifest::ToolFlowDeclaration>(serde_json::json!({
            "egress": false,
            "declassification_purposes": []
        }))
        .is_err()
    );
}

fn compartment_label(name: &str) -> InformationLabel {
    InformationLabel::try_known(
        BTreeMap::new(),
        [Compartment::new(name).unwrap_or_else(|error| panic!("compartment: {error}"))]
            .into_iter()
            .collect(),
    )
    .unwrap_or_else(|error| panic!("label: {error}"))
}

#[test]
fn verified_registry_composes_registered_key_policy_and_runtime_topology() {
    let keypair = Keypair::from_seed(&[25; 32]);
    let mut manifest = v2_manifest(keypair.public_key().to_hex());
    let purpose_a =
        DeclassificationPurpose::new("support").unwrap_or_else(|error| panic!("purpose: {error}"));
    let purpose_b =
        DeclassificationPurpose::new("audit").unwrap_or_else(|error| panic!("purpose: {error}"));
    manifest.tools[0].flow = Some(
        chio_manifest::ToolFlowDeclaration::new(
            Some(compartment_label("publisher-output")),
            Some(InformationLabel::bottom()),
            false,
            [purpose_a.clone(), purpose_b].into_iter().collect(),
        )
        .unwrap_or_else(|error| panic!("flow: {error}")),
    );
    let signed =
        sign_manifest(&manifest, &keypair).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    let policy = AuthoritativeToolPolicy::new(
        vec![compartment_label("policy-input")],
        compartment_label("policy-output"),
        [purpose_a.clone()].into_iter().collect(),
    )
    .unwrap_or_else(|error| panic!("policy: {error}"));
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(
            signed,
            &keypair.public_key(),
            &[("read".to_string(), policy)].into_iter().collect(),
            &[("read".to_string(), RuntimeToolTopology::remote())]
                .into_iter()
                .collect(),
        )
        .unwrap_or_else(|error| panic!("register: {error}"));

    let admitted = registry
        .tool_security("srv-v2", "read")
        .unwrap_or_else(|| panic!("admitted security"));
    assert!(admitted.effective_egress());
    assert_eq!(
        admitted.declassification_purposes(),
        &[purpose_a].into_iter().collect::<BTreeSet<_>>()
    );
    assert!(admitted
        .authorize_source(&InformationLabel::bottom())
        .is_ok());
    assert!(admitted.authorize_source(&InformationLabel::Top).is_err());
    assert_eq!(registry.verified_manifests().count(), 1);
    let sidecar = registry
        .bridge_security("srv-v2", "read")
        .unwrap_or_else(|| panic!("registry bridge security"));
    assert!(sidecar.has_registry_coordinates());
    assert!(sidecar.effective_egress());
    assert_eq!(sidecar.server_id(), Some("srv-v2"));
    assert_eq!(sidecar.tool_name(), Some("read"));
    assert!(sidecar.manifest_digest().is_some());
}

#[test]
fn verified_registry_rejects_manifest_clearance_that_widens_policy() {
    let keypair = Keypair::from_seed(&[33; 32]);
    let mut manifest = v2_manifest(keypair.public_key().to_hex());
    manifest.tools[0].flow = Some(
        chio_manifest::ToolFlowDeclaration::new(
            None,
            Some(compartment_label("manifest-only")),
            true,
            BTreeSet::new(),
        )
        .unwrap_or_else(|error| panic!("flow: {error}")),
    );
    let signed = sign_manifest(&manifest, &keypair).unwrap_or_else(|error| panic!("sign: {error}"));
    let policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        InformationLabel::bottom(),
        BTreeSet::new(),
    )
    .unwrap_or_else(|error| panic!("policy: {error}"));
    let error = match VerifiedManifestRegistry::default().register(
        signed,
        &keypair.public_key(),
        &[("read".to_string(), policy)].into_iter().collect(),
        &[("read".to_string(), RuntimeToolTopology::remote())]
            .into_iter()
            .collect(),
    ) {
        Ok(_) => panic!("manifest clearance widening was accepted"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        VerifiedManifestAdmissionError::ManifestClearanceWidensPolicy(tool) if tool == "read"
    ));
}

#[test]
fn verified_registry_requires_an_exact_live_bridge_security_value() {
    let signer = Keypair::from_seed(&[34; 32]);
    let manifest = v2_manifest(signer.public_key().to_hex());
    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign first manifest: {error}"));
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .unwrap_or_else(|error| panic!("register first manifest: {error}"));
    let sidecar = registry
        .bridge_security("srv-v2", "read")
        .unwrap_or_else(|| panic!("bridge security"));
    assert!(sidecar.has_registry_coordinates());
    registry
        .validate_bridge_security("srv-v2", "read", &sidecar)
        .unwrap_or_else(|error| panic!("validate exact sidecar: {error}"));

    for (field, replacement) in [
        ("manifest_digest", serde_json::json!("00".repeat(32))),
        ("server_id", serde_json::json!("other-server")),
        ("tool_name", serde_json::json!("other-tool")),
        ("effective_egress", serde_json::json!(false)),
    ] {
        let mut value = serde_json::to_value(&sidecar)
            .unwrap_or_else(|error| panic!("serialize sidecar: {error}"));
        value[field] = replacement;
        let forged = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("decode forged sidecar: {error}"));
        assert!(registry
            .validate_bridge_security("srv-v2", "read", &forged)
            .is_err());
    }

    let mut flow_value = serde_json::to_value(&sidecar)
        .unwrap_or_else(|error| panic!("serialize flow sidecar: {error}"));
    flow_value["flow"] = serde_json::json!({
        "output_label": {"kind": "known", "owners": {}, "compartments": []},
        "input_clearance": {"kind": "known", "owners": {}, "compartments": []},
        "egress": true
    });
    let forged_flow = serde_json::from_value(flow_value)
        .unwrap_or_else(|error| panic!("decode forged flow sidecar: {error}"));
    assert!(registry
        .validate_bridge_security("srv-v2", "read", &forged_flow)
        .is_err());
    assert!(registry
        .validate_bridge_security("other-server", "read", &sidecar)
        .is_err());
    assert!(registry
        .validate_bridge_security("srv-v2", "other-tool", &sidecar)
        .is_err());

    let second_signer = Keypair::from_seed(&[35; 32]);
    let mut second_manifest = v2_manifest(second_signer.public_key().to_hex());
    second_manifest.version = "2.0.1".to_string();
    let second_signed = sign_manifest(&second_manifest, &second_signer)
        .unwrap_or_else(|error| panic!("sign second manifest: {error}"));
    let mut second_registry = VerifiedManifestRegistry::default();
    second_registry
        .register_public_only(
            second_signed,
            &second_signer.public_key(),
            RuntimeToolTopology::remote(),
        )
        .unwrap_or_else(|error| panic!("register second manifest: {error}"));
    assert!(second_registry
        .validate_bridge_security("srv-v2", "read", &sidecar)
        .is_err());
}

#[test]
fn verified_registry_rejects_tampering_and_remote_tools_without_policy_clearance() {
    let keypair = Keypair::from_seed(&[26; 32]);
    let manifest = v2_manifest(keypair.public_key().to_hex());
    let policy =
        AuthoritativeToolPolicy::new(Vec::new(), InformationLabel::bottom(), BTreeSet::new())
            .unwrap_or_else(|error| panic!("policy: {error}"));
    let policies = [("read".to_string(), policy)].into_iter().collect();
    let topologies = [("read".to_string(), RuntimeToolTopology::remote())]
        .into_iter()
        .collect();
    let mut registry = VerifiedManifestRegistry::default();
    let signed =
        sign_manifest(&manifest, &keypair).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    assert!(registry
        .register(signed, &keypair.public_key(), &policies, &topologies)
        .is_err());

    let policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        InformationLabel::bottom(),
        BTreeSet::new(),
    )
    .unwrap_or_else(|error| panic!("policy: {error}"));
    let mut tampered =
        sign_manifest(&manifest, &keypair).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    tampered.manifest.tools[0].description = "tampered".to_string();
    assert!(registry
        .register(
            tampered,
            &keypair.public_key(),
            &[("read".to_string(), policy)].into_iter().collect(),
            &topologies,
        )
        .is_err());
}

#[test]
fn legacy_v1_migration_is_deterministic_and_unsigned() {
    let legacy = serde_json::json!({
        "schema": "chio.manifest.v1",
        "server_id": "legacy",
        "name": "Legacy",
        "description": null,
        "version": "1.0.0",
        "tools": [{
            "name": "write",
            "description": "Write",
            "input_schema": {"type": "object"},
            "output_schema": null,
            "pricing": null,
            "has_side_effects": true,
            "latency_hint": "moderate"
        }],
        "server_tools": [],
        "required_permissions": null,
        "public_key": Keypair::from_seed(&[9; 32]).public_key().to_hex()
    });
    let bytes = serde_json::to_vec(&legacy).unwrap_or_else(|error| panic!("legacy bytes: {error}"));
    let first = migrate_legacy_manifest_v1(&bytes)
        .unwrap_or_else(|error| panic!("migrate legacy: {error}"));
    let second = migrate_legacy_manifest_v1(&bytes)
        .unwrap_or_else(|error| panic!("migrate legacy: {error}"));
    let first_manifest = first
        .manifest()
        .unwrap_or_else(|error| panic!("first manifest: {error}"));
    let second_manifest = second
        .manifest()
        .unwrap_or_else(|error| panic!("second manifest: {error}"));
    assert_eq!(
        serde_json::to_value(first_manifest).unwrap_or_else(|error| panic!("first: {error}")),
        serde_json::to_value(second_manifest).unwrap_or_else(|error| panic!("second: {error}"))
    );
    assert!(first.requires_operator_resigning());
    assert!(!first.requires_permission_amendment());
    assert_eq!(first_manifest.schema, "chio.manifest.v2");
    let tool = &first_manifest.tools[0];
    assert!(!tool.annotations.read_only);
    assert!(tool.annotations.destructive);
    assert!(tool.annotations.requires_approval);
    assert_eq!(tool.latency_hint, Some(LatencyHint::Moderate));
}

#[test]
fn legacy_duration_thresholds_and_dual_latency_rejection_are_exact() {
    for (millis, expected) in [
        (0, LatencyHint::Instant),
        (1, LatencyHint::Instant),
        (2, LatencyHint::Fast),
        (999, LatencyHint::Fast),
        (1_000, LatencyHint::Moderate),
        (59_999, LatencyHint::Moderate),
        (60_000, LatencyHint::Slow),
    ] {
        let legacy = format!(
            r#"{{"schema":"chio.manifest.v1","server_id":"legacy","name":"Legacy","description":null,"version":"1","tools":[{{"name":"read","description":"Read","input_schema":{{"type":"object"}},"output_schema":null,"pricing":null,"annotations":{{"read_only":true,"destructive":false,"idempotent":true,"requires_approval":false,"estimated_duration_ms":{millis}}}}}],"server_tools":[],"required_permissions":null,"public_key":"{}"}}"#,
            Keypair::from_seed(&[8; 32]).public_key().to_hex()
        );
        let migrated = migrate_legacy_manifest_v1(legacy.as_bytes())
            .unwrap_or_else(|error| panic!("duration {millis}: {error}"));
        assert_eq!(
            migrated
                .manifest()
                .unwrap_or_else(|error| panic!("duration manifest: {error}"))
                .tools[0]
                .latency_hint,
            Some(expected)
        );
    }

    let dual = r#"{"schema":"chio.manifest.v1","server_id":"legacy","name":"Legacy","description":null,"version":"1","tools":[{"name":"read","description":"Read","input_schema":{"type":"object"},"output_schema":null,"pricing":null,"latency_hint":"fast","annotations":{"read_only":true,"destructive":false,"idempotent":true,"requires_approval":false,"estimated_duration_ms":10}}],"server_tools":[],"required_permissions":null,"public_key":"00"}"#;
    assert!(migrate_legacy_manifest_v1(dual.as_bytes()).is_err());
}

#[test]
fn legacy_permissions_require_operator_profile_and_port_amendment() {
    let legacy = serde_json::json!({
        "schema": "chio.manifest.v1",
        "server_id": "legacy",
        "name": "Legacy",
        "description": null,
        "version": "1.0.0",
        "tools": [{
            "name": "read",
            "description": "Read",
            "input_schema": {"type": "object"},
            "output_schema": null,
            "pricing": null,
            "has_side_effects": false
        }],
        "server_tools": [],
        "required_permissions": {
            "read_paths": ["/srv/data"],
            "write_paths": null,
            "network_hosts": ["API.Example.COM"],
            "environment_variables": ["CHIO_MODE"]
        },
        "public_key": Keypair::from_seed(&[24; 32]).public_key().to_hex()
    });
    let migration = migrate_legacy_manifest_v1(
        &serde_json::to_vec(&legacy).unwrap_or_else(|error| panic!("legacy: {error}")),
    )
    .unwrap_or_else(|error| panic!("migrate: {error}"));
    assert!(migration.requires_permission_amendment());
    assert!(migration.manifest().is_err());
    assert_eq!(migration.legacy_network_hosts(), ["api.example.com"]);

    let amended = migration
        .amend_permissions(
            NativeSyscallProfile::BrokeredNativeV1,
            vec![NetworkDestination::new("api.example.com", 443)
                .unwrap_or_else(|error| panic!("destination: {error}"))],
        )
        .unwrap_or_else(|error| panic!("amend: {error}"));
    let permissions = amended
        .required_permissions
        .unwrap_or_else(|| panic!("amended permissions"));
    assert_eq!(
        permissions.native_syscall_profile,
        NativeSyscallProfile::BrokeredNativeV1
    );
    assert_eq!(
        permissions
            .read_paths
            .as_deref()
            .and_then(|paths| paths.first())
            .map(String::as_str),
        Some("/srv/data")
    );
    assert_eq!(
        permissions
            .network_destinations
            .as_deref()
            .map(|v| v[0].port()),
        Some(443)
    );
}

#[test]
fn required_permissions_reject_implicit_ports_and_loader_environment() {
    assert!(
        serde_json::from_value::<RequiredPermissions>(serde_json::json!({
            "read_paths": null,
            "write_paths": null,
            "network_destinations": [{"host": "api.example.com"}],
            "environment_variables": null,
            "native_syscall_profile": "native_minimal_v1"
        }))
        .is_err()
    );
    assert!(EnvironmentVariableName::new("LD_PRELOAD").is_err());
    assert!(NetworkDestination::new("*.example.com", 443).is_err());
    let mut zero_port = v2_manifest(Keypair::from_seed(&[3; 32]).public_key().to_hex());
    zero_port.required_permissions = serde_json::from_value(serde_json::json!({
        "network_destinations": [{"host": "api.example.com", "port": 0}],
        "native_syscall_profile": "native_minimal_v1"
    }))
    .ok();
    assert!(chio_manifest::validate_manifest(&zero_port).is_err());
}

#[test]
fn environment_variable_names_accept_non_sensitive_operational_names() {
    for name in [
        "CHIO_MODE",
        "APP_REGION",
        "AUTHORITY_MODE",
        "MONKEY_PATCH",
        "_INTERNAL_FLAG",
        "lowercase_name",
    ] {
        assert!(
            EnvironmentVariableName::new(name).is_ok(),
            "safe environment variable was rejected: {name}"
        );
    }
}

#[test]
fn environment_variable_names_reject_injection_and_credential_names() {
    for name in [
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "BASH_FUNC_payload",
        "MALLOC_CHECK_",
        "BASH_ENV",
        "DOCKER_CONFIG",
        "ENV",
        "GCONV_PATH",
        "GEM_HOME",
        "GEM_PATH",
        "GIT_ASKPASS",
        "GLIBC_TUNABLES",
        "GPG_AGENT_INFO",
        "IFS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "KRB5CCNAME",
        "LOCPATH",
        "NETRC",
        "NLSPATH",
        "NODE_OPTIONS",
        "NODE_PATH",
        "NPM_CONFIG_USERCONFIG",
        "PERL5OPT",
        "PERL5LIB",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUBYLIB",
        "RUBYOPT",
        "RUSTC_WRAPPER",
        "SSLKEYLOGFILE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SSH_AUTH_SOCK",
        "SUDO_ASKPASS",
        "ZDOTDIR",
        "_JAVA_OPTIONS",
        "SESSION_TOKEN",
        "CLIENT_SECRET",
        "DATABASE_PASSWORD",
        "SYSTEM_PASSWD",
        "AWS_CREDENTIAL_FILE",
        "OPENAI_API_KEY",
        "SIGNING_PRIVATE_KEY",
        "AWS_ACCESS_KEY_ID",
        "HTTP_AUTHORIZATION",
        "ld_preload",
        "openai_api_key",
        "Java_Tool_Options",
        "ssh_auth_sock",
    ] {
        assert!(
            EnvironmentVariableName::new(name).is_err(),
            "dangerous environment variable was accepted: {name}"
        );
    }

    assert!(
        serde_json::from_value::<RequiredPermissions>(serde_json::json!({
            "environment_variables": ["OPENAI_API_KEY"],
            "native_syscall_profile": "native_minimal_v1"
        }))
        .is_err()
    );
}

#[test]
fn v2_schema_accepts_runtime_shape_and_rejects_unknown_nested_fields() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/chio-wire/v1/security/tool-manifest-v2.schema.json"
    )))
    .unwrap_or_else(|error| panic!("manifest schema: {error}"));
    let flow_schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/chio-wire/v1/security/tool-flow-declaration.schema.json"
    )))
    .unwrap_or_else(|error| panic!("flow schema: {error}"));
    let registry = jsonschema::Registry::new()
        .add(
            "https://chio.world/schemas/chio-wire/v1/security/tool-flow-declaration.schema.json",
            &flow_schema,
        )
        .unwrap_or_else(|error| panic!("register flow schema: {error}"))
        .prepare()
        .unwrap_or_else(|error| panic!("prepare schema registry: {error}"));
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap_or_else(|error| panic!("compile manifest schema: {error}"));
    let mut manifest = v2_manifest(Keypair::from_seed(&[6; 32]).public_key().to_hex());
    manifest.tools[0].flow = Some(chio_manifest::ToolFlowDeclaration::public_egress());
    let value = serde_json::to_value(&manifest)
        .unwrap_or_else(|error| panic!("serialize v2 manifest: {error}"));
    assert!(validator.is_valid(&value));

    for forbidden_name in [
        "LD_PRELOAD",
        "BASH_FUNC_payload",
        "GLIBC_TUNABLES",
        "JAVA_TOOL_OPTIONS",
        "SSH_AUTH_SOCK",
        "OPENAI_API_KEY",
        "ld_preload",
        "openai_api_key",
    ] {
        let mut forbidden = value.clone();
        forbidden["required_permissions"]["environment_variables"] =
            serde_json::json!([forbidden_name]);
        assert!(
            !validator.is_valid(&forbidden),
            "schema accepted dangerous environment variable: {forbidden_name}"
        );
    }

    let mut unknown = value;
    unknown["tools"][0]["annotations"]["estimated_duration_ms"] = serde_json::json!(10);
    assert!(!validator.is_valid(&unknown));
}
