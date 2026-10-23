use chio_core::crypto::Keypair;
use chio_manifest::{
    load_existing_verified_manifest_registry, sign_manifest, verify_manifest,
    AuthoritativeToolPolicy, DeclassificationPurpose, EnvironmentVariableName, LatencyHint,
    ManifestError, NativeSyscallProfile, NetworkDestination, RequiredPermissions,
    RuntimeToolTopology, ServerTool, ToolAnnotations, ToolDefinition, ToolManifest,
    VerifiedManifestAdmissionError, VerifiedManifestInvocationError, VerifiedManifestLoadError,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_security_types::{Compartment, InformationLabel};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[path = "manifest_admission/json_boundary.rs"]
mod json_boundary;

macro_rules! assert_refused {
    ($result:expr, $pattern:pat $(if $guard:expr)?) => {
        match $result {
            Err(error) => assert!(
                matches!(&error, $pattern $(if $guard)?),
                "wrong refusal: {error:?}"
            ),
            Ok(_) => panic!("expected a refusal"),
        }
    };
}

fn decode_error<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> String {
    match serde_json::from_value::<T>(value) {
        Ok(_) => panic!("decode unexpectedly succeeded"),
        Err(error) => error.to_string(),
    }
}

fn platform_manifest(public_key: String) -> ToolManifest {
    ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "srv-platform".to_string(),
        name: "Platform server".to_string(),
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
    static NEXT_PATH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT_PATH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "chio-manifest-{name}-{}-{sequence}.json",
        std::process::id()
    ))
}

fn write_signed_manifest_fixture(name: &str) -> (PathBuf, Keypair) {
    let keypair = Keypair::generate();
    let signed = sign_manifest(&platform_manifest(keypair.public_key().to_hex()), &keypair)
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
        "srv-platform",
        RuntimeToolTopology::remote(),
    )
    .unwrap_or_else(|error| panic!("load registry: {error}"));
    let security = registry
        .bridge_security("srv-platform", "read")
        .unwrap_or_else(|| panic!("admitted bridge security"));
    assert!(security.has_registry_coordinates());
    assert!(security.effective_egress());

    let wrong_key = Keypair::generate();
    assert_refused!(
        load_existing_verified_manifest_registry(
            &path,
            &wrong_key.public_key().to_hex(),
            "srv-platform",
            RuntimeToolTopology::remote(),
        ),
        VerifiedManifestLoadError::Admission(VerifiedManifestAdmissionError::Manifest(
            ManifestError::VerificationFailed
        ))
    );
    assert_refused!(
        load_existing_verified_manifest_registry(
            &path,
            &keypair.public_key().to_hex(),
            "different-server",
            RuntimeToolTopology::remote(),
        ),
        VerifiedManifestLoadError::ServerIdMismatch { expected, actual }
            if expected == "different-server" && actual == "srv-platform"
    );
    std::fs::remove_file(path).unwrap_or_else(|error| panic!("remove fixture: {error}"));
}

#[test]
fn existing_signed_manifest_loader_never_creates_missing_paths() {
    let path = unique_manifest_path("missing");
    let keypair = Keypair::generate();
    assert_refused!(
        load_existing_verified_manifest_registry(
            &path,
            &keypair.public_key().to_hex(),
            "srv-platform",
            RuntimeToolTopology::remote(),
        ),
        VerifiedManifestLoadError::Open { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound
    );
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn existing_signed_manifest_loader_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let (target, keypair) = write_signed_manifest_fixture("symlink-target");
    let link = unique_manifest_path("symlink-link");
    symlink(&target, &link).unwrap_or_else(|error| panic!("create symlink: {error}"));
    assert_refused!(
        load_existing_verified_manifest_registry(
            &link,
            &keypair.public_key().to_hex(),
            "srv-platform",
            RuntimeToolTopology::remote(),
        ),
        VerifiedManifestLoadError::Open { .. }
    );
    std::fs::remove_file(link).unwrap_or_else(|error| panic!("remove symlink: {error}"));
    std::fs::remove_file(target).unwrap_or_else(|error| panic!("remove target: {error}"));
}

#[test]
fn verified_registry_admits_provider_server_tools_only_as_remote_egress() {
    let signer = Keypair::from_seed(&[30; 32]);
    let mut manifest = platform_manifest(signer.public_key().to_hex());
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
        .bridge_security_for_server_tool("srv-platform", "bash_20241022")
        .unwrap_or_else(|| panic!("server-tool bridge security"));
    assert!(security.has_registry_coordinates());
    assert!(security.effective_egress());
    assert_eq!(security.tool_name(), Some("bash"));
    assert_eq!(
        registry
            .tool_security_for_server_tool("srv-platform", "bash_20241022")
            .unwrap_or_else(|| panic!("server-tool admitted security")),
        registry
            .tool_security_for_server_tool("srv-platform", "bash")
            .unwrap_or_else(|| panic!("stable server-tool admitted security"))
    );
    registry
        .validate_bridge_security("srv-platform", "bash_20241022", &security)
        .unwrap_or_else(|error| panic!("validate server-tool sidecar: {error}"));
    registry
        .validate_invocation_arguments(
            "srv-platform",
            "bash_20241022",
            &security,
            &serde_json::json!({"command": "pwd"}),
        )
        .unwrap_or_else(|error| panic!("validate trusted server-tool arguments: {error}"));
    registry
        .validate_invocation_arguments(
            "srv-platform",
            "bash_20250124",
            &security,
            &serde_json::json!({"restart": true}),
        )
        .unwrap_or_else(|error| panic!("validate date-suffixed server-tool family: {error}"));
    assert!(matches!(
        registry.validate_invocation_arguments(
            "srv-platform",
            "bash_20241022",
            &security,
            &serde_json::json!({"command": 7}),
        ),
        Err(VerifiedManifestInvocationError::TrustedServerToolSchemaMismatch {
            server_id,
            tool_name,
        }) if server_id == "srv-platform" && tool_name == "bash_20241022"
    ));

    let mut local_registry = VerifiedManifestRegistry::default();
    assert_refused!(
        local_registry.register_public_only(
            signed,
            &signer.public_key(),
            RuntimeToolTopology::local(),
        ),
        VerifiedManifestAdmissionError::ServerToolRequiresRemoteTopology(name) if name == "bash"
    );

    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign broker-confused server-tool manifest: {error}"));
    let mut broker_registry = VerifiedManifestRegistry::default();
    assert_refused!(
        broker_registry.register_public_only(
            signed,
            &signer.public_key(),
            RuntimeToolTopology::brokered(),
        ),
        VerifiedManifestAdmissionError::ServerToolRequiresRemoteTopology(name) if name == "bash"
    );
}

#[test]
fn verified_registry_runtime_requirement_includes_derived_remote_topology() {
    let signer = Keypair::from_seed(&[32; 32]);
    let manifest = platform_manifest(signer.public_key().to_hex());
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
    let mut local_manifest = platform_manifest(signer.public_key().to_hex());
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
        .authorize_cage_manifest("srv-platform")
        .unwrap_or_else(|error| panic!("authorize local cage manifest: {error}"));
    assert_eq!(local.topology(), RuntimeToolTopology::local());
    assert_eq!(local.server_id(), "srv-platform");
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
        remote_registry.authorize_cage_manifest("srv-platform"),
        Err(VerifiedManifestAdmissionError::CageTopologyMismatch { .. })
    ));

    let broker_signer = Keypair::from_seed(&[37; 32]);
    let broker_manifest = platform_manifest(broker_signer.public_key().to_hex());
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
        .authorize_cage_manifest("srv-platform")
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
        wrong_local_registry.authorize_cage_manifest("srv-platform"),
        Err(VerifiedManifestAdmissionError::CageTopologyMismatch { .. })
    ));
}

#[test]
fn cage_authorization_binds_registry_manifest_and_every_tool_topology() {
    let signer = Keypair::from_seed(&[38; 32]);
    let mut manifest = platform_manifest(signer.public_key().to_hex());
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
        .authorize_cage_manifest("srv-platform")
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
        mixed_registry.authorize_cage_manifest("srv-platform"),
        Err(VerifiedManifestAdmissionError::CageTopologyMismatch { .. })
    ));

    let other_signer = Keypair::from_seed(&[39; 32]);
    let mut other_manifest = platform_manifest(other_signer.public_key().to_hex());
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
        .authorize_cage_manifest("srv-platform")
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
fn manifest_signs_and_verifies_with_normalized_permissions() {
    let keypair = Keypair::generate();
    let manifest = platform_manifest(keypair.public_key().to_hex());
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
    let mut manifest = platform_manifest(keypair.public_key().to_hex());
    manifest.tools[0].flow = Some(chio_manifest::ToolFlowDeclaration::public_egress());
    let mut signed = sign_manifest(&manifest, &keypair)
        .unwrap_or_else(|error| panic!("sign flow manifest: {error}"));
    signed.manifest.tools[0].flow = None;
    assert_refused!(
        verify_manifest(&signed, &keypair.public_key()),
        ManifestError::VerificationFailed
    );
}

#[test]
fn manifest_rejects_alternate_json_spellings_of_signed_fields() {
    let keypair = Keypair::from_seed(&[23; 32]);
    let manifest = platform_manifest(keypair.public_key().to_hex());
    let canonical = serde_json::to_value(&manifest)
        .unwrap_or_else(|error| panic!("serialize manifest: {error}"));

    let mut explicit_description_null = canonical.clone();
    explicit_description_null["description"] = serde_json::Value::Null;
    assert!(decode_error::<ToolManifest>(explicit_description_null)
        .contains("explicit null is not a canonical manifest representation"));

    let mut explicit_server_tools_empty = canonical.clone();
    explicit_server_tools_empty["server_tools"] = serde_json::json!([]);
    assert!(decode_error::<ToolManifest>(explicit_server_tools_empty)
        .contains("explicit empty array is not a canonical manifest representation"));

    let mut explicit_output_schema_null = canonical.clone();
    explicit_output_schema_null["tools"][0]["output_schema"] = serde_json::Value::Null;
    assert!(decode_error::<ToolManifest>(explicit_output_schema_null)
        .contains("explicit null is not a canonical manifest representation"));

    let mut missing_annotation = canonical;
    missing_annotation["tools"][0]["annotations"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("annotations object"))
        .remove("destructive");
    assert!(
        decode_error::<ToolManifest>(missing_annotation).contains("missing field `destructive`")
    );
}

#[test]
fn manifest_rejects_noncanonical_permission_spellings() {
    let keypair = Keypair::from_seed(&[29; 32]);
    let manifest = platform_manifest(keypair.public_key().to_hex());
    let canonical = serde_json::to_value(&manifest)
        .unwrap_or_else(|error| panic!("serialize manifest: {error}"));

    let mut uppercase_host = canonical.clone();
    uppercase_host["required_permissions"]["network_destinations"][0]["host"] =
        serde_json::json!("API.Example.COM");
    assert!(decode_error::<ToolManifest>(uppercase_host).contains(
        "invalid required permission required_permissions.network_destinations.host: API.Example.COM"
    ));

    for path in ["/workspace/./data", "/workspace//data", "/workspace/"] {
        let mut aliased_path = canonical.clone();
        aliased_path["required_permissions"]["read_paths"] = serde_json::json!([path]);
        let parsed = serde_json::from_value::<ToolManifest>(aliased_path)
            .unwrap_or_else(|error| panic!("parse aliased path {path}: {error}"));
        assert_refused!(
            chio_manifest::validate_manifest(&parsed),
            ManifestError::InvalidRequiredPermission { field, value }
                if *field == "required_permissions.read_paths" && value == path
        );
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
        let expected_field = format!("required_permissions.{field}");
        assert_refused!(
            chio_manifest::validate_manifest(&parsed),
            ManifestError::InvalidRequiredPermission { field, value }
                if *field == expected_field && value == "[]"
        );
    }
}

fn old_shape_tool() -> serde_json::Value {
    serde_json::json!({
        "name": "file_read",
        "description": "Read a file",
        "input_schema": {"type": "object"},
        "has_side_effects": false
    })
}

#[test]
fn old_tool_shape_under_the_current_id_is_refused_structurally() {
    let payload = serde_json::json!({
        "schema": TOOL_MANIFEST_SCHEMA,
        "server_id": "srv-old-shape",
        "name": "Old shape",
        "version": "1.0.0",
        "tools": [old_shape_tool()],
        "public_key": Keypair::from_seed(&[21; 32]).public_key().to_hex()
    });
    let error = serde_json::from_value::<ToolManifest>(payload)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error.as_deref(), Some(
            "unknown field `has_side_effects`, expected one of `name`, `description`, `input_schema`, `output_schema`, `pricing`, `annotations`, `latency_hint`, `flow`"
        ));
}

#[test]
fn old_permission_shape_under_the_current_id_is_refused_structurally() {
    let payload = serde_json::json!({
        "schema": TOOL_MANIFEST_SCHEMA,
        "server_id": "srv-old-shape",
        "name": "Old shape",
        "version": "1.0.0",
        "tools": [{
            "name": "file_read",
            "description": "Read a file",
            "input_schema": {"type": "object"},
            "annotations": {
                "read_only": true,
                "destructive": false,
                "idempotent": true,
                "requires_approval": false
            }
        }],
        "required_permissions": {
            "network_hosts": ["api.example.com"],
            "native_syscall_profile": "native_minimal_v1"
        },
        "public_key": Keypair::from_seed(&[21; 32]).public_key().to_hex()
    });
    let error = serde_json::from_value::<ToolManifest>(payload)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error.as_deref(), Some(
            "unknown field `network_hosts`, expected one of `read_paths`, `write_paths`, `network_destinations`, `environment_variables`, `native_syscall_profile`"
        ));
}

#[test]
fn retired_manifest_ids_are_refused_as_unsupported_schema() {
    let keypair = Keypair::from_seed(&[24; 32]);
    for retired in ["chio.manifest.v2", "chio.manifest.v0"] {
        let mut manifest = platform_manifest(keypair.public_key().to_hex());
        manifest.schema = retired.to_string();
        let expected = format!("manifest schema version is not supported: {retired}");
        let validation = chio_manifest::validate_manifest(&manifest)
            .err()
            .map(|error| error.to_string());
        assert_eq!(validation.as_deref(), Some(expected.as_str()));
        let signing = sign_manifest(&manifest, &keypair)
            .err()
            .map(|error| error.to_string());
        assert_eq!(signing.as_deref(), Some(expected.as_str()));
    }
}

#[test]
fn flow_rejects_null_and_explicit_empty_aliases() {
    assert!(
        decode_error::<chio_manifest::ToolFlowDeclaration>(serde_json::json!({
            "egress": false,
            "output_label": null
        }))
        .contains("invalid type: null, expected a strict known or top information label")
    );
    assert!(
        decode_error::<chio_manifest::ToolFlowDeclaration>(serde_json::json!({
            "egress": false,
            "declassification_purposes": []
        }))
        .contains("explicit empty array is not a canonical flow representation")
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
fn verified_registry_merge_preserves_security_and_rejects_duplicates_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::from_seed(&[26; 32]);
    let registry = |servers: &[&str]| -> Result<_, Box<dyn std::error::Error>> {
        let mut registry = VerifiedManifestRegistry::default();
        for server in servers {
            let mut manifest = platform_manifest(keypair.public_key().to_hex());
            manifest.server_id = (*server).into();
            registry.register(
                sign_manifest(&manifest, &keypair)?,
                &keypair.public_key(),
                &BTreeMap::from([("read".into(), AuthoritativeToolPolicy::public_only())]),
                &BTreeMap::from([("read".into(), RuntimeToolTopology::brokered())]),
            )?;
        }
        Ok(registry)
    };
    let mut selected = registry(&["existing"])?;
    let conflicting = registry(&["added", "existing"])?;
    assert!(
        matches!(selected.merge_verified(&conflicting), Err(VerifiedManifestAdmissionError::DuplicateServer(server)) if server == "existing")
    );
    assert_eq!(selected.verified_manifests().count(), 1);
    assert!(selected.verified_manifest("added").is_none());
    let added = registry(&["added"])?;
    selected.merge_verified(&added)?;
    assert_eq!(selected.verified_manifests().count(), 2);
    assert_eq!(
        selected.tool_security("added", "read"),
        added.tool_security("added", "read")
    );
    assert_eq!(
        selected.bridge_security("added", "read"),
        added.bridge_security("added", "read")
    );
    assert!(selected
        .tool_security("added", "read")
        .ok_or("missing security")?
        .effective_egress());
    Ok(())
}

#[test]
fn verified_registry_composes_registered_key_policy_and_runtime_topology() {
    let keypair = Keypair::from_seed(&[25; 32]);
    let mut manifest = platform_manifest(keypair.public_key().to_hex());
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
        .tool_security("srv-platform", "read")
        .unwrap_or_else(|| panic!("admitted security"));
    assert!(admitted.effective_egress());
    assert_eq!(
        admitted.declassification_purposes(),
        &[purpose_a].into_iter().collect::<BTreeSet<_>>()
    );
    assert!(admitted
        .authorize_source(&InformationLabel::bottom())
        .is_ok());
    assert_refused!(
        admitted.authorize_source(&InformationLabel::Top),
        VerifiedManifestAdmissionError::TopSource
    );
    assert_eq!(registry.verified_manifests().count(), 1);
    let sidecar = registry
        .bridge_security("srv-platform", "read")
        .unwrap_or_else(|| panic!("registry bridge security"));
    assert!(sidecar.has_registry_coordinates());
    assert!(sidecar.effective_egress());
    assert_eq!(sidecar.server_id(), Some("srv-platform"));
    assert_eq!(sidecar.tool_name(), Some("read"));
    assert!(sidecar.manifest_digest().is_some());
}

#[test]
fn verified_registry_rejects_manifest_clearance_that_widens_policy() {
    let keypair = Keypair::from_seed(&[33; 32]);
    let mut manifest = platform_manifest(keypair.public_key().to_hex());
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
    let manifest = platform_manifest(signer.public_key().to_hex());
    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign first manifest: {error}"));
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .unwrap_or_else(|error| panic!("register first manifest: {error}"));
    let sidecar = registry
        .bridge_security("srv-platform", "read")
        .unwrap_or_else(|| panic!("bridge security"));
    assert!(sidecar.has_registry_coordinates());
    registry
        .validate_bridge_security("srv-platform", "read", &sidecar)
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
        assert_refused!(
            registry.validate_bridge_security("srv-platform", "read", &forged),
            VerifiedManifestAdmissionError::BridgeSecurityMismatch { server_id, tool_name }
                if server_id == "srv-platform" && tool_name == "read"
        );
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
    assert_refused!(
        registry.validate_bridge_security("srv-platform", "read", &forged_flow),
        VerifiedManifestAdmissionError::BridgeSecurityMismatch { server_id, tool_name }
            if server_id == "srv-platform" && tool_name == "read"
    );
    assert_refused!(
        registry.validate_bridge_security("other-server", "read", &sidecar),
        VerifiedManifestAdmissionError::BridgeSecurityMismatch { server_id, tool_name }
            if server_id == "other-server" && tool_name == "read"
    );
    assert_refused!(
        registry.validate_bridge_security("srv-platform", "other-tool", &sidecar),
        VerifiedManifestAdmissionError::BridgeSecurityMismatch { server_id, tool_name }
            if server_id == "srv-platform" && tool_name == "other-tool"
    );

    let second_signer = Keypair::from_seed(&[35; 32]);
    let mut second_manifest = platform_manifest(second_signer.public_key().to_hex());
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
    assert_refused!(
        second_registry.validate_bridge_security("srv-platform", "read", &sidecar),
        VerifiedManifestAdmissionError::BridgeSecurityMismatch { server_id, tool_name }
            if server_id == "srv-platform" && tool_name == "read"
    );
}

#[test]
fn verified_registry_rejects_tampering_and_remote_tools_without_policy_clearance() {
    let keypair = Keypair::from_seed(&[26; 32]);
    let manifest = platform_manifest(keypair.public_key().to_hex());
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
    assert_refused!(
        registry.register(signed, &keypair.public_key(), &policies, &topologies),
        VerifiedManifestAdmissionError::MissingPolicyClearance(name) if name == "read"
    );

    let policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        InformationLabel::bottom(),
        BTreeSet::new(),
    )
    .unwrap_or_else(|error| panic!("policy: {error}"));
    let mut tampered =
        sign_manifest(&manifest, &keypair).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    tampered.manifest.tools[0].description = "tampered".to_string();
    assert_refused!(
        registry.register(
            tampered,
            &keypair.public_key(),
            &[("read".to_string(), policy)].into_iter().collect(),
            &topologies,
        ),
        VerifiedManifestAdmissionError::Manifest(ManifestError::VerificationFailed)
    );
}

#[test]
fn required_permissions_reject_implicit_ports_and_loader_environment() {
    assert!(decode_error::<RequiredPermissions>(serde_json::json!({
        "network_destinations": [{"host": "api.example.com"}],
        "native_syscall_profile": "native_minimal_v1"
    }))
    .contains("missing field `port`"));
    assert_refused!(
        EnvironmentVariableName::new("LD_PRELOAD"),
        ManifestError::InvalidRequiredPermission { field, value }
            if *field == "required_permissions.environment_variables" && value == "LD_PRELOAD"
    );
    assert_refused!(
        NetworkDestination::new("*.example.com", 443),
        ManifestError::InvalidRequiredPermission { field, value }
            if *field == "required_permissions.network_destinations.host"
                && value == "*.example.com"
    );
    assert!(decode_error::<RequiredPermissions>(serde_json::json!({
        "network_destinations": [{"host": "api.example.com", "port": 0}],
        "native_syscall_profile": "native_minimal_v1"
    }))
    .contains("invalid value: integer `0`, expected a nonzero u16"));
    assert_refused!(
        NetworkDestination::new("api.example.com", 0),
        ManifestError::InvalidRequiredPermission { field, value }
            if *field == "required_permissions.network_destinations.port" && value == "0"
    );
    for port in [1, u16::MAX] {
        let wire = serde_json::json!({"host": "api.example.com", "port": port});
        let destination: NetworkDestination = serde_json::from_value(wire.clone())
            .unwrap_or_else(|error| panic!("valid boundary port: {error}"));
        assert_eq!(destination.port(), port);
        assert_eq!(
            serde_json::to_value(destination)
                .unwrap_or_else(|error| panic!("encode boundary port: {error}")),
            wire,
        );
    }
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
        match EnvironmentVariableName::new(name) {
            Err(ManifestError::InvalidRequiredPermission { field, value }) => {
                assert_eq!(field, "required_permissions.environment_variables");
                assert_eq!(value, name);
            }
            other => panic!("dangerous environment variable {name} was not refused: {other:?}"),
        }
    }

    assert!(decode_error::<RequiredPermissions>(serde_json::json!({
        "environment_variables": ["OPENAI_API_KEY"],
        "native_syscall_profile": "native_minimal_v1"
    }))
    .contains(
        "invalid required permission required_permissions.environment_variables: OPENAI_API_KEY"
    ));
}

#[test]
fn current_manifest_consumer_corpus_preserves_wire_and_registered_signature() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/fixtures/manifest-consumers.json"
    )))
    .unwrap_or_else(|error| panic!("manifest consumer corpus: {error}"));
    let cases = corpus["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("manifest consumer cases must be an array"));
    assert_eq!(cases.len(), 14);
    // This pin comes from the existing cage vector, not the envelope under test.
    let registered = chio_core::crypto::PublicKey::from_hex(
        "d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da",
    )
    .unwrap_or_else(|error| panic!("registered vector key: {error}"));
    for case in cases {
        let parsed =
            serde_json::from_value::<chio_manifest::SignedManifest>(case["instance"].clone());
        let valid = case["valid"]
            .as_bool()
            .unwrap_or_else(|| panic!("manifest consumer validity must be a boolean"));
        assert_eq!(parsed.is_ok(), valid, "consumer case {}", case["name"]);
        if let Ok(signed) = parsed {
            verify_manifest(&signed, &registered)
                .unwrap_or_else(|error| panic!("registered vector signature: {error}"));
            let source = chio_core::canonical_json_bytes(&case["instance"])
                .unwrap_or_else(|error| panic!("canonical source: {error}"));
            let encoded = chio_core::canonical_json_bytes(&signed)
                .unwrap_or_else(|error| panic!("canonical round trip: {error}"));
            assert_eq!(source, encoded);
            assert_eq!(
                chio_core::sha256_hex(&encoded),
                "b3387974261d22131bee3b2d2113e761db60bf610921e96955a76b349ac60bc2"
            );
        }
    }
}

#[test]
fn manifest_schema_accepts_runtime_shape_and_rejects_unknown_nested_fields() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/chio-wire/v1/security/tool-manifest-v1.schema.json"
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
    let mut manifest = platform_manifest(Keypair::from_seed(&[6; 32]).public_key().to_hex());
    manifest.tools[0].flow = Some(chio_manifest::ToolFlowDeclaration::public_egress());
    let value = serde_json::to_value(&manifest)
        .unwrap_or_else(|error| panic!("serialize manifest: {error}"));
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
    assert!(
        decode_error::<ToolManifest>(unknown).contains("unknown field `estimated_duration_ms`"),
        "the runtime must reject the same second latency authority as its schema",
    );
}

/// JSON value whose object members keep insertion order, so a fixture can append
/// an unknown member after the sorted ones exactly as a hostile peer would.
#[derive(Clone)]
enum Ordered {
    Object(Vec<(String, Ordered)>),
    Array(Vec<Ordered>),
    Leaf(serde_json::Value),
}

impl Ordered {
    fn from_value(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Object(members) => Ordered::Object(
                members
                    .iter()
                    .map(|(key, member)| (key.clone(), Ordered::from_value(member)))
                    .collect(),
            ),
            serde_json::Value::Array(items) => {
                Ordered::Array(items.iter().map(Ordered::from_value).collect())
            }
            leaf => Ordered::Leaf(leaf.clone()),
        }
    }

    fn at(&mut self, key: &str) -> &mut Ordered {
        match self {
            Ordered::Object(members) => members
                .iter_mut()
                .find(|(name, _)| name == key)
                .map(|(_, member)| member)
                .unwrap_or_else(|| panic!("missing member {key}")),
            _ => panic!("not an object: {key}"),
        }
    }

    fn item(&mut self, index: usize) -> &mut Ordered {
        match self {
            Ordered::Array(items) => &mut items[index],
            _ => panic!("not an array: {index}"),
        }
    }

    fn set(&mut self, key: &str, value: serde_json::Value) {
        match self {
            Ordered::Object(members) => match members.iter_mut().find(|(name, _)| name == key) {
                Some((_, member)) => *member = Ordered::Leaf(value),
                None => members.push((key.to_string(), Ordered::Leaf(value))),
            },
            _ => panic!("not an object: {key}"),
        }
    }

    fn remove(&mut self, key: &str) {
        match self {
            Ordered::Object(members) => {
                let before = members.len();
                members.retain(|(name, _)| name != key);
                assert_eq!(members.len() + 1, before, "missing member {key}");
            }
            _ => panic!("not an object: {key}"),
        }
    }
}

impl serde::Serialize for Ordered {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self {
            Ordered::Object(members) => {
                let mut map = serializer.serialize_map(Some(members.len()))?;
                for (key, member) in members {
                    map.serialize_entry(key, member)?;
                }
                map.end()
            }
            Ordered::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Ordered::Leaf(value) => value.serialize(serializer),
        }
    }
}

#[derive(serde::Serialize)]
struct ConsumerCase {
    name: &'static str,
    schema_file: &'static str,
    valid: bool,
    instance: Ordered,
}

#[derive(serde::Serialize)]
struct ConsumerCorpus {
    cases: Vec<ConsumerCase>,
}

fn consumer_signed_manifest() -> chio_manifest::SignedManifest {
    let server = Keypair::from_seed(&[21u8; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "srv-bindings-demo".to_string(),
        name: "Bindings Demo".to_string(),
        description: Some("Manifest vector for bindings-core SDK fixtures".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "file_read".to_string(),
            description: "Tool definition for file_read".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
            output_schema: Some(serde_json::json!({
                "type": "object",
                "properties": { "ok": { "type": "boolean" } }
            })),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: Some(LatencyHint::Fast),
            flow: Some(chio_manifest::ToolFlowDeclaration::public_egress()),
        }],
        server_tools: Vec::new(),
        required_permissions: Some(RequiredPermissions {
            read_paths: Some(vec!["/workspace".to_string()]),
            write_paths: Some(vec!["/workspace/output".to_string()]),
            network_destinations: Some(vec![NetworkDestination::new("api.example.com", 443)
                .unwrap_or_else(|error| panic!("destination: {error}"))]),
            environment_variables: Some(vec![EnvironmentVariableName::new("CHIO_ENV")
                .unwrap_or_else(|error| panic!("environment name: {error}"))]),
            native_syscall_profile: NativeSyscallProfile::NativeStandardV1,
        }),
        public_key: server.public_key().to_hex(),
    };
    sign_manifest(&manifest, &server)
        .unwrap_or_else(|error| panic!("sign consumer manifest: {error}"))
}

fn consumer_corpus_text() -> String {
    let base = Ordered::from_value(
        &serde_json::to_value(consumer_signed_manifest())
            .unwrap_or_else(|error| panic!("serialize consumer manifest: {error}")),
    );
    let case = |name: &'static str, valid: bool, mutate: &dyn Fn(&mut Ordered)| {
        let mut instance = base.clone();
        mutate(&mut instance);
        ConsumerCase {
            name,
            schema_file: "security/signed-tool-manifest-v1.schema.json",
            valid,
            instance,
        }
    };
    let corpus = ConsumerCorpus {
        cases: vec![
            case("signed-manifest", true, &|_| {}),
            case("unknown-envelope-field", false, &|v| {
                v.set("authorized", serde_json::json!(true));
            }),
            case("unknown-manifest-field", false, &|v| {
                v.at("manifest")
                    .set("allow_unconfined", serde_json::json!(true));
            }),
            case("second-latency-authority", false, &|v| {
                v.at("manifest")
                    .at("tools")
                    .item(0)
                    .at("annotations")
                    .set("estimated_duration_ms", serde_json::json!(50));
            }),
            case("null-flow-alias", false, &|v| {
                v.at("manifest")
                    .at("tools")
                    .item(0)
                    .set("flow", serde_json::Value::Null);
            }),
            case("null-latency-alias", false, &|v| {
                v.at("manifest")
                    .at("tools")
                    .item(0)
                    .set("latency_hint", serde_json::Value::Null);
            }),
            case("missing-annotation", false, &|v| {
                v.at("manifest")
                    .at("tools")
                    .item(0)
                    .at("annotations")
                    .remove("destructive");
            }),
            case("numeric-boolean", false, &|v| {
                v.at("manifest")
                    .at("tools")
                    .item(0)
                    .at("annotations")
                    .set("destructive", serde_json::json!(0));
            }),
            case("missing-egress", false, &|v| {
                v.at("manifest")
                    .at("tools")
                    .item(0)
                    .at("flow")
                    .remove("egress");
            }),
            case("unknown-flow-field", false, &|v| {
                v.at("manifest")
                    .at("tools")
                    .item(0)
                    .at("flow")
                    .set("allow_declassification", serde_json::json!(true));
            }),
            case("unknown-native-profile", false, &|v| {
                v.at("manifest")
                    .at("required_permissions")
                    .set("native_syscall_profile", serde_json::json!("unconfined"));
            }),
            case("old-shape-network-hosts", false, &|v| {
                v.at("manifest")
                    .at("required_permissions")
                    .set("network_hosts", serde_json::json!(["api.example.com"]));
            }),
            case("missing-network-port", false, &|v| {
                v.at("manifest")
                    .at("required_permissions")
                    .at("network_destinations")
                    .item(0)
                    .remove("port");
            }),
            case("zero-network-port", false, &|v| {
                v.at("manifest")
                    .at("required_permissions")
                    .at("network_destinations")
                    .item(0)
                    .set("port", serde_json::json!(0));
            }),
        ],
    };
    let mut rendered = serde_json::to_string_pretty(&corpus)
        .unwrap_or_else(|error| panic!("render consumer corpus: {error}"));
    rendered.push('\n');
    rendered
}

fn consumer_corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/bindings/fixtures/manifest-consumers.json")
}

#[test]
fn manifest_consumer_corpus_is_current() {
    let path = consumer_corpus_path();
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(
        committed,
        consumer_corpus_text(),
        "fixture {} is out of date",
        path.display()
    );
}

#[test]
#[ignore = "regenerator: rewrite tests/bindings/fixtures/manifest-consumers.json from the manifest builder; run with --ignored"]
fn regenerate_manifest_consumer_corpus() {
    let path = consumer_corpus_path();
    std::fs::write(&path, consumer_corpus_text())
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}
