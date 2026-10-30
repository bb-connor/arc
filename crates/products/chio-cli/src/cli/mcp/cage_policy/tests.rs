use super::*;
use chio_security_types::EnterpriseMigrationStateStore;
use chio_test_support::prelude::*;

fn signed_manifest(
    profile: chio_manifest::NativeSyscallProfile,
) -> (chio_manifest::SignedManifest, chio_core::Keypair) {
    let keypair = chio_core::Keypair::from_seed(&[91; 32]);
    let manifest = chio_manifest::ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "cage-policy-test".to_string(),
        name: "Cage policy test".to_string(),
        description: None,
        version: "1".to_string(),
        tools: vec![chio_manifest::ToolDefinition {
            name: "echo".to_string(),
            description: "Echo".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: Some(chio_manifest::LatencyHint::Fast),
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: Some(chio_manifest::RequiredPermissions {
            read_paths: None,
            write_paths: None,
            network_destinations: None,
            environment_variables: None,
            native_syscall_profile: profile,
        }),
        public_key: keypair.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &keypair).test_unwrap();
    (signed, keypair)
}

pub(super) fn policy(
    manifest_profile: chio_manifest::NativeSyscallProfile,
    ceiling_profile: chio_manifest::NativeSyscallProfile,
) -> McpCageLaunchPolicy {
    let (signed_manifest, keypair) = signed_manifest(manifest_profile);
    let deployment_id = chio_security_types::ports::RecordId::new("production.test")
        .test_expect("cage migration deployment id");
    let tool_server_id = chio_security_types::ports::RecordId::new("cage-policy-test")
        .test_expect("cage migration tool server id");
    let migration_key = chio_security_types::EnterpriseMigrationKey {
        deployment_id: deployment_id.clone(),
        scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
        scope_id: tool_server_id,
        control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
    };
    McpCageLaunchPolicy {
        schema: MCP_CAGE_LAUNCH_POLICY_SCHEMA.to_string(),
        signed_manifest,
        registered_public_key: keypair.public_key(),
        operator_ceilings: CageOperatorCeilings {
            read_paths: BTreeSet::new(),
            write_paths: BTreeSet::new(),
            network_destinations: BTreeSet::new(),
            environment_variables: BTreeSet::new(),
            native_syscall_profiles: [ceiling_profile].into_iter().collect(),
            forbidden_paths: BTreeSet::new(),
        },
        runtime: CageRuntimePolicy {
            cage_init_path: PathBuf::from("/operator/chio-cage-init"),
            cage_init_binding_digest: "1".repeat(64),
            target_path: PathBuf::from("/operator/mcp-server"),
            target_binding_digest: "2".repeat(64),
            working_directory: PathBuf::from("/operator/workdir"),
            runtime_files: BTreeSet::new(),
            target_argv: vec!["/operator/mcp-server".to_string()],
            execution_identity: chio_cage::ExecutionIdentity::new(10001, 10001, Vec::new())
                .test_expect("valid execution identity"),
        },
        limits: CageLimitPolicy {
            max_artifact_bytes: 1024 * 1024,
            launch_timeout_ms: 10_000,
            nofile_soft: 192,
            nofile_hard: 192,
        },
        receipt: CageReceiptRuntimePolicy {
            database_path: PathBuf::from("/operator/cage-receipts.sqlite3"),
            rollback_anchor_root: None,
            signer_seed_path: PathBuf::from("/operator/cage-receipt-seed"),
            trusted_signer_public_key: keypair.public_key().to_hex(),
            capability_id: "cage-launch-capability".to_string(),
            tenant_id: Some("tenant-test".to_string()),
        },
        enterprise_migration: CageMigrationPolicy {
            state_database_path: PathBuf::from("/operator/enterprise-migration.sqlite3"),
            deployment_id,
            trusted_transition_signers: vec![keypair.public_key()],
            head: chio_security_types::EnterpriseMigrationHead {
                key: migration_key,
                transition_digest: chio_security_types::ports::Digest32::new([0x77; 32]),
            },
        },
        broker: None,
    }
}

pub(super) fn signed_policy(
    policy: McpCageLaunchPolicy,
    signer: &chio_core::Keypair,
) -> SignedMcpCageLaunchPolicy {
    let (signature, _) = signer
        .sign_canonical(&policy)
        .test_expect("sign cage launch policy");
    SignedMcpCageLaunchPolicy {
        body: policy,
        signer_public_key: signer.public_key(),
        signature,
    }
}

fn test_launch_contract() -> chio_security_types::CageLaunchContractDigests {
    chio_security_types::CageLaunchContractDigests {
        policy_schema_digest: chio_security_types::ports::Digest32::new([0x80; 32]),
        policy_signer_digest: chio_security_types::ports::Digest32::new([0x81; 32]),
        signed_manifest_digest: chio_security_types::ports::Digest32::new([0x82; 32]),
        registered_public_key_digest: chio_security_types::ports::Digest32::new([0x83; 32]),
        operator_ceilings_digest: chio_security_types::ports::Digest32::new([0x84; 32]),
        runtime_digest: chio_security_types::ports::Digest32::new([0x85; 32]),
        limits_digest: chio_security_types::ports::Digest32::new([0x86; 32]),
        receipt_digest: chio_security_types::ports::Digest32::new([0x87; 32]),
        broker_binding_digest: chio_security_types::ports::Digest32::new([0x88; 32]),
        migration_ledger_digest: chio_security_types::ports::Digest32::new([0x89; 32]),
    }
}

fn durable_migration_policy(directory: &Path) -> (CageMigrationPolicy, chio_core::Keypair) {
    durable_migration_policy_with_evidence(directory, 0x31)
}

fn durable_migration_policy_with_evidence(
    directory: &Path,
    evidence: u8,
) -> (CageMigrationPolicy, chio_core::Keypair) {
    let trusted_directory = directory
        .canonicalize()
        .test_expect("canonical cage migration directory");
    let state_database_path = trusted_directory.join("enterprise-migration.sqlite3");
    let signer = chio_core::Keypair::from_seed(&[94; 32]);
    let deployment_id = chio_security_types::ports::RecordId::new("production.test")
        .test_expect("cage migration deployment id");
    let tool_server_id = chio_security_types::ports::RecordId::new("cage-policy-test")
        .test_expect("cage migration tool server id");
    let key = chio_security_types::EnterpriseMigrationKey {
        deployment_id: deployment_id.clone(),
        scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
        scope_id: tool_server_id.clone(),
        control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
    };
    let store = chio_store_sqlite::SqliteEnterpriseMigrationStateStore::open(
        &state_database_path,
        chio_store_sqlite::SqliteEnterpriseMigrationOpenPolicy::new(
            vec![signer.public_key()],
            Vec::new(),
        )
        .test_expect("cage migration open policy"),
    )
    .test_expect("open cage migration ledger");
    let body = chio_security_types::EnterpriseMigrationTransitionBody::enforced(
        key.clone(),
        chio_security_types::cage_migration_posture_digest(
            &deployment_id,
            &tool_server_id,
            &test_launch_contract(),
        )
        .test_expect("cage migration posture"),
        chio_security_types::ports::Digest32::new([evidence; 32]),
        chio_security_types::ports::Digest32::new([0x32; 32]),
        chio_security_types::ports::Digest32::new([0x33; 32]),
        1,
        signer.public_key().to_hex(),
    )
    .test_expect("cage migration registration body");
    let registration = chio_store_sqlite::sign_enterprise_migration_transition(body, &signer)
        .test_expect("sign cage migration registration");
    let _ = store
        .register(&registration)
        .test_expect("register cage migration ledger");
    let state = store
        .load(&key)
        .test_expect("load cage migration registration")
        .test_expect("cage migration registration exists");
    (
        CageMigrationPolicy {
            state_database_path,
            deployment_id,
            trusted_transition_signers: vec![signer.public_key()],
            head: state.head(),
        },
        signer,
    )
}

#[test]
fn cage_policy_requires_canonical_deny_unknown_json() {
    let body = policy(
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    );
    let signer = chio_core::Keypair::from_seed(&[92; 32]);
    let signed = signed_policy(body, &signer);
    let canonical = chio_core::canonical_json_bytes(&signed).test_unwrap();
    decode_cage_policy(Path::new("policy.json"), &canonical, &signer.public_key()).test_unwrap();

    let mut noncanonical = canonical.clone();
    noncanonical.push(b'\n');
    assert!(decode_cage_policy(
        Path::new("policy.json"),
        &noncanonical,
        &signer.public_key(),
    )
    .test_unwrap_err()
    .to_string()
    .contains("canonical JSON"));

    let mut value = serde_json::to_value(signed).test_unwrap();
    value["unknown"] = serde_json::json!(true);
    let unknown = chio_core::canonical_json_bytes(&value).test_unwrap();
    assert!(decode_cage_policy(Path::new("policy.json"), &unknown, &signer.public_key(),).is_err());
    assert!(decode_cage_policy(
        Path::new("policy.json"),
        &canonical,
        &chio_core::Keypair::from_seed(&[93; 32]).public_key(),
    )
    .is_err());

    let mut forged_body = serde_json::to_value(policy(
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    ))
    .test_unwrap();
    forged_body["runtime"]["execution_identity"]["uid"] = serde_json::json!(0);
    let forged_body: McpCageLaunchPolicy = serde_json::from_value(forged_body).test_unwrap();
    let forged = signed_policy(forged_body, &signer);
    let forged = chio_core::canonical_json_bytes(&forged).test_unwrap();
    assert!(
        decode_cage_policy(Path::new("policy.json"), &forged, &signer.public_key(),)
            .test_unwrap_err()
            .to_string()
            .contains("execution identity")
    );
}

#[test]
fn live_registry_rejects_replayed_policy_manifest_before_compilation() {
    let mut policy = policy(
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    );
    let original = policy.signed_manifest.clone();
    let mut registry = chio_manifest::VerifiedManifestRegistry::default();
    registry
        .register_public_only(
            original,
            &policy.registered_public_key,
            chio_manifest::RuntimeToolTopology::local(),
        )
        .test_expect("register live manifest");

    policy
        .signed_manifest
        .manifest
        .required_permissions
        .as_mut()
        .test_expect("test manifest permissions")
        .read_paths = Some(vec!["/operator/broader".to_string()]);
    let manifest_signer = chio_core::Keypair::from_seed(&[91; 32]);
    policy.signed_manifest =
        chio_manifest::sign_manifest(&policy.signed_manifest.manifest, &manifest_signer)
            .test_expect("sign replayed broader manifest");

    let error = resolve_launch_manifest_registry(
        &policy,
        chio_manifest::RuntimeToolTopology::local(),
        Some(Arc::new(registry)),
        "test launch",
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("not byte-identical"));
}

#[test]
fn migration_posture_changes_with_every_authority_component() {
    let policy_signer = chio_core::Keypair::from_seed(&[92; 32]);
    let mut first = policy(
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    );
    let first_contract = cage_launch_contract_digests(&first, &policy_signer.public_key())
        .test_expect("first launch contract");
    first.runtime.execution_identity = chio_cage::ExecutionIdentity::new(10003, 10001, Vec::new())
        .test_expect("changed execution identity");
    let changed_contract = cage_launch_contract_digests(&first, &policy_signer.public_key())
        .test_expect("changed launch contract");
    assert_ne!(
        first_contract.runtime_digest,
        changed_contract.runtime_digest
    );

    let deployment_id =
        chio_security_types::ports::RecordId::new("production.test").test_expect("deployment id");
    let tool_server_id =
        chio_security_types::ports::RecordId::new("cage-policy-test").test_expect("tool server id");
    let first_posture = chio_security_types::cage_migration_posture_digest(
        &deployment_id,
        &tool_server_id,
        &first_contract,
    )
    .test_expect("first posture");
    let changed_posture = chio_security_types::cage_migration_posture_digest(
        &deployment_id,
        &tool_server_id,
        &changed_contract,
    )
    .test_expect("changed posture");
    assert_ne!(first_posture, changed_posture);
}

const IDENTITY_POINT_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000";

#[test]
fn an_identity_point_trust_root_cannot_authenticate_a_forged_policy() {
    let directory = tempfile::tempdir().test_expect("forged policy directory");
    let path = directory.path().join("cage-policy.json");
    let identity =
        chio_core::PublicKey::from_hex(IDENTITY_POINT_HEX).test_expect("identity point key");
    // R = identity point, s = 0 verifies for every message under the identity key
    // unless verification is strict.
    let forged = SignedMcpCageLaunchPolicy {
        body: policy(
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        ),
        signer_public_key: identity,
        signature: chio_core::Signature::from_hex(&format!(
            "{IDENTITY_POINT_HEX}{}",
            "0".repeat(64)
        ))
        .test_expect("forged signature"),
    };
    std::fs::write(
        &path,
        chio_core::canonical_json_bytes(&forged).test_expect("canonical forged policy"),
    )
    .test_expect("write forged policy");
    assert!(SignedCagePolicyLaunchFactory::new(path, IDENTITY_POINT_HEX.to_string()).is_err());
}

#[test]
fn launch_factory_pins_verified_policy_bytes_at_construction() {
    let directory = tempfile::tempdir().test_expect("launch factory directory");
    let path = directory.path().join("cage-policy.json");
    let signer = chio_core::Keypair::from_seed(&[92; 32]);
    let signed = signed_policy(
        policy(
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        ),
        &signer,
    );
    std::fs::write(
        &path,
        chio_core::canonical_json_bytes(&signed).test_expect("canonical signed policy"),
    )
    .test_expect("write signed cage policy");
    let factory = SignedCagePolicyLaunchFactory::new(path.clone(), signer.public_key().to_hex())
        .test_expect("pin signed cage policy");
    let pinned =
        chio_mcp_adapter::transport::NativeMcpLaunchFactory::authorization_contract_digest(
            &factory,
        )
        .test_expect("pinned launch authorization");

    std::fs::write(&path, b"substituted").test_expect("replace policy path");
    let after_replacement =
        chio_mcp_adapter::transport::NativeMcpLaunchFactory::authorization_contract_digest(
            &factory,
        )
        .test_expect("retained pinned launch authorization");
    assert_eq!(pinned, after_replacement);
}

#[test]
fn cage_migration_binding_fails_closed_when_the_ledger_is_replaced() {
    let directory = tempfile::tempdir().test_expect("cage migration test directory");
    let (policy, _signer) = durable_migration_policy(directory.path());
    let enforcer =
        load_cage_migration_enforcer(&policy, "cage-policy-test", &test_launch_contract())
            .test_expect("load enforced cage migration binding");
    enforcer
        .revalidate()
        .test_expect("revalidate unchanged cage migration binding");

    let replacement = tempfile::tempdir().test_expect("replacement ledger directory");
    let (replacement_policy, _) = durable_migration_policy_with_evidence(replacement.path(), 0x41);
    std::fs::remove_file(&policy.state_database_path).test_expect("remove pinned ledger");
    std::fs::copy(
        &replacement_policy.state_database_path,
        &policy.state_database_path,
    )
    .test_expect("install a different valid ledger");
    assert!(enforcer.revalidate().is_err());

    let error = load_cage_migration_enforcer(&policy, "cage-policy-test", &test_launch_contract())
        .err()
        .test_expect("a replaced ledger cannot satisfy the pinned registration head");
    assert_eq!(
        error.to_string(),
        CliError::cli_other_error(
            "cage migration ledger denied: enterprise migration state schema or transition ledger failed integrity validation"
        )
        .to_string()
    );
}

#[test]
fn cage_migration_binding_refuses_a_different_launch_posture() {
    let directory = tempfile::tempdir().test_expect("cage migration test directory");
    let (policy, _signer) = durable_migration_policy(directory.path());
    let mut changed_contract = test_launch_contract();
    changed_contract.limits_digest = chio_security_types::ports::Digest32::new([0x99; 32]);
    let error = load_cage_migration_enforcer(&policy, "cage-policy-test", &changed_contract)
        .err()
        .test_expect("a different launch contract cannot bind the registered posture");
    assert_eq!(
        error.to_string(),
        CliError::cli_other_error(
            "cage migration runtime binding denied: enterprise migration posture differs from the registered posture"
        )
        .to_string()
    );
}

#[test]
fn independent_operator_ceiling_rejection_precedes_runtime_launch() {
    let error = compose_cage_required_launch(
        policy(
            chio_manifest::NativeSyscallProfile::NativeStandardV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        ),
        &"a".repeat(64),
        "/operator/mcp-server",
        &[],
        &test_launch_contract(),
        None,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("operator ceilings"));
}

#[test]
fn retired_launch_policy_schema_id_is_refused() {
    let mut retired = policy(
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    );
    retired.schema = "chio.mcp.cage-launch-policy.v2".to_string();
    let error = compose_cage_required_launch(
        retired,
        &"a".repeat(64),
        "/operator/mcp-server",
        &[],
        &test_launch_contract(),
        None,
    )
    .test_unwrap_err();
    assert_eq!(
        error.to_string(),
        CliError::cli_other_error("unsupported MCP cage launch policy schema").to_string()
    );
}

#[test]
fn operator_runtime_file_cannot_widen_verified_manifest_authority() {
    let mut policy = policy(
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    );
    policy
        .runtime
        .runtime_files
        .insert(PathBuf::from("/operator/arbitrary-secret"));

    let error = compose_cage_required_launch(
        policy,
        &"a".repeat(64),
        "/operator/mcp-server",
        &[],
        &test_launch_contract(),
        None,
    )
    .test_unwrap_err();
    assert!(error
        .to_string()
        .contains("exact read paths in the verified manifest"));
}

#[test]
fn brokered_profile_without_authenticated_broker_binding_is_rejected() {
    let error = compose_cage_required_launch(
        policy(
            chio_manifest::NativeSyscallProfile::BrokeredNativeV1,
            chio_manifest::NativeSyscallProfile::BrokeredNativeV1,
        ),
        &"a".repeat(64),
        "/operator/mcp-server",
        &[],
        &test_launch_contract(),
        None,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("authenticated broker FD"));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn provisioned_broker_socket_authenticates_live_peer() {
    let directory = tempfile::tempdir().test_expect("broker directory");
    let socket_path = directory.path().join("broker.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket_path).test_expect("broker listener");
    let peer = chio_cage::BrokerPeerIdentity::current_process().test_expect("broker peer");
    let binding = ProvisionedBrokerBinding {
        socket_path,
        authentication_digest: "ab".repeat(32),
        expected_peer_identity: peer,
    };
    binding.validate().test_expect("reviewed binding");
    let retained = retain_policy_broker(binding.policy_binding()).test_expect("live broker");
    assert_eq!(
        retained.authentication_digest(),
        binding.authentication_digest
    );
    drop(retained);
    let mut wrong = binding.clone();
    wrong.expected_peer_identity.pid += 1;
    assert!(retain_policy_broker(wrong.policy_binding()).is_err());
    drop(listener);
    assert!(retain_policy_broker(binding.policy_binding()).is_err());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn prepared_broker_retains_the_original_socket_without_reconnecting() {
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    let directory = tempfile::tempdir().test_expect("prepared broker directory");
    let path = directory.path().join("prepared.sock");
    let listener = UnixListener::bind(&path).test_expect("prepared listener");
    let stream = UnixStream::connect(&path).test_expect("prepared connection");
    let (_accepted, _) = listener.accept().test_expect("prepared accept");
    let original = std::fs::File::from(OwnedFd::from(
        stream
            .try_clone()
            .test_expect("original descriptor witness"),
    ));
    let identity = original.metadata().test_expect("original identity");
    let binding = ProvisionedBrokerBinding {
        socket_path: path,
        authentication_digest: "cd".repeat(32),
        expected_peer_identity: chio_cage::BrokerPeerIdentity::current_process()
            .test_expect("prepared broker peer"),
    };
    // Closing the listener prevents a new connection. The authenticated
    // prepared channel is still live and must be the retained channel.
    drop(listener);
    let retained = retain_prepared_policy_broker(binding.policy_binding(), stream)
        .test_expect("retain original prepared channel");
    assert_eq!(retained.identity().device(), identity.dev());
    assert_eq!(retained.identity().inode(), identity.ino());
    assert_eq!(
        retained.authentication_digest(),
        binding.authentication_digest
    );
    assert_eq!(retained.peer_identity(), binding.expected_peer_identity);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn prepared_broker_rejects_another_endpoint_peer_or_binding() {
    use std::os::unix::net::{UnixListener, UnixStream};

    let directory = tempfile::tempdir().test_expect("prepared broker directory");
    let path = directory.path().join("prepared.sock");
    let other_path = directory.path().join("other.sock");
    let _listener = UnixListener::bind(&path).test_expect("prepared listener");
    let _other = UnixListener::bind(&other_path).test_expect("other listener");
    let binding = ProvisionedBrokerBinding {
        socket_path: path.clone(),
        authentication_digest: "cd".repeat(32),
        expected_peer_identity: chio_cage::BrokerPeerIdentity::current_process()
            .test_expect("prepared broker peer"),
    };
    // Both listeners have identical kernel peer credentials. The signed
    // endpoint binding must still reject a different connected socket.
    assert!(retain_prepared_policy_broker(
        binding.policy_binding(),
        UnixStream::connect(&other_path).test_expect("other connection"),
    )
    .is_err());
    let mut wrong_peer = binding.policy_binding();
    wrong_peer.expected_peer_identity.pid += 1;
    assert!(retain_prepared_policy_broker(
        wrong_peer,
        UnixStream::connect(&path).test_expect("wrong peer connection"),
    )
    .is_err());
    let mut ambiguous = binding.policy_binding();
    ambiguous.inherited_fd = Some(3);
    assert!(retain_prepared_policy_broker(
        ambiguous,
        UnixStream::connect(&path).test_expect("ambiguous connection"),
    )
    .is_err());
    let mut invalid_digest = binding.policy_binding();
    invalid_digest.authentication_digest = "invalid".to_string();
    assert!(retain_prepared_policy_broker(
        invalid_digest,
        UnixStream::connect(&path).test_expect("invalid digest connection"),
    )
    .is_err());
}

#[test]
fn unprotected_wrapper_uses_signed_registry_flow_requirement() {
    let mut policy = policy(
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    );
    let keypair = chio_core::Keypair::from_seed(&[91; 32]);
    policy.signed_manifest.manifest.tools[0].flow =
        Some(chio_manifest::ToolFlowDeclaration::public_egress());
    policy.signed_manifest =
        chio_manifest::sign_manifest(&policy.signed_manifest.manifest, &keypair).test_unwrap();

    let mut registry = chio_manifest::VerifiedManifestRegistry::default();
    registry
        .register_public_only(
            policy.signed_manifest,
            &keypair.public_key(),
            chio_manifest::RuntimeToolTopology::local(),
        )
        .test_unwrap();
    assert!(registry.authorize_cage_manifest("cage-policy-test").is_ok());

    assert!(registry.requires_flow_runtime());
    let error =
        super::super::wrap::require_unprotected_wrap_compatible(&registry).test_unwrap_err();
    assert!(error
        .to_string()
        .contains("rejects flow-required manifests"));

    let (signed_manifest, registered_key) =
        signed_manifest(chio_manifest::NativeSyscallProfile::NativeMinimalV1);
    let mut flow_free_registry = chio_manifest::VerifiedManifestRegistry::default();
    flow_free_registry
        .register_public_only(
            signed_manifest,
            &registered_key.public_key(),
            chio_manifest::RuntimeToolTopology::local(),
        )
        .test_expect("register flow-free signed manifest");
    assert!(!flow_free_registry.requires_flow_runtime());
    super::super::wrap::require_unprotected_wrap_compatible(&flow_free_registry)
        .test_expect("flow-free registry remains wrapper compatible");
}

#[test]
fn staged_migration_policy_shapes_are_refused() {
    let body = policy(
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    );
    let current = serde_json::to_value(&body).test_unwrap();
    for (field, value) in [
        ("stage", serde_json::json!("enforced")),
        (
            "minimum_head",
            current["enterprise_migration"]["head"].clone(),
        ),
    ] {
        let mut staged = current.clone();
        staged["enterprise_migration"][field] = value;
        let error = serde_json::from_value::<McpCageLaunchPolicy>(staged)
            .err()
            .test_expect("a staged migration policy shape decoded");
        assert!(
            error
                .to_string()
                .starts_with(&format!("unknown field `{field}`")),
            "{field}: {error}"
        );
    }
    let mut generation_bound = current;
    generation_bound["enterprise_migration"]["head"]["minimum_generation"] = serde_json::json!(2);
    let error = serde_json::from_value::<McpCageLaunchPolicy>(generation_bound)
        .err()
        .test_expect("a generation-bounded head decoded");
    assert!(
        error
            .to_string()
            .starts_with("unknown field `minimum_generation`"),
        "{error}"
    );
}
