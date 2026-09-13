#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chio_cage::{
    admit as admit_authorized, compile, retain_broker_ipc, retain_runtime_resources,
    AdmittedManifest, BrokerPeerIdentity, CageError, ExecutionIdentity, FdPurpose,
    FilesystemGrantAccess, NetworkMode, OperatorCeilings, ResourceKind, RuntimeResourcePaths,
    SeccompDefaultAction,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_manifest::{
    sign_manifest, EnvironmentVariableName, LatencyHint, NativeSyscallProfile, RequiredPermissions,
    RuntimeToolTopology, SignedManifest, ToolAnnotations, ToolDefinition, ToolManifest,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_test_support::prelude::*;

static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

struct TestTree {
    root: PathBuf,
    helper: PathBuf,
    target: PathBuf,
    workdir: PathBuf,
    runtime: PathBuf,
    readable: PathBuf,
    writable: PathBuf,
    forbidden: PathBuf,
}

impl TestTree {
    fn new() -> Self {
        let sequence = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("chio-cage-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&root).test_unwrap();
        let helper = root.join("cage-init");
        let target = root.join("target");
        let workdir = root.join("workdir");
        let runtime = root.join("runtime.data");
        let readable = root.join("readable.data");
        let writable = root.join("writable.data");
        let forbidden = root.join("forbidden.data");
        write_executable(&helper);
        write_executable(&target);
        std::fs::create_dir(&workdir).test_unwrap();
        std::fs::write(&runtime, b"runtime").test_unwrap();
        std::fs::write(&readable, b"readable").test_unwrap();
        std::fs::write(&forbidden, b"forbidden").test_unwrap();
        Self {
            root,
            helper,
            target,
            workdir,
            runtime,
            readable,
            writable,
            forbidden,
        }
    }

    fn runtime_paths(&self) -> RuntimeResourcePaths {
        RuntimeResourcePaths::new(
            self.helper.clone(),
            self.target.clone(),
            self.workdir.clone(),
            BTreeSet::new(),
            ExecutionIdentity::new(10001, 10001, Vec::new()).test_unwrap(),
        )
    }

    fn runtime_paths_with(&self, runtime_files: BTreeSet<PathBuf>) -> RuntimeResourcePaths {
        RuntimeResourcePaths::new(
            self.helper.clone(),
            self.target.clone(),
            self.workdir.clone(),
            runtime_files,
            ExecutionIdentity::new(10001, 10001, Vec::new()).test_unwrap(),
        )
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write_executable(path: &Path) {
    let machine = match std::env::consts::ARCH {
        "x86_64" => 62_u16,
        "aarch64" => 183_u16,
        architecture => panic!("unsupported test architecture {architecture}"),
    };
    let image_len = 120_u64;
    let mut image = vec![0_u8; image_len as usize];
    image[..4].copy_from_slice(b"\x7fELF");
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image[16..18].copy_from_slice(&3_u16.to_le_bytes());
    image[18..20].copy_from_slice(&machine.to_le_bytes());
    image[20..24].copy_from_slice(&1_u32.to_le_bytes());
    image[24..32].copy_from_slice(&64_u64.to_le_bytes());
    image[32..40].copy_from_slice(&64_u64.to_le_bytes());
    image[52..54].copy_from_slice(&64_u16.to_le_bytes());
    image[54..56].copy_from_slice(&56_u16.to_le_bytes());
    image[56..58].copy_from_slice(&1_u16.to_le_bytes());
    image[64..68].copy_from_slice(&1_u32.to_le_bytes());
    image[68..72].copy_from_slice(&5_u32.to_le_bytes());
    image[96..104].copy_from_slice(&image_len.to_le_bytes());
    image[104..112].copy_from_slice(&image_len.to_le_bytes());
    image[112..120].copy_from_slice(&8_u64.to_le_bytes());
    std::fs::write(path, image).test_unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).test_unwrap();
}

fn write_header_only_executable(path: &Path) {
    let machine = match std::env::consts::ARCH {
        "x86_64" => 62_u16,
        "aarch64" => 183_u16,
        architecture => panic!("unsupported test architecture {architecture}"),
    };
    let mut header = vec![0_u8; 64];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    header[16..18].copy_from_slice(&3_u16.to_le_bytes());
    header[18..20].copy_from_slice(&machine.to_le_bytes());
    header[20..24].copy_from_slice(&1_u32.to_le_bytes());
    header[52..54].copy_from_slice(&64_u16.to_le_bytes());
    std::fs::write(path, header).test_unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).test_unwrap();
}

fn write_dynamically_linked_executable(path: &Path) {
    let machine = match std::env::consts::ARCH {
        "x86_64" => 62_u16,
        "aarch64" => 183_u16,
        architecture => panic!("unsupported test architecture {architecture}"),
    };
    let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
    let program_header_offset = 64_u64;
    let interpreter_offset = 120_u64;
    let mut image = vec![0_u8; interpreter_offset as usize + interpreter.len()];
    image[..4].copy_from_slice(b"\x7fELF");
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image[16..18].copy_from_slice(&3_u16.to_le_bytes());
    image[18..20].copy_from_slice(&machine.to_le_bytes());
    image[20..24].copy_from_slice(&1_u32.to_le_bytes());
    image[32..40].copy_from_slice(&program_header_offset.to_le_bytes());
    image[52..54].copy_from_slice(&64_u16.to_le_bytes());
    image[54..56].copy_from_slice(&56_u16.to_le_bytes());
    image[56..58].copy_from_slice(&1_u16.to_le_bytes());
    image[64..68].copy_from_slice(&3_u32.to_le_bytes());
    image[72..80].copy_from_slice(&interpreter_offset.to_le_bytes());
    image[96..104].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
    image[104..112].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
    image[interpreter_offset as usize..].copy_from_slice(interpreter);
    std::fs::write(path, image).test_unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).test_unwrap();
}

fn signed_manifest(
    keypair: &Keypair,
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    profile: NativeSyscallProfile,
    environment_variables: Vec<EnvironmentVariableName>,
) -> SignedManifest {
    sign_manifest(
        &ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "cage-linux-test".to_string(),
            name: "Cage Linux test".to_string(),
            description: None,
            version: "1".to_string(),
            tools: vec![ToolDefinition {
                name: "run".to_string(),
                description: "Run".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations {
                    read_only: false,
                    destructive: true,
                    idempotent: false,
                    requires_approval: true,
                },
                latency_hint: Some(LatencyHint::Fast),
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: Some(RequiredPermissions {
                read_paths: path_strings(read_paths),
                write_paths: path_strings(write_paths),
                network_destinations: None,
                environment_variables: if environment_variables.is_empty() {
                    None
                } else {
                    Some(environment_variables)
                },
                native_syscall_profile: profile,
            }),
            public_key: keypair.public_key().to_hex(),
        },
        keypair,
    )
    .test_unwrap()
}

fn admit(
    signed: &SignedManifest,
    registered_key: &PublicKey,
    ceilings: &OperatorCeilings,
) -> Result<AdmittedManifest, CageError> {
    let profile = signed
        .manifest
        .required_permissions
        .as_ref()
        .map(|permissions| permissions.native_syscall_profile)
        .unwrap_or(NativeSyscallProfile::NativeMinimalV1);
    let topology = if profile == NativeSyscallProfile::BrokeredNativeV1 {
        RuntimeToolTopology::brokered()
    } else {
        RuntimeToolTopology::local()
    };
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed.clone(), registered_key, topology)
        .test_unwrap();
    let authorization = registry
        .authorize_cage_manifest(&signed.manifest.server_id)
        .test_unwrap();
    admit_authorized(authorization, ceilings)
}

fn path_strings(paths: Vec<PathBuf>) -> Option<Vec<String>> {
    if paths.is_empty() {
        None
    } else {
        Some(
            paths
                .into_iter()
                .map(|path| path.to_str().test_unwrap().to_string())
                .collect(),
        )
    }
}

fn ceilings(
    tree: &TestTree,
    profile: NativeSyscallProfile,
    environment_variables: BTreeSet<EnvironmentVariableName>,
) -> OperatorCeilings {
    OperatorCeilings::new(
        [tree.readable.clone()].into_iter().collect(),
        [tree.writable.clone()].into_iter().collect(),
        BTreeSet::new(),
        environment_variables,
        [profile].into_iter().collect(),
    )
    .with_forbidden_paths([tree.forbidden.clone()].into_iter().collect())
}

#[test]
fn compile_is_deterministic_and_starts_from_deny_all() {
    let tree = TestTree::new();
    let keypair = Keypair::from_seed(&[41; 32]);
    let app_mode = EnvironmentVariableName::new("APP_MODE").test_unwrap();
    let signed = signed_manifest(
        &keypair,
        vec![tree.readable.clone()],
        vec![tree.writable.clone()],
        NativeSyscallProfile::NativeMinimalV1,
        vec![app_mode.clone()],
    );
    let ceilings = ceilings(
        &tree,
        NativeSyscallProfile::NativeMinimalV1,
        [app_mode].into_iter().collect(),
    );
    let parent_environment = BTreeMap::from([
        ("APP_MODE".to_string(), "production".to_string()),
        ("HOME".to_string(), "/must-not-leak".to_string()),
    ]);

    let first = compile(
        admit(&signed, &keypair.public_key(), &ceilings).test_unwrap(),
        retain_runtime_resources(&tree.runtime_paths()).test_unwrap(),
        &parent_environment,
        None,
    )
    .test_unwrap();
    let second = compile(
        admit(&signed, &keypair.public_key(), &ceilings).test_unwrap(),
        retain_runtime_resources(&tree.runtime_paths()).test_unwrap(),
        &parent_environment,
        None,
    )
    .test_unwrap();

    assert_eq!(first.profile_digest(), second.profile_digest());
    assert_eq!(first.plan_digest(), second.plan_digest());
    assert!(first.plan().landlock.default_filesystem_deny);
    assert_eq!(first.plan().landlock.network_mode, NetworkMode::Blocked);
    assert_eq!(
        first.plan().seccomp.default_action,
        SeccompDefaultAction::KillProcess
    );
    assert_eq!(first.plan().resource_limits.nofile_hard, 192);
    assert_eq!(first.plan().target_fd_slot, 255);
    assert!(!first.plan().environment.contains_key("HOME"));
    assert_eq!(
        first.plan().environment.get("APP_MODE").map(String::as_str),
        Some("production")
    );
    assert!(first
        .plan()
        .fd_table
        .windows(2)
        .all(|pair| pair[0].slot < pair[1].slot));
    assert!(first
        .plan()
        .fd_table
        .iter()
        .any(|entry| matches!(entry.purpose, FdPurpose::WriteGrant { .. })));
    assert_eq!(
        first.profile().cage_authorization_digest,
        first.admitted().cage_authorization_digest()
    );
    let metadata = std::fs::metadata(&tree.writable).test_unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(first.admitted().write_resources()[0]
        .creation_parent()
        .is_some());
}

#[test]
fn compiled_profile_binds_the_exact_registry_snapshot() {
    let tree = TestTree::new();
    let signer = Keypair::from_seed(&[46; 32]);
    let signed = signed_manifest(
        &signer,
        Vec::new(),
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(
            signed.clone(),
            &signer.public_key(),
            RuntimeToolTopology::local(),
        )
        .test_unwrap();

    let mut expanded_registry = registry.clone();
    let other_signer = Keypair::from_seed(&[47; 32]);
    let mut other_manifest = signed.manifest.clone();
    other_manifest.server_id = "other-cage-server".to_string();
    other_manifest.name = "Other cage server".to_string();
    other_manifest.public_key = other_signer.public_key().to_hex();
    let other_signed = sign_manifest(&other_manifest, &other_signer).test_unwrap();
    expanded_registry
        .register_public_only(
            other_signed,
            &other_signer.public_key(),
            RuntimeToolTopology::local(),
        )
        .test_unwrap();

    let exact = compile(
        admit_authorized(
            registry
                .authorize_cage_manifest("cage-linux-test")
                .test_unwrap(),
            &ceilings,
        )
        .test_unwrap(),
        retain_runtime_resources(&tree.runtime_paths()).test_unwrap(),
        &BTreeMap::new(),
        None,
    )
    .test_unwrap();
    let expanded = compile(
        admit_authorized(
            expanded_registry
                .authorize_cage_manifest("cage-linux-test")
                .test_unwrap(),
            &ceilings,
        )
        .test_unwrap(),
        retain_runtime_resources(&tree.runtime_paths()).test_unwrap(),
        &BTreeMap::new(),
        None,
    )
    .test_unwrap();

    assert_eq!(
        exact.admitted().manifest_digest(),
        expanded.admitted().manifest_digest()
    );
    assert_ne!(
        exact.admitted().registry_digest(),
        expanded.admitted().registry_digest()
    );
    assert_ne!(
        exact.profile().cage_authorization_digest,
        expanded.profile().cage_authorization_digest
    );
    assert_ne!(exact.profile_digest(), expanded.profile_digest());
    assert_ne!(exact.plan_digest(), expanded.plan_digest());
}

#[test]
fn target_argv_is_bounded_and_bound_into_the_plan_digest() {
    let tree = TestTree::new();
    let keypair = Keypair::from_seed(&[46; 32]);
    let signed = signed_manifest(
        &keypair,
        Vec::new(),
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    let argv = vec![
        tree.target.to_str().test_unwrap().to_string(),
        "--mode".to_string(),
        "stdio".to_string(),
    ];
    let runtime_paths = tree.runtime_paths().with_target_argv(argv.clone());
    let compiled = compile(
        admit(&signed, &keypair.public_key(), &ceilings).test_unwrap(),
        retain_runtime_resources(&runtime_paths).test_unwrap(),
        &BTreeMap::new(),
        None,
    )
    .test_unwrap();
    assert_eq!(compiled.plan().target_argv, argv);

    let changed = compile(
        admit(&signed, &keypair.public_key(), &ceilings).test_unwrap(),
        retain_runtime_resources(&tree.runtime_paths().with_target_argv(vec![
            tree.target.to_str().test_unwrap().to_string(),
            "changed".into(),
        ]))
        .test_unwrap(),
        &BTreeMap::new(),
        None,
    )
    .test_unwrap();
    assert_ne!(compiled.plan_digest(), changed.plan_digest());

    let empty = tree.runtime_paths().with_target_argv(Vec::new());
    assert!(matches!(
        retain_runtime_resources(&empty),
        Err(CageError::InvalidTargetArgv)
    ));
    let nul = tree
        .runtime_paths()
        .with_target_argv(vec!["bad\0argument".to_string()]);
    assert!(matches!(
        retain_runtime_resources(&nul),
        Err(CageError::InvalidTargetArgv)
    ));
}

#[test]
fn executable_runtime_file_gets_exact_execute_read_grant() {
    let tree = TestTree::new();
    std::fs::set_permissions(&tree.runtime, std::fs::Permissions::from_mode(0o700)).test_unwrap();
    let keypair = Keypair::from_seed(&[47; 32]);
    let signed = signed_manifest(
        &keypair,
        vec![tree.runtime.clone()],
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        [tree.runtime.clone()].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    let compiled = compile(
        admit(&signed, &keypair.public_key(), &ceilings).test_unwrap(),
        retain_runtime_resources(
            &tree.runtime_paths_with([tree.runtime.clone()].into_iter().collect()),
        )
        .test_unwrap(),
        &BTreeMap::new(),
        None,
    )
    .test_unwrap();
    let runtime_slot = compiled
        .plan()
        .fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::RuntimeFile { index: 0 }))
        .map(|entry| entry.slot)
        .test_unwrap();
    let grant = compiled
        .plan()
        .landlock
        .grants
        .iter()
        .find(|grant| grant.fd_slot == runtime_slot)
        .test_unwrap();
    assert_eq!(grant.access, FilesystemGrantAccess::ExecuteRead);
    assert!(!compiled
        .plan()
        .fd_table
        .iter()
        .any(|entry| matches!(entry.purpose, FdPurpose::ReadGrant { .. })));
}

#[test]
fn arbitrary_secret_runtime_file_requires_exact_signed_read_authority() {
    let tree = TestTree::new();
    let secret = tree.root.join("operator-secret.data");
    std::fs::write(&secret, b"must-not-enter-cage").test_unwrap();
    let keypair = Keypair::from_seed(&[48; 32]);
    let signed = signed_manifest(
        &keypair,
        Vec::new(),
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());

    assert!(matches!(
        compile(
            admit(&signed, &keypair.public_key(), &ceilings).test_unwrap(),
            retain_runtime_resources(
                &tree.runtime_paths_with([secret.clone()].into_iter().collect()),
            )
            .test_unwrap(),
            &BTreeMap::new(),
            None,
        ),
        Err(CageError::UnauthorizedRuntimeFile(path)) if path == secret
    ));
}

#[test]
fn runtime_file_rebound_to_forbidden_descriptor_fails_closed() {
    let tree = TestTree::new();
    let keypair = Keypair::from_seed(&[49; 32]);
    let signed = signed_manifest(
        &keypair,
        vec![tree.runtime.clone()],
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        [tree.runtime.clone()].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths([tree.forbidden.clone()].into_iter().collect());
    let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();

    std::fs::remove_file(&tree.runtime).test_unwrap();
    std::fs::hard_link(&tree.forbidden, &tree.runtime).test_unwrap();
    let runtime = retain_runtime_resources(
        &tree.runtime_paths_with([tree.runtime.clone()].into_iter().collect()),
    )
    .test_unwrap();

    assert!(matches!(
        compile(admitted, runtime, &BTreeMap::new(), None),
        Err(CageError::ForbiddenDescriptorAlias { allowed, forbidden })
            if allowed == tree.runtime && forbidden == tree.forbidden
    ));
}

#[test]
fn script_target_is_rejected_before_launch() {
    let tree = TestTree::new();
    let script = tree.root.join("target-script");
    std::fs::write(&script, b"#!/bin/sh\nexit 0\n").test_unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).test_unwrap();
    let paths = RuntimeResourcePaths::new(
        tree.helper.clone(),
        script.clone(),
        tree.workdir.clone(),
        BTreeSet::new(),
        ExecutionIdentity::new(10001, 10001, Vec::new()).test_unwrap(),
    );
    assert!(matches!(
        retain_runtime_resources(&paths),
        Err(CageError::InvalidExecutable(path)) if path == script
    ));
}

#[test]
fn dynamically_linked_cage_init_is_rejected_before_descriptor_transfer() {
    let tree = TestTree::new();
    write_dynamically_linked_executable(&tree.helper);

    assert!(matches!(
        retain_runtime_resources(&tree.runtime_paths()),
        Err(CageError::InvalidExecutable(path)) if path == tree.helper
    ));
}

#[test]
fn header_only_cage_init_is_rejected_before_descriptor_transfer() {
    let tree = TestTree::new();
    write_header_only_executable(&tree.helper);

    assert!(matches!(
        retain_runtime_resources(&tree.runtime_paths()),
        Err(CageError::InvalidExecutable(path)) if path == tree.helper
    ));
}

#[test]
fn retained_grant_survives_path_replacement_without_reopening() {
    let tree = TestTree::new();
    let keypair = Keypair::from_seed(&[42; 32]);
    let signed = signed_manifest(
        &keypair,
        vec![tree.readable.clone()],
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        [tree.readable.clone()].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();
    let retained_identity = admitted.read_resources()[0].identity();
    let old_path = tree.root.join("readable.old");
    std::fs::rename(&tree.readable, &old_path).test_unwrap();
    std::fs::write(&tree.readable, b"replacement").test_unwrap();

    let compiled = compile(
        admitted,
        retain_runtime_resources(&tree.runtime_paths()).test_unwrap(),
        &BTreeMap::new(),
        None,
    )
    .test_unwrap();
    let planned = compiled
        .plan()
        .fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::ReadGrant { .. }))
        .test_unwrap();
    assert_eq!(planned.identity, retained_identity);
    assert_ne!(
        planned.identity.inode(),
        std::fs::metadata(&tree.readable).test_unwrap().ino()
    );
}

#[test]
fn forbidden_hard_link_alias_is_rejected_before_compilation() {
    use std::os::unix::fs::symlink;

    let tree = TestTree::new();
    std::fs::remove_file(&tree.forbidden).test_unwrap();
    std::fs::hard_link(&tree.readable, &tree.forbidden).test_unwrap();
    let keypair = Keypair::from_seed(&[43; 32]);
    let signed = signed_manifest(
        &keypair,
        vec![tree.readable.clone()],
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        [tree.readable.clone()].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths([tree.forbidden.clone()].into_iter().collect());
    assert!(matches!(
        admit(&signed, &keypair.public_key(), &ceilings),
        Err(CageError::ForbiddenDescriptorAlias { .. })
    ));

    let symlink_path = tree.root.join("readable-link");
    symlink(&tree.readable, &symlink_path).test_unwrap();
    let signed = signed_manifest(
        &keypair,
        vec![symlink_path.clone()],
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        [symlink_path].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    assert!(matches!(
        admit(&signed, &keypair.public_key(), &ceilings),
        Err(CageError::SymbolicLink(_))
    ));

    let nested_tree = TestTree::new();
    let allowed_directory = nested_tree.root.join("allowed-directory");
    let nested_directory = allowed_directory.join("nested");
    let forbidden_alias = nested_directory.join("forbidden-alias");
    std::fs::create_dir(&allowed_directory).test_unwrap();
    std::fs::create_dir(&nested_directory).test_unwrap();
    std::fs::hard_link(&nested_tree.forbidden, &forbidden_alias).test_unwrap();
    let signed = signed_manifest(
        &keypair,
        vec![allowed_directory.clone()],
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        [allowed_directory].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths([nested_tree.forbidden.clone()].into_iter().collect());
    assert!(matches!(
        admit(&signed, &keypair.public_key(), &ceilings),
        Err(CageError::ForbiddenDescriptorAlias { allowed, forbidden })
            if allowed == forbidden_alias && forbidden == nested_tree.forbidden
    ));
}

#[test]
fn directory_read_grant_is_bounded_to_its_admitted_descendant_inode_closure() {
    use std::os::unix::fs::symlink;

    let tree = TestTree::new();
    let allowed_directory = tree.root.join("allowed-directory");
    let nested_directory = allowed_directory.join("nested");
    let existing_file = nested_directory.join("existing.data");
    let forbidden_symlink = allowed_directory.join("forbidden-symlink");
    let late_forbidden_alias = allowed_directory.join("late-forbidden-alias");
    std::fs::create_dir(&allowed_directory).test_unwrap();
    std::fs::create_dir(&nested_directory).test_unwrap();
    std::fs::write(&existing_file, b"existing").test_unwrap();
    symlink(&tree.forbidden, &forbidden_symlink).test_unwrap();

    let keypair = Keypair::from_seed(&[53; 32]);
    let signed = signed_manifest(
        &keypair,
        vec![allowed_directory.clone()],
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        [allowed_directory.clone()].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths([tree.forbidden.clone()].into_iter().collect());
    let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();
    assert_eq!(admitted.read_resources().len(), 3);

    std::fs::hard_link(&tree.forbidden, &late_forbidden_alias).test_unwrap();
    let compiled = compile(
        admitted,
        retain_runtime_resources(&tree.runtime_paths()).test_unwrap(),
        &BTreeMap::new(),
        None,
    )
    .test_unwrap();

    let grants = compiled
        .plan()
        .landlock
        .grants
        .iter()
        .map(|grant| {
            let entry = compiled
                .plan()
                .fd_table
                .iter()
                .find(|entry| entry.slot == grant.fd_slot)
                .test_unwrap();
            (entry.path.as_deref().test_unwrap(), grant.access)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        grants.get(allowed_directory.to_str().test_unwrap()),
        Some(&FilesystemGrantAccess::ReadDirectory)
    );
    assert_eq!(
        grants.get(nested_directory.to_str().test_unwrap()),
        Some(&FilesystemGrantAccess::ReadDirectory)
    );
    assert_eq!(
        grants.get(existing_file.to_str().test_unwrap()),
        Some(&FilesystemGrantAccess::Read)
    );
    assert!(!grants.contains_key(late_forbidden_alias.to_str().test_unwrap()));
    assert!(!grants.contains_key(forbidden_symlink.to_str().test_unwrap()));
    assert!(compiled.plan().landlock.grants.iter().all(|grant| {
        let forbidden = compiled.plan().landlock.forbidden_resources[0].identity;
        grant.identity.kind() == ResourceKind::Directory
            || grant.identity.device() != forbidden.device()
            || grant.identity.inode() != forbidden.inode()
    }));
    assert!(!compiled
        .plan()
        .seccomp
        .allowed_syscalls
        .iter()
        .any(|name| name == "link" || name == "linkat"));

    let overflow_tree = TestTree::new();
    let overflow_directory = overflow_tree.root.join("overflow-directory");
    std::fs::create_dir(&overflow_directory).test_unwrap();
    for index in 0..64 {
        std::fs::write(overflow_directory.join(format!("entry-{index:02}")), b"x").test_unwrap();
    }
    let signed = signed_manifest(
        &keypair,
        vec![overflow_directory.clone()],
        Vec::new(),
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        [overflow_directory].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    assert!(matches!(
        admit(&signed, &keypair.public_key(), &ceilings),
        Err(CageError::ResourceLimitExceeded("read grants"))
    ));
}

#[test]
fn broker_profile_requires_a_connected_authenticated_unix_descriptor() {
    let tree = TestTree::new();
    let keypair = Keypair::from_seed(&[44; 32]);
    let signed = signed_manifest(
        &keypair,
        Vec::new(),
        Vec::new(),
        NativeSyscallProfile::BrokeredNativeV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::BrokeredNativeV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();
    assert!(matches!(
        compile(
            admitted,
            retain_runtime_resources(&tree.runtime_paths()).test_unwrap(),
            &BTreeMap::new(),
            None,
        ),
        Err(CageError::BrokerProfileMismatch)
    ));

    let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();
    let (parent, peer) = UnixStream::pair().test_unwrap();
    let parent_file = File::from(OwnedFd::from(parent));
    let ipc = retain_broker_ipc(
        parent_file,
        "11".repeat(32),
        BrokerPeerIdentity::current_process().test_unwrap(),
    )
    .test_unwrap();
    let compiled = compile(
        admitted,
        retain_runtime_resources(&tree.runtime_paths()).test_unwrap(),
        &BTreeMap::new(),
        Some(ipc),
    )
    .test_unwrap();
    assert!(compiled
        .plan()
        .fd_table
        .iter()
        .any(|entry| entry.slot == 8 && matches!(entry.purpose, FdPurpose::BrokerIpc)));
    drop(peer);
}

#[test]
fn missing_write_parent_and_runtime_aliases_fail_closed() {
    let tree = TestTree::new();
    let keypair = Keypair::from_seed(&[45; 32]);
    let missing = tree.root.join("missing-parent").join("output");
    let signed = signed_manifest(
        &keypair,
        Vec::new(),
        vec![missing.clone()],
        NativeSyscallProfile::NativeMinimalV1,
        Vec::new(),
    );
    let ceilings = OperatorCeilings::new(
        BTreeSet::new(),
        [missing].into_iter().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    assert!(matches!(
        admit(&signed, &keypair.public_key(), &ceilings),
        Err(CageError::RetainPath { .. }) | Err(CageError::MissingWriteParent(_))
    ));

    let aliased = RuntimeResourcePaths::new(
        tree.helper.clone(),
        tree.helper.clone(),
        tree.workdir.clone(),
        BTreeSet::new(),
        ExecutionIdentity::new(10001, 10001, Vec::new()).test_unwrap(),
    );
    assert!(matches!(
        retain_runtime_resources(&aliased),
        Err(CageError::RuntimeDescriptorAlias { .. })
    ));
}
