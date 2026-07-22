#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "real-linux-enforcement"
))]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chio_cage::{
    admit as admit_authorized, compile, launch, launch_prepared, prepare_launch,
    retain_runtime_resources, AdmittedManifest, CageEnforcementState, CageError, CageLaunchOptions,
    ExecutionIdentity, ObservedRulesetStatus, OperatorCeilings, RuntimeResourcePaths,
    SeccompEnforcementStatus, TerminationSignal, MINIMUM_LANDLOCK_ABI, NONO_PATCH_VERSION,
    PINNED_NONO_VERSION, PINNED_SECCOMPILER_VERSION,
};
#[cfg(feature = "enforcement-mutants")]
use chio_cage::{CageEnforcementFailureCode, EnforcementMutation};
use chio_core::crypto::{Keypair, PublicKey};
use chio_manifest::{
    sign_manifest, LatencyHint, NativeSyscallProfile, RequiredPermissions, RuntimeToolTopology,
    SignedManifest, ToolAnnotations, ToolDefinition, ToolManifest, VerifiedManifestRegistry,
    TOOL_MANIFEST_SCHEMA,
};
use chio_test_support::prelude::*;

static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

fn cage_init_helper() -> PathBuf {
    std::env::var_os("CHIO_CAGE_TEST_HELPER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_chio-cage-init")))
}

fn path_texts(paths: Vec<PathBuf>) -> Option<Vec<String>> {
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

fn signed_manifest(
    keypair: &Keypair,
    read_path: Option<&Path>,
    write_path: Option<&Path>,
) -> chio_manifest::SignedManifest {
    signed_manifest_with_read_paths(
        keypair,
        read_path.into_iter().map(Path::to_path_buf).collect(),
        write_path,
    )
}

fn signed_manifest_with_read_paths(
    keypair: &Keypair,
    read_paths: Vec<PathBuf>,
    write_path: Option<&Path>,
) -> chio_manifest::SignedManifest {
    sign_manifest(
        &ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "cage-enforcement-test".to_string(),
            name: "Cage enforcement test".to_string(),
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
                read_paths: path_texts(read_paths),
                write_paths: path_texts(write_path.into_iter().map(Path::to_path_buf).collect()),
                network_destinations: None,
                environment_variables: None,
                native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
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
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed.clone(), registered_key, RuntimeToolTopology::local())
        .test_unwrap();
    let authorization = registry
        .authorize_cage_manifest(&signed.manifest.server_id)
        .test_unwrap();
    admit_authorized(authorization, ceilings)
}

fn compiled_with(
    helper: &Path,
    target: &Path,
    read_path: Option<&Path>,
    write_path: Option<&Path>,
) -> chio_cage::CompiledCage {
    let execution_identity = execution_identity();
    if let Some(path) = write_path {
        prepare_write_owner(path, &execution_identity);
    }
    let workdir = std::env::temp_dir();
    let keypair = Keypair::from_seed(&[73; 32]);
    let signed = signed_manifest(&keypair, read_path, write_path);
    let ceilings = OperatorCeilings::new(
        read_path.into_iter().map(Path::to_path_buf).collect(),
        write_path.into_iter().map(Path::to_path_buf).collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();
    let runtime = retain_runtime_resources(&RuntimeResourcePaths::new(
        helper.to_path_buf(),
        target.to_path_buf(),
        workdir,
        BTreeSet::new(),
        execution_identity,
    ))
    .test_unwrap();
    compile(admitted, runtime, &BTreeMap::new(), None).test_unwrap()
}

fn compiled(target: &Path) -> chio_cage::CompiledCage {
    compiled_with(&cage_init_helper(), target, None, None)
}

fn compiled_with_runtime_files(
    target: &Path,
    runtime_files: BTreeSet<PathBuf>,
) -> chio_cage::CompiledCage {
    let workdir = std::env::temp_dir();
    let keypair = Keypair::from_seed(&[75; 32]);
    let signed =
        signed_manifest_with_read_paths(&keypair, runtime_files.iter().cloned().collect(), None);
    let ceilings = OperatorCeilings::new(
        runtime_files.clone(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    )
    .with_forbidden_paths(BTreeSet::new());
    let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();
    let runtime = retain_runtime_resources(&RuntimeResourcePaths::new(
        cage_init_helper(),
        target.to_path_buf(),
        workdir,
        runtime_files,
        execution_identity(),
    ))
    .test_unwrap();
    compile(admitted, runtime, &BTreeMap::new(), None).test_unwrap()
}

fn compiled_with_argv(target: &Path, argv: Vec<String>) -> chio_cage::CompiledCage {
    let workdir = std::env::temp_dir();
    let keypair = Keypair::from_seed(&[74; 32]);
    let signed = signed_manifest(&keypair, None, None);
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
    let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();
    let runtime = retain_runtime_resources(
        &RuntimeResourcePaths::new(
            cage_init_helper(),
            target.to_path_buf(),
            workdir,
            BTreeSet::new(),
            execution_identity(),
        )
        .with_target_argv(argv),
    )
    .test_unwrap();
    compile(admitted, runtime, &BTreeMap::new(), None).test_unwrap()
}

fn execution_identity() -> ExecutionIdentity {
    // SAFETY: the credential accessors have no pointer arguments.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if uid == 0 {
        return ExecutionIdentity::new(10001, 10001, Vec::new()).test_unwrap();
    }
    // SAFETY: a zero count queries the number of supplementary groups.
    let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(group_count >= 0);
    let mut groups = vec![0; usize::try_from(group_count).test_unwrap()];
    if group_count > 0 {
        // SAFETY: groups has exactly group_count writable gid_t elements.
        assert_eq!(
            unsafe { libc::getgroups(group_count, groups.as_mut_ptr()) },
            group_count
        );
    }
    groups.sort_unstable();
    ExecutionIdentity::new(uid, gid, groups).test_unwrap()
}

fn prepare_write_owner(path: &Path, execution_identity: &ExecutionIdentity) {
    // SAFETY: geteuid has no pointer arguments.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).test_unwrap();
    // SAFETY: path is NUL terminated and both IDs are validated non-root IDs.
    assert_eq!(
        unsafe {
            libc::chown(
                path.as_ptr(),
                execution_identity.uid(),
                execution_identity.gid(),
            )
        },
        0
    );
}

struct TestTree(PathBuf);

impl TestTree {
    fn new() -> Self {
        let sequence = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "chio-cage-enforcement-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).test_unwrap();
        Self(path)
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct EnvironmentRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl EnvironmentRestore {
    fn set(values: &[(&'static str, &'static str)]) -> Self {
        let prior = values
            .iter()
            .map(|(name, _)| (*name, std::env::var_os(name)))
            .collect();
        for (name, value) in values {
            std::env::set_var(name, value);
        }
        Self(prior)
    }
}

impl Drop for EnvironmentRestore {
    fn drop(&mut self) {
        for (name, prior) in self.0.drain(..) {
            if let Some(value) = prior {
                std::env::set_var(name, value);
            } else {
                std::env::remove_var(name);
            }
        }
    }
}

fn required_path(name: &str) -> PathBuf {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("required environment {name}"));
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn wait_for_zombie(process_id: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let state = std::fs::read_to_string(format!("/proc/{process_id}/stat"))
            .ok()
            .and_then(|stat| {
                let (_, remainder) = stat.rsplit_once(") ")?;
                remainder.chars().next()
            });
        if state == Some('Z') {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "successful probe did not become waitable"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn required_runtime_paths(name: &str) -> BTreeSet<PathBuf> {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("required environment {name}"));
    let paths = value
        .lines()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>();
    assert!(!paths.is_empty(), "{name} must name runtime artifacts");
    assert!(paths.iter().all(|path| path.is_absolute()));
    paths
}

fn open_file_descriptor_count() -> usize {
    std::fs::read_dir("/proc/self/fd").test_unwrap().count()
}

fn assert_probe_exit(environment_name: &str, expected_exit: i32) {
    let record = launch(
        compiled(&required_path(environment_name)),
        CageLaunchOptions::default(),
    )
    .test_unwrap()
    .wait()
    .test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(expected_exit),
        "probe {environment_name} did not return its expected exit code"
    );
}

fn assert_probe_sigsys(environment_name: &str) {
    let record = launch(
        compiled(&required_path(environment_name)),
        CageLaunchOptions::default(),
    )
    .test_unwrap()
    .wait()
    .test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.signal),
        Some(libc::SIGSYS),
        "probe {environment_name} was not killed by default-deny seccomp"
    );
}

#[test]
fn real_kernel_reports_fully_enforced_then_clean_exit() {
    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_SUCCESS")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    assert!(child.evidence().status_eof_observed);
    let prepared = &child.evidence().prepared;
    assert_eq!(prepared.applied_execution_identity, execution_identity());
    assert!(prepared.landlock_abi >= MINIMUM_LANDLOCK_ABI);
    assert_eq!(prepared.nono_version, PINNED_NONO_VERSION);
    assert_eq!(prepared.nono_patch_version, NONO_PATCH_VERSION);
    assert_eq!(
        prepared.landlock_filesystem_status,
        ObservedRulesetStatus::FullyEnforced
    );
    assert_eq!(
        prepared.landlock_network_status,
        ObservedRulesetStatus::FullyEnforced
    );
    assert_eq!(prepared.seccompiler_version, PINNED_SECCOMPILER_VERSION);
    assert_eq!(
        prepared.seccomp_status,
        SeccompEnforcementStatus::FullyEnforced
    );
    let record = child.wait().test_unwrap();
    assert_eq!(record.state, CageEnforcementState::Exited);
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn execution_identity_is_exact_after_root_drop_or_unprivileged_launch() {
    // SAFETY: geteuid has no pointer arguments.
    let launched_from_root = unsafe { libc::geteuid() } == 0;
    let expected = execution_identity();
    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_SUCCESS")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    assert_eq!(
        child.evidence().prepared.applied_execution_identity,
        expected
    );
    if launched_from_root {
        assert_eq!(expected.uid(), 10001);
        assert_eq!(expected.gid(), 10001);
    }
    assert_eq!(
        child
            .wait()
            .test_unwrap()
            .exit
            .as_ref()
            .and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn sealed_launch_preparation_is_secret_free_and_owns_descriptors_without_launching() {
    let baseline_descriptor_count = open_file_descriptor_count();
    let launch_marker = Path::new("/tmp/chio-cage-allowed-write");
    let _ = std::fs::remove_file(launch_marker);
    std::fs::write(launch_marker, b"").test_unwrap();
    let helper = cage_init_helper();
    let target = required_path("CHIO_CAGE_TEST_WRITE");
    let compiled = compiled_with(&helper, &target, None, Some(launch_marker));
    let compiled_descriptor_count = open_file_descriptor_count();
    assert!(compiled_descriptor_count > baseline_descriptor_count);
    let manifest_digest = compiled.admitted().manifest_digest().to_string();
    let compiler_fd_table_digest = compiled.profile().fd_table_digest.clone();
    let helper_binding_digest = compiled.profile().helper_binding_digest.clone();
    let target_binding_digest = compiled.profile().target_binding_digest.clone();
    let prepared = prepare_launch(compiled).test_unwrap();
    let prepared_descriptor_count = open_file_descriptor_count();
    assert!(prepared_descriptor_count > compiled_descriptor_count);
    let evidence = prepared.evidence();

    assert_eq!(evidence.manifest_digest(), manifest_digest.as_str());
    assert_eq!(
        evidence.helper_binding_digest(),
        helper_binding_digest.as_str()
    );
    assert_eq!(
        evidence.target_binding_digest(),
        target_binding_digest.as_str()
    );
    assert_ne!(
        evidence.fd_table_digest(),
        compiler_fd_table_digest.as_str()
    );
    assert_eq!(evidence.profile_digest().len(), 64);
    assert_eq!(evidence.plan_digest().len(), 64);
    assert_eq!(
        evidence.seal_mask(),
        (libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL) as u32
    );
    assert!(evidence.exact_requirements_match());
    assert_eq!(evidence.target_launch_count(), 0);
    let serialized = serde_json::to_value(evidence).test_unwrap();
    let serialized_object = serialized
        .as_object()
        .test_expect("serialized preparation evidence object");
    assert_eq!(
        serialized_object
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [
            "exact_requirements_match",
            "fd_table_digest",
            "helper_binding_digest",
            "manifest_digest",
            "plan_digest",
            "profile_digest",
            "seal_mask",
            "target_binding_digest",
            "target_launch_count",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
    let serialized_text = serde_json::to_string(evidence).test_unwrap();
    for forbidden in [
        helper.to_str().test_unwrap(),
        target.to_str().test_unwrap(),
        launch_marker.to_str().test_unwrap(),
        "must-not-cross",
    ] {
        assert!(!serialized_text.contains(forbidden));
    }
    assert!(std::fs::read(launch_marker).test_unwrap().is_empty());
    drop(prepared);
    assert_eq!(open_file_descriptor_count(), baseline_descriptor_count);
    let _ = std::fs::remove_file(launch_marker);
}

#[test]
fn launch_prepared_revalidates_mutated_retained_target_before_spawn() {
    let tree = TestTree::new();
    let target = tree.0.join("prepared-target");
    std::fs::copy(required_path("CHIO_CAGE_TEST_SUCCESS"), &target).test_unwrap();
    let prepared = prepare_launch(compiled(&target)).test_unwrap();
    std::fs::copy(required_path("CHIO_CAGE_TEST_SOCKET"), &target).test_unwrap();

    let error = launch_prepared(prepared, CageLaunchOptions::default()).test_unwrap_err();
    assert_eq!(error.record().state, CageEnforcementState::BootstrapFailed);
    assert_eq!(
        error.record().failure.as_ref().map(|failure| failure.code),
        Some(chio_cage::CageEnforcementFailureCode::DescriptorIdentityMismatch)
    );
    assert_eq!(
        error
            .record()
            .failure
            .as_ref()
            .map(|failure| failure.stage.as_str()),
        Some("retained_bindings")
    );
}

#[test]
fn real_launch_consumes_the_observed_sealed_preparation_contract() {
    let prepared = prepare_launch(compiled(&required_path("CHIO_CAGE_TEST_SUCCESS"))).test_unwrap();
    let observed = prepared.evidence().clone();
    let child = launch_prepared(prepared, CageLaunchOptions::default()).test_unwrap();
    let enforced = &child.evidence().prepared;

    assert_eq!(
        enforced.manifest_digest.as_str(),
        observed.manifest_digest()
    );
    assert_eq!(enforced.profile_digest.as_str(), observed.profile_digest());
    assert_eq!(enforced.plan_digest.as_str(), observed.plan_digest());
    assert_eq!(
        enforced.fd_table_digest.as_str(),
        observed.fd_table_digest()
    );
    assert_eq!(
        enforced.helper_binding_digest.as_str(),
        observed.helper_binding_digest()
    );
    assert_eq!(
        enforced.target_binding_digest.as_str(),
        observed.target_binding_digest()
    );
    assert_eq!(
        child
            .wait()
            .test_unwrap()
            .exit
            .as_ref()
            .and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn dynamically_linked_target_uses_only_retained_runtime_artifacts() {
    let target = required_path("CHIO_CAGE_TEST_DYNAMIC");
    let runtime_files = required_runtime_paths("CHIO_CAGE_TEST_DYNAMIC_RUNTIME");
    let record = launch(
        compiled_with_runtime_files(&target, runtime_files),
        CageLaunchOptions::default(),
    )
    .test_unwrap()
    .wait()
    .test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn fully_enforced_child_exposes_authenticated_stdio_and_exact_argv() {
    let target = required_path("CHIO_CAGE_TEST_STDIO");
    let argv = vec![
        target.to_str().test_unwrap().to_string(),
        "--probe".to_string(),
        "stdio".to_string(),
    ];
    let compiled = compiled_with_argv(&target, argv);
    let compiler_fd_table_digest = compiled.profile().fd_table_digest.clone();
    let mut child = launch(compiled, CageLaunchOptions::default()).test_unwrap();
    assert_ne!(
        child.evidence().prepared.fd_table_digest,
        compiler_fd_table_digest,
        "the sealed launch table must bind the session-specific stdio descriptors"
    );
    let stdio = child
        .take_stdio()
        .test_expect("fully enforced stdio handles");
    let (mut stdin, mut stdout, _stderr) = stdio.into_parts();
    stdin.write_all(b"cage-stdio-probe").test_unwrap();
    drop(stdin);
    let mut response = [0_u8; 16];
    stdout.read_exact(&mut response).test_unwrap();
    assert_eq!(&response, b"cage-stdio-probe");
    let record = child.wait().test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn target_exec_has_no_leaked_control_or_resource_descriptors() {
    let source = std::fs::File::open("/dev/null").test_unwrap();
    // SAFETY: fcntl receives a live descriptor and creates an independent descriptor.
    let ambient_fd = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD, 192) };
    assert!(
        (192..255).contains(&ambient_fd),
        "ambient descriptor must occupy an unnamed cage slot"
    );
    // SAFETY: successful F_DUPFD returned a fresh descriptor owned by this test.
    let ambient = unsafe { OwnedFd::from_raw_fd(ambient_fd) };
    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_FD_LEAK")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    drop(ambient);
    let record = child.wait().test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn independent_seccomp_filter_kills_forbidden_socket() {
    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_SOCKET")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let record = child.wait().test_unwrap();
    assert_eq!(record.state, CageEnforcementState::Exited);
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.signal),
        Some(libc::SIGSYS)
    );
}

#[test]
fn landlock_denies_ungranted_path_after_fd_based_target_exec() {
    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_LANDLOCK")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let record = child.wait().test_unwrap();
    assert_eq!(record.state, CageEnforcementState::Exited);
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn seccomp_kills_forbidden_process_creation() {
    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_CLONE")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let record = child.wait().test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.signal),
        Some(libc::SIGSYS)
    );
}

#[test]
fn landlock_denies_file_creation_without_a_grant() {
    let forbidden = Path::new("/tmp/chio-cage-forbidden-create");
    let _ = std::fs::remove_file(forbidden);
    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_CREATE")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let record = child.wait().test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
    assert!(!forbidden.exists());
}

#[test]
fn retained_target_survives_path_replacement() {
    let tree = TestTree::new();
    let target = tree.0.join("target");
    let retained = tree.0.join("retained-target");
    std::fs::copy(required_path("CHIO_CAGE_TEST_SUCCESS"), &target).test_unwrap();
    let compiled = compiled(&target);
    std::fs::rename(&target, &retained).test_unwrap();
    std::fs::copy(required_path("CHIO_CAGE_TEST_SOCKET"), &target).test_unwrap();
    let record = launch(compiled, CageLaunchOptions::default())
        .test_unwrap()
        .wait()
        .test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn retained_helper_survives_path_replacement_without_reopening() {
    let tree = TestTree::new();
    let helper = tree.0.join("cage-init");
    let retained = tree.0.join("retained-cage-init");
    std::fs::copy(cage_init_helper(), &helper).test_unwrap();
    let compiled = compiled_with(
        &helper,
        &required_path("CHIO_CAGE_TEST_SUCCESS"),
        None,
        None,
    );
    std::fs::rename(&helper, &retained).test_unwrap();
    std::fs::copy(required_path("CHIO_CAGE_TEST_SUCCESS"), &helper).test_unwrap();
    let record = launch(compiled, CageLaunchOptions::default())
        .test_unwrap()
        .wait()
        .test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn pidfd_forwards_an_allowed_termination_signal() {
    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_WAIT")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    child.signal(TerminationSignal::Terminate).test_unwrap();
    let record = child.wait().test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.signal),
        Some(libc::SIGTERM)
    );

    let mut child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_SUCCESS")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let process_id = child.process_id();
    wait_for_zombie(process_id);
    let record = child.try_wait().test_unwrap().test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
    assert_eq!(record.exit.as_ref().and_then(|exit| exit.signal), None);
    assert!(child.try_wait().test_unwrap().is_none());
    assert!(!Path::new(&format!("/proc/{process_id}")).exists());
    let started = Instant::now();
    drop(child);
    assert!(started.elapsed() < Duration::from_secs(1));

    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_SUCCESS")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let process_id = child.process_id();
    wait_for_zombie(process_id);
    let record = child.terminate().test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
    assert_eq!(record.exit.as_ref().and_then(|exit| exit.signal), None);
    assert!(!Path::new(&format!("/proc/{process_id}")).exists());

    let child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_WAIT")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let process_id = child.process_id();
    let record = child.terminate().test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.signal),
        Some(libc::SIGTERM)
    );
    assert!(!Path::new(&format!("/proc/{process_id}")).exists());

    let mut child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_IGNORE_TERM")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let process_id = child.process_id();
    let (stdin, mut stdout, stderr) = child.take_stdio().test_unwrap().into_parts();
    let mut ready = [0_u8; 1];
    stdout.read_exact(&mut ready).test_unwrap();
    assert_eq!(ready, *b"r");
    drop((stdin, stdout, stderr));

    let started = Instant::now();
    let record = child.terminate().test_unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(1));
    assert!(elapsed < Duration::from_secs(10));
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.signal),
        Some(libc::SIGKILL)
    );
    assert!(!Path::new(&format!("/proc/{process_id}")).exists());

    let mut child = launch(
        compiled(&required_path("CHIO_CAGE_TEST_IGNORE_TERM")),
        CageLaunchOptions::default(),
    )
    .test_unwrap();
    let process_id = child.process_id();
    let (stdin, mut stdout, stderr) = child.take_stdio().test_unwrap().into_parts();
    let mut ready = [0_u8; 1];
    stdout.read_exact(&mut ready).test_unwrap();
    assert_eq!(ready, *b"r");
    drop((stdin, stdout, stderr));

    let started = Instant::now();
    drop(child);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(1));
    assert!(elapsed < Duration::from_secs(10));
    assert!(!Path::new(&format!("/proc/{process_id}")).exists());
}

#[test]
fn exact_write_and_read_grants_are_enforced_from_retained_descriptors() {
    let write_path = Path::new("/tmp/chio-cage-allowed-write");
    let read_path = Path::new("/tmp/chio-cage-allowed-read");
    let _ = std::fs::remove_file(write_path);
    std::fs::write(write_path, b"").test_unwrap();
    std::fs::write(read_path, b"r").test_unwrap();

    let write_record = launch(
        compiled_with(
            &cage_init_helper(),
            &required_path("CHIO_CAGE_TEST_WRITE"),
            None,
            Some(write_path),
        ),
        CageLaunchOptions::default(),
    )
    .test_unwrap()
    .wait()
    .test_unwrap();
    assert_eq!(
        write_record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
    assert_eq!(std::fs::read(write_path).test_unwrap(), b"x");

    let read_record = launch(
        compiled_with(
            &cage_init_helper(),
            &required_path("CHIO_CAGE_TEST_READ"),
            Some(read_path),
            None,
        ),
        CageLaunchOptions::default(),
    )
    .test_unwrap()
    .wait()
    .test_unwrap();
    assert_eq!(
        read_record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
    let _ = std::fs::remove_file(write_path);
    let _ = std::fs::remove_file(read_path);
}

#[test]
fn directory_read_grant_denies_a_forbidden_hard_link_created_after_compilation() {
    let allowed_directory = PathBuf::from("/tmp/chio-cage-allowed-directory");
    let existing_file = allowed_directory.join("existing.data");
    let late_forbidden_link = allowed_directory.join("late-forbidden-link");
    let forbidden_file = PathBuf::from("/tmp/chio-cage-directory-forbidden.data");
    let _ = std::fs::remove_dir_all(&allowed_directory);
    let _ = std::fs::remove_file(&forbidden_file);
    std::fs::create_dir(&allowed_directory).test_unwrap();
    std::fs::write(&existing_file, b"existing").test_unwrap();
    std::fs::write(&forbidden_file, b"forbidden").test_unwrap();

    let compile_for_target = |target: PathBuf| {
        let keypair = Keypair::from_seed(&[79; 32]);
        let signed = signed_manifest(&keypair, Some(&allowed_directory), None);
        let ceilings = OperatorCeilings::new(
            [allowed_directory.clone()].into_iter().collect(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            [NativeSyscallProfile::NativeMinimalV1]
                .into_iter()
                .collect(),
        )
        .with_forbidden_paths([forbidden_file.clone()].into_iter().collect());
        let admitted = admit(&signed, &keypair.public_key(), &ceilings).test_unwrap();
        let runtime = retain_runtime_resources(&RuntimeResourcePaths::new(
            cage_init_helper(),
            target,
            std::env::temp_dir(),
            BTreeSet::new(),
            execution_identity(),
        ))
        .test_unwrap();
        compile(admitted, runtime, &BTreeMap::new(), None).test_unwrap()
    };

    let existing_control = compile_for_target(required_path("CHIO_CAGE_TEST_DIRECTORY_READ"));
    let late_link_attack = compile_for_target(required_path("CHIO_CAGE_TEST_DIRECTORY_HARD_LINK"));
    std::fs::hard_link(&forbidden_file, &late_forbidden_link).test_unwrap();

    for compiled in [existing_control, late_link_attack] {
        let record = launch(compiled, CageLaunchOptions::default())
            .test_unwrap()
            .wait()
            .test_unwrap();
        assert_eq!(
            record.exit.as_ref().and_then(|exit| exit.exit_code),
            Some(0)
        );
    }

    std::fs::remove_dir_all(&allowed_directory).test_unwrap();
    std::fs::remove_file(&forbidden_file).test_unwrap();
}

#[test]
fn landlock_grant_does_not_follow_a_replaced_path() {
    let path = Path::new("/tmp/chio-cage-allowed-read");
    let retained = Path::new("/tmp/chio-cage-allowed-read-retained");
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(retained);
    std::fs::write(path, b"original").test_unwrap();
    let compiled = compiled_with(
        &cage_init_helper(),
        &required_path("CHIO_CAGE_TEST_READ_SWAP"),
        Some(path),
        None,
    );
    std::fs::rename(path, retained).test_unwrap();
    std::fs::write(path, b"replacement").test_unwrap();
    let record = launch(compiled, CageLaunchOptions::default())
        .test_unwrap()
        .wait()
        .test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(retained);
}

#[test]
fn target_exec_exception_cannot_be_recreated_after_exec() {
    let record = launch(
        compiled(&required_path("CHIO_CAGE_TEST_REEXEC")),
        CageLaunchOptions::default(),
    )
    .test_unwrap()
    .wait()
    .test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn landlock_denies_write_to_existing_ungranted_file() {
    let forbidden = Path::new("/tmp/chio-cage-forbidden-write-existing");
    std::fs::write(forbidden, b"unchanged").test_unwrap();
    assert_probe_exit("CHIO_CAGE_TEST_WRITE_FORBIDDEN", 0);
    assert_eq!(std::fs::read(forbidden).test_unwrap(), b"unchanged");
    let _ = std::fs::remove_file(forbidden);
}

#[test]
fn default_deny_blocks_remove_rename_and_hard_link() {
    for target in [
        "/tmp/chio-cage-forbidden-rename-target",
        "/tmp/chio-cage-forbidden-link-target",
    ] {
        let _ = std::fs::remove_file(target);
    }
    for (environment_name, path) in [
        ("CHIO_CAGE_TEST_REMOVE", "/tmp/chio-cage-forbidden-remove"),
        (
            "CHIO_CAGE_TEST_RENAME",
            "/tmp/chio-cage-forbidden-rename-source",
        ),
        (
            "CHIO_CAGE_TEST_HARD_LINK",
            "/tmp/chio-cage-forbidden-link-source",
        ),
    ] {
        std::fs::write(path, b"source").test_unwrap();
        assert_probe_sigsys(environment_name);
        assert!(Path::new(path).exists());
        let _ = std::fs::remove_file(path);
    }
    assert!(!Path::new("/tmp/chio-cage-forbidden-rename-target").exists());
    assert!(!Path::new("/tmp/chio-cage-forbidden-link-target").exists());
}

#[test]
fn landlock_denies_symlink_traversal_escape() {
    use std::os::unix::fs::symlink;

    let escape = Path::new("/tmp/chio-cage-symlink-escape");
    let _ = std::fs::remove_file(escape);
    symlink("/etc/passwd", escape).test_unwrap();
    assert_probe_exit("CHIO_CAGE_TEST_SYMLINK", 0);
    let _ = std::fs::remove_file(escape);
}

#[test]
fn default_deny_blocks_ipv4_and_ipv6_connect_and_bind() {
    for environment_name in [
        "CHIO_CAGE_TEST_CONNECT_IPV4",
        "CHIO_CAGE_TEST_BIND_IPV4",
        "CHIO_CAGE_TEST_CONNECT_IPV6",
        "CHIO_CAGE_TEST_BIND_IPV6",
    ] {
        assert_probe_sigsys(environment_name);
    }
}

#[test]
fn default_deny_blocks_unreviewed_syscall() {
    assert_probe_sigsys("CHIO_CAGE_TEST_FORBIDDEN_SYSCALL");
}

#[test]
fn target_receives_no_parent_secret_or_loader_injection_environment() {
    let _restore = EnvironmentRestore::set(&[
        ("CHIO_CAGE_PARENT_SECRET", "must-not-cross"),
        ("LD_PRELOAD", "/must/not/load.so"),
        ("LD_LIBRARY_PATH", "/must/not/search"),
    ]);
    let record = launch(
        compiled(&required_path("CHIO_CAGE_TEST_ENVIRONMENT")),
        CageLaunchOptions::default(),
    )
    .test_unwrap()
    .wait()
    .test_unwrap();
    assert_eq!(
        record.exit.as_ref().and_then(|exit| exit.exit_code),
        Some(0)
    );
}

#[test]
fn default_deny_blocks_undeclared_executable_path() {
    assert_probe_sigsys("CHIO_CAGE_TEST_UNDECLARED_EXEC");
}

#[cfg(feature = "enforcement-mutants")]
fn assert_mutation_denied(mutation: EnforcementMutation) {
    let error = launch(
        compiled(&required_path("CHIO_CAGE_TEST_SUCCESS")),
        CageLaunchOptions::default().with_enforcement_mutation(mutation),
    )
    .test_unwrap_err();
    assert_eq!(error.record().state, CageEnforcementState::BootstrapFailed);
    assert_eq!(
        error.record().failure.as_ref().map(|failure| failure.code),
        Some(CageEnforcementFailureCode::PreparedRecordInvalid)
    );
    error
        .receipt_bindings()
        .test_expect("compiled failure bindings")
        .validate()
        .test_expect("valid failure bindings");
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn enforcement_mutation_disabling_landlock_denies_launch() {
    assert_mutation_denied(EnforcementMutation::DisableLandlock);
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn enforcement_mutation_partial_landlock_denies_launch() {
    assert_mutation_denied(EnforcementMutation::PartialLandlock);
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn enforcement_mutation_disabling_seccomp_denies_launch() {
    assert_mutation_denied(EnforcementMutation::DisableSeccomp);
}

#[cfg(feature = "enforcement-mutants")]
fn assert_bootstrap_mutation_denied(
    mutation: EnforcementMutation,
    expected: CageEnforcementFailureCode,
) {
    let error = launch(
        compiled(&required_path("CHIO_CAGE_TEST_SUCCESS")),
        CageLaunchOptions::default().with_enforcement_mutation(mutation),
    )
    .test_unwrap_err();
    assert_eq!(error.record().state, CageEnforcementState::BootstrapFailed);
    assert_eq!(
        error.record().failure.as_ref().map(|failure| failure.code),
        Some(expected)
    );
    error
        .receipt_bindings()
        .test_expect("compiled failure bindings")
        .validate()
        .test_expect("valid failure bindings");
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn bootstrap_mutation_unsealed_plan_denies_launch() {
    assert_bootstrap_mutation_denied(
        EnforcementMutation::UnsealedPlan,
        CageEnforcementFailureCode::InvalidPlanSeals,
    );
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn bootstrap_mutation_corrupt_plan_digest_denies_launch() {
    assert_bootstrap_mutation_denied(
        EnforcementMutation::CorruptPlanDigest,
        CageEnforcementFailureCode::InvalidPlan,
    );
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn bootstrap_mutation_missing_descriptor_denies_launch() {
    assert_bootstrap_mutation_denied(
        EnforcementMutation::DropDescriptor,
        CageEnforcementFailureCode::DescriptorCountMismatch,
    );
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn bootstrap_mutation_malformed_status_denies_launch() {
    assert_bootstrap_mutation_denied(
        EnforcementMutation::MalformedStatus,
        CageEnforcementFailureCode::StatusProtocolViolation,
    );
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn bootstrap_mutation_trace_binding_mismatch_denies_launch() {
    assert_bootstrap_mutation_denied(
        EnforcementMutation::TraceBindingMismatch,
        CageEnforcementFailureCode::PreparedRecordInvalid,
    );
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn bootstrap_mutation_exit_before_exec_denies_launch() {
    assert_bootstrap_mutation_denied(
        EnforcementMutation::ExitBeforeExec,
        CageEnforcementFailureCode::ChildExitedBeforeExec,
    );
}

#[cfg(feature = "enforcement-mutants")]
#[test]
fn bootstrap_mutation_skipped_execution_identity_denies_launch() {
    assert_bootstrap_mutation_denied(
        EnforcementMutation::SkipExecutionIdentity,
        CageEnforcementFailureCode::ExecutionIdentityMismatch,
    );
}
