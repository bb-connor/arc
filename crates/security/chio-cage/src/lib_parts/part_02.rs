fn resource_fd_entry(
    slot: u32,
    purpose: FdPurpose,
    resource: &RetainedResource,
) -> Result<FdTableEntry, CageError> {
    Ok(FdTableEntry {
        slot,
        purpose,
        identity: resource.identity,
        path: Some(path_text(&resource.path)?.to_string()),
        binding_digest: None,
        broker_peer_identity: None,
        close_on_exec: true,
    })
}

fn build_landlock_plan(
    admitted: &AdmittedManifest,
    fd_table: &[FdTableEntry],
) -> Result<LandlockPolicyPlan, CageError> {
    let forbidden_resources = admitted
        .forbidden_resources
        .iter()
        .map(|resource| {
            Ok(ForbiddenResourceBinding {
                path: path_text(&resource.path)?.to_string(),
                identity: resource.identity,
            })
        })
        .collect::<Result<Vec<_>, CageError>>()?;
    let mut grants = Vec::new();
    for entry in fd_table {
        let access = match entry.purpose {
            FdPurpose::ReadGrant { .. } if entry.identity.kind() == ResourceKind::Directory => {
                Some(FilesystemGrantAccess::ReadDirectory)
            }
            FdPurpose::ReadGrant { .. } => Some(FilesystemGrantAccess::Read),
            FdPurpose::WriteGrant { .. } => Some(FilesystemGrantAccess::WriteExactFile),
            // A retained runtime file with executable mode may be the ELF
            // interpreter selected by PT_INTERP. Landlock must authorize the
            // kernel's interpreter transition, while seccomp still prevents
            // every target-side exec except the retained target FD.
            FdPurpose::RuntimeFile { .. } if entry.identity.mode() & 0o111 != 0 => {
                Some(FilesystemGrantAccess::ExecuteRead)
            }
            FdPurpose::RuntimeFile { .. } => Some(FilesystemGrantAccess::Read),
            FdPurpose::TargetExecutable => Some(FilesystemGrantAccess::ExecuteRead),
            FdPurpose::CageInitHelper
            | FdPurpose::WorkingDirectory
            | FdPurpose::TargetStdin
            | FdPurpose::TargetStdout
            | FdPurpose::TargetStderr
            | FdPurpose::BrokerIpc => None,
        };
        if let Some(access) = access {
            grants.push(FilesystemGrant {
                fd_slot: entry.slot,
                access,
                identity: entry.identity,
            });
        }
    }
    Ok(LandlockPolicyPlan {
        default_filesystem_deny: true,
        network_mode: NetworkMode::Blocked,
        forbidden_resources,
        grants,
    })
}

fn build_seccomp_plan(
    architecture: SandboxArchitecture,
    profile: NativeSyscallProfile,
) -> Result<SeccompProfilePlan, CageError> {
    const BASE: &[&str] = &[
        "brk",
        "clock_gettime",
        "close",
        "execveat",
        "exit",
        "exit_group",
        "faccessat2",
        "fstat",
        "futex",
        "getpid",
        "getrandom",
        "gettid",
        "ioctl",
        "lseek",
        "madvise",
        "mmap",
        "mprotect",
        "munmap",
        "newfstatat",
        "openat",
        "openat2",
        "ppoll",
        "pread64",
        "prlimit64",
        "read",
        "readlinkat",
        "rseq",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "sched_yield",
        "set_robust_list",
        "set_tid_address",
        "sigaltstack",
        "statx",
        "write",
        "writev",
    ];
    const STANDARD: &[&str] = &[
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "eventfd2",
        "getcwd",
        "getdents64",
        "mremap",
        "nanosleep",
        "pipe2",
        "readv",
        "restart_syscall",
        "setitimer",
        "tgkill",
    ];
    const BROKERED: &[&str] = &["recvfrom", "recvmsg", "sendmsg", "sendto"];

    let mut allowed = BASE.iter().copied().collect::<BTreeSet<_>>();
    if architecture == SandboxArchitecture::X86_64 {
        // glibc's ELF loader probes /etc/ld.so.preload with access(2). The
        // subsequent open remains independently confined by Landlock.
        allowed.extend(["access", "arch_prctl", "poll"]);
    }
    match profile {
        NativeSyscallProfile::NativeMinimalV1 => {}
        NativeSyscallProfile::NativeStandardV1 => allowed.extend(STANDARD.iter().copied()),
        NativeSyscallProfile::BrokeredNativeV1 => {
            allowed.extend(STANDARD.iter().copied());
            allowed.extend(BROKERED.iter().copied());
        }
    }
    for forbidden in [
        "socket",
        "socketpair",
        "connect",
        "bind",
        "listen",
        "accept",
    ] {
        if allowed.contains(forbidden) {
            return Err(CageError::UnsafeSyscallProfile(forbidden));
        }
    }
    let mut argument_constraints = BTreeMap::from([(
        "execveat".to_string(),
        vec![
            SyscallArgumentConstraint {
                argument_index: 0,
                comparison: SeccompArgumentComparison::Equal,
                value: u64::from(TARGET_FD_SLOT),
            },
            SyscallArgumentConstraint {
                argument_index: 4,
                comparison: SeccompArgumentComparison::Equal,
                value: AT_EMPTY_PATH,
            },
        ],
    )]);
    if profile == NativeSyscallProfile::BrokeredNativeV1 {
        for syscall in BROKERED {
            argument_constraints.insert(
                (*syscall).to_string(),
                vec![SyscallArgumentConstraint {
                    argument_index: 0,
                    comparison: SeccompArgumentComparison::Equal,
                    value: u64::from(BROKER_IPC_FD_SLOT),
                }],
            );
        }
    }
    Ok(SeccompProfilePlan {
        architecture,
        profile,
        default_action: SeccompDefaultAction::KillProcess,
        allowed_syscalls: allowed.into_iter().map(str::to_string).collect(),
        argument_constraints,
    })
}

fn validate_sha256_hex(value: &str, field: &'static str) -> Result<(), CageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CageError::InvalidDigest(field));
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<&str, CageError> {
    path.to_str()
        .ok_or_else(|| CageError::InvalidPath(path.to_path_buf()))
}

fn digest<T: Serialize>(value: &T) -> Result<String, CageError> {
    let bytes = chio_core::canonical_json_bytes(value)?;
    Ok(chio_core::sha256_hex(&bytes))
}

/// Fail-closed cage admission and compilation errors.
#[derive(Debug, thiserror::Error)]
pub enum CageError {
    #[error("canonical cage encoding failed: {0}")]
    Canonical(#[from] chio_core::Error),
    #[error("native cage admission requires explicit platform permissions")]
    MissingRequiredPermissions,
    #[error("publisher permissions exceed operator ceilings")]
    OperatorCeilingExceeded,
    #[error("operator policy must explicitly configure the complete forbidden-path set")]
    MissingForbiddenPathPolicy,
    #[error("a path cannot request both read and write access")]
    AmbiguousFilesystemAccess,
    #[error("native cage admission is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("unsupported seccomp architecture: {0}")]
    UnsupportedArchitecture(String),
    #[error("required Linux kernel feature is unavailable: {0}")]
    UnsupportedKernelFeature(&'static str),
    #[error("invalid absolute normalized cage path: {0}")]
    InvalidPath(PathBuf),
    #[error("allowed path {allowed} overlaps forbidden path {forbidden}")]
    ForbiddenPathOverlap {
        allowed: PathBuf,
        forbidden: PathBuf,
    },
    #[error("allowed path {allowed} aliases forbidden descriptor {forbidden}")]
    ForbiddenDescriptorAlias {
        allowed: PathBuf,
        forbidden: PathBuf,
    },
    #[error("grant paths {first} and {second} alias the same descriptor identity")]
    GrantDescriptorAlias { first: PathBuf, second: PathBuf },
    #[error("runtime paths {first} and {second} alias the same descriptor identity")]
    RuntimeDescriptorAlias { first: PathBuf, second: PathBuf },
    #[error("runtime file is absent from the verified manifest read authority: {0}")]
    UnauthorizedRuntimeFile(PathBuf),
    #[error("runtime file identity differs from its verified manifest read authority: {0}")]
    RuntimeFileAuthorityChanged(PathBuf),
    #[error("failed to retain path {path}: {source}")]
    RetainPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to enumerate retained directory {path}: {source}")]
    DirectoryEnumeration {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read descriptor metadata for {path}: {source}")]
    DescriptorMetadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("symbolic links are not admissible: {0}")]
    SymbolicLink(PathBuf),
    #[error("unsupported filesystem object kind: {0}")]
    UnsupportedResourceKind(PathBuf),
    #[error("write grants must name exact regular files: {0}")]
    WritableDirectory(PathBuf),
    #[error("missing writable file has no existing safe parent: {0}")]
    MissingWriteParent(PathBuf),
    #[error("securely created file has unexpected ownership or mode: {0}")]
    UnsafeCreatedFile(PathBuf),
    #[error("descriptor identity changed while retaining path: {0}")]
    DescriptorIdentityChanged(PathBuf),
    #[error("runtime artifact is not an executable regular file: {0}")]
    InvalidExecutable(PathBuf),
    #[error("runtime artifact is too large: {0}")]
    ArtifactTooLarge(PathBuf),
    #[error("runtime artifact content changed while it was hashed: {0}")]
    ArtifactChanged(PathBuf),
    #[error("runtime artifact digest no longer matches its retained descriptor: {0}")]
    ArtifactDigestMismatch(PathBuf),
    #[error("unable to determine mount identity for descriptor: {0}")]
    MissingMountIdentity(PathBuf),
    #[error("invalid limit: {0}")]
    InvalidLimit(&'static str),
    #[error("invalid target execution identity: {0}")]
    InvalidExecutionIdentity(&'static str),
    #[error("applied target execution identity does not match the sealed plan")]
    ExecutionIdentityMismatch,
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(&'static str),
    #[error("invalid broker authentication descriptor")]
    InvalidBrokerDescriptor,
    #[error("failed to create target stdio channel: {0}")]
    TargetStdio(#[source] std::io::Error),
    #[error("target stdio channel is not an authenticated Unix socket")]
    InvalidTargetStdio,
    #[error("target stdio handles are unavailable")]
    TargetStdioUnavailable,
    #[error("target stdio is already bound into the launch plan")]
    TargetStdioAlreadyBound,
    #[error("connected broker peer credentials do not match operator configuration")]
    BrokerPeerIdentityMismatch,
    #[error("brokered syscall profile and authenticated broker descriptor must be paired")]
    BrokerProfileMismatch,
    #[error("invalid SHA-256 digest for {0}")]
    InvalidDigest(&'static str),
    #[error("forbidden environment variable: {0}")]
    ForbiddenEnvironmentVariable(String),
    #[error("invalid environment value for {0}")]
    InvalidEnvironmentValue(String),
    #[error("target argument vector is empty, malformed, or exceeds cage bounds")]
    InvalidTargetArgv,
    #[error("descriptor slot arithmetic overflow")]
    FdSlotOverflow,
    #[error("compiled descriptor table contains a duplicate slot")]
    DuplicateFdSlot,
    #[error("invalid target executable descriptor binding: {0}")]
    InvalidTargetFdBinding(&'static str),
    #[error("reviewed seccomp profile unexpectedly allows {0}")]
    UnsafeSyscallProfile(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_manifest::{
        sign_manifest, LatencyHint, RequiredPermissions, RuntimeToolTopology, SignedManifest,
        ToolAnnotations, ToolDefinition, ToolManifest, VerifiedManifestRegistry,
        TOOL_MANIFEST_SCHEMA,
    };
    use chio_test_support::prelude::*;

    fn signed_manifest(keypair: &Keypair) -> SignedManifest {
        sign_manifest(
            &ToolManifest {
                schema: TOOL_MANIFEST_SCHEMA.to_string(),
                server_id: "cage-test".to_string(),
                name: "Cage test".to_string(),
                description: None,
                version: "1".to_string(),
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
                    latency_hint: Some(LatencyHint::Fast),
                    flow: None,
                }],
                server_tools: Vec::new(),
                required_permissions: Some(RequiredPermissions {
                    read_paths: None,
                    write_paths: None,
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

    fn ceilings() -> OperatorCeilings {
        OperatorCeilings::new(
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            [NativeSyscallProfile::NativeMinimalV1]
                .into_iter()
                .collect(),
        )
        .with_forbidden_paths(BTreeSet::new())
    }

    #[test]
    fn signature_is_verified_before_permissions_are_read() {
        let keypair = Keypair::from_seed(&[27; 32]);
        let mut signed = signed_manifest(&keypair);
        signed.manifest.required_permissions = None;
        let mut registry = VerifiedManifestRegistry::default();
        assert!(matches!(
            registry.register_public_only(
                signed,
                &keypair.public_key(),
                RuntimeToolTopology::local(),
            ),
            Err(chio_manifest::VerifiedManifestAdmissionError::Manifest(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn admission_consumes_nonforgeable_registry_authorization() {
        let keypair = Keypair::from_seed(&[29; 32]);
        let signed = signed_manifest(&keypair);
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &keypair.public_key(), RuntimeToolTopology::local())
            .test_unwrap();
        let authorization = registry.authorize_cage_manifest("cage-test").test_unwrap();
        let authorization_digest = authorization.authorization_digest().to_string();

        let admitted = admit(authorization, &ceilings()).test_unwrap();

        assert_eq!(admitted.cage_authorization_digest(), authorization_digest);
        assert_eq!(admitted.manifest_digest().len(), 64);
        assert_eq!(admitted.registry_digest().len(), 64);
        assert_eq!(admitted.signed_manifest_digest().len(), 64);
    }

    #[test]
    fn environment_is_minimal_and_credentials_fail_closed() {
        let safe = EnvironmentVariableName::new("APP_MODE").test_unwrap();
        let parent = BTreeMap::from([
            ("APP_MODE".to_string(), "production".to_string()),
            ("OPENAI_API_KEY".to_string(), "secret".to_string()),
            ("HOME".to_string(), "/untrusted".to_string()),
        ]);
        let environment = build_environment(&[safe].into_iter().collect(), &parent).test_unwrap();
        assert_eq!(
            environment.get("APP_MODE").map(String::as_str),
            Some("production")
        );
        assert!(!environment.contains_key("HOME"));
        for forbidden in [
            "OPENAI_API_KEY",
            "openai_api_key",
            "GLIBC_TUNABLES",
            "ld_preload",
            "JAVA_TOOL_OPTIONS",
            "SSH_AUTH_SOCK",
            "SSL_CERT_FILE",
        ] {
            assert!(EnvironmentVariableName::new(forbidden).is_err());
            assert!(is_credential_or_injection_name(forbidden));
        }
        assert!(!is_credential_or_injection_name("APP_MODE"));
    }

    #[test]
    fn every_syscall_profile_is_default_deny_and_has_no_network_creation() {
        for profile in [
            NativeSyscallProfile::NativeMinimalV1,
            NativeSyscallProfile::NativeStandardV1,
            NativeSyscallProfile::BrokeredNativeV1,
        ] {
            let plan = build_seccomp_plan(SandboxArchitecture::X86_64, profile).test_unwrap();
            assert_eq!(plan.default_action, SeccompDefaultAction::KillProcess);
            for forbidden in [
                "socket",
                "socketpair",
                "connect",
                "bind",
                "listen",
                "accept",
            ] {
                assert!(!plan.allowed_syscalls.iter().any(|name| name == forbidden));
            }
            assert_eq!(
                plan.argument_constraints
                    .get("execveat")
                    .and_then(|constraints| constraints.first())
                    .map(|constraint| constraint.value),
                Some(u64::from(TARGET_FD_SLOT))
            );
        }
    }

    #[test]
    fn descriptor_purpose_rejects_unknown_nested_fields() {
        for kind in [
            "cage_init_helper",
            "target_executable",
            "working_directory",
            "target_stdin",
            "target_stdout",
            "target_stderr",
            "broker_ipc",
        ] {
            let encoded = serde_json::json!({
                "kind": kind,
                "index": 0,
            });
            assert!(
                serde_json::from_value::<FdPurpose>(encoded).is_err(),
                "unit purpose accepted an unknown index: {kind}"
            );
        }

        for kind in ["runtime_file", "read_grant", "write_grant"] {
            let encoded = serde_json::json!({
                "kind": kind,
                "index": 0,
                "unexpected": true,
            });
            assert!(
                serde_json::from_value::<FdPurpose>(encoded).is_err(),
                "indexed purpose accepted an unknown field: {kind}"
            );
        }

        let exact = serde_json::json!({"kind": "target_executable"});
        assert_eq!(
            serde_json::from_value::<FdPurpose>(exact.clone()).test_unwrap(),
            FdPurpose::TargetExecutable
        );
        assert_eq!(
            serde_json::to_value(FdPurpose::TargetExecutable).test_unwrap(),
            exact
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_denies_after_verified_admission() {
        let keypair = Keypair::from_seed(&[28; 32]);
        let signed = signed_manifest(&keypair);
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &keypair.public_key(), RuntimeToolTopology::local())
            .test_unwrap();
        let authorization = registry.authorize_cage_manifest("cage-test").test_unwrap();
        assert!(matches!(
            admit(authorization, &ceilings()),
            Err(CageError::UnsupportedPlatform)
        ));
    }
}
