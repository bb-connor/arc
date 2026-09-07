fn duplicate_helper_exec_fd(source: RawFd) -> Result<OwnedFd, CageLaunchError> {
    // The helper must be executed from the descriptor whose identity and
    // content were admitted. Spawning the retained pathname would reopen a
    // mutable directory entry and let a replacement image run before the
    // parent could perform its post-exec identity check.
    // SAFETY: source is a live retained helper descriptor and
    // F_DUPFD_CLOEXEC returns a new independently owned descriptor.
    let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, TEMP_FD_START) };
    if duplicate < 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_descriptor_duplicate",
        ));
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returns a fresh descriptor and this
    // is its only conversion into an owning Rust value.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn validate_envelope(envelope: &LaunchEnvelope, peer: libc::ucred) -> Result<(), BootstrapFault> {
    if envelope.schema != LAUNCH_ENVELOPE_SCHEMA
        || envelope.parent_process_id == 0
        || peer.pid <= 0
        || u32::try_from(peer.pid).ok() != Some(envelope.parent_process_id)
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "parent_binding",
        ));
    }
    // SAFETY: getppid takes no pointers and returns the kernel-recorded parent.
    let parent = unsafe { libc::getppid() };
    if parent <= 0 || u32::try_from(parent).ok() != Some(envelope.parent_process_id) {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "parent_process",
        ));
    }
    validate_digest(&envelope.trace_session_digest)?;
    validate_digest(&envelope.plan_digest)?;
    validate_digest(&envelope.fd_table_digest)?;
    validate_digest(&envelope.helper_binding_digest)?;
    validate_digest(&envelope.target_binding_digest)?;
    if envelope.plan.schema != CAGE_INIT_PLAN_SCHEMA
        || envelope.plan.compiler_version != CAGE_COMPILER_VERSION
        || envelope.plan.plan_fd_slot != PLAN_FD as u32
        || envelope.plan.status_fd_slot != STATUS_FD as u32
        || envelope.plan.target_fd_slot != TARGET_FD as u32
        || envelope.plan.resource_limits.nofile_soft > u64::from(envelope.plan.target_fd_slot)
        || envelope.plan.resource_limits.nofile_hard < envelope.plan.resource_limits.nofile_soft
        || envelope.plan.resource_limits.nofile_hard > u64::from(envelope.plan.target_fd_slot)
        || envelope.plan.seccomp.default_action != SeccompDefaultAction::KillProcess
        || !envelope.plan.landlock.default_filesystem_deny
        || envelope.plan.landlock.network_mode != NetworkMode::Blocked
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_shape",
        ));
    }
    let plan_bytes = chio_core::canonical_json_bytes(&envelope.plan)
        .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_digest"))?;
    if chio_core::sha256_hex(&plan_bytes) != envelope.plan_digest {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_digest",
        ));
    }
    let table_bytes = chio_core::canonical_json_bytes(&envelope.plan.fd_table).map_err(|_| {
        BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "fd_table_digest")
    })?;
    if chio_core::sha256_hex(&table_bytes) != envelope.fd_table_digest {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "fd_table_digest",
        ));
    }
    crate::validate_target_argv(&envelope.plan.target_argv)
        .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "target_argv"))?;
    envelope.plan.execution_identity.validate().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityInvalid,
            "execution_identity",
        )
    })?;
    validate_fd_table_shape(&envelope.plan)
}

fn validate_fd_table_shape(plan: &CageInitPlan) -> Result<(), BootstrapFault> {
    if plan.fd_table.is_empty() || plan.fd_table.len() + 1 > MAX_TRANSFER_FDS {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "fd_table_count",
        ));
    }
    let mut slots = BTreeSet::new();
    let mut helper = 0_u8;
    let mut target = 0_u8;
    let mut workdir = 0_u8;
    let mut target_stdin = 0_u8;
    let mut target_stdout = 0_u8;
    let mut target_stderr = 0_u8;
    let mut broker = 0_u8;
    for (position, entry) in plan.fd_table.iter().enumerate() {
        if !slots.insert(entry.slot)
            || position > 0 && plan.fd_table[position - 1].slot >= entry.slot
            || entry.slot <= plan.status_fd_slot
            || entry.purpose != FdPurpose::TargetExecutable
                && entry.slot >= plan.resource_limits.nofile_hard as u32
        {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::InvalidPlan,
                "fd_table_slots",
            ));
        }
        match entry.purpose {
            FdPurpose::CageInitHelper => {
                helper = helper.saturating_add(1);
                if entry.slot != plan.helper_fd_slot || !entry.close_on_exec {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "helper_slot",
                    ));
                }
            }
            FdPurpose::TargetExecutable => {
                target = target.saturating_add(1);
                if entry.slot != plan.target_fd_slot || !entry.close_on_exec {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "target_slot",
                    ));
                }
            }
            FdPurpose::WorkingDirectory => {
                workdir = workdir.saturating_add(1);
                if entry.slot != plan.working_directory_fd_slot || !entry.close_on_exec {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "workdir_slot",
                    ));
                }
            }
            FdPurpose::TargetStdin => validate_stdio_entry(
                entry,
                &mut target_stdin,
                crate::TARGET_STDIN_FD_SLOT,
                "target_stdin_slot",
            )?,
            FdPurpose::TargetStdout => validate_stdio_entry(
                entry,
                &mut target_stdout,
                crate::TARGET_STDOUT_FD_SLOT,
                "target_stdout_slot",
            )?,
            FdPurpose::TargetStderr => validate_stdio_entry(
                entry,
                &mut target_stderr,
                crate::TARGET_STDERR_FD_SLOT,
                "target_stderr_slot",
            )?,
            FdPurpose::BrokerIpc => {
                broker = broker.saturating_add(1);
                if entry.slot != crate::BROKER_IPC_FD_SLOT
                    || entry.close_on_exec
                    || entry.broker_peer_identity.is_none()
                    || entry.identity.kind() != crate::ResourceKind::UnixSocket
                    || entry.path.is_some()
                    || entry.binding_digest.as_deref()
                        != plan.broker_authentication_digest.as_deref()
                {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "broker_slot",
                    ));
                }
            }
            FdPurpose::RuntimeFile { .. }
            | FdPurpose::ReadGrant { .. }
            | FdPurpose::WriteGrant { .. } => {
                if !entry.close_on_exec {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "resource_close_on_exec",
                    ));
                }
            }
        }
    }
    if helper != 1
        || target != 1
        || workdir != 1
        || target_stdin != 1
        || target_stdout != 1
        || target_stderr != 1
        || broker > 1
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "fd_table_roles",
        ));
    }
    let brokered = plan.seccomp.profile == chio_manifest::NativeSyscallProfile::BrokeredNativeV1;
    if brokered != (broker == 1) || brokered != plan.broker_authentication_digest.is_some() {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "broker_profile",
        ));
    }
    if let Some(authentication_digest) = plan.broker_authentication_digest.as_deref() {
        validate_digest(authentication_digest)?;
    }
    Ok(())
}

fn validate_stdio_entry(
    entry: &crate::FdTableEntry,
    count: &mut u8,
    expected_slot: u32,
    stage: &'static str,
) -> Result<(), BootstrapFault> {
    *count = (*count).saturating_add(1);
    if entry.slot != expected_slot
        || !entry.close_on_exec
        || entry.identity.kind() != crate::ResourceKind::UnixSocket
        || entry.path.is_some()
        || entry.binding_digest.is_some()
        || entry.broker_peer_identity.is_some()
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            stage,
        ));
    }
    Ok(())
}

fn transfer_descriptors(compiled: &CompiledCage) -> Result<Vec<RawFd>, CageLaunchError> {
    compiled
        .plan()
        .fd_table
        .iter()
        .map(|entry| match entry.purpose {
            FdPurpose::CageInitHelper => {
                Ok(compiled.runtime().helper().resource().file().as_raw_fd())
            }
            FdPurpose::TargetExecutable => {
                Ok(compiled.runtime().target().resource().file().as_raw_fd())
            }
            FdPurpose::WorkingDirectory => Ok(compiled
                .runtime()
                .working_directory()
                .resource()
                .file()
                .as_raw_fd()),
            FdPurpose::TargetStdin | FdPurpose::TargetStdout | FdPurpose::TargetStderr => compiled
                .target_stdio()
                .and_then(|stdio| stdio.child_file(&entry.purpose))
                .map(std::os::fd::AsRawFd::as_raw_fd)
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "target_stdio_descriptor",
                    )
                }),
            FdPurpose::RuntimeFile { index } => compiled
                .runtime()
                .runtime_files()
                .get(index as usize)
                .map(|artifact| artifact.resource().file().as_raw_fd())
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "runtime_descriptor",
                    )
                }),
            FdPurpose::ReadGrant { index } => compiled
                .admitted()
                .read_resources()
                .get(index as usize)
                .map(|resource| resource.file().as_raw_fd())
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "read_descriptor",
                    )
                }),
            FdPurpose::WriteGrant { index } => compiled
                .admitted()
                .write_resources()
                .get(index as usize)
                .map(|resource| resource.file().as_raw_fd())
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "write_descriptor",
                    )
                }),
            FdPurpose::BrokerIpc => compiled
                .broker_ipc()
                .map(|broker| broker.file().as_raw_fd())
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "broker_descriptor",
                    )
                }),
        })
        .collect()
}

fn verify_descriptor_table(
    envelope: &LaunchEnvelope,
    files: &[File],
) -> Result<(), BootstrapFault> {
    if files.len() != envelope.plan.fd_table.len() {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "received_descriptor_count",
        ));
    }
    let mut live_target_binding = None;
    for (entry, file) in envelope.plan.fd_table.iter().zip(files) {
        let observed_identity = verify_received_descriptor_identity(entry, file)?;
        if matches!(
            entry.purpose,
            FdPurpose::CageInitHelper | FdPurpose::TargetExecutable
        ) || matches!(entry.purpose, FdPurpose::RuntimeFile { .. })
            && entry.identity.mode() & 0o111 != 0
        {
            verify_unprivileged_executable(file)?;
        }
        match entry.purpose {
            FdPurpose::CageInitHelper
            | FdPurpose::TargetExecutable
            | FdPurpose::RuntimeFile { .. } => {
                let expected = entry.binding_digest.as_ref().ok_or_else(|| {
                    BootstrapFault::new(
                        CageEnforcementFailureCode::DescriptorIdentityMismatch,
                        "artifact_binding",
                    )
                })?;
                let observed_binding_digest = hash_file(file)?;
                if observed_binding_digest != *expected {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::DescriptorIdentityMismatch,
                        "artifact_binding",
                    ));
                }
                if matches!(entry.purpose, FdPurpose::TargetExecutable) {
                    live_target_binding = Some((observed_identity, observed_binding_digest));
                }
            }
            FdPurpose::WorkingDirectory
            | FdPurpose::TargetStdin
            | FdPurpose::TargetStdout
            | FdPurpose::TargetStderr
            | FdPurpose::ReadGrant { .. }
            | FdPurpose::WriteGrant { .. } => {}
            FdPurpose::BrokerIpc => {
                let expected = entry.broker_peer_identity.ok_or_else(|| {
                    BootstrapFault::new(
                        CageEnforcementFailureCode::DescriptorIdentityMismatch,
                        "broker_peer",
                    )
                })?;
                let actual = peer_credentials(file.as_raw_fd())?;
                if u32::try_from(actual.pid).ok() != Some(expected.pid)
                    || actual.uid != expected.uid
                    || actual.gid != expected.gid
                {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::DescriptorIdentityMismatch,
                        "broker_peer",
                    ));
                }
            }
        }
    }
    let helper = helper_entry(&envelope.plan)?;
    let target = target_entry(&envelope.plan)?;
    if helper.binding_digest.as_deref() != Some(&envelope.helper_binding_digest)
        || target.binding_digest.as_deref() != Some(&envelope.target_binding_digest)
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "runtime_bindings",
        ));
    }
    let (observed_identity, observed_binding_digest) = live_target_binding.ok_or_else(|| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "target_descriptor",
        )
    })?;
    crate::validate_cage_target_fd_binding(
        &envelope.plan,
        &observed_binding_digest,
        observed_identity,
    )
    .map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "target_fd_binding",
        )
    })?;
    Ok(())
}

pub(super) fn validate_cage_target_fd_binding_production_paths(
    template: &CageInitPlan,
    target: &File,
    mutation: CageTargetFdBindingMutation,
) -> Result<CageTargetFdBindingProductionValidation, CageError> {
    let stdio = crate::CompiledTargetStdio::create()?;
    let working_directory = File::open(".")
        .map_err(|_| CageError::InvalidTargetFdBinding("conformance_working_directory"))?;
    let mut plan = template.clone();
    let mut files = Vec::with_capacity(plan.fd_table.len());
    for entry in &mut plan.fd_table {
        let file = match &entry.purpose {
            FdPurpose::CageInitHelper | FdPurpose::TargetExecutable => target
                .try_clone()
                .map_err(|_| CageError::InvalidTargetFdBinding("conformance_target_clone"))?,
            FdPurpose::WorkingDirectory => working_directory.try_clone().map_err(|_| {
                CageError::InvalidTargetFdBinding("conformance_working_directory_clone")
            })?,
            FdPurpose::TargetStdin | FdPurpose::TargetStdout | FdPurpose::TargetStderr => stdio
                .child_file(&entry.purpose)
                .ok_or(CageError::InvalidTargetFdBinding("conformance_stdio"))?
                .try_clone()
                .map_err(|_| CageError::InvalidTargetFdBinding("conformance_stdio_clone"))?,
            FdPurpose::RuntimeFile { .. }
            | FdPurpose::ReadGrant { .. }
            | FdPurpose::WriteGrant { .. }
            | FdPurpose::BrokerIpc => {
                return Err(CageError::InvalidTargetFdBinding(
                    "conformance_descriptor_shape",
                ));
            }
        };
        entry.identity = crate::linux::descriptor_identity(&file, None)?;
        if matches!(
            entry.purpose,
            FdPurpose::CageInitHelper | FdPurpose::TargetExecutable
        ) {
            entry.binding_digest = Some(
                hash_file(&file)
                    .map_err(|_| CageError::InvalidTargetFdBinding("conformance_hash"))?,
            );
        }
        files.push(file);
    }

    let target_index = plan
        .fd_table
        .iter()
        .position(|entry| matches!(entry.purpose, FdPurpose::TargetExecutable))
        .ok_or(CageError::InvalidTargetFdBinding("conformance_target_entry"))?;
    match mutation {
        CageTargetFdBindingMutation::None => {}
        CageTargetFdBindingMutation::Slot => {
            plan.fd_table[target_index].slot =
                plan.fd_table[target_index].slot.saturating_sub(1);
        }
        CageTargetFdBindingMutation::BindingDigest => {
            let binding_digest = plan.fd_table[target_index]
                .binding_digest
                .as_mut()
                .ok_or(CageError::InvalidTargetFdBinding(
                    "conformance_target_binding",
                ))?;
            let replacement = if binding_digest.starts_with('0') {
                "1"
            } else {
                "0"
            };
            binding_digest.replace_range(..1, replacement);
        }
        CageTargetFdBindingMutation::Identity => {
            plan.fd_table[target_index].identity.inode = plan.fd_table[target_index]
                .identity
                .inode
                .wrapping_add(1);
        }
        CageTargetFdBindingMutation::ExecveatTarget => {
            let constraint = plan
                .seccomp
                .argument_constraints
                .get_mut("execveat")
                .and_then(|constraints| {
                    constraints
                        .iter_mut()
                        .find(|constraint| constraint.argument_index == 0)
                })
                .ok_or(CageError::InvalidTargetFdBinding(
                    "conformance_execveat_target",
                ))?;
            constraint.value ^= 1;
        }
    }

    let plan_digest = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&plan)?);
    let fd_table_digest =
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(&plan.fd_table)?);
    let helper_binding_digest = plan
        .fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::CageInitHelper))
        .and_then(|entry| entry.binding_digest.clone())
        .ok_or(CageError::InvalidTargetFdBinding(
            "conformance_helper_binding",
        ))?;
    let observed_target_binding_digest = hash_file(target)
        .map_err(|_| CageError::InvalidTargetFdBinding("conformance_target_hash"))?;
    let parent_accepted = validate_compiled_plan(CompiledPlanValidation {
        plan: &plan,
        profile_digest: plan.profile_digest.as_str(),
        manifest_digest: plan.manifest_digest.as_str(),
        plan_digest: &plan_digest,
        target,
    })
    .is_ok();
    let envelope = LaunchEnvelope {
        schema: LAUNCH_ENVELOPE_SCHEMA.to_string(),
        parent_process_id: std::process::id(),
        trace_session_digest: "0".repeat(64),
        plan_digest,
        fd_table_digest,
        helper_binding_digest,
        target_binding_digest: observed_target_binding_digest,
        plan,
    };
    let child_accepted = verify_descriptor_table(&envelope, &files).is_ok();
    Ok(CageTargetFdBindingProductionValidation {
        parent_accepted,
        child_accepted,
    })
}

fn verify_received_descriptor_identity(
    entry: &crate::FdTableEntry,
    file: &File,
) -> Result<crate::FileIdentity, BootstrapFault> {
    let identity = crate::linux::descriptor_identity(file, None).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "descriptor_identity",
        )
    })?;
    if identity != entry.identity {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "descriptor_identity",
        ));
    }
    Ok(identity)
}

fn verify_helper_self(envelope: &LaunchEnvelope, files: &[File]) -> Result<(), BootstrapFault> {
    let helper_position = envelope
        .plan
        .fd_table
        .iter()
        .position(|entry| matches!(entry.purpose, FdPurpose::CageInitHelper))
        .ok_or_else(|| {
            BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "helper_descriptor",
            )
        })?;
    let expected_file = files.get(helper_position).ok_or_else(|| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "helper_descriptor",
        )
    })?;
    let live = File::open("/proc/self/exe").map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_self",
        )
    })?;
    let expected_identity =
        crate::linux::descriptor_identity(expected_file, None).map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::HelperIdentityMismatch,
                "helper_self_identity",
            )
        })?;
    let live_identity = crate::linux::descriptor_identity(&live, None).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_self_identity",
        )
    })?;
    let live_binding_digest = hash_file(&live)?;
    if !helper_identity_and_binding_match(
        expected_identity,
        live_identity,
        &envelope.helper_binding_digest,
        &live_binding_digest,
    ) {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_self_binding",
        ));
    }
    Ok(())
}


fn helper_entry(plan: &CageInitPlan) -> Result<&crate::FdTableEntry, BootstrapFault> {
    plan.fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::CageInitHelper))
        .ok_or_else(|| {
            BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "helper_entry",
            )
        })
}

fn target_entry(plan: &CageInitPlan) -> Result<&crate::FdTableEntry, BootstrapFault> {
    plan.fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::TargetExecutable))
        .ok_or_else(|| {
            BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "target_entry",
            )
        })
}

fn remap_descriptors(
    control: File,
    plan_memfd: File,
    resources: Vec<File>,
    plan: &CageInitPlan,
) -> Result<(), BootstrapFault> {
    let mut mappings = Vec::with_capacity(resources.len() + 2);
    mappings.push((control.as_raw_fd(), STATUS_FD, true));
    mappings.push((plan_memfd.as_raw_fd(), PLAN_FD, true));
    for (entry, file) in plan.fd_table.iter().zip(&resources) {
        mappings.push((file.as_raw_fd(), entry.slot as RawFd, entry.close_on_exec));
    }
    let mut temporary = Vec::with_capacity(mappings.len());
    for (source, target, close_on_exec) in mappings {
        // SAFETY: source is live and F_DUPFD_CLOEXEC returns a new descriptor
        // at or above the collision-free temporary range.
        let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, TEMP_FD_START) };
        if duplicate < 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "descriptor_duplicate",
            ));
        }
        temporary.push((duplicate, target, close_on_exec));
    }
    drop(resources);
    drop(plan_memfd);
    drop(control);
    for (source, target, close_on_exec) in &temporary {
        let flags = if *close_on_exec { libc::O_CLOEXEC } else { 0 };
        // SAFETY: both descriptor numbers are valid, distinct, and the flags
        // value is the only one accepted by dup3.
        if unsafe { libc::dup3(*source, *target, flags) } < 0 {
            close_raw_descriptors(&temporary);
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "descriptor_remap",
            ));
        }
    }
    close_raw_descriptors(&temporary);
    remap_target_stdio(plan)?;
    close_unnamed_descriptors(plan)?;
    Ok(())
}

fn remap_target_stdio(plan: &CageInitPlan) -> Result<(), BootstrapFault> {
    for (purpose, target) in [
        (FdPurpose::TargetStdin, 0),
        (FdPurpose::TargetStdout, 1),
        (FdPurpose::TargetStderr, 2),
    ] {
        let source = plan
            .fd_table
            .iter()
            .find(|entry| entry.purpose == purpose)
            .map(|entry| entry.slot as RawFd)
            .ok_or_else(|| {
                BootstrapFault::new(
                    CageEnforcementFailureCode::DescriptorCountMismatch,
                    "target_stdio_remap",
                )
            })?;
        // SAFETY: the fixed source slot was populated from an authenticated
        // descriptor and the target is one of the standard descriptors.
        if unsafe { libc::dup3(source, target, 0) } < 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "target_stdio_remap",
            ));
        }
    }
    Ok(())
}

fn close_raw_descriptors(descriptors: &[(RawFd, RawFd, bool)]) {
    for (source, _, _) in descriptors {
        // SAFETY: each temporary descriptor is uniquely owned by this vector.
        unsafe { libc::close(*source) };
    }
}


fn close_range(first: u32, last: u32) -> Result<(), BootstrapFault> {
    if first > last {
        return Ok(());
    }
    // SAFETY: close_range receives only integer bounds and zero flags.
    let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) };
    if result != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::UnsupportedKernel,
            "close_range",
        ));
    }
    Ok(())
}

fn reset_signal_state() -> Result<(), BootstrapFault> {
    // SAFETY: sigset_t is an all-integer C structure valid when zeroed before
    // sigemptyset initializes it.
    let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: set is a live output object and the old mask is not requested.
    if unsafe { libc::sigemptyset(&mut set) } != 0
        || unsafe { libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) } != 0
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "signal_mask",
        ));
    }
    Ok(())
}

fn apply_resource_limits(plan: &CageInitPlan) -> Result<(), BootstrapFault> {
    if plan.resource_limits.nofile_soft > u64::from(plan.target_fd_slot)
        || plan.resource_limits.nofile_hard < plan.resource_limits.nofile_soft
        || plan.resource_limits.nofile_hard > u64::from(plan.target_fd_slot)
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "nofile_limit",
        ));
    }
    let limit = libc::rlimit {
        rlim_cur: plan.resource_limits.nofile_soft,
        rlim_max: plan.resource_limits.nofile_hard,
    };
    // SAFETY: limit is fully initialized and RLIMIT_NOFILE accepts this shape.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::UnsupportedKernel,
            "nofile_apply",
        ));
    }
    Ok(())
}

fn observe_execution_identity() -> Result<ExecutionIdentity, BootstrapFault> {
    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    let mut real_gid = 0;
    let mut effective_gid = 0;
    let mut saved_gid = 0;
    // SAFETY: all pointers name live uid_t or gid_t outputs.
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_observe",
        ));
    }
    if real_uid != effective_uid
        || real_uid != saved_uid
        || real_gid != effective_gid
        || real_gid != saved_gid
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_saved_ids",
        ));
    }

    // SAFETY: a zero count queries the required group count without writing.
    let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let group_count = usize::try_from(group_count).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_groups_count",
        )
    })?;
    if group_count > MAX_SUPPLEMENTARY_GIDS {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_groups_count",
        ));
    }
    let group_count_i32 = i32::try_from(group_count).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_groups_count",
        )
    })?;
    let mut supplementary_gids = vec![0; group_count];
    if group_count > 0 {
        // SAFETY: the vector contains group_count writable gid_t elements.
        let observed = unsafe { libc::getgroups(group_count_i32, supplementary_gids.as_mut_ptr()) };
        if observed != group_count_i32 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
                "execution_identity_groups",
            ));
        }
    }
    supplementary_gids.sort_unstable();
    ExecutionIdentity::new(real_uid, real_gid, supplementary_gids).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_observed",
        )
    })
}

fn apply_execution_identity(
    expected: &ExecutionIdentity,
) -> Result<ExecutionIdentity, BootstrapFault> {
    expected.validate().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityInvalid,
            "execution_identity",
        )
    })?;

    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    // SAFETY: all pointers name live uid_t outputs.
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_observe",
        ));
    }
    if effective_uid != 0 {
        let observed = observe_execution_identity()?;
        if observed != *expected {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityMismatch,
                "execution_identity_unprivileged",
            ));
        }
    }

    // SAFETY: both prctl operations only clear privilege-retention state.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
            "execution_identity_capabilities",
        ));
    }

    if effective_uid == 0 {
        let groups = expected.supplementary_gids();
        let groups_pointer = if groups.is_empty() {
            std::ptr::null()
        } else {
            groups.as_ptr()
        };
        // SAFETY: the pointer is null for an empty slice or names the complete
        // immutable gid_t slice bound by the validated execution identity.
        if unsafe { libc::setgroups(groups.len(), groups_pointer) } != 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
                "execution_identity_setgroups",
            ));
        }
        // SAFETY: validated gid values are written to every process gid slot.
        if unsafe { libc::setresgid(expected.gid(), expected.gid(), expected.gid()) } != 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
                "execution_identity_setresgid",
            ));
        }
        // SAFETY: validated uid values are written to every process uid slot.
        if unsafe { libc::setresuid(expected.uid(), expected.uid(), expected.uid()) } != 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::ExecutionIdentityApplyFailed,
                "execution_identity_setresuid",
            ));
        }
    }

    let observed = observe_execution_identity()?;
    if observed != *expected {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_verify",
        ));
    }
    Ok(observed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LandlockEnforcement {
    abi: u32,
    filesystem: ObservedRulesetStatus,
    network: ObservedRulesetStatus,
}

fn apply_landlock(plan: &CageInitPlan) -> Result<LandlockEnforcement, BootstrapFault> {
    if nono_chio::UPSTREAM_NONO_VERSION != PINNED_NONO_VERSION
        || nono_chio::CHIO_PATCH_VERSION != NONO_PATCH_VERSION
        || nono_chio::MINIMUM_LANDLOCK_ABI != MINIMUM_LANDLOCK_ABI
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::LandlockUnavailable,
            "landlock_dependency_version",
        ));
    }

    let mut capabilities = nono_chio::CapabilitySet::new();
    for grant in &plan.landlock.grants {
        let entry = plan
            .fd_table
            .iter()
            .find(|entry| entry.slot == grant.fd_slot)
            .ok_or_else(|| {
                BootstrapFault::new(
                    CageEnforcementFailureCode::DescriptorIdentityMismatch,
                    "landlock_grant",
                )
            })?;
        if entry.identity != grant.identity {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "landlock_grant_identity",
            ));
        }
        let access = match grant.access {
            FilesystemGrantAccess::Read => nono_chio::PathAccess::Read,
            FilesystemGrantAccess::ReadDirectory => nono_chio::PathAccess::ReadDirectory,
            FilesystemGrantAccess::WriteExactFile => nono_chio::PathAccess::WriteExactFile,
            FilesystemGrantAccess::ExecuteRead => nono_chio::PathAccess::ExecuteRead,
        };
        let is_directory = entry.identity.kind() == crate::ResourceKind::Directory;
        // SAFETY: each slot is populated from the authenticated descriptor
        // table and remains open until target exec. BorrowedFd cannot outlive
        // this capability set or the child bootstrap frame.
        let descriptor = unsafe { BorrowedFd::borrow_raw(grant.fd_slot as RawFd) };
        capabilities.add_path_fd(descriptor, access, is_directory);
    }

    let status = capabilities.enforce().map_err(|error| match error {
        nono_chio::Error::AbiProbe(_) | nono_chio::Error::UnsupportedAbi { .. } => {
            BootstrapFault::new(
                CageEnforcementFailureCode::LandlockUnavailable,
                "landlock_abi",
            )
        }
        _ => BootstrapFault::new(
            CageEnforcementFailureCode::LandlockPartial,
            "landlock_enforcement",
        ),
    })?;
    Ok(LandlockEnforcement {
        abi: status.abi,
        filesystem: map_ruleset_status(status.filesystem),
        network: map_ruleset_status(status.network),
    })
}

const fn map_ruleset_status(status: nono_chio::RulesetStatus) -> ObservedRulesetStatus {
    match status {
        nono_chio::RulesetStatus::FullyEnforced => ObservedRulesetStatus::FullyEnforced,
        nono_chio::RulesetStatus::PartiallyEnforced => ObservedRulesetStatus::PartiallyEnforced,
        nono_chio::RulesetStatus::NotEnforced => ObservedRulesetStatus::NotEnforced,
    }
}

fn compile_seccomp_filter(
    plan: &crate::SeccompProfilePlan,
) -> Result<seccompiler::BpfProgram, CageLaunchError> {
    let current = SandboxArchitecture::current().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::SeccompArchitectureMismatch,
            "seccomp_architecture",
        )
    })?;
    if current != plan.architecture {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::SeccompArchitectureMismatch,
            "seccomp_architecture",
        ));
    }
    if !seccomp_profile_is_fail_closed(plan) {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_fail_closed",
        ));
    }
    let target_arch = match current {
        SandboxArchitecture::X86_64 => seccompiler::TargetArch::x86_64,
        SandboxArchitecture::Aarch64 => seccompiler::TargetArch::aarch64,
    };
    let mut rules = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for name in &plan.allowed_syscalls {
        if !seen.insert(name.as_str()) {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::SeccompInstallFailed,
                "seccomp_duplicate",
            ));
        }
        let number = i64::from(syscall_number(current, name).ok_or_else(|| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::SeccompArchitectureMismatch,
                "seccomp_syscall",
            )
        })?);
        let constraints = plan
            .argument_constraints
            .get(name)
            .map_or(&[][..], Vec::as_slice);
        let rule_chain = compile_seccomp_rule(constraints)?;
        if rules.insert(number, rule_chain).is_some() {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::SeccompInstallFailed,
                "seccomp_duplicate_number",
            ));
        }
    }
    if plan
        .argument_constraints
        .keys()
        .any(|name| !seen.contains(name.as_str()))
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_constraint",
        ));
    }
    let filter = seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::KillProcess,
        seccompiler::SeccompAction::Allow,
        target_arch,
    )
    .map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_filter",
        )
    })?;
    filter.try_into().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_compile",
        )
    })
}


fn compile_seccomp_rule(
    constraints: &[SyscallArgumentConstraint],
) -> Result<Vec<seccompiler::SeccompRule>, CageLaunchError> {
    if constraints.is_empty() {
        return Ok(Vec::new());
    }
    let mut conditions = Vec::with_capacity(constraints.len());
    let mut seen = BTreeSet::new();
    for constraint in constraints {
        if constraint.argument_index > 5
            || constraint.comparison != SeccompArgumentComparison::Equal
            || !seen.insert(constraint.argument_index)
        {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::SeccompInstallFailed,
                "seccomp_argument",
            ));
        }
        conditions.push(
            seccompiler::SeccompCondition::new(
                constraint.argument_index,
                seccompiler::SeccompCmpArgLen::Qword,
                seccompiler::SeccompCmpOp::Eq,
                constraint.value,
            )
            .map_err(|_| {
                CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::SeccompInstallFailed,
                    "seccomp_condition",
                )
            })?,
        );
    }
    let rule = seccompiler::SeccompRule::new(conditions).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_rule",
        )
    })?;
    Ok(vec![rule])
}

fn filter_digest(filter: &seccompiler::BpfProgram) -> Result<String, CageLaunchError> {
    let instructions = filter
        .iter()
        .map(FilterInstruction::from_seccompiler)
        .collect::<Vec<_>>();
    let bytes = chio_core::canonical_json_bytes(&instructions).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_filter_digest",
        )
    })?;
    Ok(chio_core::sha256_hex(&bytes))
}

fn install_seccomp(filter: &seccompiler::BpfProgram) -> Result<(), BootstrapFault> {
    seccompiler::apply_filter(filter).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::SeccompInstallFailed,
            "seccomp_install",
        )
    })
}
