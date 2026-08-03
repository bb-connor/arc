fn run_stdio_writer(mut writer: Box<dyn Write + Send>, writer_rx: mpsc::Receiver<WriterCommand>) {
    while let Ok(command) = writer_rx.recv() {
        let result = writer
            .write_all(&command.bytes)
            .and_then(|()| writer.flush())
            .map_err(|error| error.to_string());
        let failed = result.is_err();
        if let Some(completion) = command.completion {
            let _ = completion.try_send(result);
        } else if let Err(error) = result {
            warn!(
                target: "chio_mcp_adapter::transport",
                "asynchronous MCP stdin write failed: {error}"
            );
        }
        if failed {
            break;
        }
    }
}

fn merge_cleanup_failures<const N: usize>(
    primary: AdapterError,
    cleanup: [(&str, Result<(), AdapterError>); N],
) -> AdapterError {
    let failures = cleanup
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error}")))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        primary
    } else {
        AdapterError::ConnectionFailed(format!(
            "{primary}; cleanup also failed: {}",
            failures.join("; ")
        ))
    }
}

fn fail_caged_child(
    primary: AdapterError,
    child: chio_cage::EnforcedChild,
    cage_receipts: &ActiveCageReceiptPersistence,
    failure: Option<(
        chio_cage::CageEnforcementState,
        chio_cage::CageEnforcementFailureCode,
        &'static str,
    )>,
) -> AdapterError {
    let failure_receipt = failure.map_or(Ok(()), |(state, code, stage)| {
        cage_receipts.persist_failure(state, code, stage)
    });
    let terminal_receipt = persist_pre_fully_enforced_terminal(child, cage_receipts);
    merge_cleanup_failures(
        primary,
        [
            ("failure receipt", failure_receipt),
            ("terminal receipt", terminal_receipt),
        ],
    )
}

fn poll_natural_child_exit(
    lifecycle_mutex: &Mutex<ChildLifecycle>,
    cage_receipts: Option<&ActiveCageReceiptPersistence>,
) -> NaturalExitPoll {
    let mut lifecycle = match lifecycle_mutex.lock() {
        Ok(lifecycle) => lifecycle,
        Err(error) => {
            return NaturalExitPoll::Failed(AdapterError::ConnectionFailed(format!(
                "child lifecycle lock poisoned: {error}"
            )))
        }
    };
    if !matches!(&lifecycle.terminal, ChildTerminalState::Running) {
        return NaturalExitPoll::Stopped;
    }
    let observation = match lifecycle.child.as_mut() {
        Some(ManagedChild::Legacy(child)) => match child.try_wait() {
            Ok(Some(_)) => Ok(Some(NaturalChildExit::Legacy)),
            Ok(None) => Ok(None),
            Err(error) => Err(AdapterError::ConnectionFailed(format!(
                "failed to poll MCP child status: {error}"
            ))),
        },
        Some(ManagedChild::Caged(child)) => match child.try_wait() {
            Ok(Some(record)) => Ok(Some(NaturalChildExit::Caged(Box::new(record)))),
            Ok(None) => Ok(None),
            Err(error) => Err(AdapterError::ConnectionFailed(format!(
                "failed to poll fully enforced MCP child status: {error}"
            ))),
        },
        None => Err(AdapterError::ConnectionFailed(
            "running MCP child lifecycle lost its retained process handle".to_string(),
        )),
    };
    let observation = match observation {
        Ok(observation) => observation,
        Err(error) => {
            drop(lifecycle);
            let terminal = finish_child_lifecycle(lifecycle_mutex, cage_receipts);
            return NaturalExitPoll::Failed(merge_cleanup_failures(
                error,
                [("terminal receipt", terminal)],
            ));
        }
    };
    match observation {
        None => NaturalExitPoll::Running,
        Some(NaturalChildExit::Legacy) => {
            lifecycle.child.take();
            lifecycle.terminal = ChildTerminalState::Exited;
            NaturalExitPoll::Exited
        }
        Some(NaturalChildExit::Caged(record)) => {
            lifecycle.child.take();
            let persistence = if record.state != chio_cage::CageEnforcementState::Exited {
                Err(AdapterError::ConnectionFailed(
                    "fully enforced child poll produced a non-exit record".to_string(),
                ))
            } else {
                cage_receipts
                    .ok_or_else(|| {
                        AdapterError::ConnectionFailed(
                            "caged child lost its mandatory receipt persistence context"
                                .to_string(),
                        )
                    })
                    .and_then(|cage_receipts| cage_receipts.persist(*record))
            };
            match persistence {
                Ok(()) => {
                    lifecycle.terminal = ChildTerminalState::Exited;
                    NaturalExitPoll::Exited
                }
                Err(error) => {
                    lifecycle.terminal = ChildTerminalState::Failed(error.to_string());
                    NaturalExitPoll::Failed(error)
                }
            }
        }
    }
}

fn notify_active_request_after_terminal(
    active_request: &Mutex<Option<ActiveRequest>>,
    shutdown_requested: bool,
    terminal_failure: Option<String>,
) {
    let Ok(mut active_request) = active_request.lock() else {
        return;
    };
    let Some(active_request) = active_request.take() else {
        return;
    };
    let message = match terminal_failure {
        Some(error) => RequestMessage::ReadError(error),
        None if shutdown_requested => {
            RequestMessage::Cancelled("upstream MCP request cancelled by shutdown".to_string())
        }
        None => RequestMessage::ReadError("upstream MCP process exited".to_string()),
    };
    let _ = active_request.sender.try_send(message);
}

fn finish_child_lifecycle(
    lifecycle: &Mutex<ChildLifecycle>,
    cage_receipts: Option<&ActiveCageReceiptPersistence>,
) -> Result<(), AdapterError> {
    let mut lifecycle = lifecycle.lock().map_err(|error| {
        AdapterError::ConnectionFailed(format!("child lifecycle lock poisoned: {error}"))
    })?;
    match &lifecycle.terminal {
        ChildTerminalState::Exited => return Ok(()),
        ChildTerminalState::Failed(error) => {
            return Err(AdapterError::ConnectionFailed(format!(
                "prior MCP terminal shutdown failed: {error}"
            )))
        }
        ChildTerminalState::Running => {}
    }
    let Some(child) = lifecycle.child.take() else {
        let error = "running MCP child lifecycle lost its retained process handle".to_string();
        lifecycle.terminal = ChildTerminalState::Failed(error.clone());
        return Err(AdapterError::ConnectionFailed(error));
    };
    match terminate_child(child, cage_receipts) {
        Ok(()) => {
            lifecycle.terminal = ChildTerminalState::Exited;
            Ok(())
        }
        Err(error) => {
            lifecycle.terminal = ChildTerminalState::Failed(error.to_string());
            Err(error)
        }
    }
}

fn terminate_child(
    child: ManagedChild,
    cage_receipts: Option<&ActiveCageReceiptPersistence>,
) -> Result<(), AdapterError> {
    match child {
        ManagedChild::Legacy(child) => terminate_legacy_child(child),
        ManagedChild::Caged(child) => {
            let cage_receipts = cage_receipts.ok_or_else(|| {
                AdapterError::ConnectionFailed(
                    "caged child lost its mandatory receipt persistence context".to_string(),
                )
            })?;
            persist_fully_enforced_terminal(*child, cage_receipts)
        }
    }
}

fn terminate_legacy_child(mut child: Child) -> Result<(), AdapterError> {
    let kill_error = child.kill().err().map(|error| error.to_string());
    let deadline = Instant::now() + LEGACY_CHILD_REAP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(error) => {
                let reaper = detach_legacy_child_reaper(child);
                return Err(merge_cleanup_failures(
                    AdapterError::ConnectionFailed(format!(
                        "failed to poll legacy MCP child after termination: {error}"
                    )),
                    [("detached child reaper", reaper)],
                ));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let kill_context = kill_error
                .as_deref()
                .map(|error| format!("; initial kill failed: {error}"))
                .unwrap_or_default();
            let reaper = detach_legacy_child_reaper(child);
            return Err(merge_cleanup_failures(
                AdapterError::ConnectionFailed(format!(
                    "legacy MCP child did not reap within {LEGACY_CHILD_REAP_TIMEOUT:?}{kill_context}"
                )),
                [("detached child reaper", reaper)],
            ));
        }
        std::thread::sleep(std::cmp::min(UPSTREAM_REQUEST_POLL_INTERVAL, remaining));
    }
}

fn detach_legacy_child_reaper(mut child: Child) -> Result<(), AdapterError> {
    std::thread::Builder::new()
        .name("chio-mcp-legacy-reaper".to_string())
        .spawn(move || {
            let _ = child.wait();
        })
        .map(|_| ())
        .map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "failed to spawn legacy MCP child reaper: {error}"
            ))
        })
}

fn persist_fully_enforced_terminal(
    child: chio_cage::EnforcedChild,
    cage_receipts: &ActiveCageReceiptPersistence,
) -> Result<(), AdapterError> {
    let record = child.terminate().map_err(|_| {
        AdapterError::ConnectionFailed(
            "fully enforced caged child termination did not produce verified exit evidence"
                .to_string(),
        )
    })?;
    if record.state != chio_cage::CageEnforcementState::Exited {
        return Err(AdapterError::ConnectionFailed(
            "fully enforced caged child termination produced a non-exit record".to_string(),
        ));
    }
    cage_receipts.persist(record)
}

fn persist_pre_fully_enforced_terminal(
    child: chio_cage::EnforcedChild,
    cage_receipts: &ActiveCageReceiptPersistence,
) -> Result<(), AdapterError> {
    match child.terminate() {
        Ok(record) => cage_receipts.persist(record),
        Err(_) => Err(AdapterError::ConnectionFailed(
            "caged child termination did not produce verified exit evidence".to_string(),
        )),
    }
}

fn now_unix_ms() -> Result<u64, AdapterError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        AdapterError::ConnectionFailed("system clock is before the Unix epoch".to_string())
    })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| {
        AdapterError::ConnectionFailed("system clock does not fit cage receipt time".to_string())
    })
}

fn validate_cage_required_inputs(
    command: &str,
    args: &[&str],
    manifest_registry: &chio_manifest::VerifiedManifestRegistry,
    server_id: &str,
    compiled: &chio_cage::CompiledCage,
) -> Result<ExpectedCageEvidence, AdapterError> {
    let authorization = validate_cage_registry_binding(manifest_registry, server_id, compiled)?;
    let manifest_digest = authorization.manifest_digest().to_string();

    let target_path = compiled.runtime().target().resource().path();
    if !std::path::Path::new(command).is_absolute() || std::path::Path::new(command) != target_path
    {
        return Err(AdapterError::ConnectionFailed(
            "cage-required command does not match the retained target executable".into(),
        ));
    }
    let expected_argv = std::iter::once(command.to_string())
        .chain(args.iter().map(|argument| (*argument).to_string()))
        .collect::<Vec<_>>();
    if compiled.runtime().target_argv() != expected_argv
        || compiled.plan().target_argv != expected_argv
    {
        return Err(AdapterError::ConnectionFailed(
            "cage-required argv does not match the compiled launch plan".into(),
        ));
    }

    if compiled.admitted().native_syscall_profile()
        == chio_manifest::NativeSyscallProfile::BrokeredNativeV1
        && (compiled.broker_ipc().is_none()
            || !compiled.admitted().read_resources().is_empty()
            || !compiled.admitted().write_resources().is_empty()
            || !compiled.admitted().environment_variables().is_empty()
            || !compiled.plan().environment.is_empty())
    {
        return Err(AdapterError::ConnectionFailed(
            "brokered cage launch requires only authenticated preconnected broker IPC and no raw file or environment grants".into(),
        ));
    }

    Ok(ExpectedCageEvidence {
        manifest_digest,
        helper_binding_digest: compiled.runtime().helper().binding_digest().to_string(),
        target_binding_digest: compiled.runtime().target().binding_digest().to_string(),
        target_identity: compiled.runtime().target().resource().identity(),
    })
}

fn validate_cage_registry_binding<'a>(
    manifest_registry: &'a chio_manifest::VerifiedManifestRegistry,
    server_id: &str,
    compiled: &chio_cage::CompiledCage,
) -> Result<chio_manifest::VerifiedCageManifest<'a>, AdapterError> {
    let authorization = manifest_registry
        .authorize_cage_manifest(server_id)
        .map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "cage-required registry authorization failed: {error}"
            ))
        })?;
    let manifest_digest = authorization.manifest_digest();
    let authorization_digest = authorization.authorization_digest();
    if compiled.admitted().manifest_digest() != manifest_digest
        || compiled.plan().manifest_digest != manifest_digest
        || compiled.profile().manifest_digest != manifest_digest
        || compiled.admitted().signed_manifest_digest() != authorization.signed_manifest_digest()
        || compiled.admitted().registry_digest() != authorization.registry_digest()
        || compiled.admitted().cage_authorization_digest() != authorization_digest
        || compiled.profile().cage_authorization_digest != authorization_digest
    {
        return Err(AdapterError::ConnectionFailed(
            "cage-required compiled admission does not match the live registry authorization"
                .into(),
        ));
    }
    Ok(authorization)
}

fn validate_cage_evidence(
    evidence: &chio_cage::FullyEnforcedEvidence,
    expected: &ExpectedCageEvidence,
) -> Result<(), AdapterError> {
    evidence.validate().map_err(|_| {
        AdapterError::ConnectionFailed("cage-required enforcement evidence is invalid".into())
    })?;
    if !evidence.status_eof_observed
        || evidence.prepared.manifest_digest != expected.manifest_digest
        || evidence.prepared.helper_binding_digest != expected.helper_binding_digest
        || evidence.prepared.target_binding_digest != expected.target_binding_digest
        || evidence.prepared.target_identity != expected.target_identity
        || evidence.exec_transition.target_binding_digest != expected.target_binding_digest
        || evidence.exec_transition.target_identity != expected.target_identity
    {
        return Err(AdapterError::ConnectionFailed(
            "cage-required enforcement evidence does not match the admitted launch".into(),
        ));
    }
    Ok(())
}

fn validate_signed_mcp_tool_surface(
    transport: &StdioMcpTransport,
    admitted_manifest: &chio_manifest::ToolManifest,
) -> Result<(), AdapterError> {
    let tools = transport
        .list_tools()?
        .into_iter()
        .map(crate::manifest::tool_definition_from_mcp)
        .collect::<Result<Vec<_>, _>>()?;
    let mut discovered = admitted_manifest.clone();
    discovered.tools = tools;
    crate::verify_discovered_manifest_surface(&discovered, admitted_manifest)
}

#[cfg(test)]
mod cage_launch_tests {
    use std::cell::Cell;

    use chio_test_support::prelude::*;

    use super::*;

    struct TestMigrationStore {
        state: chio_security_types::EnterpriseMigrationState,
    }

    impl chio_security_types::EnterpriseMigrationStateStore for TestMigrationStore {
        fn register(
            &self,
            _transition: &chio_security_types::EnterpriseMigrationTransition,
        ) -> chio_security_types::ports::PortResult<
            chio_security_types::EnterpriseMigrationRegisterOutcome,
        > {
            Ok(
                chio_security_types::EnterpriseMigrationRegisterOutcome::Existing(
                    self.state.clone(),
                ),
            )
        }

        fn load(
            &self,
            key: &chio_security_types::EnterpriseMigrationKey,
        ) -> chio_security_types::ports::PortResult<
            Option<chio_security_types::EnterpriseMigrationState>,
        > {
            Ok((key == &self.state.key).then(|| self.state.clone()))
        }

        fn compare_and_promote(
            &self,
            _transition: &chio_security_types::EnterpriseMigrationTransition,
        ) -> chio_security_types::ports::PortResult<
            chio_security_types::EnterpriseMigrationCasOutcome,
        > {
            Ok(chio_security_types::EnterpriseMigrationCasOutcome::Conflict(self.state.clone()))
        }
    }

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn identity() -> chio_cage::FileIdentity {
        serde_json::from_value(serde_json::json!({
            "device": 1,
            "inode": 2,
            "mount_id": 3,
            "mode": 0o100700,
            "uid": 1000,
            "gid": 1000,
            "kind": "regular_file"
        }))
        .test_expect("valid identity")
    }

    fn evidence() -> chio_cage::FullyEnforcedEvidence {
        let prepared = chio_cage::EnforcementPrepared {
            schema: chio_cage::ENFORCEMENT_PREPARED_SCHEMA.to_string(),
            process_id: 42,
            manifest_digest: digest('1'),
            profile_digest: digest('2'),
            plan_digest: digest('3'),
            fd_table_digest: digest('4'),
            helper_binding_digest: digest('5'),
            target_binding_digest: digest('6'),
            target_identity: identity(),
            applied_execution_identity: chio_cage::ExecutionIdentity::new(
                10_001,
                10_001,
                vec![10_002],
            )
            .test_expect("valid execution identity"),
            nono_version: chio_cage::PINNED_NONO_VERSION.to_string(),
            nono_patch_version: chio_cage::NONO_PATCH_VERSION.to_string(),
            landlock_abi: 6,
            landlock_filesystem_status: chio_cage::ObservedRulesetStatus::FullyEnforced,
            landlock_network_status: chio_cage::ObservedRulesetStatus::FullyEnforced,
            seccompiler_version: chio_cage::PINNED_SECCOMPILER_VERSION.to_string(),
            seccomp_status: chio_cage::SeccompEnforcementStatus::FullyEnforced,
            seccomp_architecture: chio_cage::SandboxArchitecture::X86_64,
            seccomp_filter_digest: digest('7'),
            trace_session_digest: digest('8'),
            prepared_at_unix_ms: 1_000,
        };
        let transition = chio_cage::ExecTransitionObserved {
            schema: chio_cage::EXEC_TRANSITION_OBSERVED_SCHEMA.to_string(),
            process_id: 42,
            trace_session_digest: digest('8'),
            target_binding_digest: digest('6'),
            target_identity: identity(),
            observed_at_unix_ms: 1_001,
        };
        chio_cage::FullyEnforcedEvidence::new(prepared, transition, true)
            .test_expect("valid evidence")
    }

    fn legacy_authorization(
        flow: Option<chio_manifest::ToolFlowDeclaration>,
    ) -> LegacyNativeLaunchAuthorization {
        let server_id = "flow-cage";
        let key = chio_security_types::EnterpriseMigrationKey {
            deployment_id: chio_security_types::ports::RecordId::new("test-deployment")
                .test_expect("deployment id"),
            scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
            scope_id: chio_security_types::ports::RecordId::new(server_id).test_expect("server id"),
            control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
        };
        let posture = chio_security_types::ports::Digest32::new([0x11; 32]);
        let state = chio_security_types::EnterpriseMigrationState {
            schema_version: chio_security_types::ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION,
            key: key.clone(),
            stage: chio_security_types::EnterpriseMigrationStage::Shadow,
            generation: 1,
            transition_digest: chio_security_types::ports::Digest32::new([0x12; 32]),
            prior_head_digest: Some(chio_security_types::ports::Digest32::new([0x13; 32])),
            posture_digest: posture,
            evidence_digest: chio_security_types::ports::Digest32::new([0x14; 32]),
            authorization_digest: chio_security_types::ports::Digest32::new([0x15; 32]),
            intent_digest: chio_security_types::ports::Digest32::new([0x16; 32]),
            updated_at_unix_ms: 1,
            signer_public_key: "test-signer".to_string(),
        };
        let store: Arc<dyn chio_security_types::EnterpriseMigrationStateStore> =
            Arc::new(TestMigrationStore { state });
        let migration = chio_security_types::EnterpriseMigrationRuntimeBinding::load(
            &store,
            &key,
            chio_security_types::EnterpriseMigrationStage::Shadow,
            posture,
        )
        .test_expect("load migration binding");

        let signer = chio_core::Keypair::from_seed(&[73; 32]);
        let manifest = chio_manifest::ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: server_id.to_string(),
            name: "Flow cage".to_string(),
            description: None,
            version: "1".to_string(),
            tools: vec![chio_manifest::ToolDefinition {
                name: "send".to_string(),
                description: "Send".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: false,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: Some(chio_manifest::LatencyHint::Moderate),
                flow,
            }],
            server_tools: Vec::new(),
            required_permissions: Some(chio_manifest::RequiredPermissions {
                read_paths: None,
                write_paths: None,
                network_destinations: None,
                environment_variables: None,
                native_syscall_profile: chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            }),
            public_key: signer.public_key().to_hex(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &signer)
            .test_expect("sign manifest authorization");
        let mut registry = chio_manifest::VerifiedManifestRegistry::default();
        registry
            .register_public_only(
                signed,
                &signer.public_key(),
                chio_manifest::RuntimeToolTopology::local(),
            )
            .test_expect("register manifest authorization");
        LegacyNativeLaunchAuthorization::new(server_id, migration, Arc::new(registry))
            .test_expect("construct legacy launch authorization")
    }

    #[test]
    fn legacy_launch_retains_verified_flow_runtime_requirement() {
        let authorization =
            legacy_authorization(Some(chio_manifest::ToolFlowDeclaration::public_egress()));
        assert!(authorization.requires_flow_runtime());
        assert!(
            NativeMcpLaunch::LegacyAuthorized(Box::new(authorization)).requires_flow_runtime()
        );
        assert!(!legacy_authorization(None).requires_flow_runtime());
    }

    #[test]
    fn legacy_launch_rejects_discovered_tool_surface_drift() {
        let script = r#"
import json
import sys

def respond(value):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "drifted", "version": "1"}
            }
        })
    elif method == "tools/list":
        respond({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "tools": [{
                    "name": "unexpected",
                    "description": "Unexpected",
                    "inputSchema": {"type": "object"}
                }]
            }
        })
"#;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_expect("legacy surface test clock")
            .as_nanos();
        let script_path = std::env::temp_dir().join(format!(
            "chio-mcp-adapter-drifted-{}-{stamp}.py",
            std::process::id()
        ));
        std::fs::write(&script_path, script).test_expect("write legacy surface test server");
        let script_argument = script_path
            .to_str()
            .test_expect("legacy surface test path is UTF-8");

        let result = StdioMcpTransport::spawn(
            "python3",
            &[script_argument],
            NativeMcpLaunch::LegacyAuthorized(Box::new(legacy_authorization(None))),
        );
        let _ = std::fs::remove_file(script_path);
        let error = match result {
            Ok(transport) => {
                let _ = transport.shutdown();
                panic!("legacy launch accepted a tool surface outside its signed manifest")
            }
            Err(error) => error,
        };

        assert!(
            matches!(error, AdapterError::ManifestSurfaceMismatch(_)),
            "{error}"
        );
    }

    #[test]
    fn cage_launch_contract_requires_registry_authorized_local_topology() {
        let keypair = chio_core::Keypair::from_seed(&[73; 32]);
        let manifest = chio_manifest::ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "flow-cage".to_string(),
            name: "Flow cage".to_string(),
            description: None,
            version: "1".to_string(),
            tools: vec![chio_manifest::ToolDefinition {
                name: "send".to_string(),
                description: "Send".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: false,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: Some(chio_manifest::LatencyHint::Moderate),
                flow: Some(chio_manifest::ToolFlowDeclaration::public_egress()),
            }],
            server_tools: Vec::new(),
            required_permissions: Some(chio_manifest::RequiredPermissions {
                read_paths: None,
                write_paths: None,
                network_destinations: None,
                environment_variables: None,
                native_syscall_profile: chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            }),
            public_key: keypair.public_key().to_hex(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &keypair).test_expect("sign manifest");

        let mut remote_registry = chio_manifest::VerifiedManifestRegistry::default();
        remote_registry
            .register_public_only(
                signed.clone(),
                &keypair.public_key(),
                chio_manifest::RuntimeToolTopology::remote(),
            )
            .test_expect("register remote manifest");
        assert!(remote_registry
            .authorize_cage_manifest("flow-cage")
            .is_err());

        let mut local_registry = chio_manifest::VerifiedManifestRegistry::default();
        local_registry
            .register_public_only(
                signed,
                &keypair.public_key(),
                chio_manifest::RuntimeToolTopology::local(),
            )
            .test_expect("register local manifest");
        assert!(local_registry.authorize_cage_manifest("flow-cage").is_ok());
    }

    #[test]
    fn cage_required_success_uses_only_the_cage_backend() {
        let legacy_calls = Cell::new(0);
        let cage_calls = Cell::new(0);
        let result = dispatch_native_launch(
            NativeLaunchRequirement::CageRequired,
            || {
                legacy_calls.set(legacy_calls.get() + 1);
                Ok::<_, &'static str>(1)
            },
            || {
                cage_calls.set(cage_calls.get() + 1);
                Ok::<_, &'static str>(7)
            },
        );
        assert_eq!(result, Ok(7));
        assert_eq!(legacy_calls.get(), 0);
        assert_eq!(cage_calls.get(), 1);
    }

    #[test]
    fn unsupported_or_failed_cage_has_no_direct_spawn_fallback() {
        let legacy_calls = Cell::new(0);
        let cage_calls = Cell::new(0);
        let result = dispatch_native_launch(
            NativeLaunchRequirement::CageRequired,
            || {
                legacy_calls.set(legacy_calls.get() + 1);
                Ok::<_, &'static str>(1)
            },
            || {
                cage_calls.set(cage_calls.get() + 1);
                Err::<u8, _>("unsupported")
            },
        );
        assert_eq!(result, Err("unsupported"));
        assert_eq!(legacy_calls.get(), 0);
        assert_eq!(cage_calls.get(), 1);
    }

    #[test]
    fn legacy_non_required_launch_never_calls_the_cage_backend() {
        let cage_calls = Cell::new(0);
        let result = dispatch_native_launch(
            NativeLaunchRequirement::LegacyAllowed,
            || Ok::<_, &'static str>(3),
            || {
                cage_calls.set(cage_calls.get() + 1);
                Ok::<_, &'static str>(9)
            },
        );
        assert_eq!(result, Ok(3));
        assert_eq!(cage_calls.get(), 0);
    }

    #[test]
    fn helper_or_target_evidence_mismatch_is_rejected() {
        let expected = ExpectedCageEvidence {
            manifest_digest: digest('1'),
            helper_binding_digest: digest('5'),
            target_binding_digest: digest('9'),
            target_identity: identity(),
        };
        let error = validate_cage_evidence(&evidence(), &expected).test_expect_err("mismatch");
        assert!(error.to_string().contains("does not match"));
    }

    fn write_stdio_server_script(name: &str, script: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_expect("stdio lifecycle test clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "chio-mcp-adapter-{name}-{}-{stamp}.py",
            std::process::id()
        ));
        std::fs::write(&path, script).test_expect("write stdio lifecycle test server");
        path
    }

    fn short_request_timeouts() -> StdioRequestTimeouts {
        StdioRequestTimeouts {
            initialization: Duration::from_secs(1),
            discovery: Duration::from_millis(200),
            request: Duration::from_millis(200),
        }
    }

    #[test]
    fn initialization_has_a_bounded_deadline() {
        let script = r#"
import sys

for _line in sys.stdin:
    pass
"#;
        let script_path = write_stdio_server_script("initialize-timeout", script);
        let script_argument = script_path
            .to_str()
            .test_expect("initialize timeout script path is UTF-8");
        let started = Instant::now();
        let result = StdioMcpTransport::spawn_legacy_unchecked_for_test_with_timeouts(
            "python3",
            &[script_argument],
            short_request_timeouts(),
        );
        let elapsed = started.elapsed();
        let _ = std::fs::remove_file(script_path);
        let error = match result {
            Ok(transport) => {
                let _ = transport.shutdown();
                panic!("initialize without a response exceeded its deadline contract")
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("initialize request timed out"));
        assert!(elapsed < Duration::from_secs(3), "elapsed: {elapsed:?}");
    }

    #[test]
    fn discovery_and_tool_requests_use_distinct_bounded_deadlines() {
        let script = r#"
import json
import sys

def respond(value):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "timeout", "version": "1"}
            }
        })
"#;
        let script_path = write_stdio_server_script("discovery-timeout", script);
        let script_argument = script_path
            .to_str()
            .test_expect("discovery timeout script path is UTF-8");
        let transport = StdioMcpTransport::spawn_legacy_unchecked_for_test_with_timeouts(
            "python3",
            &[script_argument],
            short_request_timeouts(),
        )
        .test_expect("initialize timeout test transport");
        assert_eq!(
            transport.request_timeout_for("tools/list"),
            short_request_timeouts().discovery
        );
        assert_eq!(
            transport.request_timeout_for("tools/call"),
            short_request_timeouts().request
        );
        let error = transport
            .list_tools()
            .test_expect_err("tools/list without a response must time out");
        assert!(error.to_string().contains("tools/list request timed out"));
        transport.shutdown().test_expect("shutdown timeout server");
        let _ = std::fs::remove_file(script_path);
    }

    #[test]
    fn request_timeout_is_bounded_and_terminal() {
        let script = r#"
import json
import sys

def respond(value):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "timeout", "version": "1"}
            }
        })
"#;
        let script_path = write_stdio_server_script("request-cancel", script);
        let script_argument = script_path
            .to_str()
            .test_expect("request cancellation script path is UTF-8");
        let transport = StdioMcpTransport::spawn_legacy_unchecked_for_test_with_timeouts(
            "python3",
            &[script_argument],
            short_request_timeouts(),
        )
        .test_expect("initialize request cancellation test transport");
        let started = Instant::now();
        let error = transport
            .call_tool("hang", json!({}))
            .test_expect_err("tools/call without a response must time out");
        assert!(error.to_string().contains("tools/call request timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
        {
            let lifecycle = transport
                .child_lifecycle
                .lock()
                .test_expect("request timeout lifecycle lock");
            assert!(matches!(&lifecycle.terminal, ChildTerminalState::Exited));
        }
        transport
            .list_tools()
            .test_expect_err("timed-out transport must not accept another request");
        transport
            .shutdown()
            .test_expect("shutdown cancellation server");
        let _ = std::fs::remove_file(script_path);
    }

    #[test]
    fn shutdown_preempts_a_hung_stdio_request() {
        let script = r#"
import json
import pathlib
import sys

marker = pathlib.Path(sys.argv[1])

def respond(value):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "shutdown", "version": "1"}
            }
        })
    elif method == "tools/call":
        marker.write_text("entered")
"#;
        let script_path = write_stdio_server_script("shutdown-preempt", script);
        let marker_path = script_path.with_extension("entered");
        let script_argument = script_path
            .to_str()
            .test_expect("shutdown preemption script path is UTF-8");
        let marker_argument = marker_path
            .to_str()
            .test_expect("shutdown preemption marker path is UTF-8");
        let transport = Arc::new(
            StdioMcpTransport::spawn_legacy_unchecked_for_test_with_timeouts(
                "python3",
                &[script_argument, marker_argument],
                StdioRequestTimeouts {
                    initialization: Duration::from_secs(1),
                    discovery: Duration::from_secs(1),
                    request: Duration::from_secs(30),
                },
            )
            .test_expect("initialize shutdown preemption transport"),
        );
        let request_transport = transport.clone();
        let request_thread =
            std::thread::spawn(move || request_transport.call_tool("hang", json!({})));
        for _ in 0..200 {
            if marker_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(marker_path.exists(), "hung request did not reach the child");
        let started = Instant::now();
        transport
            .shutdown()
            .test_expect("shutdown hung stdio request");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown did not preempt the request"
        );
        let request_error = request_thread
            .join()
            .unwrap_or_else(|_| panic!("hung request thread panicked"))
            .test_expect_err("shutdown must cancel the hung request");
        assert!(
            request_error.to_string().contains("cancelled by shutdown")
                || request_error.to_string().contains("process exited"),
            "unexpected shutdown request error: {request_error}"
        );
        let _ = std::fs::remove_file(marker_path);
        let _ = std::fs::remove_file(script_path);
    }

    #[test]
    fn natural_child_exit_is_terminalized_once_before_request_error() {
        let script = r#"
import json
import subprocess
import sys

for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "exit", "version": "1"}
            }
        }) + "\n")
        sys.stdout.flush()
    elif request.get("method") == "tools/call":
        subprocess.Popen([
            sys.executable,
            "-c",
            "import time; time.sleep(1)"
        ])
        sys.exit(17)
"#;
        let script_path = write_stdio_server_script("natural-exit", script);
        let script_argument = script_path
            .to_str()
            .test_expect("natural exit script path is UTF-8");
        let transport = StdioMcpTransport::spawn_legacy_unchecked_for_test_with_timeouts(
            "python3",
            &[script_argument],
            short_request_timeouts(),
        )
        .test_expect("initialize natural exit test transport");
        let error = transport
            .call_tool("exit", json!({}))
            .test_expect_err("natural child exit must fail the request");
        assert!(
            error.to_string().contains("process exited")
                || error.to_string().contains("closed stdout"),
            "unexpected natural-exit error: {error}"
        );
        {
            let lifecycle = transport
                .child_lifecycle
                .lock()
                .test_expect("natural exit lifecycle lock");
            assert!(lifecycle.child.is_none());
            assert!(matches!(&lifecycle.terminal, ChildTerminalState::Exited));
        }
        transport
            .shutdown()
            .test_expect("first idempotent shutdown");
        transport
            .shutdown()
            .test_expect("second idempotent shutdown");
        let _ = std::fs::remove_file(script_path);
    }
}
