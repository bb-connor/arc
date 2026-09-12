// Reopen the original stores. No imported lifecycle is activated on recovery.
use super::*;
use chio_kernel::admission_operation::{AdmissionOperationV1, RetainedToolAdmissionRequestV1};
use chio_kernel::tool_outcome::ToolOutcomeStore;

fn retained(
    authority: &SqliteAuthorityStore,
    request: &ToolCallRequest,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &request.request_id)?,
            &authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or_else(|| "original operation is absent".into())
}

fn configure_original_selection(
    kernel: &mut ChioKernel,
    original: &RetainedToolAdmissionRequestV1,
    witness: &Witness,
) -> TestResult {
    let profile = original
        .authority_profile()
        .ok_or("original authority profile")?;
    if let Some(binding) = profile.runtime() {
        use chio_runtime_core::*;
        let source =
            SqliteRuntimeOrchestrationStore::open(witness.directory.join("native-runtime.db"))?;
        let now = now_ms()?;
        // Recovery has no new signed admission inputs. This real hook preserves
        // the original authority selection but cannot authorize a new execution.
        kernel.set_federation_local_kernel_id("native-combined-runtime-kernel");
        kernel.set_runtime_admission_hook(Arc::new(
            ChioRuntimeAdmissionHook::new(
                RuntimeAdmissionProfile {
                    schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.into(),
                    profile_id: "native-runtime-profile".into(),
                    local_kernel_id: "native-combined-runtime-kernel".into(),
                    verifier_id: "native-runtime-verifier".into(),
                    issued_at_unix_ms: now,
                    expires_at_unix_ms: now.checked_add(600_000).ok_or("time overflow")?,
                },
                source,
            )
            .with_operation_owned_runtime_replay(binding.clone()),
        ));
    }
    if let Some(binding) = profile.approval() {
        kernel.set_operation_owned_governed_approval_source(
            binding.clone(),
            Arc::new(chio_store_sqlite::SqliteGovernedApprovalReplaySource::open(
                witness.directory.join("native-approval.db"),
            )?),
        )?;
    }
    if let Some(binding) = profile.dpop() {
        kernel.set_operation_owned_dpop_authority(binding.clone())?;
    }
    let disclosure = witness
        .declassification_signer
        .as_ref()
        .map(|seed| Keypair::from_seed_hex(seed))
        .transpose()?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(resolver(
        witness.binding.clone(),
        disclosure.as_ref(),
    )?));
    if witness.request.execution_nonce.is_some() {
        kernel.set_execution_nonce_store(
            chio_kernel::execution_nonce::ExecutionNonceConfig {
                require_nonce: true,
                nonce_ttl_secs: 120,
                ..Default::default()
            },
            Box::new(nonce::NoLegacyNonce(Arc::new(AtomicUsize::new(0)))),
        );
    }
    Ok(())
}

fn effects(root: &Path) -> TestResult<String> {
    match std::fs::read_to_string(root.join("effect.log")) {
        Ok(value) => Ok(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error.into()),
    }
}

fn quota(authority: &SqliteAuthorityStore, request: &ToolCallRequest) -> TestResult<(u32, u32)> {
    Ok(authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&request.capability.id, 0))?
        .map_or((0, 0), |usage| {
            (usage.reserved_invocations, usage.captured_invocations)
        }))
}

fn credentials(
    authority: &SqliteAuthorityStore,
    operation: &AdmissionOperationV1,
    captured: bool,
) -> TestResult {
    use chio_kernel::admission_operation::{
        dpop_claim::DpopReplayClaimDisposition as Dpop,
        governed_approval_claim::GovernedApprovalClaimDisposition as Approval,
        runtime_participant::RuntimeParticipantDisposition as Runtime,
    };
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let id = operation.binding().operation_id();
    let (_, runtime) = store
        .load_runtime_participant_history(id, &fence, now_ms()?)?
        .ok_or("runtime")?;
    let (_, approval) = store
        .load_governed_approval_claim_history(id, &fence, now_ms()?)?
        .ok_or("approval")?;
    let (_, dpop) = store
        .load_dpop_replay_claim_history(id, &fence, now_ms()?)?
        .ok_or("DPoP")?;
    assert_eq!((runtime.len(), approval.len(), dpop.len()), (1, 1, 1));
    assert_eq!(runtime[0].intent.resources().len(), 1);
    assert_eq!(
        runtime[0].disposition,
        if captured {
            Runtime::RetainedAfterDispatchCommit
        } else {
            Runtime::ReleasedBeforeDispatch
        }
    );
    assert_eq!(
        approval[0].disposition,
        if captured {
            Approval::RetainedAfterDispatchCommit
        } else {
            Approval::ReleasedBeforeDispatch
        }
    );
    assert_eq!(
        dpop[0].disposition,
        if captured {
            Dpop::RetainedAfterDispatchCommit
        } else {
            Dpop::ReleasedBeforeDispatch
        }
    );
    Ok(())
}

fn cumulative(
    authority: &SqliteAuthorityStore,
    operation: &AdmissionOperationV1,
    captured: bool,
) -> TestResult {
    use chio_kernel::budget_store::BudgetCumulativeApprovalState;
    let budget = authority.budget_store();
    let usage = budget
        .get_cumulative_approval_operation_usage(operation.binding().operation_id().as_str())?
        .ok_or("cumulative operation")?;
    assert_eq!(usage.requested_authorized.units, 60);
    assert_eq!(usage.requested_authorized.currency, "USD");
    assert_eq!(
        usage.state,
        if captured {
            BudgetCumulativeApprovalState::Captured
        } else {
            BudgetCumulativeApprovalState::ReversedBeforeDispatch
        }
    );
    assert_eq!(
        (
            usage.reserved_authorized_after.units,
            usage.captured_authorized_after.units
        ),
        (0, if captured { 60 } else { 0 })
    );
    let account = budget
        .get_cumulative_approval_account_usage(&usage.account_key)?
        .ok_or("cumulative account")?;
    assert_eq!(
        (
            account.reserved_authorized.units,
            account.captured_authorized.units
        ),
        (0, if captured { 60 } else { 0 })
    );
    Ok(())
}

pub(super) fn verify(
    root: &Path,
    witness: &Witness,
    profile: Profile,
    point: Point,
    recovery: RecoveryMode,
) -> TestResult {
    assert_eq!(
        effects(root)?,
        if point.effected() { "effect\n" } else { "" }
    );
    let authority = SqliteAuthorityStore::open_serving(
        witness.directory.join("admission.db"),
        witness.directory.join("locks"),
    )?;
    let fence = authority.mutation_fence();
    assert!(fence.owner_epoch > witness.fence.owner_epoch);
    assert!(
        SqliteAuthorityStore::open_serving(
            witness.directory.join("admission.db"),
            witness.directory.join("locks")
        )
        .is_err(),
        "competing process owner must not enter serving mode"
    );
    let (before, original) = retained(&authority, &witness.request)?;
    let store = authority.admission_operation_store();
    assert!(
        store
            .load_retained_tool_request(before.binding().operation_id(), &witness.fence, now_ms()?)
            .is_err(),
        "old serving owner must be fenced"
    );
    assert_eq!(before.dispatch_commit().is_some(), point.captured());
    assert_eq!(
        before.native_dispatch_ledger_digest().is_some(),
        point.captured()
    );
    assert_eq!(
        quota(&authority, &witness.request)?,
        if point.captured() {
            (0, 1)
        } else if point == Point::BeforeParticipants {
            (0, 0)
        } else {
            (1, 0)
        }
    );
    let egress_before = store
        .load_native_security_egress(before.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("egress operation")?
        .1;
    let signer = Keypair::from_seed_hex(&witness.signer)?;
    let (mut kernel, invocations) = open_kernel(&witness.directory, &authority, &signer)?;
    configure_original_selection(&mut kernel, &original, witness)?;
    match recovery {
        RecoveryMode::Serial => {}
        RecoveryMode::CompetingWorkers => {
            let barrier = std::sync::Barrier::new(2);
            std::thread::scope(|scope| -> TestResult {
                let workers: Vec<_> = (0..2)
                    .map(|_| {
                        scope.spawn(|| {
                            barrier.wait();
                            kernel.reconcile_recoverable_admissions()
                        })
                    })
                    .collect();
                let mut successes = 0;
                for worker in workers {
                    successes += usize::from(
                        worker
                            .join()
                            .map_err(|_| "recovery worker panicked")?
                            .is_ok(),
                    );
                }
                assert!(successes >= 1, "at least one worker must reconcile");
                Ok(())
            })?;
        }
        RecoveryMode::LateCallerReport => {
            let barrier = std::sync::Barrier::new(2);
            std::thread::scope(|scope| -> TestResult {
                let worker = scope.spawn(|| {
                    barrier.wait();
                    kernel.reconcile_recoverable_admissions()
                });
                barrier.wait();
                let result = kernel.reconcile_caller_execution_blocking(
                    witness
                        .request
                        .execution_nonce
                        .as_ref()
                        .ok_or("native nonce")?,
                    &witness.request.arguments,
                    chio_kernel::CallerExecutionReport {
                        output: serde_json::json!({"forged_late_report": true}),
                        realized_cost: None,
                    },
                );
                assert!(
                    matches!(result, Err(KernelError::DurableAdmission(ref reason)) if reason.contains("caller")),
                    "late caller transport must be rejected: {result:?}"
                );
                worker
                    .join()
                    .map_err(|_| "late-report recovery panicked")??;
                Ok(())
            })?;
        }
    }
    let startup = kernel.reconcile_durable_admission_startup();
    if matches!(point, Point::OutputJoined | Point::Finalization(_)) && !point.released() {
        assert!(
            startup.is_err(),
            "missing original release owner must block readiness: {startup:?}"
        );
    } else {
        startup?;
    }
    let (after, retained_after) = retained(&authority, &witness.request)?;
    assert_eq!(retained_after.canonical_bytes(), original.canonical_bytes());
    assert_eq!(
        quota(&authority, &witness.request)?,
        (0, u32::from(point.captured()))
    );
    assert_eq!(after.dispatch_commit(), before.dispatch_commit());
    assert_eq!(
        store
            .load_native_security_egress(after.binding().operation_id(), &fence, now_ms()?)?
            .ok_or("egress operation")?
            .1,
        egress_before
    );
    let expected = if point.released() {
        AdmissionOperationState::Completed
    } else if matches!(point, Point::OutputJoined | Point::Finalization(_)) {
        AdmissionOperationState::Finalizing
    } else if point.captured() {
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    } else {
        AdmissionOperationState::CompensatedBeforeDispatch
    };
    assert_eq!(after.state(), expected, "{profile:?}/{point:?}");
    assert_eq!(
        authority
            .tool_outcome_store()
            .lookup_security_release(after.binding().operation_id())?
            .is_some(),
        point.released()
    );
    if profile == Profile::Combined {
        credentials(&authority, &after, point.captured())?;
    }
    if profile == Profile::Cumulative {
        cumulative(&authority, &after, point.captured())?;
    }
    if profile == Profile::Nonce {
        assert!(after.execution_nonce_issuance_digest().is_some());
        assert!(store
            .load_execution_nonce_reservation(after.binding().operation_id(), &fence, now_ms()?)?
            .is_some());
        let connection = rusqlite::Connection::open_with_flags(
            witness.directory.join("admission.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut statement = connection.prepare("SELECT kind FROM admission_execution_nonce_transitions WHERE operation_id = ?1 ORDER BY kind")?;
        let phases = statement
            .query_map([after.binding().operation_id().as_str()], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            phases,
            if point.captured() {
                vec!["capture_pending", "committed"]
            } else {
                vec!["cancelled", "capture_pending"]
            }
        );
    }
    if profile == Profile::Declassification {
        let connection = rusqlite::Connection::open_with_flags(
            witness.directory.join("admission.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (state, outbox): (String, i64) = connection.query_row(
            "SELECT state, (SELECT COUNT(*) FROM security_participant_state_declassification_receipt_outbox) FROM security_participant_state_declassification_uses",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let joined = matches!(point, Point::OutputJoined) || point.released();
        assert_eq!(
            (state.as_str(), outbox),
            if joined {
                ("released", 2)
            } else {
                ("consumed_pending_dispatch", 1)
            }
        );
        let key = crate::security::adapters::flow_key(witness.context.as_v1());
        let observed =
            store.observe_native_security_flow(&witness.binding, &key, &fence, now_ms()?)?;
        let state = observed
            .snapshot()
            .ok_or("retained declassification taint")?;
        for label in [
            &state.principal_label,
            &state.lineage_label,
            &state.session_label,
        ] {
            assert_eq!(
                label,
                &restricted_label(),
                "declassification never lowers inherited taint"
            );
        }
    }
    let replay = kernel
        .evaluate_tool_call_blocking_with_security_context(&witness.request, &witness.context);
    if point.released() {
        let response = replay?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(
            matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &witness.request.arguments)
        );
        assert!(response.receipt.verify_signature()?);
        let second = kernel.evaluate_tool_call_blocking_with_security_context(
            &witness.request,
            &witness.context,
        )?;
        assert_eq!(
            chio_core::canonical_json_bytes(&response.receipt)?,
            chio_core::canonical_json_bytes(&second.receipt)?
        );
    } else if matches!(point, Point::OutputJoined | Point::Finalization(_)) {
        assert!(replay.is_err(), "uncheckpointed output must never escape");
    } else {
        match replay {
            Ok(response) => {
                assert_eq!(response.verdict, Verdict::Deny);
                assert!(response.output.is_none());
                assert!(response.receipt.verify_signature()?);
                assert!(
                    response
                        .reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains(&format!("{expected:?}"))),
                    "retry must deny on the retained disposition: {:?}",
                    response.reason
                );
            }
            Err(KernelError::DurableAdmission(reason)) => {
                assert!(reason.contains(&format!("{expected:?}")), "{reason}")
            }
            Err(error) => return Err(format!("unexpected retry failure: {error}").into()),
        }
    }
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "no execution from recovery or retry"
    );
    assert_eq!(
        effects(root)?,
        if point.effected() { "effect\n" } else { "" }
    );
    assert_eq!(
        quota(&authority, &witness.request)?,
        (0, u32::from(point.captured()))
    );
    assert_eq!(retained(&authority, &witness.request)?.0, after);
    Ok(())
}
