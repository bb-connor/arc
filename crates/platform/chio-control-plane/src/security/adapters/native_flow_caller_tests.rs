// Actual native authority, resolver, committed caller start and durable executor.
use super::*;
use chio_kernel::caller_delivery::CallerExecutorIdentityV1;
use chio_kernel::tool_outcome::ToolOutcomeStore;
use chio_kernel::{CallerExecutionReport, CallerStartCredentials, CallerStartResponse};
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;

mod denial {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_caller_denial_tests.rs"
    ));
}

#[cfg(unix)]
mod restart {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_caller_restart_tests.rs"
    ));
}

enum DeliveryMode {
    Live,
    #[cfg(unix)]
    Restart {
        disclosure: Option<Box<Keypair>>,
        expire: bool,
    },
}

#[test]
fn native_caller_releases_only_the_authenticated_original_guarded_output() -> TestResult {
    let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
    let legacy = super::nonce::execution::configure(&mut fixture, false)?;
    exercise_original_output(fixture, legacy)
}

#[test]
fn native_caller_composes_local_egress_declassification_and_complete_credentials() -> TestResult {
    for combined in [false, true] {
        for profile in ["local", "egress", "declassification"] {
            let (fixture, legacy) = if profile == "declassification" {
                let (mut fixture, _) = super::declassification::profile(combined, 300)?;
                let legacy = super::nonce::execution::install_nonce(&mut fixture, 120);
                (fixture, legacy)
            } else {
                let mut fixture = if combined {
                    Fixture::combined_native_credentials()?
                } else {
                    Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?
                };
                let legacy = super::nonce::execution::configure(&mut fixture, profile == "egress")?;
                (fixture, legacy)
            };
            // Bind every originally presented credential to the new start,
            // including the independently consumed native declassification use.
            exercise_original_output(fixture, legacy).map_err(|error| {
                std::io::Error::other(format!(
                    "native caller profile={profile} combined={combined}: {error}"
                ))
            })?;
        }
    }
    Ok(())
}

fn start_credentials(fixture: &Fixture) -> CallerStartCredentials {
    CallerStartCredentials {
        dpop_proof: fixture.request.dpop_proof.clone(),
        approval_token: fixture.request.approval_token.clone(),
        approval_tokens: fixture.request.approval_tokens.clone(),
        threshold_approval_proposal: fixture.request.threshold_approval_proposal.clone(),
        declassification_grant: fixture.request.declassification_grant.clone(),
    }
}

fn exercise_original_output(fixture: Fixture, legacy: Arc<AtomicUsize>) -> TestResult {
    exercise_delivery(fixture, legacy, DeliveryMode::Live)
}

fn exercise_delivery(
    mut fixture: Fixture,
    legacy: Arc<AtomicUsize>,
    mode: DeliveryMode,
) -> TestResult {
    let executor_key = Keypair::generate();
    let executor = CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "native-caller-executor")?,
        public_key: executor_key.public_key(),
        key_epoch: 41,
    };
    fixture.kernel.set_caller_executor(executor.clone())?;
    let operation_id = super::nonce::execution::issue(&mut fixture)?;
    let reserved = fixture
        .kernel
        .reserve_caller_execution_blocking_with_security_context(
            &fixture.request,
            &fixture.context,
        )?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    assert!(reserved.output.is_none());
    let nonce = reserved.execution_nonce.ok_or("reserved nonce")?;
    let authorization = match fixture
        .kernel
        .start_caller_execution_blocking_with_security_context(
            &nonce,
            &fixture.request.arguments,
            start_credentials(&fixture),
            &fixture.context,
        )? {
        CallerStartResponse::Authorized(authorization) => *authorization,
        CallerStartResponse::Denied(response) => {
            return Err(format!("native caller start denied: {:?}", response.reason).into())
        }
    };
    assert_eq!(
        authorization.authorization.invocation.operation_id,
        operation_id
    );
    let store = fixture.authority.admission_operation_store();
    let captured = store
        .load_by_operation_id(&operation_id)?
        .ok_or("captured operation")?;
    assert_eq!(captured.state(), AdmissionOperationState::DispatchCommitted);
    assert!(captured.native_dispatch_ledger_digest().is_some());
    assert!(captured.caller_dispatch_context_digest().is_some());
    assert_captured_quota(&fixture)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture._directory.path().join("executor.db"),
        executor.clone(),
        4,
    )?;
    let effects = AtomicUsize::new(0);
    let report = ledger.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        &executor_key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(CallerExecutionReport {
                output: serde_json::json!({"native_external_effect": true}),
                realized_cost: None,
            })
        },
    )?;
    drop(store);
    #[cfg(unix)]
    let mut _clock = None;
    let historical_time = match mode {
        DeliveryMode::Live => None,
        #[cfg(unix)]
        DeliveryMode::Restart { disclosure, expire } => {
            fixture = restart::reopen(fixture, &executor, disclosure.as_deref())?;
            let retained = fixture
                .authority
                .admission_operation_store()
                .load_by_operation_id(&operation_id)?
                .ok_or("restarted caller operation")?;
            assert_eq!(
                retained.state(),
                AdmissionOperationState::AwaitingCallerReport
            );
            assert_captured_quota(&fixture)?;
            if expire {
                let until = fixture
                    .request
                    .capability
                    .expires_at
                    .max(u64::try_from(nonce.expires_at())?);
                _clock = Some(chio_kernel::scope_fixed_runtime_for_current_thread(
                    until + 1,
                    [],
                ));
                Some((until + 1) * 1_000)
            } else {
                None
            }
        }
    };
    let completed = fixture
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(completed.verdict, Verdict::Allow, "{:?}", completed.reason);
    assert!(
        matches!(&completed.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &report.report.output)
    );
    assert!(completed.receipt.verify_signature()?);
    assert!(completed.execution_nonce.is_none());
    assert_eq!(
        fixture
            .authority
            .admission_operation_store()
            .load_by_operation_id(&operation_id)?
            .ok_or("terminal operation")?
            .state(),
        AdmissionOperationState::Completed
    );
    assert!(fixture
        .authority
        .tool_outcome_store()
        .lookup_security_release(&operation_id)?
        .is_some());
    let replay = fixture
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&completed.receipt)?,
        chio_core::canonical::canonical_json_bytes(&replay.receipt)?
    );
    assert_captured_quota(&fixture)?;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.load(Ordering::SeqCst), 0);
    assert_native_original_evidence(
        &fixture,
        &operation_id,
        &executor_key,
        historical_time.unwrap_or(now_ms()?),
    )?;
    if let Some(grant) = fixture.request.declassification_grant.as_ref() {
        let connection = rusqlite::Connection::open_with_flags(
            fixture._directory.path().join("admission.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (state, evidence_count): (String, i64) = connection.query_row(
            "SELECT state, (SELECT COUNT(*) FROM security_participant_state_declassification_receipt_outbox WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3)
             FROM security_participant_state_declassification_uses WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3",
            rusqlite::params![fixture.binding.security_authority_id().as_str(), fixture.context.as_v1().tenant_id().as_str(), grant.body().grant_id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!((state.as_str(), evidence_count), ("released", 2));
    }
    Ok(())
}

fn assert_captured_quota(fixture: &Fixture) -> TestResult {
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("captured quota")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 1)
    );
    Ok(())
}

fn assert_native_original_evidence(
    fixture: &Fixture,
    id: &chio_kernel::admission_operation::AdmissionOperationId,
    executor_key: &Keypair,
    observed_at: u64,
) -> TestResult {
    use chio_kernel::admission_operation::AdmissionCallerDispatchContextV1;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, original) = store
        .load_retained_tool_request(id, &fence, observed_at)?
        .ok_or("original")?;
    let nonce = store
        .load_execution_nonce_reservation(id, &fence, observed_at)?
        .ok_or("nonce")?;
    let frame = store
        .load_caller_dispatch_context(id, &fence, observed_at)?
        .ok_or("caller frame")?;
    let raw = fixture
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(id)?
        .ok_or("raw return")?;
    let evidence = raw
        .to_persisted()
        .caller_delivery_evidence
        .ok_or("private signed evidence")?;
    let custody = evidence.validate_native_original(&operation, &original, &nonce, &frame)?;
    for replace_kernel in [false, true] {
        use chio_kernel::caller_delivery::{
            CallerDeliveryEvidenceV1, SignedCallerDeliveryReportV1,
            SignedCallerDispatchAuthorizationV1,
        };
        let replacement = Keypair::generate();
        let (kernel_key, executor_key) = if replace_kernel {
            (&replacement, executor_key)
        } else {
            (&fixture.signer, &replacement)
        };
        let mut authorization_body = evidence.authorization.authorization.clone();
        authorization_body.kernel_public_key = kernel_key.public_key();
        authorization_body.executor.public_key = executor_key.public_key();
        let authorization =
            SignedCallerDispatchAuthorizationV1::sign(authorization_body, kernel_key)?;
        let mut report_body = evidence.report.report.clone();
        report_body.executor = authorization.authorization.executor.clone();
        report_body.authorization_digest = authorization.verify_historical(
            &kernel_key.public_key(),
            &authorization.authorization.executor,
            &authorization.authorization.invocation,
        )?;
        let report = SignedCallerDeliveryReportV1::sign(report_body, executor_key)?;
        report.verify(
            &authorization,
            &kernel_key.public_key(),
            &authorization.authorization.executor,
            &authorization.authorization.invocation,
        )?;
        // Both signatures are valid and internally consistent. Only the
        // independently retained original pins can reject this substitution.
        let substituted = CallerDeliveryEvidenceV1 {
            authorization,
            report,
        };
        assert!(substituted
            .validate_native_original(&operation, &original, &nonce, &frame)
            .is_err());
    }
    let ledger = store
        .load_native_dispatch_ledger(id, &fence, observed_at)?
        .ok_or("native ledger")?;
    assert_eq!(custody.ledger_bytes(), ledger.canonical_record);
    assert_eq!(custody.ledger_digest(), &ledger.record_digest);
    assert!(
        evidence.authorization.authorization.expires_at_unix_ms <= custody.valid_until_unix_ms()
    );
    let ledger_value: serde_json::Value = serde_json::from_slice(&ledger.canonical_record)?;
    let prepared = chio_kernel::admission_operation::AdmissionOperationV1::from_persisted(
        serde_json::from_value(ledger_value["operation"].clone())?,
    )?;
    assert_eq!(prepared.state(), AdmissionOperationState::CapturePending);
    assert!(prepared.caller_dispatch_context_digest().is_none());
    AdmissionCallerDispatchContextV1::from_canonical_bytes(
        frame.canonical_bytes(),
        &prepared,
        &original,
    )?;
    let frame_value: serde_json::Value = serde_json::from_slice(frame.canonical_bytes())?;
    for change in [
        "schema", "missing", "ledger", "request", "deadline", "identity",
    ] {
        let mut frame_value = frame_value.clone();
        let mut payload: serde_json::Value = serde_json::from_str(
            frame_value["kernel_context_json"]
                .as_str()
                .ok_or("kernel payload")?,
        )?;
        match change {
            "schema" => payload["schema"] = "chio.kernel-caller-return-context.v4".into(),
            "missing" => {
                payload
                    .as_object_mut()
                    .ok_or("payload")?
                    .remove("native_custody");
            }
            "ledger" => payload["native_custody"]["ledger_json"] = "{}".into(),
            "request" => {
                payload["native_custody"]["release_request_digest"] = "f".repeat(64).into()
            }
            "deadline" => payload["native_custody"]["valid_until_unix_ms"] = 0.into(),
            "identity" => payload["native_custody"]["security_context"] = serde_json::Value::Null,
            _ => unreachable!(),
        }
        frame_value["kernel_context_json"] =
            String::from_utf8(chio_core::canonical_json_bytes(&payload)?)?.into();
        // Calibrate against an unbound, physically retained preparation too:
        // rejection must not depend only on the committed outer frame digest.
        assert!(
            AdmissionCallerDispatchContextV1::from_canonical_bytes(
                &chio_core::canonical_json_bytes(&frame_value)?,
                &prepared,
                &original
            )
            .is_err(),
            "{change}"
        );
    }
    Ok(())
}
