//! Real kernel-created native operations cannot acquire dispatch authority by
//! entering a lower-level store API, even after both egress phases commit.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationCommand, AdmissionOperationV1, QualifiedAdmissionOperationStoreExt,
};
use chio_kernel::budget_store::{BudgetCaptureInvocationRequest, BudgetEventAuthority};
use chio_kernel::BudgetStore;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
enum Route {
    Combined,
    Split,
    Generic,
}

#[test]
fn native_combined_capture_requires_supported_security_dispatch_custody() -> TestResult {
    exercise(Route::Combined)
}

#[test]
fn native_split_capture_cannot_bypass_security_dispatch_custody() -> TestResult {
    exercise(Route::Split)
}

#[test]
fn native_generic_dispatch_commit_cannot_bypass_security_dispatch_custody() -> TestResult {
    exercise(Route::Generic)
}

fn exercise(route: Route) -> TestResult {
    for committed_egress in [false, true] {
        let mut fixture = Fixture::new()?;
        fixture.nonce_enabled = false;
        let mut runtime = fixture.open()?;
        let selected = initialize(&fixture, &runtime, "capture-source")?;
        let request = fixture.request(&runtime, "native-capture-refusal")?;
        let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            TenantId::new("native-tenant")?,
            SessionId::new("native-session")?,
            PrincipalId::new(request.agent_id.clone())?,
            IsolationEpochId::new("native-epoch")?,
            LineageId::new(request.capability.id.clone())?,
            1,
        ));
        let probe = Arc::new(NativeAdmissionProbe {
            store: runtime.authority.admission_operation_store(),
            fence: runtime.authority.mutation_fence(),
            selected,
            context: context.clone(),
            calls: AtomicUsize::new(0),
            preparation_calls: AtomicUsize::new(0),
            dispatch_calls: AtomicUsize::new(0),
            mode: PreparationMode::Normal,
        });
        let result = Arc::new(Mutex::new(None));
        let calls = Arc::new(AtomicUsize::new(0));
        let store = runtime.authority.admission_operation_store();
        let budget = runtime.authority.budget_store();
        let fence = runtime.authority.mutation_fence();
        let claimant = AdmissionIdentifier::try_new(
            "claimant",
            format!("kernel:{}", fixture.signer.public_key().to_hex()),
        )?;
        let database = fixture.database();
        let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(probe.clone());
        kernel.install_native_egress_checkpoint_hook(Arc::new({
            let result = result.clone();
            let calls = calls.clone();
            move |kernel, operation, request, context| {
                calls.fetch_add(1, Ordering::SeqCst);
                let check = || -> TestResult {
                    assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
                    let (_, original) = store
                        .load_retained_tool_request(
                            operation.binding().operation_id(),
                            &fence,
                            now_ms()?,
                        )?
                        .ok_or("retained original")?;
                    assert!(original.native_security_authority_binding().is_some());
                    assert!(original.authority_profile().is_some());
                    if committed_egress {
                        let history = kernel
                            .prepare_native_security_egress(
                                operation.binding().operation_id(),
                                request,
                                context,
                            )?
                            .acquire(now_ms()? + 60_000)?
                            .commit()?;
                        assert!(history.commitment.is_some());
                    }
                    let now = now_ms()?;
                    let lease = store.claim_recovery(
                        operation.binding().operation_id(),
                        operation.version(),
                        &claimant,
                        now,
                        now + 60_000,
                        &fence,
                    )?;
                    let before = snapshot(&database, operation)?;
                    let capture = BudgetCaptureInvocationRequest {
                        capability_id: operation.binding().capability_id().as_str().into(),
                        grant_index: 0,
                        hold_id: operation
                            .budget_hold_id()
                            .ok_or("physical hold")?
                            .as_str()
                            .into(),
                        event_id: "unsupported-native-capture".into(),
                        trusted_time: None,
                        authority: Some(BudgetEventAuthority {
                            authority_id: fence.store_uuid.clone(),
                            lease_id: fence.lease_id.clone(),
                            lease_epoch: fence.owner_epoch,
                        }),
                    };
                    let denial = match route {
                        Route::Combined => store
                            .capture_invocation_and_commit_dispatch(
                                operation,
                                &lease,
                                capture,
                                &fence,
                                now_ms()?,
                            )
                            .map(|_| ())
                            .map_err(|error| error.to_string()),
                        Route::Split => budget
                            .capture_invocation_reservations(capture)
                            .map(|_| ())
                            .map_err(|error| error.to_string()),
                        Route::Generic => store
                            .compare_and_swap(
                                &AdmissionOperationCommand::new(
                                    operation.binding().operation_id().clone(),
                                    operation.version(),
                                    lease,
                                    vec![],
                                    Some(AdmissionOperationState::DispatchCommitted),
                                    None,
                                    None,
                                )?,
                                now_ms()?,
                            )
                            .map(|_| ())
                            .map_err(|error| error.to_string()),
                    };
                    let error = denial.err().ok_or("unsupported native capture succeeded")?;
                    assert!(
                        error.contains("native security dispatch custody is unsupported"),
                        "{error}"
                    );
                    assert_eq!(snapshot(&database, operation)?, before);
                    assert_eq!(
                        store
                            .load_by_operation_id(operation.binding().operation_id())?
                            .as_ref(),
                        Some(operation)
                    );
                    Ok(())
                };
                if let Ok(mut result) = result.lock() {
                    *result = Some(check().map_err(|error| error.to_string()));
                }
            }
        }));
        let response = runtime
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&request, &context);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        result
            .lock()
            .map_err(|_| "checkpoint poisoned")?
            .take()
            .ok_or("checkpoint absent")??;
        let response = response?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(
            response.reason.as_deref(),
            Some("native security dispatch lifecycle is unsupported")
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(probe.dispatch_calls.load(Ordering::SeqCst), 0);
        assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    }
    Ok(())
}

fn snapshot(
    database: &std::path::Path,
    operation: &AdmissionOperationV1,
) -> TestResult<(Vec<u8>, i64, i64, i64)> {
    Ok(rusqlite::Connection::open(database)?.query_row(
        "SELECT (SELECT operation_json FROM admission_operations WHERE operation_id = ?1),
          (SELECT COUNT(*) FROM authority_global_commits),
          (SELECT COUNT(*) FROM budget_mutation_events),
          (SELECT COUNT(*) FROM admission_operation_commits)",
        [operation.binding().operation_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?)
}
