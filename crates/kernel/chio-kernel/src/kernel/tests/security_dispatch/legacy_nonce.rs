//! A lost legacy-store acknowledgement cannot be promoted by a retry or Drop.

use super::*;

#[derive(Clone, Copy, Debug)]
enum Mode {
    Retain,
    Replay,
    Error,
    Panic,
}

struct Probe {
    mode: Mode,
    calls: Arc<AtomicU64>,
    consumed: Arc<AtomicBool>,
}

impl ExecutionNonceStore for Probe {
    fn reserve(&self, _: &str) -> Result<bool, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.consumed.store(true, Ordering::SeqCst);
        match self.mode {
            Mode::Retain => Ok(true),
            Mode::Replay => Ok(false),
            Mode::Error => Err(KernelError::Internal("lost nonce acknowledgement".into())),
            Mode::Panic => panic!("nonce callback panicked after consumption"),
        }
    }
}

fn install(
    kernel: &mut ChioKernel,
    mode: Mode,
) -> Result<(Arc<AtomicU64>, Arc<AtomicBool>), KernelError> {
    let calls = Arc::new(AtomicU64::new(0));
    let consumed = Arc::new(AtomicBool::new(false));
    kernel.set_execution_nonce_store(
        kernel
            .execution_nonce_config
            .clone()
            .ok_or_else(|| KernelError::Internal("nonce configuration".into()))?,
        Box::new(Probe {
            mode,
            calls: calls.clone(),
            consumed: consumed.clone(),
        }),
    );
    Ok((calls, consumed))
}

#[test]
fn legacy_nonce_failure_stays_failed_without_another_store_call() -> TestResult {
    for mode in [Mode::Replay, Mode::Error, Mode::Panic] {
        for explicit_rollback in [false, true] {
            let (mut kernel, cap, request, _) =
                request_with_legacy_execution_nonce_store("sticky-nonce")?;
            let (calls, consumed) = install(&mut kernel, mode)?;
            let mut reservation = kernel.reserve_dispatch_credentials(
                &request,
                &cap,
                false,
                current_unix_timestamp(),
                false,
            )?;
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(reservation
                .reserve_legacy_execution_nonce_at_effect_boundary()
                .is_err());
            assert!(reservation
                .reserve_legacy_execution_nonce_at_effect_boundary()
                .is_err());
            assert!(reservation.commit().is_err());
            assert!(reservation.retain_if_dropped().is_err());
            if explicit_rollback {
                assert_eq!(
                    reservation.rollback_before_dispatch_with_disposition()?,
                    PaymentCredentialDisposition::RetentionOutcomeUnknown
                );
            } else {
                drop(reservation);
            }
            assert!(consumed.load(Ordering::SeqCst));
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{mode:?}");
        }
    }
    Ok(())
}

#[test]
fn confirmed_legacy_nonce_retention_survives_reversible_cleanup() -> TestResult {
    let (mut kernel, cap, request, _) =
        request_with_legacy_execution_nonce_store("retained-nonce")?;
    let (calls, consumed) = install(&mut kernel, Mode::Retain)?;
    let mut reservation = kernel.reserve_dispatch_credentials(
        &request,
        &cap,
        false,
        current_unix_timestamp(),
        false,
    )?;
    reservation.retain_if_dropped()?;
    reservation.reserve_legacy_execution_nonce_at_effect_boundary()?;
    assert_eq!(
        reservation.rollback_before_dispatch_with_disposition()?,
        PaymentCredentialDisposition::RetainedAfterAuthorization
    );
    assert!(consumed.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn retention_failure_after_security_acceptance_records_failed_dispatch() -> TestResult {
    for nested in [false, true] {
        for mode in [Mode::Replay, Mode::Error, Mode::Panic] {
            for recording_fault in [false, true] {
                let (mut kernel, _, request, _) =
                    request_with_legacy_execution_nonce_store("post-security-retention")?;
                let (calls, consumed) = install(&mut kernel, mode)?;
                let invocations = Arc::new(AtomicU64::new(0));
                kernel.register_tool_server(Box::new(CountingDispatchServer {
                    id: request.server_id.clone(),
                    tool: request.tool_name.clone(),
                    invocations: invocations.clone(),
                }));
                kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
                kernel.set_security_pre_dispatch_hook(Arc::new(Hook(if recording_fault {
                    Fault::Record
                } else {
                    Fault::None
                })));
                let result = super::credentials::evaluate(&kernel, &request, nested);
                if recording_fault {
                    let error = result
                        .err()
                        .ok_or("recording failure became a signed denial")?;
                    assert!(matches!(
                        error.downcast_ref::<KernelError>(),
                        Some(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
                    ));
                } else {
                    let response = result?;
                    assert_eq!(response.verdict, Verdict::Deny);
                    assert!(response
                        .reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("credential retention failed")));
                    assert!(response.receipt.verify_signature()?);
                    assert_eq!(
                        response.receipt.metadata.as_ref().ok_or("metadata")?["chio_runtime"]
                            ["dispatch_credential_disposition"],
                        "retention_outcome_unknown"
                    );
                }
                assert_eq!(invocations.load(Ordering::SeqCst), 0);
                assert!(consumed.load(Ordering::SeqCst));
                assert_eq!(calls.load(Ordering::SeqCst), 1);
            }
        }
    }
    Ok(())
}
