use super::*;

struct ApprovalAttemptObserver {
    identities: StdArc<Mutex<Vec<String>>>,
}

impl Guard for ApprovalAttemptObserver {
    fn name(&self) -> &str {
        "approval-attempt-observer"
    }

    fn evidence_declaration(&self) -> crate::GuardEvidenceDeclaration {
        crate::GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        let identity = context.invocation_attempt_id().ok_or_else(|| {
            KernelError::GuardDenied("approval retry lacks a kernel attempt".to_owned())
        })?;
        self.identities
            .lock()
            .map_err(|_| KernelError::GuardDenied("approval observer lock failed".to_owned()))?
            .push(identity.to_owned());
        Ok(GuardDecision::allow())
    }
}

#[test]
fn approved_session_retry_keeps_admitted_attempt_identity_and_one_dispatch() -> TestResult {
    let mut fixture = Fixture::new()?;
    let identities = StdArc::new(Mutex::new(Vec::new()));
    fixture.kernel.add_guard(Box::new(ApprovalAttemptObserver {
        identities: identities.clone(),
    }));
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;

    assert_approved(&fixture, &context)?;

    let identities = identities
        .lock()
        .map_err(|_| "approval observer poisoned")?
        .clone();
    let first = identities
        .first()
        .ok_or("approved retry never evaluated guards")?;
    assert!(first.starts_with("admission-operation:"));
    assert!(identities.iter().all(|identity| identity == first));
    assert!(matches!(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request)),
        Err(KernelError::Session(
            crate::session::SessionError::DuplicateRequestLineage { .. }
        ))
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
