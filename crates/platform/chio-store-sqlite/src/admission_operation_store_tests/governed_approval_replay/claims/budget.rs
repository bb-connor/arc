use super::*;

fn authorization(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
) -> AnchoredTestResult<BudgetAuthorizeHoldRequest> {
    Ok(BudgetAuthorizeHoldRequest {
        capability_id: operation.binding().capability_id().as_str().into(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: vec![],
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: operation.binding().operation_id().as_str().into(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec![operation
                .binding()
                .capability_id()
                .as_str()
                .into()])?,
            authorization_artifact_digests: vec![operation
                .to_persisted()
                .binding
                .authorization_capability_hash
                .as_str()
                .into()],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 0,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: Some("approval-budget-hold".into()),
        event_id: Some("approval-budget-authorize".into()),
        authority: Some(BudgetEventAuthority {
            authority_id: fixture.fence.store_uuid.clone(),
            lease_id: fixture.fence.lease_id.clone(),
            lease_epoch: fixture.fence.owner_epoch,
        }),
    })
}

#[test]
fn real_budget_authorization_checks_new_authority_but_acknowledges_expired_history(
) -> AnchoredTestResult {
    for already_authorized in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let binding = activate(&fixture, &source)?;
        let (operation, lease, mut credential) = setup(&fixture, "real-budget-authorization")?;
        let expires = now_ms() / 1000 + 60;
        credential.expires_at_unix_secs = expires;
        let intent = candidate(&operation, &binding, "claim", credential)?;
        let (operation, _) =
            fixture
                .store
                .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
        let lease = renew(&fixture, &operation, &lease, now_ms())?;
        let request = authorization(&fixture, &operation)?;
        let original = if already_authorized {
            Some(fixture.store.authorize_budget_and_commit_admission(
                &operation,
                &lease,
                request.clone(),
                None,
                None,
                &fixture.fence,
                now_ms(),
            )?)
        } else {
            None
        };
        let count = global_count(&fixture);
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
        let result = fixture.store.authorize_budget_and_commit_admission(
            &operation,
            &lease,
            request,
            None,
            None,
            &fixture.fence,
            expires * 1000,
        );
        match original {
            Some((_, authorized)) => assert_eq!(result?.1, authorized),
            None => assert!(result.is_err()),
        }
        assert_eq!(global_count(&fixture), count);
        assert_eq!(
            fixture.store.connection()?.query_row(
                "SELECT COUNT(*) FROM budget_authorization_holds",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            i64::from(already_authorized)
        );
    }
    Ok(())
}

#[test]
fn real_capture_checks_new_authority_but_acknowledges_expired_dispatch_history(
) -> AnchoredTestResult {
    for already_captured in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let binding = activate(&fixture, &source)?;
        let (operation, lease, mut credential) = setup(&fixture, "real-budget-capture")?;
        let expires = now_ms() / 1000 + 60;
        credential.expires_at_unix_secs = expires;
        let intent = candidate(&operation, &binding, "claim", credential)?;
        let (operation, _) =
            fixture
                .store
                .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
        let lease = renew(&fixture, &operation, &lease, now_ms())?;
        let request = authorization(&fixture, &operation)?;
        let capture = BudgetCaptureInvocationRequest {
            capability_id: request.capability_id.clone(),
            grant_index: 0,
            hold_id: request.hold_id.clone().ok_or("hold missing")?,
            event_id: "approval-budget-capture".into(),
            trusted_time: None,
            authority: request.authority.clone(),
        };
        let (_, mut operation) = fixture.store.authorize_budget_and_commit_admission(
            &operation,
            &lease,
            request,
            None,
            None,
            &fixture.fence,
            now_ms(),
        )?;
        for state in [
            AdmissionOperationState::ReadyToDispatch,
            AdmissionOperationState::CapturePending,
        ] {
            let lease = renew(&fixture, &operation, &lease, now_ms())?;
            operation = fixture
                .store
                .compare_and_swap(&command(&operation, lease, vec![], state, None), now_ms())?
                .into_operation();
        }
        let lease = renew(&fixture, &operation, &lease, now_ms())?;
        let original = if already_captured {
            Some(fixture.store.capture_invocation_and_commit_dispatch(
                &operation,
                &lease,
                capture.clone(),
                &fixture.fence,
                now_ms(),
            )?)
        } else {
            None
        };
        let count = global_count(&fixture);
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
        let result = fixture.store.capture_invocation_and_commit_dispatch(
            &operation,
            &lease,
            capture,
            &fixture.fence,
            expires * 1000,
        );
        match original {
            Some((_, committed)) => {
                let (decision, restored) = result?;
                assert!(matches!(
                    decision,
                    BudgetInvocationCaptureDecision::AlreadyCaptured(_)
                ));
                assert_eq!(restored, committed);
            }
            None => assert!(result.is_err()),
        }
        assert_eq!(global_count(&fixture), count);
        let state: String = fixture.store.connection()?.query_row(
            "SELECT invocation_state FROM budget_authorization_holds",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            state,
            if already_captured {
                "captured"
            } else {
                "authorized"
            }
        );
    }
    Ok(())
}
