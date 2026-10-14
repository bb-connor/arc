use super::*;

#[tokio::test]
async fn recovery_equal_labels_with_a_new_foreign_generation_are_stale() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let send_denied = |key: &'static str| async {
        let request =
            f.process
                .tool_request("root", key, "server-a", "send", f.seed.arguments.clone())?;
        let response = f.process.invoke_known_only("root", key, &request).await?;
        assert_eq!(response.verdict, chio_kernel::Verdict::Deny);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    // Real denied calls join input through the native owner. No fixture SQL
    // invents protected history or supplies a fake generation.
    send_denied("initial-influence").await?;
    let id = f.ready().await?;
    let frozen = f.record(&id)?.action.ok_or("action")?;
    let before = f.kernel.observe_recovery_source(f.runtime.scope())?;
    send_denied("foreign-influence").await?;
    let after = f.kernel.observe_recovery_source(f.runtime.scope())?;
    let before = before.snapshot().ok_or("before")?;
    let after = after.snapshot().ok_or("after")?;
    assert_eq!(before.principal_label, after.principal_label);
    assert_eq!(before.lineage_label, after.lineage_label);
    assert_eq!(before.session_label, after.session_label);
    assert!(after.context_generation > before.context_generation);
    let record = f.record(&id)?;
    assert!(f
        .execute(
            "stale-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: record.revision,
            }
        )
        .await
        .is_err());
    let record = f.record(&id)?;
    assert_eq!(record.action.as_ref(), Some(&frozen));
    assert!(!record.captured);
    assert_eq!(external_count(&f.path)?, 0);
    assert_eq!(f.process.process("root")?.tree_calls, 4);
    Ok(())
}

#[tokio::test]
async fn recovery_protected_identity_and_history_tampering_fail_closed() -> TestResult {
    for mutation in [
        "UPDATE admission_operation_recovery_records SET payload=CAST(replace(CAST(payload AS TEXT),'private-canary','foreign-canary') AS BLOB) WHERE kind='workflow'",
        "UPDATE admission_operation_recovery_records SET native_namespace=NULL,native_request=NULL WHERE kind='workflow'",
        "DROP TRIGGER admission_operation_recovery_no_delete; DELETE FROM admission_operation_recovery_records WHERE kind='workflow'",
        "DROP TRIGGER admission_operation_recovery_event_no_update; UPDATE admission_operation_recovery_events SET event_digest=printf('%064d',0) WHERE sequence=1",
    ] {
        let f = RecoveryFixture::new(false)?;
        let id = f.ready().await?;
        crate::recovery::freeze_original_for_test(&f.runtime, &f.control, &id)?;
        let record = f.record(&id)?;
        let db = rusqlite::Connection::open(f.path.join("admission.db"))?;
        // Identity triggers can reject the edit. Edits that get through must
        // still fail protected read/commit validation without another effect.
        let applied = db.execute_batch(mutation).is_ok();
        // A batch may drop a protected trigger before a later statement is
        // refused. That partial DDL change must also fence native reads.
        if applied || f.record(&id).is_err() {
            assert!(f.record(&id).is_err());
            assert!(
                f.execute(
                    "tampered-resume",
                    RecoveryCommandBodyV1::ResumeWorkflow {
                        workflow_id: id.clone(),
                        expected_revision: record.revision,
                    }
                )
                .await
                .is_err()
            );
            // Native authority validation now also fences the process snapshot;
            // corrupted protected history cannot supply a raw diagnostic route.
            assert!(f.process.process("root").is_err());
        } else {
            assert_eq!(f.process.process("root")?.tree_calls, 2);
        }
        assert_eq!(external_count(&f.path)?, 0);
        let journal = rusqlite::Connection::open_with_flags(
            f.path.join("process.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let calls: u32 = journal.query_row(
            "SELECT tree_calls FROM processes WHERE id='root'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(calls, 2);
    }
    Ok(())
}

#[tokio::test]
async fn recovery_current_preview_clearance_does_not_leak_the_retained_payload() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let store = f.authority.admission_operation_store();
    let mut deployment =
        store.deployment(f.runtime.scope(), &f.authority.mutation_fence(), now_ms()?)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let error = f
        .runtime
        .review_document(&f.control, &id)
        .err()
        .ok_or("preview leaked")?;
    assert!(!error.to_string().contains("canary"));
    assert!(f.record(&id).is_err());
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}
#[tokio::test]
async fn recovery_constrained_control_tokens_cannot_skip_their_enforcement() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let command = f.command(
        "inspect-control-profile",
        RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: id.clone(),
        },
    )?;
    f.runtime.execute_command(&f.control, &command).await?;
    let before = f.record(&id)?;
    for mutation in 0..5 {
        let mut scope = f.control.scope.clone();
        let grant = scope
            .grants
            .iter_mut()
            .find(|grant| grant.tool_name == "inspect")
            .ok_or("inspect grant")?;
        match mutation {
            0 => grant.dpop_required = Some(true),
            1 => grant.max_invocations = Some(1),
            2 => {
                grant.max_cost_per_invocation =
                    Some(chio_core_types::capability::scope::MonetaryAmount {
                        units: 1,
                        currency: "USD".into(),
                    })
            }
            3 => {
                grant.max_total_cost = Some(chio_core_types::capability::scope::MonetaryAmount {
                    units: 1,
                    currency: "USD".into(),
                })
            }
            4 => {
                // A second unrestricted grant cannot erase a matching grant's
                // sender proof or budget obligation by changing its order.
                let mut constrained = grant.clone();
                constrained.dpop_required = Some(true);
                scope.grants.push(constrained);
            }
            _ => return Err("unknown control mutation".into()),
        }
        let token = f.kernel.issue_capability(&f.control.subject, scope, 1200)?;
        assert!(token.verify_signature()?);
        assert!(matches!(
            f.runtime.execute_command(&token, &command).await,
            Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
        ));
        assert_eq!(f.record(&id)?.revision, before.revision);
        assert_eq!(external_count(&f.path)?, 0);
        assert_eq!(f.process.process("root")?.tree_calls, 2);
    }
    Ok(())
}
