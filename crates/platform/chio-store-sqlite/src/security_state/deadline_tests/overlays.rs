use super::*;
use chio_security_types::ports::PortErrorKind;

fn apply_request(work: &ScheduledWork) -> TestResult<OverlayApplyRequest> {
    let session = SessionId::new("session")?;
    let target = containment_session_target(&work.tenant_id, &session)?;
    let current = OverlaySnapshot {
        target: target.clone(),
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())?,
        highest_fencing_token: 0,
    };
    let body = b"{\"posture_rank\":1}";
    let mut hash = [0; 32];
    hash.copy_from_slice(sha256(body).as_ref());
    let contribution = OverlayContribution {
        effect_id: EffectId::new("effect")?,
        posture_rank: 1,
        contribution_hash: Digest32::new(hash),
        expires_at_unix_ms: Some(3_000),
    };
    let request = EffectRequest {
        tenant_id: work.tenant_id.clone(),
        action_id: work.action_id.clone(),
        plan_hash: Digest32::new([3; 32]),
        effect_id: contribution.effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendSession,
        target: ResponseTarget::Session {
            session_id: session,
        },
        plan_expires_at_unix_ms: 3_000,
        operation: EffectOperation::Apply,
        idempotency_key: RecordId::new("response_effect_command:apply")?,
        expected_version_hash: containment_overlay_version_hash(&current)?,
        scheduler_lease_owner_id: work.lease_owner_id.clone(),
        scheduler_fencing_token: work.fencing_token,
        canonical_contribution: CanonicalBody::new(body.to_vec())?,
        contribution_hash: contribution.contribution_hash,
    };
    let command = ContainmentOverlayCommand {
        request,
        result: EffectResult {
            effect_id: contribution.effect_id.clone(),
            resulting_version_hash: containment_installed_version_hash(&target, &contribution)?,
            applied: true,
        },
        resulting_snapshot: predict_containment_overlay_apply(
            &current,
            &contribution,
            work.fencing_token,
        )?,
    };
    Ok(OverlayApplyRequest {
        target,
        action_id: work.action_id.clone(),
        contribution,
        expected_generation: 0,
        scheduler_fencing_token: work.fencing_token,
        command,
    })
}

#[test]
fn overlay_apply_checks_current_scheduler_time_after_write_wait() -> TestResult {
    for now in [1_499, 1_500] {
        let fixture = Fixture::new()?;
        let work = fixture
            .store
            .claim_due(&fixture.scheduler_request()?)?
            .remove(0);
        let apply = apply_request(&work)?;
        let result =
            fixture.after_database_wait(false, now, |store| store.apply_contribution(&apply))?;
        if now == 1_499 {
            assert_eq!(result?, apply.command.resulting_snapshot);
        } else {
            assert_kind(result, PortErrorKind::Conflict);
            assert!(fixture.store.load_effective(&apply.target)?.is_none());
        }
    }
    Ok(())
}

#[test]
fn overlay_removal_checks_current_scheduler_time_after_write_wait() -> TestResult {
    for now in [1_499, 1_500] {
        let fixture = Fixture::new()?;
        let work = fixture
            .store
            .claim_due(&fixture.scheduler_request()?)?
            .remove(0);
        let apply = apply_request(&work)?;
        let installed = fixture.store.apply_contribution(&apply)?;
        let resulting_snapshot = predict_containment_overlay_remove(
            &installed,
            &apply.contribution.effect_id,
            work.fencing_token,
        )?;
        let mut command = apply.command.clone();
        command.request.operation = EffectOperation::Remove;
        command.request.idempotency_key = RecordId::new("response_effect_command:remove")?;
        command.request.expected_version_hash = command.result.resulting_version_hash;
        command.result.applied = false;
        command.result.resulting_version_hash =
            containment_overlay_version_hash(&resulting_snapshot)?;
        command.resulting_snapshot = resulting_snapshot.clone();
        let remove = OverlayRemoveRequest {
            target: apply.target.clone(),
            action_id: work.action_id,
            effect_id: apply.contribution.effect_id,
            expected_generation: installed.generation,
            scheduler_fencing_token: work.fencing_token,
            command,
        };
        let result =
            fixture.after_database_wait(false, now, |store| store.remove_contribution(&remove))?;
        if now == 1_499 {
            assert_eq!(result?, resulting_snapshot);
        } else {
            assert_kind(result, PortErrorKind::Conflict);
            assert_eq!(
                fixture.store.load_effective(&apply.target)?,
                Some(installed)
            );
        }
    }
    Ok(())
}
