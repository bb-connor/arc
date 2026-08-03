use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, predict_containment_overlay_apply,
    predict_containment_overlay_remove, ActionId, CanonicalBody, ContainmentOverlayCommand,
    ContainmentOverlayStore, Digest32, EffectExecutionStatus, EffectId, EffectOperation,
    EffectRequest, EffectResult, EffectResultQuery, LeaseOwnerId, OverlayApplyRequest,
    OverlayContribution, OverlayContributions, OverlayRemoveRequest, OverlaySnapshot, RecordId,
    ResponsePlanRecord, ResponseStore, SchedulerClaimRequest, SessionId, TenantId, TenantScopedId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};
use chio_store_sqlite::security_state::{ActiveDefenseOverlayInventory, SqliteSecurityStateStore};

fn now_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before Unix epoch: {error}"));
    u64::try_from(elapsed.as_millis()).unwrap_or_else(|error| panic!("clock range: {error}"))
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn tenant() -> TenantId {
    TenantId::new("tenant-host-lifecycle").unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn target() -> TenantScopedId {
    containment_session_target(
        &tenant(),
        &SessionId::new("session-host-lifecycle")
            .unwrap_or_else(|error| panic!("session: {error}")),
    )
    .unwrap_or_else(|error| panic!("target: {error}"))
}

fn empty_snapshot() -> OverlaySnapshot {
    OverlaySnapshot {
        target: target(),
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())
            .unwrap_or_else(|error| panic!("contributions: {error}")),
        highest_fencing_token: 0,
    }
}

fn install_containment(
    path: &Path,
) -> (
    SqliteSecurityStateStore,
    OverlayRemoveRequest,
    EffectResultQuery,
) {
    let store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    let now = now_unix_ms();
    let action_id =
        ActionId::new("action-host-lifecycle").unwrap_or_else(|error| panic!("action: {error}"));
    let body =
        CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan body: {error}"));
    store
        .create(&ResponsePlanRecord {
            tenant_id: tenant(),
            action_id: action_id.clone(),
            generation: 0,
            state: RecordId::new("active").unwrap_or_else(|error| panic!("state: {error}")),
            body_hash: digest(body.as_bytes()),
            canonical_body: body,
            due_at_unix_ms: Some(now.saturating_sub(1)),
        })
        .unwrap_or_else(|error| panic!("create plan: {error}"));
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant(),
            claim_id: RecordId::new("claim-host-lifecycle")
                .unwrap_or_else(|error| panic!("claim: {error}")),
            lease_owner_id: LeaseOwnerId::new("worker-host-lifecycle")
                .unwrap_or_else(|error| panic!("owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(120_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("claim plan: {error}"));
    let claimed_work = work
        .first()
        .unwrap_or_else(|| panic!("claimed work missing"));
    let fencing_token = claimed_work.fencing_token;
    let effect_id =
        EffectId::new("effect-host-lifecycle").unwrap_or_else(|error| panic!("effect: {error}"));
    let contribution_bytes = b"{\"posture_rank\":3}".to_vec();
    let contribution_hash = digest(&contribution_bytes);
    let expires_at_unix_ms = now.saturating_add(120_000);
    let current = empty_snapshot();
    let contribution = OverlayContribution {
        effect_id: effect_id.clone(),
        posture_rank: 3,
        contribution_hash,
        expires_at_unix_ms: Some(expires_at_unix_ms),
    };
    let request = EffectRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        plan_hash: digest(b"plan-host-lifecycle"),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendSession,
        target: ResponseTarget::Session {
            session_id: SessionId::new("session-host-lifecycle")
                .unwrap_or_else(|error| panic!("session: {error}")),
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: RecordId::new("response_effect_command:host-lifecycle-apply")
            .unwrap_or_else(|error| panic!("idempotency key: {error}")),
        expected_version_hash: containment_overlay_version_hash(&current)
            .unwrap_or_else(|error| panic!("current version: {error}")),
        scheduler_lease_owner_id: claimed_work.lease_owner_id.clone(),
        scheduler_fencing_token: fencing_token,
        canonical_contribution: CanonicalBody::new(contribution_bytes)
            .unwrap_or_else(|error| panic!("contribution body: {error}")),
        contribution_hash,
    };
    let resulting_snapshot =
        predict_containment_overlay_apply(&current, &contribution, fencing_token)
            .unwrap_or_else(|error| panic!("predict apply: {error}"));
    let apply = OverlayApplyRequest {
        target: current.target.clone(),
        action_id: action_id.clone(),
        contribution: contribution.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token: fencing_token,
        command: ContainmentOverlayCommand {
            request: request.clone(),
            result: EffectResult {
                effect_id: effect_id.clone(),
                resulting_version_hash: containment_installed_version_hash(
                    &current.target,
                    &contribution,
                )
                .unwrap_or_else(|error| panic!("installed version: {error}")),
                applied: true,
            },
            resulting_snapshot,
        },
    };
    let applied = store
        .apply_contribution(&apply)
        .unwrap_or_else(|error| panic!("apply contribution: {error}"));
    let mut remove_request = request.clone();
    remove_request.operation = EffectOperation::Remove;
    remove_request.idempotency_key = RecordId::new("response_effect_command:host-lifecycle-remove")
        .unwrap_or_else(|error| panic!("remove idempotency key: {error}"));
    remove_request.expected_version_hash = apply.command.result.resulting_version_hash;
    remove_request.scheduler_fencing_token = fencing_token;
    let removed_snapshot = predict_containment_overlay_remove(&applied, &effect_id, fencing_token)
        .unwrap_or_else(|error| panic!("predict remove: {error}"));
    let remove = OverlayRemoveRequest {
        target: apply.target,
        action_id,
        effect_id: effect_id.clone(),
        expected_generation: applied.generation,
        scheduler_fencing_token: fencing_token,
        command: ContainmentOverlayCommand {
            request: remove_request,
            result: EffectResult {
                effect_id,
                resulting_version_hash: containment_overlay_version_hash(&removed_snapshot)
                    .unwrap_or_else(|error| panic!("removed version: {error}")),
                applied: false,
            },
            resulting_snapshot: removed_snapshot,
        },
    };
    let query = EffectResultQuery {
        tenant_id: request.tenant_id,
        action_id: request.action_id,
        plan_hash: request.plan_hash,
        effect_id: request.effect_id,
        effect_kind: request.effect_kind,
        target: request.target,
        plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
        operation: request.operation,
        idempotency_key: request.idempotency_key,
        expected_version_hash: request.expected_version_hash,
        contribution_hash: request.contribution_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id,
        scheduler_fencing_token: request.scheduler_fencing_token,
    };
    (store, remove, query)
}

#[test]
fn overlay_inventory_is_exact_across_restart_and_preserves_command_history() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory
        .path()
        .join("active-defense-overlay-inventory.sqlite");
    let (store, remove, apply_query) = install_containment(&path);

    assert_eq!(
        store
            .active_defense_overlay_inventory()
            .unwrap_or_else(|error| panic!("inventory: {error}")),
        ActiveDefenseOverlayInventory {
            containment_contributions: 1,
            session_throttle_contributions: 0,
            capability_suspension_contributions: 0,
            issuance_freeze_contributions: 0,
            egress_restriction_contributions: 0,
        }
    );
    drop(store);

    let restarted = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("restart security store: {error}"));
    assert!(restarted
        .active_defense_overlay_inventory()
        .unwrap_or_else(|error| panic!("restart inventory: {error}"))
        .has_active_contributions());
    restarted
        .remove_contribution(&remove)
        .unwrap_or_else(|error| panic!("remove contribution: {error}"));
    assert_eq!(
        restarted
            .active_defense_overlay_inventory()
            .unwrap_or_else(|error| panic!("empty inventory: {error}")),
        ActiveDefenseOverlayInventory::default()
    );
    assert!(matches!(
        restarted
            .load_containment_overlay_result(&apply_query)
            .unwrap_or_else(|error| panic!("load preserved command: {error}")),
        EffectExecutionStatus::Completed { .. }
    ));
}
