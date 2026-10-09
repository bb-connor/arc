use super::*;

const LIVE_SET_CAP: usize = 1024;

struct Applied {
    apply: CapabilitySetSuspensionApplyRequest,
    snapshot: CapabilitySetSuspensionSnapshot,
}

fn apply_set(
    store: &SqliteSecurityStateStore,
    work: &[ScheduledWork],
    action_id: &ActionId,
    index: usize,
) -> Applied {
    let member = format!("historical-capability-{index}");
    let affected_ids = affected(&[member.as_str()]);
    let empty = empty_capability_set_suspension_snapshot(key(&affected_ids))
        .unwrap_or_else(|error| panic!("empty snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect(&format!("historical-effect-{index}")),
        affected_ids,
        &empty,
        work_for(work, action_id).fencing_token,
        &format!("historical-apply-{index}"),
    );
    let snapshot = store
        .apply_capability_set_suspension(&apply)
        .unwrap_or_else(|error| panic!("apply set {index}: {error}"));
    Applied { apply, snapshot }
}

fn lift_set(
    store: &SqliteSecurityStateStore,
    work: &[ScheduledWork],
    applied: &Applied,
    index: usize,
) {
    let remove = remove_request(
        &applied.apply,
        &applied.snapshot,
        work_for(work, &applied.apply.contribution.action_id).fencing_token,
        &format!("historical-remove-{index}"),
    );
    store
        .remove_capability_set_suspension(&remove)
        .unwrap_or_else(|error| panic!("lift set {index}: {error}"));
}

type Opened = (
    tempfile::TempDir,
    SqliteSecurityStateStore,
    Vec<ScheduledWork>,
    ActionId,
);

fn open(name: &str) -> Opened {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join(name);
    let action_id = action("historical-action");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    (directory, store, work, action_id)
}

#[test]
fn lifted_sets_stop_counting_against_the_lookup_budget() {
    let (_directory, store, work, action_id) = open("historical-lifted.db");
    for index in 0..=LIVE_SET_CAP {
        let applied = apply_set(&store, &work, &action_id, index);
        lift_set(&store, &work, &applied, index);
    }
    let result = store.evaluate_capability_suspension(&CapabilitySuspensionQuery {
        tenant_id: tenant(),
        capability_id: record("historical-capability-0"),
    });
    let decision = result.unwrap_or_else(|error| panic!("lookup after history: {error}"));
    assert!(!decision.denied);
    assert!(decision.active_matches.is_empty());
}

#[test]
fn more_live_sets_than_the_cap_still_refuse() {
    let (_directory, store, work, action_id) = open("historical-live.db");
    for index in 0..LIVE_SET_CAP {
        apply_set(&store, &work, &action_id, index);
    }
    assert!(!decision(&store, "unrelated").denied);
    apply_set(&store, &work, &action_id, LIVE_SET_CAP);
    let refusal = require_error(
        store.evaluate_capability_suspension(&CapabilitySuspensionQuery {
            tenant_id: tenant(),
            capability_id: record("unrelated"),
        }),
    );
    assert_eq!(refusal.kind(), PortErrorKind::Unavailable);
    assert_eq!(
        refusal.code().as_str(),
        "store.suspension_lookup_budget_exhausted"
    );
}

#[test]
fn active_suspension_among_many_lifted_sets_is_enforced() {
    let (_directory, store, work, action_id) = open("historical-mixed.db");
    for index in 0..LIVE_SET_CAP {
        let applied = apply_set(&store, &work, &action_id, index);
        lift_set(&store, &work, &applied, index);
    }
    apply_set(&store, &work, &action_id, LIVE_SET_CAP + 1);
    let live = decision(
        &store,
        &format!("historical-capability-{}", LIVE_SET_CAP + 1),
    );
    assert!(live.denied);
    assert_eq!(live.active_matches.len(), 1);
    assert!(!decision(&store, "historical-capability-3").denied);
}

#[test]
fn stale_apply_cannot_resurrect_a_lifted_set() {
    let (_directory, store, work, action_id) = open("historical-replay.db");
    let applied = apply_set(&store, &work, &action_id, 0);
    lift_set(&store, &work, &applied, 0);
    assert!(!decision(&store, "historical-capability-0").denied);

    let mut stale = applied.apply.clone();
    stale.command.request.idempotency_key = record("response_effect_command:historical-stale");
    assert_eq!(
        require_error(store.apply_capability_set_suspension(&stale)).kind(),
        PortErrorKind::Conflict
    );
    let _ = store.apply_capability_set_suspension(&applied.apply);
    assert!(!decision(&store, "historical-capability-0").denied);
}
