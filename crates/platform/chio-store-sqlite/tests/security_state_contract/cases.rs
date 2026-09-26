use super::*;

#[test]
fn cross_key_flow_contract_holds_for_in_memory_model() {
    exercise_cross_key_flow_contract(&ModelStore::default());
}

#[test]
fn cross_key_flow_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("flow-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_cross_key_flow_contract(&store);
}

#[test]
fn scheduler_takeover_contract_holds_for_in_memory_model() {
    exercise_scheduler_takeover_contract(&ModelStore::default());
}

#[test]
fn scheduler_takeover_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("scheduler-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_scheduler_takeover_contract(&store);
}

#[test]
fn response_effect_recovery_contract_holds_for_in_memory_model() {
    exercise_response_effect_recovery_contract(&ModelStore::default());
}

#[test]
fn response_effect_recovery_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("effect-recovery.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_response_effect_recovery_contract(&store);
}

#[test]
fn overlay_action_binding_contract_holds_for_in_memory_model() {
    exercise_overlay_action_binding_contract(&ModelStore::default());
}

#[test]
fn overlay_action_binding_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("overlay-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_overlay_action_binding_contract(&store);
}

#[test]
fn durable_write_contracts_hold_for_in_memory_model() {
    let store = Faulting::new(ModelStore::default());
    exercise_contracts(&store);
}

#[test]
fn durable_write_contracts_hold_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("security-contract.db");
    let sqlite = SqliteSecurityStateStore::open_with_isolation_epoch_verifier(
        &path,
        Arc::new(AcceptIsolationEvidence),
    )
    .unwrap_or_else(|error| panic!("open security store: {error}"));
    let store = Faulting::new(sqlite);
    exercise_contracts(&store);
}
