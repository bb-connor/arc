//! Store operations the kernel performs while authorizing one tool call,
//! measured against a populated database.
//!
//! Each group populates its tables to `POPULATED_ROWS` before the first
//! measured iteration. An empty table measures index descent that production
//! never performs, so the populated state is part of the measurement rather
//! than setup convenience.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_kernel::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetEventAuthority,
    BudgetReleaseHoldRequest,
};
use chio_kernel::{
    AdmissionOperation, AdmissionOperationCreateOutcome, AdmissionOperationKind,
    AdmissionOperationStore, BudgetStore, PreparedAdmissionOperation,
};
use chio_security_types::ports::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    empty_capability_set_suspension_snapshot, predict_capability_set_suspension_apply,
    response_affected_set_hash, ActionId, CanonicalBody, CapabilitySetSuspensionApplyRequest,
    CapabilitySetSuspensionCommand, CapabilitySetSuspensionContribution,
    CapabilitySetSuspensionKey, CapabilitySetSuspensionSpec, CapabilitySetSuspensionStore,
    CapabilitySuspensionQuery, Digest32, EffectId, EffectOperation, EffectRequest, EffectResult,
    LeaseOwnerId, RecordId, RecordIdSet, ResponsePlanRecord, ResponseStore, SchedulerClaimRequest,
    TenantId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};
use chio_store_sqlite::{
    SqliteBudgetStore, SqliteSecurityAdmissionOperationStore, SqliteSecurityStateStore,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Rows each store carries before its first measured iteration.
const POPULATED_ROWS: usize = 20_000;

/// Capability grants the populated budget rows spread across, so the measured
/// authorize lands in an index of realistic depth rather than on one hot row.
const POPULATED_CAPABILITIES: usize = 512;

/// Suspension records the populated security state carries. The scheduler admits
/// one claimed plan per record, so this group populates to a lower count than
/// the append-only tables.
const POPULATED_SUSPENSIONS: usize = 2_000;

/// Plans the scheduler will hand out in one claim, which is its own ceiling.
const SCHEDULER_CLAIM_BATCH: u32 = 1_024;

const SUSPENSION_TENANT: &str = "tenant-authorization-bench";

fn fail_bench(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

fn unique_db_path(prefix: &str) -> PathBuf {
    let nonce = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_nanos(),
        Err(error) => fail_bench(&format!("time before epoch: {error}")),
    };
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn now_unix_ms() -> u64 {
    let elapsed = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed,
        Err(error) => fail_bench(&format!("time before epoch: {error}")),
    };
    match u64::try_from(elapsed.as_millis()) {
        Ok(millis) => millis,
        Err(error) => fail_bench(&format!("clock out of range: {error}")),
    }
}

fn bench_authority() -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: "bench-budget-authority".to_string(),
        lease_id: "bench-budget-lease".to_string(),
        lease_epoch: 1,
    }
}

fn bench_capability(index: usize) -> String {
    format!("bench-capability-{}", index % POPULATED_CAPABILITIES)
}

fn authorize_request(index: usize) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: bench_capability(index),
        grant_index: 0,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(100),
        hold_id: Some(format!("bench-hold-{index}")),
        event_id: Some(format!("bench-authorize-{index}")),
        authority: Some(bench_authority()),
    }
}

fn release_request(index: usize) -> BudgetReleaseHoldRequest {
    BudgetReleaseHoldRequest {
        capability_id: bench_capability(index),
        grant_index: 0,
        released_exposure_units: 100,
        hold_id: Some(format!("bench-hold-{index}")),
        event_id: Some(format!("bench-release-{index}")),
        authority: Some(bench_authority()),
    }
}

fn charge_and_release(store: &SqliteBudgetStore, index: usize) {
    match store.authorize_budget_hold(authorize_request(index)) {
        Ok(BudgetAuthorizeHoldDecision::Authorized(hold)) => {
            black_box(hold);
        }
        Ok(other) => fail_bench(&format!("budget hold was not authorized: {other:?}")),
        Err(error) => fail_bench(&format!("authorize budget hold: {error}")),
    }
    if let Err(error) = store.release_budget_hold(release_request(index)) {
        fail_bench(&format!("release budget hold: {error}"));
    }
}

fn bench_budget_charge_release(c: &mut Criterion) {
    let path = unique_db_path("chio-bench-budget-charge-release");
    let store = match SqliteBudgetStore::open(&path) {
        Ok(store) => store,
        Err(error) => fail_bench(&format!("open sqlite budget store: {error}")),
    };
    for index in 0..POPULATED_ROWS {
        charge_and_release(&store, index);
    }

    let mut index = POPULATED_ROWS;
    c.bench_function("budget_charge_release_pair_populated", |b| {
        b.iter(|| {
            charge_and_release(&store, index);
            index += 1;
        });
    });

    drop(store);
    let _ = std::fs::remove_file(path);
}

fn admission_operation(index: usize) -> AdmissionOperation {
    let prepared = PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: "bench-coordinator".to_string(),
        request_id: format!("bench-request-{index}"),
        capability_id: bench_capability(index),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: "33".repeat(32),
        broker_attempt_id: Some(format!("bench-attempt-{index}")),
        budget_hold_id: Some(format!("bench-admission-hold-{index}")),
        approval_set_hash: Some("44".repeat(32)),
        execution_nonce_id: Some(format!("bench-nonce-{index}")),
        coordinator_lease_epoch: 1,
    };
    match AdmissionOperation::prepared(prepared) {
        Ok(operation) => operation,
        Err(error) => fail_bench(&format!("prepare admission operation: {error}")),
    }
}

fn record_admission_operation(store: &SqliteSecurityAdmissionOperationStore, index: usize) {
    match store.create_prepared(admission_operation(index)) {
        Ok(AdmissionOperationCreateOutcome::Created(operation)) => {
            black_box(operation);
        }
        Ok(other) => fail_bench(&format!("admission operation already existed: {other:?}")),
        Err(error) => fail_bench(&format!("create prepared admission operation: {error}")),
    }
}

fn bench_admission_operation_record_and_read(c: &mut Criterion) {
    let path = unique_db_path("chio-bench-admission-operation");
    let store = match SqliteSecurityAdmissionOperationStore::open(&path) {
        Ok(store) => store,
        Err(error) => fail_bench(&format!("open sqlite admission operation store: {error}")),
    };
    for index in 0..POPULATED_ROWS {
        record_admission_operation(&store, index);
    }

    let mut index = POPULATED_ROWS;
    c.bench_function("admission_operation_record_populated", |b| {
        b.iter(|| {
            record_admission_operation(&store, index);
            index += 1;
        });
    });

    let recorded = admission_operation(POPULATED_ROWS / 2);
    c.bench_function("admission_operation_read_populated", |b| {
        b.iter(|| match store.load(recorded.operation_id()) {
            Ok(Some(operation)) => {
                black_box(operation);
            }
            Ok(None) => fail_bench("populated admission operation is missing"),
            Err(error) => fail_bench(&format!("load admission operation: {error}")),
        });
    });

    drop(store);
    let _ = std::fs::remove_file(path);
}

fn suspension_tenant() -> TenantId {
    match TenantId::new(SUSPENSION_TENANT) {
        Ok(tenant) => tenant,
        Err(error) => fail_bench(&format!("tenant id: {error}")),
    }
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn suspended_capability(index: usize) -> RecordId {
    match RecordId::new(format!("bench-suspended-capability-{index}")) {
        Ok(record) => record,
        Err(error) => fail_bench(&format!("record id: {error}")),
    }
}

fn suspension_key(affected: &RecordIdSet) -> CapabilitySetSuspensionKey {
    let tenant_id = suspension_tenant();
    let affected_set_hash = match response_affected_set_hash(&tenant_id, affected) {
        Ok(hash) => hash,
        Err(error) => fail_bench(&format!("affected set hash: {error}")),
    };
    CapabilitySetSuspensionKey {
        tenant_id,
        affected_set_hash,
    }
}

/// Install `POPULATED_SUSPENSIONS` capability-set suspensions, each covering one
/// capability, and return a capability the denial path must refuse.
fn populate_suspensions(path: &Path) -> (SqliteSecurityStateStore, RecordId) {
    let store = match SqliteSecurityStateStore::open(path) {
        Ok(store) => store,
        Err(error) => fail_bench(&format!("open sqlite security state store: {error}")),
    };
    let tenant_id = suspension_tenant();
    let now = now_unix_ms();

    let actions: Vec<ActionId> = (0..POPULATED_SUSPENSIONS)
        .map(
            |index| match ActionId::new(format!("bench-suspension-{index}")) {
                Ok(action) => action,
                Err(error) => fail_bench(&format!("action id: {error}")),
            },
        )
        .collect();
    for action_id in &actions {
        let canonical_body = match CanonicalBody::new(b"{}".to_vec()) {
            Ok(body) => body,
            Err(error) => fail_bench(&format!("response plan body: {error}")),
        };
        let plan = ResponsePlanRecord {
            tenant_id: tenant_id.clone(),
            action_id: action_id.clone(),
            generation: 0,
            state: match RecordId::new("active") {
                Ok(state) => state,
                Err(error) => fail_bench(&format!("plan state: {error}")),
            },
            body_hash: digest(canonical_body.as_bytes()),
            canonical_body,
            due_at_unix_ms: Some(now.saturating_sub(1)),
        };
        if let Err(error) = store.create(&plan) {
            fail_bench(&format!("create response plan: {error}"));
        }
    }

    let lease_owner_id = match LeaseOwnerId::new("bench-suspension-worker") {
        Ok(owner) => owner,
        Err(error) => fail_bench(&format!("lease owner: {error}")),
    };
    let mut work = Vec::with_capacity(actions.len());
    let mut batch = 0_usize;
    while work.len() < actions.len() {
        let claim_id = match RecordId::new(format!("bench-suspension-claim-{batch}")) {
            Ok(record) => record,
            Err(error) => fail_bench(&format!("claim id: {error}")),
        };
        // The scheduler rejects a claim whose clock has drifted from the store's,
        // and populating this many plans takes longer than that tolerance, so the
        // claim time is read again for each batch.
        let claimed_at = now_unix_ms();
        let claimed = match store.claim_due(&SchedulerClaimRequest {
            tenant_id: tenant_id.clone(),
            claim_id,
            lease_owner_id: lease_owner_id.clone(),
            now_unix_ms: claimed_at,
            lease_expires_at_unix_ms: claimed_at.saturating_add(3_600_000),
            max_claims: SCHEDULER_CLAIM_BATCH,
        }) {
            Ok(claimed) => claimed,
            Err(error) => fail_bench(&format!("claim response plans: {error}")),
        };
        if claimed.is_empty() {
            fail_bench(&format!(
                "scheduler claimed {} of {} response plans",
                work.len(),
                actions.len()
            ));
        }
        work.extend(claimed);
        batch += 1;
    }

    for (index, scheduled) in work.iter().enumerate() {
        let capability = suspended_capability(index);
        let affected = match RecordIdSet::new(vec![capability.clone()]) {
            Ok(set) => set,
            Err(error) => fail_bench(&format!("affected set: {error}")),
        };
        let key = suspension_key(&affected);
        let current = match empty_capability_set_suspension_snapshot(key) {
            Ok(snapshot) => snapshot,
            Err(error) => fail_bench(&format!("empty suspension snapshot: {error}")),
        };
        let request = suspension_apply_request(
            &current,
            scheduled.action_id.clone(),
            affected,
            scheduled.fencing_token,
            index,
            &lease_owner_id,
        );
        if let Err(error) = store.apply_capability_set_suspension(&request) {
            fail_bench(&format!("apply capability set suspension: {error}"));
        }
    }

    (store, suspended_capability(POPULATED_SUSPENSIONS / 2))
}

fn suspension_apply_request(
    current: &chio_security_types::ports::CapabilitySetSuspensionSnapshot,
    action_id: ActionId,
    affected_ids: RecordIdSet,
    scheduler_fencing_token: u64,
    index: usize,
    scheduler_lease_owner_id: &LeaseOwnerId,
) -> CapabilitySetSuspensionApplyRequest {
    let spec = CapabilitySetSuspensionSpec {
        affected_ids: affected_ids.clone(),
    };
    let contribution_bytes = match canonical_json_bytes(&spec) {
        Ok(bytes) => bytes,
        Err(error) => fail_bench(&format!("canonical suspension contribution: {error}")),
    };
    let contribution_hash = digest(&contribution_bytes);
    let expires_at_unix_ms = now_unix_ms().saturating_add(600_000);
    let effect_id = match EffectId::new(format!("bench-suspension-effect-{index}")) {
        Ok(effect) => effect,
        Err(error) => fail_bench(&format!("effect id: {error}")),
    };
    let idempotency_key = match RecordId::new(format!("response_effect_command:bench-{index}")) {
        Ok(record) => record,
        Err(error) => fail_bench(&format!("idempotency key: {error}")),
    };
    let canonical_contribution = match CanonicalBody::new(contribution_bytes) {
        Ok(body) => body,
        Err(error) => fail_bench(&format!("suspension contribution body: {error}")),
    };
    let expected_version_hash = match capability_set_suspension_version_hash(current) {
        Ok(hash) => hash,
        Err(error) => fail_bench(&format!("base suspension version: {error}")),
    };
    let request = EffectRequest {
        tenant_id: suspension_tenant(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("bench-plan-{index}").as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendCapabilitySet,
        target: ResponseTarget::CapabilitySet {
            affected_set_hash: current.key.affected_set_hash,
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key,
        expected_version_hash,
        scheduler_lease_owner_id: scheduler_lease_owner_id.clone(),
        scheduler_fencing_token,
        canonical_contribution,
        contribution_hash,
    };
    let contribution = CapabilitySetSuspensionContribution {
        action_id,
        effect_id: effect_id.clone(),
        affected_ids,
        contribution_hash,
        expires_at_unix_ms,
    };
    let resulting_snapshot = match predict_capability_set_suspension_apply(
        current,
        &contribution,
        scheduler_fencing_token,
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => fail_bench(&format!("predict suspension apply: {error}")),
    };
    let resulting_version_hash =
        match capability_set_suspension_installed_version_hash(&current.key, &contribution) {
            Ok(hash) => hash,
            Err(error) => fail_bench(&format!("installed suspension version: {error}")),
        };
    CapabilitySetSuspensionApplyRequest {
        key: current.key.clone(),
        contribution,
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: CapabilitySetSuspensionCommand {
            request,
            result: EffectResult {
                effect_id,
                resulting_version_hash,
                applied: true,
            },
            resulting_snapshot,
        },
    }
}

fn bench_security_state_denial_read(c: &mut Criterion) {
    let path = unique_db_path("chio-bench-security-state-denial");
    let (store, suspended) = populate_suspensions(&path);
    let tenant_id = suspension_tenant();

    let denied_query = CapabilitySuspensionQuery {
        tenant_id: tenant_id.clone(),
        capability_id: suspended,
    };
    let allowed_query = CapabilitySuspensionQuery {
        tenant_id,
        capability_id: match RecordId::new("bench-unsuspended-capability") {
            Ok(record) => record,
            Err(error) => fail_bench(&format!("record id: {error}")),
        },
    };

    c.bench_function("security_state_denial_read_populated", |b| {
        b.iter(
            || match store.evaluate_capability_suspension(&denied_query) {
                Ok(decision) => {
                    if !decision.denied {
                        fail_bench("populated suspension did not deny");
                    }
                    black_box(decision);
                }
                Err(error) => fail_bench(&format!("evaluate capability suspension: {error}")),
            },
        );
    });

    c.bench_function("security_state_allow_read_populated", |b| {
        b.iter(
            || match store.evaluate_capability_suspension(&allowed_query) {
                Ok(decision) => {
                    if decision.denied {
                        fail_bench("unsuspended capability was denied");
                    }
                    black_box(decision);
                }
                Err(error) => fail_bench(&format!("evaluate capability suspension: {error}")),
            },
        );
    });

    drop(store);
    let _ = std::fs::remove_file(path);
}

criterion_group!(
    benches,
    bench_budget_charge_release,
    bench_admission_operation_record_and_read,
    bench_security_state_denial_read
);
criterion_main!(benches);
