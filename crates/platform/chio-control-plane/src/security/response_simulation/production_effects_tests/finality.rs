use chio_security_types::ports::{EffectExecutionStatus, EffectResult};
use rusqlite::types::Value;

use super::*;

mod migration;
mod tenant_isolation;

const REMOVABLE_KINDS: [ResponseEffectKind; 4] = [
    ResponseEffectKind::SuspendSession,
    ResponseEffectKind::RestrictEgress,
    ResponseEffectKind::ThrottleSession,
    ResponseEffectKind::SuspendCapabilitySet,
];

struct FinalityCase {
    fixture: ProductionEffectsFixture,
    effects: Arc<dyn EffectPort>,
    plan: ResponsePlan,
    work: ScheduledWork,
    ordinal: usize,
    session_id: SessionId,
}

struct RemovedEffect {
    apply: EffectRequest,
    applied: EffectResult,
    remove: EffectRequest,
    removed: EffectResult,
}

impl FinalityCase {
    fn new(kind: ResponseEffectKind, label: &str) -> Self {
        let fixture = ProductionEffectsFixture::new();
        let session_id = session(&format!("finality-{label}-session"));
        let (plan, work, ordinal) = Self::dispatch(&fixture, kind, &session_id, label);
        let effects = fixture.effects();
        if ordinal == 1 {
            let freeze = effects
                .execute(&effect_request(
                    &plan,
                    &plan.effects.as_slice()[0],
                    &work,
                    &format!("{label}-freeze"),
                ))
                .unwrap_or_else(|error| panic!("leading freeze: {error}"));
            assert!(freeze.applied, "the real leading freeze must hold");
        }
        Self {
            fixture,
            effects,
            plan,
            work,
            ordinal,
            session_id,
        }
    }

    fn dispatch(
        fixture: &ProductionEffectsFixture,
        kind: ResponseEffectKind,
        session_id: &SessionId,
        label: &str,
    ) -> (ResponsePlan, ScheduledWork, usize) {
        let action = format!("finality-{label}-action");
        let spec = match kind {
            ResponseEffectKind::SuspendSession => fixture.session_suspension_spec(session_id),
            ResponseEffectKind::RestrictEgress => fixture.egress_spec(session_id, &["server-a"]),
            ResponseEffectKind::ThrottleSession => ResponseEffectSpec {
                observed_base_version_hash: throttle_version(
                    &fixture.store,
                    &SessionThrottleKey {
                        tenant_id: tenant(),
                        session_id: session_id.clone(),
                    },
                ),
                ..fixture.throttle_spec(session_id)
            },
            ResponseEffectKind::SuspendCapabilitySet => {
                let mut spec =
                    fixture.capability_set_spec(&["capability-child", "capability-root"]);
                let ResponseTarget::CapabilitySet { affected_set_hash } = spec.target else {
                    panic!("capability-set target missing");
                };
                spec.observed_base_version_hash = capability_set_version(
                    &fixture.store,
                    &CapabilitySetSuspensionKey {
                        tenant_id: tenant(),
                        affected_set_hash,
                    },
                );
                spec
            }
            _ => panic!("finality case requires a removable overlay kind"),
        };
        let (affected, specs, ordinal) = if kind == ResponseEffectKind::SuspendCapabilitySet {
            (
                vec![record("capability-child"), record("capability-root")],
                vec![fixture.live_freeze_spec(&action), spec],
                1,
            )
        } else {
            (vec![record(session_id.as_str())], vec![spec], 0)
        };
        let (plan, work) = fixture.dispatch(&action, affected, specs);
        (plan, work, ordinal)
    }

    fn request(&self, command: &str) -> EffectRequest {
        effect_request(
            &self.plan,
            &self.plan.effects.as_slice()[self.ordinal],
            &self.work,
            command,
        )
    }

    fn installed_ids(&self) -> Vec<String> {
        let effect = &self.plan.effects.as_slice()[self.ordinal];
        match effect.kind {
            ResponseEffectKind::SuspendSession => {
                let target = session_containment_target(&tenant(), &self.session_id)
                    .unwrap_or_else(|error| panic!("containment target: {error}"));
                chio_security_types::ports::ContainmentOverlayStore::load_effective(
                    self.fixture.store.as_ref(),
                    &target,
                )
                .unwrap_or_else(|error| panic!("containment snapshot: {error}"))
                .map(|snapshot| {
                    snapshot
                        .active_contributions
                        .as_slice()
                        .iter()
                        .map(|entry| entry.effect_id.as_str().to_owned())
                        .collect()
                })
                .unwrap_or_default()
            }
            ResponseEffectKind::RestrictEgress => egress_effect_ids(
                &self.fixture.store,
                &EgressRestrictionSessionKey {
                    tenant_id: tenant(),
                    session_id: self.session_id.clone(),
                },
            ),
            ResponseEffectKind::ThrottleSession => throttle_effect_ids(
                &self.fixture.store,
                &SessionThrottleKey {
                    tenant_id: tenant(),
                    session_id: self.session_id.clone(),
                },
            ),
            ResponseEffectKind::SuspendCapabilitySet => {
                let ResponseTarget::CapabilitySet { affected_set_hash } = effect.target else {
                    panic!("capability-set target missing");
                };
                capability_set_effect_ids(
                    &self.fixture.store,
                    &CapabilitySetSuspensionKey {
                        tenant_id: tenant(),
                        affected_set_hash,
                    },
                )
            }
            _ => panic!("unexpected finality kind"),
        }
    }

    fn remove_original(&self, label: &str) -> RemovedEffect {
        assert!(self.fixture.trusted_now < self.plan.expires_at_unix_ms);
        assert!(self.fixture.trusted_now < self.work.lease_expires_at_unix_ms);
        let apply = self.request(&format!("{label}-apply"));
        let applied = self
            .effects
            .execute(&apply)
            .unwrap_or_else(|error| panic!("original Apply: {error}"));
        assert!(applied.applied);
        assert_eq!(
            self.installed_ids(),
            vec![apply.effect_id.as_str().to_owned()]
        );
        let mut remove = self.request(&format!("{label}-remove"));
        remove.operation = EffectOperation::Remove;
        remove.expected_version_hash = applied.resulting_version_hash;
        let removed = self
            .effects
            .execute(&remove)
            .unwrap_or_else(|error| panic!("original Remove: {error}"));
        assert!(!removed.applied);
        assert_eq!(removed.effect_id, apply.effect_id);
        assert!(self.installed_ids().is_empty());
        RemovedEffect {
            apply,
            applied,
            remove,
            removed,
        }
    }

    /// Raw rows include the original journal bytes, aggregate generations,
    /// scheduler state, preparation pin, and any new finality metadata.
    /// This scans only the fresh, small test database, never a production path.
    fn snapshot(&self) -> Vec<(String, Vec<Vec<Value>>)> {
        let connection = rusqlite::Connection::open(
            self.fixture._directory.path().join("production-effects.db"),
        )
        .unwrap_or_else(|error| panic!("open raw fixture snapshot: {error}"));
        let mut names = connection
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table' \
                 AND name LIKE 'security_%' ORDER BY name",
            )
            .unwrap_or_else(|error| panic!("prepare raw table names: {error}"));
        let tables = names
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap_or_else(|error| panic!("read raw table names: {error}"))
            .map(|row| row.unwrap_or_else(|error| panic!("raw table name: {error}")))
            .collect::<Vec<_>>();
        tables
            .into_iter()
            .map(|name| {
                assert!(name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
                let mut statement = connection
                    .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                    .unwrap_or_else(|error| panic!("prepare raw {name}: {error}"));
                let column_count = statement.column_count();
                let rows = statement
                    .query_map([], |row| {
                        (0..column_count)
                            .map(|index| row.get::<_, Value>(index))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap_or_else(|error| panic!("read raw {name}: {error}"))
                    .map(|row| row.unwrap_or_else(|error| panic!("raw {name} row: {error}")))
                    .collect();
                (name, rows)
            })
            .collect()
    }
}

fn assert_fresh_apply_refused(kind: ResponseEffectKind, label: &str) {
    let case = FinalityCase::new(kind, label);
    let removed = case.remove_original(label);
    let before = case.snapshot();
    let mut fresh = removed.apply.clone();
    fresh.idempotency_key = record(format!("response_effect_command:{label}-fresh-apply"));
    assert_ne!(fresh.idempotency_key, removed.apply.idempotency_key);
    let outcome = case
        .effects
        .execute(&fresh)
        .map_err(|error| (error.kind(), error.code().as_str().to_owned()));
    let after = case.snapshot();
    assert!(
        matches!(&outcome, Err((PortErrorKind::Conflict, code)) if code == "store.conflict"),
        "a lifted {kind:?} contribution was admitted again: {outcome:?}"
    );
    assert_eq!(after, before, "a refused fresh Apply changed durable state");
    assert!(case.installed_ids().is_empty());
    assert_eq!(
        case.effects
            .load_result(&query(&fresh))
            .unwrap_or_else(|error| panic!("fresh readback: {error}")),
        EffectExecutionStatus::NotExecuted
    );
}

#[test]
fn removed_session_suspension_refuses_a_fresh_apply() {
    assert_fresh_apply_refused(ResponseEffectKind::SuspendSession, "suspension");
}

#[test]
fn removed_egress_restriction_refuses_a_fresh_apply() {
    assert_fresh_apply_refused(ResponseEffectKind::RestrictEgress, "egress");
}

#[test]
fn removed_session_throttle_refuses_a_fresh_apply() {
    assert_fresh_apply_refused(ResponseEffectKind::ThrottleSession, "throttle");
}

#[test]
fn removed_capability_set_suspension_refuses_a_fresh_apply() {
    assert_fresh_apply_refused(ResponseEffectKind::SuspendCapabilitySet, "capability-set");
}

#[test]
fn lifted_effect_exact_apply_and_remove_replay_preserve_historical_results() {
    for (index, kind) in REMOVABLE_KINDS.into_iter().enumerate() {
        let label = format!("exact-replay-{index}");
        let case = FinalityCase::new(kind, &label);
        let removed = case.remove_original(&label);
        let before = case.snapshot();
        let restarted = case.fixture.effects();
        for (request, result) in [
            (&removed.apply, &removed.applied),
            (&removed.remove, &removed.removed),
        ] {
            assert_eq!(
                restarted
                    .execute(request)
                    .unwrap_or_else(|error| panic!("exact {kind:?} replay: {error}")),
                *result
            );
            assert_eq!(
                restarted
                    .load_result(&query(request))
                    .unwrap_or_else(|error| panic!("exact {kind:?} query: {error}")),
                EffectExecutionStatus::Completed {
                    result: result.clone()
                }
            );
            assert_eq!(
                case.snapshot(),
                before,
                "historical replay changed durable state"
            );
            assert!(
                case.installed_ids().is_empty(),
                "historical Apply replay reinstalled the effect"
            );
        }
    }
}

#[test]
fn another_action_and_effect_can_apply_after_the_original_was_lifted() {
    for (index, kind) in REMOVABLE_KINDS.into_iter().enumerate() {
        let label = format!("foreign-identity-{index}");
        let case = FinalityCase::new(kind, &label);
        let removed = case.remove_original(&label);
        let foreign_label = format!("{label}-other");
        let (plan, work, ordinal) =
            FinalityCase::dispatch(&case.fixture, kind, &case.session_id, &foreign_label);
        if ordinal == 1 {
            let freeze = case
                .effects
                .execute(&effect_request(
                    &plan,
                    &plan.effects.as_slice()[0],
                    &work,
                    &format!("{foreign_label}-freeze"),
                ))
                .unwrap_or_else(|error| panic!("foreign leading freeze: {error}"));
            assert!(freeze.applied);
        }
        let request = effect_request(
            &plan,
            &plan.effects.as_slice()[ordinal],
            &work,
            &foreign_label,
        );
        assert_ne!(request.action_id, removed.apply.action_id);
        assert_ne!(request.effect_id, removed.apply.effect_id);
        let before = case.snapshot();
        let mut rebound = request.clone();
        rebound.effect_id = removed.apply.effect_id.clone();
        let refused = case
            .effects
            .execute(&rebound)
            .err()
            .unwrap_or_else(|| panic!("foreign plan accepted the removed effect identity"));
        assert_eq!(refused.kind(), PortErrorKind::IntegrityFailure);
        assert_eq!(refused.code().as_str(), "store.integrity_failure");
        assert_eq!(case.snapshot(), before);
        let applied = case
            .effects
            .execute(&request)
            .unwrap_or_else(|error| panic!("foreign {kind:?} Apply: {error}"));
        assert!(applied.applied);
        assert_eq!(
            case.installed_ids(),
            vec![request.effect_id.as_str().to_owned()]
        );
    }
}

#[test]
fn corrupt_lift_journal_fails_closed_without_reinstalling_the_effect() {
    for (index, kind) in REMOVABLE_KINDS.into_iter().enumerate() {
        let label = format!("corrupt-lift-{index}");
        let case = FinalityCase::new(kind, &label);
        let removed = case.remove_original(&label);
        let table = match kind {
            ResponseEffectKind::SuspendSession => "security_containment_overlay_commands",
            ResponseEffectKind::RestrictEgress => "security_egress_restriction_commands",
            ResponseEffectKind::ThrottleSession => "security_session_throttle_commands",
            ResponseEffectKind::SuspendCapabilitySet => {
                "security_capability_set_suspension_commands"
            }
            _ => panic!("unexpected corruption case"),
        };
        let connection = rusqlite::Connection::open(
            case.fixture._directory.path().join("production-effects.db"),
        )
        .unwrap_or_else(|error| panic!("open corruption fixture: {error}"));
        assert_eq!(connection.execute(
            &format!("UPDATE {table} SET result_body_hash = ?1 WHERE tenant_id = ?2 AND idempotency_key = ?3"),
            rusqlite::params![vec![0xA5_u8; 32], removed.remove.tenant_id.as_str(), removed.remove.idempotency_key.as_str()],
        ).unwrap_or_else(|error| panic!("corrupt retained Remove result: {error}")), 1);
        drop(connection);
        let before = case.snapshot();
        let query_error = case
            .effects
            .load_result(&query(&removed.remove))
            .err()
            .unwrap_or_else(|| panic!("corrupt Remove journal was accepted"));
        assert_eq!(query_error.kind(), PortErrorKind::IntegrityFailure);
        assert_eq!(case.snapshot(), before);
        let mut fresh = removed.apply;
        fresh.idempotency_key = record(format!("response_effect_command:{label}-fresh-apply"));
        let outcome = case.effects.execute(&fresh).map_err(|error| error.kind());
        assert_eq!(
            outcome,
            Err(PortErrorKind::IntegrityFailure),
            "a corrupt retained lift was treated as fresh authority for {kind:?}"
        );
        assert_eq!(case.snapshot(), before);
        assert!(case.installed_ids().is_empty());
    }
}

#[test]
fn missing_active_capability_set_without_a_completed_remove_stays_an_integrity_failure() {
    let case = FinalityCase::new(
        ResponseEffectKind::SuspendCapabilitySet,
        "missing-without-lift",
    );
    let apply = case.request("missing-without-lift-apply");
    let applied = case
        .effects
        .execute(&apply)
        .unwrap_or_else(|error| panic!("real capability-set Apply: {error}"));
    assert!(applied.applied);
    assert_eq!(
        case.installed_ids(),
        vec![apply.effect_id.as_str().to_owned()]
    );
    let connection =
        rusqlite::Connection::open(case.fixture._directory.path().join("production-effects.db"))
            .unwrap_or_else(|error| panic!("open missing-contribution fixture: {error}"));
    connection
        .execute_batch("PRAGMA foreign_keys = ON")
        .unwrap_or_else(|error| panic!("preserve member FK cascade: {error}"));
    let journal_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_capability_set_suspension_commands WHERE tenant_id = ?1",
            [apply.tenant_id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("capability-set journal count: {error}"));
    assert_eq!(
        journal_rows, 1,
        "only the genuine Apply exists; no Remove was executed"
    );
    assert_eq!(connection.execute(
        "DELETE FROM security_capability_set_suspension_effects WHERE tenant_id = ?1 AND action_id = ?2 AND effect_id = ?3",
        rusqlite::params![apply.tenant_id.as_str(), apply.action_id.as_str(), apply.effect_id.as_str()],
    ).unwrap_or_else(|error| panic!("remove active row without command: {error}")), 1);
    drop(connection);
    assert!(case.installed_ids().is_empty());
    let before = case.snapshot();
    let error = case.effects.load_result(&query(&apply)).err()
        .unwrap_or_else(|| panic!("an absent active contribution without authentic Remove was accepted as historical completion"));
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(error.code().as_str(), "store.integrity_failure");
    assert_eq!(case.snapshot(), before);
}
