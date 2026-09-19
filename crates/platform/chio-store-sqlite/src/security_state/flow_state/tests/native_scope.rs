//! Test-only native writes are always rolled back. No production native writer
//! or activation capability is constructed by these SQL-semantic tests.

use super::*;
use crate::admission_operation_store::with_flow_sql_fixture;
use chio_security_types::ports::{IsolationEpochId, LineageId, RequestId, SessionId};

mod epochs;
mod equivalence;
mod fences;

const A: &str = "authority-a";
const B: &str = "authority-b";

fn label(compartment: &str) -> TestResult<InformationLabel> {
    Ok(InformationLabel::try_known(
        Default::default(),
        BTreeSet::from([chio_security_types::Compartment::new(compartment)?]),
    )?)
}

#[test]
fn colliding_native_identities_keep_labels_generations_and_transition_replay_separate() -> TestResult
{
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let a = FlowMutation::native_for_test(&tx, A);
        let b = FlowMutation::native_for_test(&tx, B);
        let mut first = request("same-transition")?;
        first.principal_join = label("a")?;
        let mut second = first.clone();
        second.principal_join = label("b")?;
        let initial_a = a.join(&first)?;
        let initial_b = b.join(&second)?;
        assert_eq!(initial_a.context_generation, 1);
        assert_eq!(initial_b.context_generation, 1);
        assert_eq!(initial_a.principal_label, first.principal_join);
        assert_eq!(initial_b.principal_label, second.principal_join);
        assert!(a.join(&second).is_err());
        assert_eq!(b.join(&second)?, initial_b);

        first.transition_id = RecordId::new("advance")?;
        first.lineage_join = label("a-lineage")?;
        assert_eq!(a.join(&first)?.context_generation, 2);
        assert_eq!(b.join(&second)?, initial_b);
        assert_eq!(
            load_scoped_flow_snapshot(b.reader(), &second.key)?,
            Some(initial_b)
        );
        assert!(
            load_scoped_flow_snapshot(FlowReader::native(&tx, "missing"), &second.key)?.is_none()
        );
        assert!(FlowMutation::native_for_test(&tx, "missing")
            .join(&second)
            .is_err());
        verify_native_flow_state(&tx, A)?;
        verify_native_flow_state(&tx, B)?;
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn every_generation_fallback_branch_is_authority_scoped() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        for table in [
            "principal_flow_state",
            "lineage_flow_state",
            "session_flow_state",
            "flow_contexts",
        ] {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let a = FlowMutation::native_for_test(&tx, A);
            let b = FlowMutation::native_for_test(&tx, B);
            let join = request("initial")?;
            a.join(&join)?;
            b.join(&join)?;
            tx.execute("DELETE FROM security_participant_state_flow_sequences", [])?;
            // Each UNION branch is tested independently; the selected catalog
            // identifier is test-owned, while the authority remains bound.
            tx.execute(&format!("UPDATE security_participant_state_{table} SET generation = 100 WHERE security_authority_id = ?1"), [B])?;
            assert_eq!(next_flow_generation(&a, "tenant")?, 2, "{table}");
            assert_eq!(next_flow_generation(&b, "tenant")?, 101, "{table}");
            tx.rollback()?;
        }
        Ok(())
    })
}

#[test]
fn each_cohort_invalidation_preserves_other_authorities_and_unrelated_contexts() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        for dimension in 0..3 {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let a = FlowMutation::native_for_test(&tx, A);
            let b = FlowMutation::native_for_test(&tx, B);
            let target = request("target")?;
            a.join(&target)?;
            b.join(&target)?;
            let mut related = request("related")?;
            match dimension {
                0 => related.key.session_id = SessionId::new("other-session")?,
                1 => {
                    related.key.principal_id =
                        chio_security_types::PrincipalId::new("other-principal")?
                }
                _ => related.key.lineage_id = LineageId::new("other-lineage")?,
            }
            a.join(&related)?;
            b.join(&related)?;
            let mut unrelated = request("unrelated")?;
            unrelated.key.principal_id = chio_security_types::PrincipalId::new("unrelated")?;
            unrelated.key.lineage_id = LineageId::new("unrelated")?;
            unrelated.key.session_id = SessionId::new("unrelated")?;
            let unrelated_before = a.join(&unrelated)?;
            let b_before = load_scoped_flow_snapshot(b.reader(), &related.key)?;
            let mut update = target.clone();
            update.transition_id = RecordId::new("taint")?;
            match dimension {
                0 => update.principal_join = label("principal")?,
                1 => update.lineage_join = label("lineage")?,
                _ => update.session_join = label("session")?,
            }
            let after = a.join(&update)?;
            let related_after = load_scoped_flow_snapshot(a.reader(), &related.key)?
                .ok_or("missing related flow")?;
            assert_eq!(related_after.context_generation, after.context_generation);
            assert_eq!(
                load_scoped_flow_snapshot(b.reader(), &related.key)?,
                b_before
            );
            assert_eq!(
                load_scoped_flow_snapshot(a.reader(), &unrelated.key)?,
                Some(unrelated_before)
            );
            verify_native_flow_state(&tx, A)?;
            verify_native_flow_state(&tx, B)?;
            tx.rollback()?;
        }
        Ok(())
    })
}

#[test]
fn initialized_native_projection_still_rejects_domain_mutations() -> TestResult {
    with_flow_sql_fixture(true, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let a = FlowMutation::native_for_test(&tx, A);
        let join = request("forbidden-live-join")?;
        let before = load_scoped_flow_snapshot(a.reader(), &join.key)?;
        assert!(before.is_some());
        assert_eq!(a.join(&join), Err(PortError::conflict()));
        assert_eq!(load_scoped_flow_snapshot(a.reader(), &join.key)?, before);
        tx.rollback()?;
        Ok(())
    })
}
