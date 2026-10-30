//! The `response_simulation` metadata projection carries no raw plan identifier and binds
//! to its report.

use std::cell::Cell;

use chio_core_types::receipt::metadata::{MetadataCommitter, MetadataOpenings, MetadataValue};
use chio_core_types::rng::{Rng, RngError};
use chio_core_types::root_authority::SaltRef;
use chio_core_types::tenant_index::{TenantIndexKey, TenantIndexKeySet};
use chio_kernel::response_simulation_report::{
    ResponseSimulationProjection, ResponseSimulationReport, SimulationProjectionError,
};
use chio_response_model::simulation::evaluate_response_simulation;
use chio_security_types::{ports::*, response_simulation::*};

#[path = "response_support/simulation.rs"]
mod support;
use support::{fixture, TestResult};

/// A receipt whose only committed block is its `response_simulation` block: one committer
/// per receipt, finished once.
trait SingleBlockReceipt {
    fn project(
        &self,
        keys: &TenantIndexKeySet,
        rng: &dyn Rng,
    ) -> Result<(ResponseSimulationProjection, MetadataOpenings), SimulationProjectionError>;

    fn matches_projection(
        &self,
        projection: &ResponseSimulationProjection,
        openings: &MetadataOpenings,
        keys: &TenantIndexKeySet,
    ) -> bool;
}

impl SingleBlockReceipt for ResponseSimulationReport {
    fn project(
        &self,
        keys: &TenantIndexKeySet,
        rng: &dyn Rng,
    ) -> Result<(ResponseSimulationProjection, MetadataOpenings), SimulationProjectionError> {
        let mut committer = MetadataCommitter::project(rng);
        let projection = self.project_with(keys, &mut committer)?;
        Ok((projection, committer.into_openings()))
    }

    fn matches_projection(
        &self,
        projection: &ResponseSimulationProjection,
        openings: &MetadataOpenings,
        keys: &TenantIndexKeySet,
    ) -> bool {
        let mut committer = MetadataCommitter::verify(openings);
        self.matches_with(projection, keys, &mut committer) && committer.finish().is_ok()
    }
}

struct CountingRng(Cell<u64>);

impl Rng for CountingRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        let next = self.0.get().wrapping_add(1);
        self.0.set(next);
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = next.to_le_bytes()[index % 8] ^ u8::try_from(index % 256).unwrap_or(0);
        }
        Ok(())
    }
}

fn key_set(active: u8, retired: &[u8]) -> TestResult<TenantIndexKeySet> {
    let key = |fill: u8| TenantIndexKey::from_set_key(&[fill; 32]);
    Ok(TenantIndexKeySet::new(
        key(active)?,
        retired
            .iter()
            .map(|fill| key(*fill))
            .collect::<Result<_, _>>()?,
    )?)
}

fn report() -> TestResult<ResponseSimulationReport> {
    let (plan, snapshot) = fixture(Some(4000))?;
    Ok(ResponseSimulationReport {
        schema: RESPONSE_SIMULATION_SCHEMA.to_owned(),
        configuration_digest: Digest32::new([11; 32]),
        authorization_capability_hash: hex::encode(
            plan.operator_capability.capability_digest.as_bytes(),
        ),
        governed_intent_hash: "22".repeat(32),
        policy_decision_hash: "33".repeat(32),
        approval_set_hash: None,
        authorized_at_unix_ms: 1000,
        evaluation: evaluate_response_simulation(&plan, &snapshot)?,
        plan,
        snapshot,
    })
}

#[test]
fn response_simulation_projection_carries_no_raw_plan_identifier() -> TestResult {
    let keys = key_set(7, &[])?;
    let report = report()?;
    let (projection, openings) = report.project(&keys, &CountingRng(Cell::new(0)))?;
    assert!(report.matches_projection(&projection, &openings, &keys));
    let encoded = chio_core_types::canonical_json_string(&projection)?;
    for raw in [
        report.plan.tenant_id.as_str(),
        report.plan.action_id.as_str(),
        report.plan.trigger_finding_id.as_str(),
        report.plan.submitter.as_str(),
        report.governed_intent_hash.as_str(),
        report.policy_decision_hash.as_str(),
    ] {
        assert!(!encoded.contains(raw), "projection carries {raw}");
    }
    for (salt_ref, opening) in openings.iter() {
        let raw = String::from_utf8_lossy(opening.value.as_bytes()).into_owned();
        assert!(!encoded.contains(&raw), "{salt_ref} leaks {raw}");
    }
    for (field, raw) in [
        (
            "policy_hash",
            serde_json::to_string(&report.plan.policy_hash)?,
        ),
        (
            "affected_set_hash",
            serde_json::to_string(&report.plan.affected_set_hash)?,
        ),
        (
            "evidence_id",
            serde_json::to_string(&report.evidence_id()?)?,
        ),
    ] {
        assert!(!encoded.contains(&raw), "projection carries raw {field}");
    }
    assert_eq!(
        projection.policy_hash.salt_ref().as_str(),
        "metadata.response_simulation.policy_hash"
    );
    let decoded: ResponseSimulationProjection = serde_json::from_str(&encoded)?;
    assert_eq!(decoded, projection);
    Ok(())
}

#[test]
fn response_simulation_projection_refuses_other_reports_openings_and_generations() -> TestResult {
    let keys = key_set(7, &[])?;
    let report = report()?;
    let (projection, openings) = report.project(&keys, &CountingRng(Cell::new(0)))?;
    let mut other = report.clone();
    other.policy_decision_hash = "44".repeat(32);
    assert!(!other.matches_projection(&projection, &openings, &keys));
    let mut moved = report.clone();
    moved.governed_intent_hash = "55".repeat(32);
    assert!(!moved.matches_projection(&projection, &openings, &keys));
    assert!(!report.matches_projection(&projection, &MetadataOpenings::new(), &keys));
    let (_, other_openings) = report.project(&keys, &CountingRng(Cell::new(1_000)))?;
    assert!(!report.matches_projection(&projection, &other_openings, &keys));
    assert!(!report.matches_projection(&projection, &openings, &key_set(8, &[])?));
    assert!(report.matches_projection(&projection, &openings, &key_set(8, &[7])?));
    let mut padded = openings.clone();
    padded.commit_value(
        SaltRef::new("metadata.response_simulation.unused")?,
        MetadataValue::from_json(&"unused")?,
        &CountingRng(Cell::new(5_000)),
    )?;
    assert!(!report.matches_projection(&projection, &padded, &keys));
    Ok(())
}
