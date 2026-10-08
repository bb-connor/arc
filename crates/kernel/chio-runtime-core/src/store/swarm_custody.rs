use chio_core_types::PublicKey;
use chio_swarm_authority::{verify_swarm_authority_for_admission, SwarmAuthorityBundle};

use crate::validation::validate_non_empty;
use crate::ChioRuntimeError;

/// Admits a swarm authority bundle into store custody.
///
/// Every signature and authority bound must verify against
/// `trusted_witness_keys` at the bundle's asserted evaluation time. Admission
/// verifies again against the verifier clock, so custody establishes
/// authenticity and admission establishes freshness.
pub(super) fn verify_swarm_bundle_for_custody(
    bundle: &SwarmAuthorityBundle,
    trusted_witness_keys: &[PublicKey],
) -> Result<(), ChioRuntimeError> {
    validate_non_empty(
        &bundle.task_graph.graph_id,
        "runtime_swarm_authority_empty_graph_id",
    )?;
    verify_swarm_authority_for_admission(bundle, trusted_witness_keys)
        .map(|_| ())
        .map_err(|error| ChioRuntimeError::Rejected {
            code: "runtime_swarm_authority_bundle_unverified",
            detail: error.runtime_detail(),
        })
}

/// What a verified incoming bundle does to the entry already held under its
/// graph id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoredSwarmBundleDisposition {
    /// The stored entry is byte-identical; the insert is an idempotent no-op.
    Keep,
    /// The stored entry does not verify against the same trust anchors, so it
    /// cannot hold the graph id against an authentic bundle.
    Replace,
}

/// Resolves a graph-id collision between a verified incoming bundle and a
/// stored entry.
///
/// Two distinct bundles that both verify against the same trust anchors are a
/// conflict and are refused. A stored entry that does not verify never blocks
/// a verified one.
pub(super) fn resolve_stored_swarm_bundle(
    stored: &SwarmAuthorityBundle,
    stored_sha256: &str,
    incoming_sha256: &str,
    trusted_witness_keys: &[PublicKey],
) -> Result<StoredSwarmBundleDisposition, ChioRuntimeError> {
    if stored_sha256 == incoming_sha256 {
        return Ok(StoredSwarmBundleDisposition::Keep);
    }
    if verify_swarm_authority_for_admission(stored, trusted_witness_keys).is_err() {
        return Ok(StoredSwarmBundleDisposition::Replace);
    }
    Err(ChioRuntimeError::Rejected {
        code: "duplicate_swarm_authority_bundle_mismatch",
        detail: "runtime swarm authority bundle graph id already exists with a different hash"
            .to_string(),
    })
}
