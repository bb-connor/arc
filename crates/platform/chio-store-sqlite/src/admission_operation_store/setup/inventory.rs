//! Required setup paths are derived from exact authenticated native profiles.
use super::*;

#[derive(Serialize)]
struct MediatorInventory<'a> {
    domain_version: VersionV1,
    native_capture: &'a RecoveryDeploymentV1,
    semantic_tools: &'a super::super::semantic::NativeSemanticInstallationV1,
    durable_knowledge: &'a super::super::knowledge::NativeKnowledgeInstallationV1,
    confined_returns: Option<super::super::knowledge::NativeConfinedInstallationV1>,
}

pub(super) fn required_coverage(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<CoverageDigest, AdmissionOperationStoreError> {
    let recovery = protected::deployment_tx(tx, scope)?;
    let semantic = super::super::semantic::installation(tx, scope)?;
    let knowledge = super::super::knowledge::installation(tx, scope)?;
    if semantic.native_authority != recovery.native_authority
        || semantic.security_context != recovery.security_context
        || knowledge.native_authority != recovery.native_authority
        || knowledge.producer_context != recovery.security_context
        || semantic.deployment.body().scope != *scope
        || knowledge.scope != *scope
    {
        return Err(refused("required mediator inventory closure"));
    }
    let confined = super::super::knowledge::setup_confinement_inventory(tx, scope)?;
    digest(
        RecoveryDigestDomain::SetupRequiredCoverage,
        &MediatorInventory {
            domain_version: VersionV1,
            native_capture: &recovery,
            semantic_tools: &semantic,
            durable_knowledge: &knowledge,
            confined_returns: confined,
        },
    )
    .map(CoverageDigest::from_bytes)
}
