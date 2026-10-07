//! Development-only exact confined contracts, not live launch/return authority.
use chio_core_types::{recovery::*, Keypair};
use chio_security_types::{confinement::*, recovery::*, InformationLabel, PrincipalId};
#[path = "recovery-knowledge-profile.rs"]
mod knowledge;

pub fn limits() -> Result<ConfinedLimitsV1, Box<dyn std::error::Error>> {
    Ok(ConfinedLimitsV1 {
        children: SafeInteger::new(16)?,
        depth: SafeInteger::new(8)?,
        input_bytes: SafeInteger::new(65536)?,
        diagnostic_bytes: SafeInteger::new(16384)?,
        launches: SafeInteger::new(1)?,
        tool_calls: SafeInteger::new(0)?,
        model_calls: SafeInteger::new(0)?,
        wall_clock_ms: SafeInteger::new(30000)?,
    })
}
pub fn contracts() -> Result<Vec<(&'static str, serde_json::Value)>, Box<dyn std::error::Error>> {
    let parent = knowledge::recipient()?;
    let m = knowledge::metadata()?;
    let reference = artifact_version_reference(&m)?;
    let execution = ConfinedExecutionProfileV1 {
        manifest: CanonicalPayloadDigest::from_bytes([1; 32]),
        profile: CanonicalPayloadDigest::from_bytes([2; 32]),
        configuration: CanonicalPayloadDigest::from_bytes([3; 32]),
        helper: CanonicalPayloadDigest::from_bytes([4; 32]),
        image: CanonicalPayloadDigest::from_bytes([5; 32]),
        provider: ConfinedProviderV1::Disabled,
    };
    let contract = ReturnContractV1 {
        domain_version: VersionV1,
        contract: ReturnContractDigest::from_bytes([6; 32]),
        schema: knowledge_content_digest(CONFINED_BOOLEAN_SCHEMA),
        implementation: knowledge_content_digest(CONFINED_BOOLEAN_IMPLEMENTATION),
        field: ProtectedText::new("eligible")?,
        parent: parent.clone(),
        source_ceiling: InformationLabel::Top,
        target: InformationLabel::bottom(),
        require_integrity: true,
        max_bytes: SafeInteger::new(8)?,
        max_values: SafeInteger::new(1)?,
        channels: NonEmptyBoundedList::new(vec![ConfinedChannelV1::Value])?,
        expires_at_unix_ms: SafeInteger::new(60000)?,
        policy: m.policy,
    };
    let boundary = IsolationBoundaryV1 {
        domain_version: VersionV1,
        boundary: EvidenceRef::new("fixture-boundary")?,
        request: RequestId::new("fixture-spawn")?,
        scope: m.scope.clone(),
        parent_capability: CapabilityBodyDigest::from_bytes([7; 32]),
        parent: parent.clone(),
        child: ProcessId::new("fixture-child")?,
        child_principal: PrincipalId::new("fixture-child-principal")?,
        child_capability: CapabilityBodyDigest::from_bytes([8; 32]),
        ancestry: NonEmptyBoundedList::new(vec![m.scope.process_id.clone()])?,
        lineage: IsolationLineageId::new("fixture-confined-lineage")?,
        isolation_epoch: ProtectedText::new("fixture-host-epoch")?,
        seed_artifacts: BoundedList::new(vec![])?,
        observation: reference.clone(),
        parent_control: CanonicalPayloadDigest::from_bytes([9; 32]),
        seed_label: m.label.clone(),
        seed_influence: m.influence.clone(),
        execution: execution.clone(),
        return_contract: contract.contract,
        limits: limits()?,
        deadline_unix_ms: SafeInteger::new(30000)?,
        policy: m.policy,
    };
    let evidence = ConfinedReturnEvidenceV1 {
        domain_version: VersionV1,
        evidence: EvidenceRef::new("fixture-return-evidence")?,
        boundary: isolation_boundary_digest(&boundary)?,
        launch: CanonicalPayloadDigest::from_bytes([10; 32]),
        artifact: reference.clone(),
        content: knowledge_content_digest(b"true"),
        size_bytes: SafeInteger::new(4)?,
        source: m.label.clone(),
        influence: m.influence.clone(),
        parent: parent.clone(),
        contract: contract.contract,
        implementation: contract.implementation,
        observation: reference.clone(),
        target: contract.target.clone(),
        policy: m.policy,
        issued_at_unix_ms: SafeInteger::new(10000)?,
        expires_at_unix_ms: SafeInteger::new(20000)?,
    };
    let release = knowledge::contracts()?
        .into_iter()
        .find(|(name, _)| *name == "artifact-release-intent.schema.json")
        .ok_or("release fixture")?
        .1;
    let admission = ReturnAdmissionV1 {
        domain_version: VersionV1,
        boundary: boundary.boundary.clone(),
        child: boundary.child.clone(),
        launch: evidence.launch,
        artifact: reference,
        contract: contract.contract,
        observed_source: m.label,
        admitted: serde_json::from_value(release)?,
        disclosure: Some(evidence.evidence.clone()),
        endorsement: Some(evidence.evidence.clone()),
    };
    let disclosure =
        SignedConfinedDisclosureV1::sign(evidence.clone(), &Keypair::from_seed(&[231; 32]))?;
    let endorsement =
        SignedConfinedEndorsementV1::sign(evidence.clone(), &Keypair::from_seed(&[232; 32]))?;
    Ok(vec![
        (
            "confined-limits.schema.json",
            serde_json::to_value(limits()?)?,
        ),
        (
            "confined-execution-profile.schema.json",
            serde_json::to_value(execution)?,
        ),
        (
            "return-contract.schema.json",
            serde_json::to_value(contract)?,
        ),
        (
            "isolation-boundary.schema.json",
            serde_json::to_value(boundary)?,
        ),
        (
            "confined-return-evidence.schema.json",
            serde_json::to_value(evidence)?,
        ),
        (
            "return-admission.schema.json",
            serde_json::to_value(admission)?,
        ),
        (
            "signed-confined-disclosure.schema.json",
            serde_json::to_value(disclosure)?,
        ),
        (
            "signed-confined-endorsement.schema.json",
            serde_json::to_value(endorsement)?,
        ),
    ])
}
