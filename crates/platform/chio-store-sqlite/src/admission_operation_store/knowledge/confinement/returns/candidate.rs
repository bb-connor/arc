//! Native canonical projection and source checks precede process-slot writes.
use super::*;

pub(super) struct VerifiedReturnBasis {
    pub(super) label: InformationLabel,
    pub(super) influence: ArtifactInfluenceV1,
}

pub(super) fn basis(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    record: &BoundaryRecord,
    profile: &NativeKnowledgeInstallationV1,
    bytes: &[u8],
    now: u64,
) -> Result<VerifiedReturnBasis, AdmissionOperationStoreError> {
    validate_current(tx, record, profile, now)?;
    let boundary = &record.reservation.boundary;
    if bytes.len() > 8 {
        return Err(refused("return staging bound"));
    }
    let boolean: bool = serde_json::from_slice(bytes).map_err(refused)?;
    if chio_core::canonical_json_bytes(&boolean)
        .map_err(refused)?
        .as_slice()
        != bytes
    {
        return Err(refused("return canonical schema"));
    }
    let exit = record
        .terminal
        .as_ref()
        .ok_or_else(|| refused("return exit"))?;
    if record.enforcement.is_none()
        || exit.fully_enforced != record.enforcement
        || exit.state != chio_cage::CageEnforcementState::Exited
        || exit.exit.as_ref().and_then(|exit| exit.exit_code) != Some(0)
        || record.observation_release.is_none()
        || now >= boundary.deadline_unix_ms.get()
        || record.expected_return != Some(knowledge_content_digest(bytes))
        || !matches!(
            record.reservation.state,
            IsolationStateV1::EnforcedRunning | IsolationStateV1::ReturnStaged
        )
    {
        return Err(refused("return producer"));
    }
    let label = source(
        tx,
        &profile.native_authority,
        &record.reservation.child_context,
    )?;
    let mut roots = boundary.seed_artifacts.as_slice().to_vec();
    roots.push(boundary.observation.clone());
    let rows = traversal::dependencies(tx, actor.scope(), &roots)?;
    let influence = traversal::influence(
        tx,
        &profile.native_authority,
        &record.reservation.child_context,
        &rows,
        false,
    )?;
    if influence.unknown || !label.flows_to(&record.installation.contract.source_ceiling) {
        return Err(refused("unknown return provenance"));
    }
    if let Some(prior) = &record.return_metadata {
        if prior.label != label || prior.influence != influence {
            return Err(refused("stale staged basis"));
        }
    }
    Ok(VerifiedReturnBasis { label, influence })
}

impl SqliteAdmissionOperationStore {
    /// This unit-only native gate authenticates the current actor and complete
    /// source before inspecting the private candidate. It exposes no seal or
    /// metadata and cannot fill the separate process journal.
    pub fn verify_confined_return_candidate(
        &self,
        input: chio_kernel::admission_operation::ConfinedReturnCandidateInput<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if input.actor.permission() != RecoveryPermission::ConfinedLaunch
            || input.actor.scope() != &input.boundary.scope
        {
            return Err(refused("return candidate authority"));
        }
        mutate(self, input.actor, fence, now, |tx, profile, now| {
            let parent = require_parent_source_audience(&tx, input.actor, profile)?;
            let record = record(&tx, input.actor.scope(), &input.boundary.request)?;
            let source = require_input_source_audience(
                &tx,
                input.actor,
                parent,
                &record.reservation.boundary,
            )?;
            require_child_source_audience(&tx, input.actor, profile, &record, source)?;
            if protected::encode(&record.reservation.boundary)?
                != protected::encode(input.boundary)?
            {
                return Err(refused("return candidate boundary"));
            }
            let _basis = basis(&tx, input.actor, &record, profile, input.bytes, now)?;
            Ok((tx, ()))
        })
    }
}
