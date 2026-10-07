//! A sealed cage preparation and live affine process handle are launch authority.
use super::*;
use chio_cage::{EnforcedChild, PreparedCageLaunch};

fn parse_digest(hex: &str) -> Result<CageMeasurementDigest, AdmissionOperationStoreError> {
    parse_cage_digest(hex).map_err(refused)
}
fn preparation_digest(
    prepared: &PreparedCageLaunch,
) -> Result<CageMeasurementDigest, AdmissionOperationStoreError> {
    parse_digest(prepared.evidence().plan_digest())
}
impl SqliteAdmissionOperationStore {
    pub fn confined_launch_reservation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeConfinedReservationV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("launch reservation authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let record = record(&tx, actor.scope(), request)?;
            validate_current(&tx, &record, profile, now)?;
            require_input_source_audience(&tx, actor, parent_source, &record.reservation.boundary)?;
            if record.reservation.state != IsolationStateV1::Reserved
                || now >= record.reservation.boundary.deadline_unix_ms.get()
            {
                return Err(refused("launch reservation"));
            }
            Ok((tx, record.reservation))
        })
    }
    /// Losing execution custody makes the observed launch uncertain. Retain
    /// every measurement, observation and consumed slot; never assert an exit.
    pub fn quarantine_confined_child(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("custody authority"));
        }
        mutate(self, actor, fence, now, |tx, _, _| {
            let mut record = record(&tx, actor.scope(), request)?;
            if matches!(
                record.reservation.state,
                IsolationStateV1::LaunchPrepared | IsolationStateV1::EnforcedRunning
            ) {
                record.reservation.state = IsolationStateV1::Quarantined;
                retain(&tx, &self.serving_owner, &record)?;
            }
            Ok((tx, ()))
        })
    }
    /// Exactly one host may move a reservation into launch preparation. A lost
    /// acknowledgement is an uncertain launch, never permission to spawn again.
    pub fn prepare_confined_launch(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        prepared: &PreparedCageLaunch,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("launch permission"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let mut record = record(&tx, actor.scope(), request)?;
            require_input_source_audience(&tx, actor, parent_source, &record.reservation.boundary)?;
            validate_current(&tx, &record, profile, now)?;
            let b = &record.reservation.boundary;
            let p = prepared.evidence();
            if record.reservation.state != IsolationStateV1::Reserved
                || now >= b.deadline_unix_ms.get()
                || parse_digest(p.manifest_digest())? != b.execution.manifest
                || parse_digest(p.base_profile_digest())? != b.execution.profile
                || parse_digest(p.base_plan_digest())? != b.execution.configuration
                || parse_digest(p.helper_binding_digest())? != b.execution.helper
                || parse_digest(p.target_binding_digest())? != b.execution.image
                || !p.exact_requirements_match()
                || p.target_launch_count() != 0
            {
                return Err(refused("sealed preparation"));
            }
            record.prepared = Some(preparation_digest(prepared)?);
            record.prepared_profile = Some(parse_digest(p.profile_digest())?);
            record.reservation.state = IsolationStateV1::LaunchPrepared;
            retain(&tx, &self.serving_owner, &record)?;
            Ok((tx, ()))
        })
    }
    /// A JSON enforcement receipt cannot call this method. The existing cage
    /// alone constructs EnforcedChild after the observed kernel exec handshake.
    pub fn record_confined_enforcement(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        child: &EnforcedChild,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeConfinedReservationV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("enforcement authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let mut record = record(&tx, actor.scope(), request)?;
            require_input_source_audience(&tx, actor, parent_source, &record.reservation.boundary)?;
            validate_current(&tx, &record, profile, now)?;
            let b = &record.reservation.boundary;
            let evidence = child.evidence();
            evidence.validate().map_err(refused)?;
            if record.reservation.state != IsolationStateV1::LaunchPrepared
                || now >= b.deadline_unix_ms.get()
                || record.prepared != Some(parse_digest(&evidence.prepared.plan_digest)?)
                || Some(parse_digest(&evidence.prepared.profile_digest)?) != record.prepared_profile
                || parse_digest(&evidence.prepared.target_binding_digest)? != b.execution.image
                || parse_digest(&evidence.prepared.helper_binding_digest)? != b.execution.helper
                || evidence.exec_transition.observed_at_unix_ms > now
            {
                return Err(refused("observed launch"));
            }
            record.launch = Some(CanonicalPayloadDigest::from_bytes(
                knowledge_digest(RecoveryDigestDomain::ConfinedLaunch, evidence)
                    .map_err(refused)?,
            ));
            record.enforcement = Some(evidence.clone());
            record.reservation.state = IsolationStateV1::EnforcedRunning;
            retain(&tx, &self.serving_owner, &record)?;
            Ok((tx, record.reservation))
        })
    }

    pub fn record_confined_exit(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        exit: &chio_cage::ObservedCageExit,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("exit authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let mut record = record(&tx, actor.scope(), request)?;
            let input = require_input_source_audience(
                &tx,
                actor,
                parent_source,
                &record.reservation.boundary,
            )?;
            require_child_source_audience(&tx, actor, profile, &record, input)?;
            validate_current(&tx, &record, profile, now)?;
            exit.record().validate().map_err(refused)?;
            if record.reservation.state != IsolationStateV1::EnforcedRunning
                || exit.record().fully_enforced != record.enforcement
                || exit.record().state != chio_cage::CageEnforcementState::Exited
                || record.terminal.is_some()
            {
                return Err(refused("exit binding"));
            }
            if exit.record().exit.as_ref().and_then(|v| v.exit_code) != Some(0) {
                record.reservation.state = IsolationStateV1::Failed;
            }
            record.terminal = Some(exit.record().clone());
            retain(&tx, &self.serving_owner, &record)?;
            Ok((tx, ()))
        })
    }

    /// Private host staging only. Every reference resolves against current
    /// anchored availability; workers never receive this inventory.
    pub fn confined_input_inventory(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Vec<NativeArtifactRecordV1>, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("input authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let record = record(&tx, actor.scope(), request)?;
            require_input_source_audience(&tx, actor, parent_source, &record.reservation.boundary)?;
            validate_current(&tx, &record, profile, now)?;
            if record.reservation.state != IsolationStateV1::EnforcedRunning
                || now >= record.reservation.boundary.deadline_unix_ms.get()
            {
                return Err(refused("input before enforced launch"));
            }
            let mut rows = vec![artifact(&tx, &record.reservation.boundary.observation)?];
            for seed in record.reservation.boundary.seed_artifacts.as_slice() {
                rows.push(artifact(&tx, seed)?);
            }
            Ok((tx, rows))
        })
    }

    /// Recompute exact packet/input hashes and the registered projection, then
    /// join every parent control channel and sensitive observation before stdin.
    pub fn admit_confined_input(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        packet: &[u8],
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeConfinedReservationV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("input authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let mut record = record(&tx, actor.scope(), request)?;
            require_input_source_audience(&tx, actor, parent_source, &record.reservation.boundary)?;
            validate_current(&tx, &record, profile, now)?;
            let DecodedConfinedInput {
                field,
                observation,
                seeds,
            } = decode_confined_input(packet).map_err(refused)?;

            let b = &record.reservation.boundary;
            if record.reservation.state != IsolationStateV1::EnforcedRunning
                || record.observation_release.is_some()
                || now >= b.deadline_unix_ms.get()
                || packet.len() as u64 > b.limits.input_bytes.get()
                || field != record.installation.contract.field.as_str()
                || seeds.len() != b.seed_artifacts.as_slice().len()
            {
                return Err(refused("input ownership"));
            }
            let observed = artifact(&tx, &b.observation)?;
            if knowledge_content_digest(observation) != observed.metadata.content
                || observation.len() as u64 != observed.metadata.size_bytes.get()
            {
                return Err(refused("observation bytes"));
            }
            for (bytes, reference) in seeds.iter().zip(b.seed_artifacts.as_slice()) {
                let seed = artifact(&tx, reference)?;
                if knowledge_content_digest(bytes) != seed.metadata.content
                    || bytes.len() as u64 != seed.metadata.size_bytes.get()
                {
                    return Err(refused("seed bytes"));
                }
            }
            let projected = project_confined_boolean(observation, field).map_err(refused)?;
            let mut roots = b.seed_artifacts.as_slice().to_vec();
            roots.push(b.observation.clone());
            let rows = traversal::dependencies(&tx, actor.scope(), &roots)?;
            let label = traversal::join_metadata(
                source(&tx, &profile.native_authority, &profile.producer_context)?,
                &rows,
            )?;
            if !label.flows_to(&record.installation.contract.source_ceiling) {
                return Err(refused("source scope"));
            }
            let influence = traversal::influence(
                &tx,
                &profile.native_authority,
                &profile.producer_context,
                &rows,
                false,
            )?;
            let recipient = ArtifactRecipientV1 {
                recipient: ArtifactRecipientId::new(&format!("child:{}", b.boundary.as_str()))
                    .map_err(refused)?,
                scope: b.scope.clone(),
                runtime: b.parent.runtime.clone(),
                principal: b.child_principal.clone(),
                lineage: b.lineage.clone(),
                isolation_epoch: b.isolation_epoch.clone(),
                context_generation: SafeInteger::new(1).map_err(refused)?,
                clearance: label.clone(),
                sink: ArtifactSinkV1::Agent,
            };
            super::super::require_finite_recipient(&recipient)?;
            let release = ArtifactReleaseIntentV1 {
                domain_version: VersionV1,
                release: ReleaseId::new(&uuid::Uuid::new_v4().to_string()).map_err(refused)?,
                kind: ArtifactReleaseKindV1::IndependentlyAdmitted {
                    request: request.clone(),
                },
                artifact: b.observation.clone(),
                source_label: label.clone(),
                admitted_label: label.clone(),
                influence,
                recipient,
                policy: profile.policy,
                // This input release uses the complete confined token identity;
                // its declared release role does not change the hash preimage.
                authorization: ReleaseAuthorizationDigest::from_bytes(
                    *capability_digest(actor.capability())?.as_bytes(),
                ),
                observation_transition: EvidenceRef::new(&format!(
                    "confined-input:{}",
                    b.boundary.as_str()
                ))
                .map_err(refused)?,
                observation_generation: SafeInteger::new(0).map_err(refused)?,
                state: ArtifactDeliveryStateV1::Admitted,
            };
            let (tx, release) = super::super::super::security_participant_state::knowledge::join(
                tx,
                &self.serving_owner,
                super::super::super::security_participant_state::knowledge::KnowledgeJoin {
                    binding: &profile.native_authority,
                    key: &recovery_flow_key(&record.reservation.child_context),
                    source: &label,
                    scope: actor.scope(),
                    release,
                    now,
                },
            )?;
            record.observation_release = Some(release);
            // The expected result digest stays classified in protected records.
            record.input_packet = Some(knowledge_content_digest(packet));
            record.expected_return = Some(knowledge_content_digest(&projected));
            retain(&tx, &self.serving_owner, &record)?;
            Ok((tx, record.reservation))
        })
    }
}
