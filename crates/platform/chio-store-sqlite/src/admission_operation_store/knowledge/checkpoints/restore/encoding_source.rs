//! A restore owner proves its exact lawful admission or outcome update.
use super::*;
use crate::admission_operation_store::knowledge::encoding::chunks::EncodingOwner;
use std::ops::Deref;

enum RestoreTransition {
    Admission,
    Acknowledgement,
}

/// Only the actual Restore owner can mint this affine native source. It has no
/// Clone, Deserialize, caller-selected purpose, independent writer or credit.
pub(in crate::admission_operation_store) struct AuthenticatedCheckpointRestoreEncodingSource<
    'tx,
    'conn,
> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    profile: &'tx NativeKnowledgeInstallationV1,
    now: u64,
    key: String,
    record: &'tx RestoreRecord,
    transition: RestoreTransition,
    previous: Option<protected::ProtectedSourceReference>,
    observation: protected::ProtectedSourceReference,
}

impl<'tx, 'conn> AuthenticatedCheckpointRestoreEncodingSource<'tx, 'conn> {
    pub(super) fn admission(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        key: &str,
        record: &'tx RestoreRecord,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let observation = super::super::super::super::security_participant_state::knowledge::release_observation_source(
            transaction,
            &record.intent,
        )?;
        let source = Self {
            transaction,
            actor,
            profile,
            now,
            key: key.to_owned(),
            record,
            transition: RestoreTransition::Admission,
            previous: None,
            observation,
        };
        source.verify(transaction)?;
        Ok(source)
    }

    pub(super) fn acknowledgement(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        key: &str,
        record: &'tx RestoreRecord,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let previous = protected::source_reference(transaction, key)?;
        let observation = super::super::super::super::security_participant_state::knowledge::release_observation_source(
            transaction,
            &record.intent,
        )?;
        let source = Self {
            transaction,
            actor,
            profile,
            now,
            key: key.to_owned(),
            record,
            transition: RestoreTransition::Acknowledgement,
            previous: Some(previous),
            observation,
        };
        source.verify(transaction)?;
        Ok(source)
    }

    /// Data-only identity for the default-off one-request fault guard.
    #[cfg(feature = "admission-test-support")]
    pub(in crate::admission_operation_store) fn extra_prefix_fixture_binding(
        &self,
    ) -> Option<(&RecoveryScopeV1, &RequestId)> {
        if !matches!(self.transition, RestoreTransition::Acknowledgement)
            || self.record.intent.state != ArtifactDeliveryStateV1::Uncertain
        {
            return None;
        }
        let ArtifactReleaseKindV1::IndependentlyAdmitted { request } = &self.record.intent.kind
        else {
            return None;
        };
        Some((&self.record.checkpoint.scope, request))
    }

    /// The closed fixture rechecks native authority and independently derives
    /// the actual typed Uncertain ACK body. A caller frame supplies no purpose.
    #[cfg(feature = "admission-test-support")]
    pub(in crate::admission_operation_store) fn verify_extra_ordinal_fixture(
        &self,
        tx: &Transaction<'conn>,
        body: &crate::admission_operation_store::knowledge::encoding::chunks::ChunkedBody,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify(tx)?;
        if self.extra_prefix_fixture_binding().is_none() || self.previous.is_none() {
            return Err(refused(
                "extra chunk fixture requires actual Uncertain acknowledgement",
            ));
        }
        let exact = encoding::logical_body(self.record)?;
        body.verify_fixture_body(&self.owner(), &exact)
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        transaction: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(transaction)) {
            return Err(refused("restore encoding changed its native transaction"));
        }
        let now = schema::authority_validation_time(transaction, self.now)?;
        let deployment = protected::deployment_tx(transaction, self.actor.scope())?;
        super::super::super::super::recovery::verify_actor(
            transaction,
            self.actor,
            &deployment,
            now,
        )?;
        let current = installation(transaction, self.actor.scope())?;
        validate_installation(transaction, &deployment, &current)?;
        let ArtifactReleaseKindV1::IndependentlyAdmitted { request } = &self.record.intent.kind
        else {
            return Err(refused("restore encoding lost its original request"));
        };
        validate_restore_identity(self.record, self.actor.scope(), request)?;
        let authorization = super::super::super::release::authority_digest(self.actor)?;
        if self.actor.permission() != RecoveryPermission::KnowledgeRead
            || self.record.intent.authorization != authorization
            || protected::encode(&current)? != protected::encode(self.profile)?
            || self.record.intent.policy != current.policy
            || !current
                .recipients
                .as_slice()
                .iter()
                .any(|selected| selected.recipient == self.record.recipient)
        {
            return Err(refused("restore encoding lost its original read authority"));
        }
        protected::verify_source_reference(transaction, &self.observation)?;
        let checked_observation = super::super::super::super::security_participant_state::knowledge::release_observation_source(
            transaction,
            &self.record.intent,
        )?;
        if checked_observation.record_key() != self.observation.record_key()
            || checked_observation.digest() != self.observation.digest()
        {
            return Err(refused("restore encoding changed its native observation"));
        }
        match self.transition {
            RestoreTransition::Admission => self.verify_admission(transaction, &current, request),
            RestoreTransition::Acknowledgement => {
                let previous = self
                    .previous
                    .as_ref()
                    .ok_or_else(|| refused("restore outcome lost its original root"))?;
                protected::verify_source_reference(transaction, previous)?;
                let (key, mut original) =
                    retained_restore(transaction, self.actor, request, authorization)?
                        .ok_or_else(|| refused("restore outcome lost its original admission"))?;
                let target = self.record.intent.state;
                if key != self.key
                    || previous.record_key() != self.key
                    || !matches!(
                        target,
                        ArtifactDeliveryStateV1::Uncertain | ArtifactDeliveryStateV1::Delivered
                    )
                    || (original.intent.state == ArtifactDeliveryStateV1::Delivered
                        && target != ArtifactDeliveryStateV1::Delivered)
                {
                    return Err(refused("restore outcome changed its monotone custody"));
                }
                // Every other field, including optional predecessor identity,
                // original opaque authorization and exact labels stays exact.
                original.intent.state = target;
                if encoding::canonical(&original)? != encoding::canonical(self.record)? {
                    return Err(refused("restore outcome changed its original logical body"));
                }
                Ok(())
            }
        }
    }

    fn verify_admission(
        &self,
        transaction: &Transaction<'conn>,
        current: &NativeKnowledgeInstallationV1,
        request: &RequestId,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.previous.is_some()
            || protected::raw_checked(transaction, &self.key)?.is_some()
            || self.record.intent.state != ArtifactDeliveryStateV1::Admitted
        {
            return Err(refused("restore admission acquired an existing root"));
        }
        let deployment = protected::deployment_tx(transaction, self.actor.scope())?;
        match (
            &self.record.actor_binding,
            self.record.installation_generation,
        ) {
            (Some(binding), Some(generation))
                if binding.principal == *self.actor.principal()
                    && binding.authority_scope == deployment.authority_scope
                    && generation == current.generation
                    && self.key == restore_key(self.actor, request)? => {}
            (None, None) if self.key == legacy_restore_key(self.actor.scope(), request)? => {}
            _ => return Err(refused("restore admission changed its actor identity")),
        }
        let checkpoint = load_visible_checkpoint(
            transaction,
            self.actor.scope(),
            &self.record.checkpoint.checkpoint,
            self.record.checkpoint.revision.get(),
        )?
        .ok_or_else(|| refused("restore admission checkpoint vanished"))?;
        if checkpoint != self.record.checkpoint
            || checkpoint.policy != current.policy
            || checkpoint.runtime.as_str() != current.producer_context.as_v1().session_id().as_str()
            || checkpoint.lineage.as_str()
                != current.producer_context.as_v1().lineage_root_id().as_str()
            || checkpoint.isolation_epoch.as_str()
                != current
                    .producer_context
                    .as_v1()
                    .isolation_epoch_id()
                    .as_str()
            || !self.observation.record_key().starts_with(
                &super::super::super::super::security_participant_state::knowledge::prefix(
                    current.native_authority.security_authority_id().as_str(),
                ),
            )
        {
            return Err(refused("restore admission checkpoint changed"));
        }
        require_finite_recipient(&self.record.recipient)?;
        let selected = current
            .recipients
            .as_slice()
            .iter()
            .find(|entry| entry.recipient == self.record.recipient)
            .ok_or_else(|| refused("restore admission recipient changed"))?;
        let mut roots = checkpoint.artifacts.as_slice().to_vec();
        for context in checkpoint.model_contexts.as_slice() {
            let receiver = current
                .recipients
                .as_slice()
                .iter()
                .find(|entry| {
                    entry.recipient.sink
                        == ArtifactSinkV1::Model {
                            context: context.clone(),
                        }
                })
                .ok_or_else(|| refused("restore admission model context changed"))?;
            require_finite_recipient(&receiver.recipient)?;
            roots.extend_from_slice(context.side_files.as_slice());
        }
        if let ArtifactSinkV1::Model { context } = &selected.recipient.sink {
            roots.extend_from_slice(context.side_files.as_slice());
        }
        let dependencies = traversal::dependencies(transaction, self.actor.scope(), &roots)?;
        let source = traversal::join_metadata(checkpoint.label, &dependencies)?;
        traversal::ensure_audience(transaction, self.actor, &source)?;
        if !source.flows_to(&selected.recipient.clearance) {
            return Err(refused("restore admission audience changed"));
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn verify_stored_body(
        &self,
        body: &[u8],
    ) -> Result<(), AdmissionOperationStoreError> {
        if encoding::logical_body(self.record)? != body {
            return Err(refused("restore encoding changed its exact logical body"));
        }
        Ok(())
    }
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn owner(&self) -> EncodingOwner {
        EncodingOwner::Restore {
            scope: self.record.checkpoint.scope.clone(),
            record_key: self.key.clone(),
            release: self.record.intent.release.clone(),
        }
    }
    pub(in crate::admission_operation_store) fn expected_root(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        self.previous.as_ref()
    }
}
