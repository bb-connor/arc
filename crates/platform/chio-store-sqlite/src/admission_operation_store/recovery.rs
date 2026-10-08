//! Protected recovery records are physical participants of native admission.
use super::*;
use chio_core as chio_core_types;
use chio_kernel::admission_operation::{
    AdmissionOperationBindingV1, NativeSecurityFlowObservationV1,
};
use chio_kernel::recovery::*;
use chio_kernel::ToolCallRequest;
use chio_security_types::recovery::*;

mod commands;
pub(super) use commands::apply as apply_command;
pub(super) use commands::apply_with_origin as apply_command_with_origin;
#[cfg(feature = "admission-test-support")]
pub(super) mod command_quota_test_support;
pub(super) mod deployment_history;
pub(super) mod historical_holds;
mod issuance;
#[cfg(feature = "admission-test-support")]
pub(super) mod legacy_audience_test_support;
#[cfg(feature = "admission-test-support")]
pub(super) mod legacy_history_test_support;
#[cfg(feature = "admission-test-support")]
pub(super) mod legacy_planning_test_support;
pub(super) mod native;
pub(in crate::admission_operation_store) mod original_resolution;
pub(in crate::admission_operation_store) mod origins;
mod preview;
pub(in crate::admission_operation_store) use preview::workflow_preview_tx;
mod provider_lookup_clock;
pub(in crate::admission_operation_store) mod resources;
mod retained_host_reply;
pub(super) mod storage;
pub(in crate::admission_operation_store) mod terminal_custody;
mod validation;
use storage::*;
use validation::*;
pub(super) use validation::{verify_actor, verify_status};

pub(super) fn require_intake_headroom(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    resources::check(connection, true)
}

fn requires_intake_headroom(permission: RecoveryPermission) -> bool {
    matches!(
        permission,
        RecoveryPermission::Create
            | RecoveryPermission::Select
            | RecoveryPermission::Approve
            | RecoveryPermission::Report
            | RecoveryPermission::Maintain
    )
}

fn requires_command_intake_headroom(body: &RecoveryCommandBodyV1) -> bool {
    match body {
        RecoveryCommandBodyV1::InspectWorkflow { .. } => false,
        RecoveryCommandBodyV1::CreateWorkflow { .. }
        | RecoveryCommandBodyV1::SelectOffer { .. }
        | RecoveryCommandBodyV1::SubmitApproval { .. }
        | RecoveryCommandBodyV1::ResumeWorkflow { .. }
        | RecoveryCommandBodyV1::CancelWorkflow { .. }
        | RecoveryCommandBodyV1::ReportDecision { .. } => true,
    }
}

pub(crate) const SQL: &str = include_str!("../admission_operation_recovery.sql");
pub(crate) use native::capture_tx;
pub(in crate::admission_operation_store) use native::{prepare_begin_tx, publish_begin_tx};
pub(crate) use storage::{projection_reference, verify_all};

impl SqliteAdmissionOperationStore {
    /// Trusted operator setup installs or rotates a scoped deployment. Every
    /// pending action revalidates the current assignment and profile digest.
    pub fn configure_recovery_deployment(
        &self,
        deployment: &RecoveryDeploymentV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        validate_deployment_installation(deployment, &self.serving_owner.fence)?;
        let mut connection = self.connection()?;
        resources::check(&connection, true)?;
        let tx = self.begin_write(&mut connection, None)?;
        super::security_participant_state::verify_recovery_initialization(
            &tx,
            &deployment.native_authority,
        )?;
        let scope = scope_key(&deployment.scope)?;
        let key = format!("deployment:{scope}");
        let encoded = encode(deployment)?;
        let context_changed =
            super::setup::register_native_setup_context(&tx, &self.serving_owner, deployment)?;
        let history_changed =
            deployment_history::preserve_installation(&tx, &self.serving_owner, deployment)?
                || context_changed;
        if raw(&tx, &key)?
            .as_ref()
            .is_some_and(|current| current.payload == encoded)
        {
            if history_changed {
                self.commit_write(tx)?;
                self.sync_after_write(&connection)?;
            } else {
                tx.commit().map_err(sqlite_error)?;
            }
            return Ok(());
        }
        save(
            &tx,
            &self.serving_owner,
            &key,
            &scope,
            "deployment",
            &encoded,
            None,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
    pub(super) fn recovery_mutation<T, E: From<AdmissionOperationStoreError>>(
        &self,
        actor: &AuthenticatedRecoveryActor,
        fence: &StoreMutationFence,
        now: u64,
        apply: impl FnOnce(&Transaction<'_>, &RecoveryDeploymentV1, u64) -> Result<T, E>,
    ) -> Result<T, E> {
        self.recovery_mutation_with_headroom(
            actor,
            fence,
            now,
            requires_intake_headroom(actor.permission()),
            apply,
        )
    }

    fn recovery_mutation_with_headroom<T, E: From<AdmissionOperationStoreError>>(
        &self,
        actor: &AuthenticatedRecoveryActor,
        fence: &StoreMutationFence,
        now: u64,
        intake: bool,
        apply: impl FnOnce(&Transaction<'_>, &RecoveryDeploymentV1, u64) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut connection = self.connection()?;
        resources::check(&connection, intake)?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = deployment_tx(&tx, actor.scope())?;
        verify_actor(&tx, actor, &deployment, now)?;
        let result = apply(&tx, &deployment, now)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(result)
    }
}

impl RecoveryAuthorityPort for SqliteAdmissionOperationStore {
    fn protected_setup_required(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<bool, AdmissionOperationStoreError> {
        SqliteAdmissionOperationStore::protected_setup_required(self, scope, fence, now)
    }

    fn reserve_provider_lookup(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        self.reserve_provider_lookup_inner(actor, workflow, fence, now, None)
    }
    fn reserve_provider_lookup_with_budget(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
        budget: RecoveryProviderLookupBudget,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        self.reserve_provider_lookup_inner(actor, workflow, fence, now, Some(budget))
    }
    fn attach_provider_finality(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        finality: &chio_core_types::recovery::SignedRecoveryProviderFinalityV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            native::attach_provider_finality(
                tx,
                &self.serving_owner,
                actor,
                workflow,
                finality,
                profile,
                now,
            )
        })
    }

    fn release_result(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        basis: &RecoveryResultReleaseBasis,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, now, |tx, profile, _now| {
            native::release_result(tx, &self.serving_owner, actor, workflow, profile, basis)
        })
    }

    fn acknowledge_reservation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        reservation: &RecoveryProcessReservationV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if let Some(reply) = self.read_retained_host_reply(
            actor,
            workflow,
            retained_host_reply::RetainedHostReplyRequest::Reservation(reservation),
            fence,
            now,
        )? {
            return match reply {
                retained_host_reply::RetainedHostReplyData::Reservation => Ok(()),
                _ => Err(invariant(
                    "retained reservation changed its closed reply purpose",
                )),
            };
        }
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            if !matches!(
                actor.permission(),
                RecoveryPermission::Create
                    | RecoveryPermission::Select
                    | RecoveryPermission::Resume
            ) {
                return Err(invariant("recovery reservation scope refused"));
            }
            let mut record = workflow_tx(tx, actor.scope(), workflow)?;
            historical_holds::require_unheld(tx, &record)?;
            if let Some(reply) = retained_host_reply::authenticate_retained_host_reply(
                tx,
                &self.serving_owner,
                actor,
                profile,
                now,
                &record,
                retained_host_reply::RetainedHostReplyRequest::Reservation(reservation),
            )? {
                reply.verify_current(tx)?;
                return Ok(());
            }
            let action = record
                .action
                .as_ref()
                .ok_or_else(|| invariant("recovery action is absent"))?;
            let encoded = ProtectedText::new(
                &String::from_utf8(encode(reservation)?)
                    .map_err(|_| invariant("recovery reservation encoding refused"))?,
            )
            .map_err(|_| invariant("recovery reservation bound exceeded"))?;
            if reservation.runtime_id != profile.security_context.as_v1().session_id().as_str()
                || reservation.process_id != record.scope.process_id.as_str()
                || reservation.continuation_id != record.continuation_id
                || reservation.operation_key
                    != format!("recovery:{}", record.continuation_id.as_str())
                || reservation.request_id != action.request_id.as_str()
                || reservation.capability_digest != sha256_hex(&encode(&record.seed.capability)?)
                || reservation.unsigned_intent
                    != IntentDigest::from_bytes(hash(
                        chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
                        action,
                    )?)
                || reservation.server_id != profile.server_id.as_str()
            {
                return Err(invariant("recovery reservation binding refused"));
            }
            terminal_custody::require_unfinished(tx, &record)?;
            require_active(&record)?;
            fresh_basis(tx, profile, &record, now)?;
            record.process_reservation = Some(encoded);
            save_workflow(
                tx,
                &self.serving_owner,
                &mut record,
                WorkflowWriteClass::Native,
            )
        })
    }

    fn reserve_review(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        review: &ApprovalIntentV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ApprovalIntentV1, AdmissionOperationStoreError> {
        if let Some(reply) = self.read_retained_host_reply(
            actor,
            workflow,
            retained_host_reply::RetainedHostReplyRequest::Review,
            fence,
            now,
        )? {
            return match reply {
                retained_host_reply::RetainedHostReplyData::Review(review) => Ok(*review),
                _ => Err(invariant(
                    "retained review changed its closed reply purpose",
                )),
            };
        }
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            if actor.permission() != RecoveryPermission::Approve {
                return Err(invariant("recovery review scope refused"));
            }
            let mut record = workflow_tx(tx, actor.scope(), workflow)?;
            historical_holds::require_unheld(tx, &record)?;
            if let Some(reply) = retained_host_reply::authenticate_retained_host_reply(
                tx,
                &self.serving_owner,
                actor,
                profile,
                now,
                &record,
                retained_host_reply::RetainedHostReplyRequest::Review,
            )? {
                reply.verify_current(tx)?;
                return record
                    .review
                    .ok_or_else(|| invariant("retained review disappeared"));
            }
            retained_host_reply::require_current_preview(tx, actor, profile, &record)?;
            terminal_custody::require_unfinished(tx, &record)?;
            require_active(&record)?;
            if !record.selected {
                return Err(invariant("recovery identity is not reserved"));
            }
            if review.reviewer != *actor.principal() {
                return Err(invariant("recovery reviewer changed"));
            }
            validate_review(&record, review, now)?;
            fresh_basis(tx, profile, &record, now)?;
            record.review = Some(review.clone());
            save_workflow(
                tx,
                &self.serving_owner,
                &mut record,
                WorkflowWriteClass::Native,
            )?;
            Ok(review.clone())
        })
    }
    fn deployment(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryDeploymentV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let result = deployment_tx(&tx, scope)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(result)
    }
    fn load_workflow(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = deployment_tx(&tx, actor.scope())?;
        verify_actor(&tx, actor, &deployment, now)?;
        let record = workflow_preview_tx(&tx, actor, &deployment, workflow)?;
        let record = historical_holds::view(&tx, record)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(record)
    }
    fn command(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        original_process: Option<&dyn RecoveryProcessOriginPort>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryCommandResponseV1, RecoveryCommandPortError> {
        self.recovery_command_outcome(actor, command, original_process, fence, now)
            .map(|outcome| outcome.response)
    }
    fn command_with_selection(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        original_process: Option<&dyn RecoveryProcessOriginPort>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryCommandPortOutcome, RecoveryCommandPortError> {
        self.recovery_command_outcome(actor, command, original_process, fence, now)
    }
    fn load_selection(
        &self,
        actor: &AuthenticatedRecoveryActor,
        selection: &RecoveryCommandPortSelection,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryCommandSelectedWorkflowData, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = deployment_tx(&tx, actor.scope())?;
        verify_actor(&tx, actor, &deployment, now)?;
        let selected = load_selected_workflow(&tx, actor, &deployment, selection)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(selected)
    }
    fn materialize(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        action: &ActionIntentV1,
        observation: &NativeSecurityFlowObservationV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        if let Some(reply) = self.read_retained_host_reply(
            actor,
            workflow,
            retained_host_reply::RetainedHostReplyRequest::Materialization(action),
            fence,
            now,
        )? {
            return match reply {
                retained_host_reply::RetainedHostReplyData::Materialization(record) => Ok(*record),
                _ => Err(invariant(
                    "retained materialization changed its closed reply purpose",
                )),
            };
        }
        self.recovery_mutation(actor, fence, now, |tx, deployment, now| {
            issuance::materialize(
                tx,
                &self.serving_owner,
                actor,
                workflow,
                issuance::Materialization {
                    action,
                    observation,
                },
                deployment,
                now,
            )
        })
    }
    fn reserve_issuance(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        body: &chio_core_types::recovery::RecoveryGrantBodyV2,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<chio_core_types::recovery::RecoveryGrantBodyV2, AdmissionOperationStoreError> {
        if let Some(reply) = self.read_retained_host_reply(
            actor,
            workflow,
            retained_host_reply::RetainedHostReplyRequest::Issuance(body),
            fence,
            now,
        )? {
            return match reply {
                retained_host_reply::RetainedHostReplyData::Issuance(body) => Ok(*body),
                _ => Err(invariant(
                    "retained issuance changed its closed reply purpose",
                )),
            };
        }
        let result = self.recovery_mutation(actor, fence, now, |tx, deployment, now| {
            issuance::reserve(
                tx,
                &self.serving_owner,
                actor,
                workflow,
                body,
                deployment,
                now,
            )
        });
        #[cfg(feature = "admission-test-support")]
        if let Err(error) = &result {
            command_quota_test_support::record_issuance_refusal(error);
        }
        result
    }
    fn attach_signature(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        grant: &chio_core_types::recovery::SignedRecoveryGrantV2,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if let Some(reply) = self.read_retained_host_reply(
            actor,
            workflow,
            retained_host_reply::RetainedHostReplyRequest::Signature(grant),
            fence,
            now,
        )? {
            return match reply {
                retained_host_reply::RetainedHostReplyData::Signature => Ok(()),
                _ => Err(invariant(
                    "retained signature changed its closed reply purpose",
                )),
            };
        }
        self.recovery_mutation(actor, fence, now, |tx, deployment, now| {
            issuance::attach(
                tx,
                &self.serving_owner,
                actor,
                workflow,
                grant,
                deployment,
                now,
            )
        })
    }
    fn finalize_envelope(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        envelope: &FinalizedRequestEnvelopeV1,
        identity: &RecoveryNativeIdentity,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if let Some(reply) = self.read_retained_host_reply(
            actor,
            workflow,
            retained_host_reply::RetainedHostReplyRequest::Envelope { envelope, identity },
            fence,
            now,
        )? {
            return match reply {
                retained_host_reply::RetainedHostReplyData::Envelope => Ok(()),
                _ => Err(invariant(
                    "retained envelope changed its closed reply purpose",
                )),
            };
        }
        self.recovery_mutation(actor, fence, now, |tx, deployment, now| {
            issuance::finalize(
                tx,
                &self.serving_owner,
                actor,
                workflow,
                issuance::Finalization { envelope, identity },
                deployment,
                now,
            )
        })
    }
    fn verification_context(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<RecoveryVerificationContextV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let result = native::context(&tx, operation, now)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(result)
    }
    fn historical_release(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<RecoveryWorkflowRecordV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let result = native::historical_release(&tx, operation, fence)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(result)
    }
    fn captured_deployment(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<RecoveryCapturedDeploymentV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let result = match native::captured_custody(&tx, operation, fence)? {
            Some((record, custody)) => Some(
                if historical_holds::blocks_original_private_settlement(&tx, &record)? {
                    RecoveryCapturedDeploymentV1::Quarantined
                } else {
                    custody
                },
            ),
            None => None,
        };
        tx.commit().map_err(sqlite_error)?;
        Ok(result)
    }
    fn quarantine_historical(
        &self,
        operation: &AdmissionOperationId,
        reason: RecoveryHistoricalHoldReasonV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        resources::check(&connection, false)?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        native::quarantine_historical(&tx, &self.serving_owner, operation, reason)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
    fn settle(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, now, |tx, deployment, now| {
            native::settle(tx, &self.serving_owner, actor, workflow, deployment, now)
        })
    }
}

impl SqliteAdmissionOperationStore {
    fn reserve_provider_lookup_inner(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        decision_time: u64,
        request_budget: Option<RecoveryProviderLookupBudget>,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, decision_time, |tx, profile, fresh_time| {
            let physical = workflow_tx(tx, actor.scope(), workflow)?;
            historical_holds::require_unheld(tx, &physical)?;
            // This owning settlement path includes the current actor, original
            // custody and external-visibility checks before any attempt debit.
            let mut record = native::settle(
                tx,
                &self.serving_owner,
                actor,
                workflow,
                profile,
                fresh_time,
            )?;
            if actor.permission() != RecoveryPermission::Settle
                || !matches!(record.effect, EffectObservationV1::Unknown { .. })
                || record.provider_lookups.get() >= 32
            {
                return Err(invariant("recovery provider observation refused"));
            }
            provider_lookup_clock::require_spacing(tx, &record, fresh_time)?;
            if let Some(budget) = request_budget {
                let capability_deadline = actor
                    .capability()
                    .expires_at
                    .checked_mul(1000)
                    .ok_or_else(|| invariant("recovery provider deadline is invalid"))?;
                // Retain the Kernel's original deadline. Waiting for this writer
                // never refreshes an observation or an expiring capability.
                let deadline = decision_time
                    .saturating_add(MAX_RECOVERY_PROVIDER_OBSERVATION_MS)
                    .min(capability_deadline);
                if deadline
                    .checked_sub(fresh_time)
                    .is_none_or(|remaining| remaining < budget.request_millis())
                {
                    return Err(invariant(
                        "recovery provider request deadline is unavailable",
                    ));
                }
            }
            record.provider_lookups = SafeInteger::new(record.provider_lookups.get() + 1)
                .map_err(|_| invariant("recovery lookup quota exhausted"))?;
            save_workflow(
                tx,
                &self.serving_owner,
                &mut record,
                WorkflowWriteClass::Native,
            )?;
            Ok(record)
        })
    }
}
