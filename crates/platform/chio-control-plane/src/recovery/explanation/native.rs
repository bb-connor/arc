//! Native observations retain independent freshness intervals. They are not an atomic
//! cross-store snapshot and cannot become an admission or disclosure grant.
use super::{ProtectedRecoveryExplanationV1, RecoveryExplanationService};
use crate::recovery::{RecoveryRuntime, RecoveryRuntimeError};
use chio_core_types::{
    capability::token::CapabilityToken, recovery::SignedRecoveryExplanationViewV1, SigningBackend,
};
use chio_kernel::recovery::{recovery_digest, AuthenticatedRecoveryActor, RecoveryPermission};
use chio_recovery::ExplanationAudience;
use chio_security_types::{recovery::*, InformationLabel};
use std::sync::Arc;

impl RecoveryRuntime {
    /// Freshly authenticated audience-safe advice. No protected graph or full
    /// report commitment crosses this boundary.
    pub fn explain(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        service: &RecoveryExplanationService,
    ) -> Result<SignedRecoveryExplanationViewV1, RecoveryRuntimeError> {
        let artifact =
            self.build_explanation(capability, workflow, service, RecoveryPermission::Inspect)?;
        self.recheck_explanation_audience(
            capability,
            workflow,
            &artifact,
            RecoveryPermission::Inspect,
        )?;
        let view = artifact.view.clone();
        service.retain_native_graph(workflow, artifact, crate::recovery::materialize::now()?)?;
        Ok(view)
    }

    /// Explicit protected inspector API for trusted host tooling. Current
    /// clearance must cover the complete graph, including hidden alternatives.
    pub fn inspect_explanation(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        service: &RecoveryExplanationService,
    ) -> Result<ProtectedRecoveryExplanationV1, RecoveryRuntimeError> {
        let artifact = self.build_explanation(
            capability,
            workflow,
            service,
            RecoveryPermission::InspectExplanationGraph,
        )?;
        let clearance = self.recheck_explanation_audience(
            capability,
            workflow,
            &artifact,
            RecoveryPermission::InspectExplanationGraph,
        )?;
        if matches!(clearance, InformationLabel::Top)
            || matches!(artifact.classification, InformationLabel::Top)
            || !artifact.classification.flows_to(&clearance)
        {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        service.retain_native_graph(
            workflow,
            artifact.clone(),
            crate::recovery::materialize::now()?,
        )?;
        Ok(artifact)
    }

    /// Resolve the exact original advisory graph under separate live authority.
    /// The opaque reference supplies no permission. Retained inputs and signed
    /// timestamps are not observed, evaluated or certified again.
    pub fn inspect_explanation_reference(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        reference: &ExplanationRef,
        service: &RecoveryExplanationService,
    ) -> Result<Arc<ProtectedRecoveryExplanationV1>, RecoveryRuntimeError> {
        self.inspect_explanation_reference_with_time(
            capability,
            workflow,
            reference,
            service,
            crate::recovery::materialize::now,
        )
    }

    fn inspect_explanation_reference_with_time(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        reference: &ExplanationRef,
        service: &RecoveryExplanationService,
        mut now: impl FnMut() -> Result<u64, RecoveryRuntimeError>,
    ) -> Result<Arc<ProtectedRecoveryExplanationV1>, RecoveryRuntimeError> {
        let clearance = self.explanation_graph_clearance(capability, workflow, service)?;
        let artifact = service.retained_native_graph(workflow, reference, now()?)?;
        Self::verify_graph_clearance(&artifact, &clearance)?;
        let clearance = self.explanation_graph_clearance(capability, workflow, service)?;
        Self::verify_graph_clearance(&artifact, &clearance)?;
        let returned_at = now()?;
        if returned_at < artifact.view.body().issued_at_unix_ms.get()
            || returned_at >= artifact.view.body().expires_at_unix_ms.get()
        {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        Ok(artifact)
    }

    #[cfg(test)]
    pub(in crate::recovery) fn inspect_explanation_reference_with_test_time(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        reference: &ExplanationRef,
        service: &RecoveryExplanationService,
        now: impl FnMut() -> Result<u64, RecoveryRuntimeError>,
    ) -> Result<Arc<ProtectedRecoveryExplanationV1>, RecoveryRuntimeError> {
        self.inspect_explanation_reference_with_time(capability, workflow, reference, service, now)
    }

    fn verify_graph_clearance(
        artifact: &ProtectedRecoveryExplanationV1,
        current: &InformationLabel,
    ) -> Result<(), RecoveryRuntimeError> {
        let joined = artifact
            .classification
            .join_restrictions(current)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        if matches!(artifact.classification, InformationLabel::Top)
            || matches!(joined, InformationLabel::Top)
            || joined != *current
        {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        Ok(())
    }

    fn explanation_graph_clearance(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        service: &RecoveryExplanationService,
    ) -> Result<InformationLabel, RecoveryRuntimeError> {
        self.scope
            .ensure_matches(&service.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let actor =
            self.explanation_actor(capability, RecoveryPermission::InspectExplanationGraph)?;
        self.validate_protected_mediation()?;
        let profile = self
            .kernel
            .recovery_deployment(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let assignment = profile
            .actors
            .as_slice()
            .iter()
            .find(|assignment| assignment.principal == *actor.principal())
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?;
        if matches!(assignment.preview_clearance, InformationLabel::Top) {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        let record = self
            .kernel
            .read_recovery_workflow(&actor, workflow)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let observation = self
            .kernel
            .observe_recovery_source(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let source = self
            .flow
            .recovery_input_source(&record.seed, &profile.security_context, &observation)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let joined = record
            .action
            .as_ref()
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?
            .authorization_requirements
            .source_label
            .join_restrictions(&source)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        if matches!(joined, InformationLabel::Top)
            || !joined.flows_to(&assignment.preview_clearance)
        {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        Ok(assignment.preview_clearance.clone())
    }

    fn explanation_actor(
        &self,
        capability: &CapabilityToken,
        permission: RecoveryPermission,
    ) -> Result<AuthenticatedRecoveryActor, RecoveryRuntimeError> {
        self.kernel
            .authenticate_recovery_actor(&self.scope, capability, permission)
            .map_err(crate::recovery::authentication_error)
    }

    fn build_explanation(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        service: &RecoveryExplanationService,
        permission: RecoveryPermission,
    ) -> Result<ProtectedRecoveryExplanationV1, RecoveryRuntimeError> {
        self.scope
            .ensure_matches(&service.scope)
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        if service.public_key() == self.signer.public_key() {
            return Err(RecoveryRuntimeError::UnsupportedProfile);
        }
        let actor = self.explanation_actor(capability, permission)?;
        self.validate_protected_mediation()?;
        let recipient = ActorId::new(actor.principal().as_str())
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        let now = crate::recovery::materialize::now()?;
        // Charge before loading an object; hidden membership cannot reset quota.
        service.admit(&recipient, now)?;
        let denied = |_| RecoveryRuntimeError::AuthorityDenied;
        let invalid = |_| RecoveryRuntimeError::InvalidCommand;
        let profile = self
            .kernel
            .recovery_deployment(&self.scope)
            .map_err(denied)?;
        let record = self
            .kernel
            .read_recovery_workflow(&actor, workflow)
            .map_err(denied)?;
        let assignment = profile
            .actors
            .as_slice()
            .iter()
            .find(|a| a.principal == *actor.principal())
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?;
        if matches!(assignment.preview_clearance, InformationLabel::Top) {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        let action = record
            .action
            .as_ref()
            .ok_or(RecoveryRuntimeError::UnsupportedProfile)?;
        let observation = self
            .kernel
            .observe_recovery_source(&self.scope)
            .map_err(denied)?;
        let source = self
            .flow
            .recovery_input_source(&record.seed, &profile.security_context, &observation)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let context_label = source
            .join_restrictions(&action.authorization_requirements.source_label)
            .unwrap_or(InformationLabel::Top);
        let issued = SafeInteger::new(now).map_err(invalid)?;
        let expires = SafeInteger::new(
            now.checked_add(MAX_EXPLANATION_VALIDITY_MS)
                .ok_or(RecoveryRuntimeError::Unavailable)?,
        )
        .map_err(invalid)?;
        let intent = IntentDigest::from_bytes(
            recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
                action,
            )
            .map_err(denied)?,
        );
        let current_basis = observation
            .snapshot()
            .filter(|state| state.context_generation == action.source_generation.get());
        let consistent = current_basis.is_some()
            && action.policy_digest == profile.policy_digest
            && action.contract_digest == profile.contract_digest
            && action.authority_scope == profile.authority_scope
            && action
                .authorization_requirements
                .validity_ceiling_unix_ms
                .get()
                > now;
        let live = self
            .kernel
            .observe_recovery_capability_liveness(&actor, workflow)
            .map_err(denied)?;
        let cap_deadline = record
            .seed
            .capability
            .expires_at
            .checked_mul(1000)
            .ok_or(RecoveryRuntimeError::Unavailable)?;
        let mut covered = false;
        let mut coverage_deadline = expires.get();
        if consistent {
            if let Some(approval) = &record.approval {
                let assignments = profile
                    .coverage
                    .as_slice()
                    .iter()
                    .map(|a| {
                        (
                            a.issuer_id.clone(),
                            chio_flow::RecoveryAuthorityAssignment {
                                principal: a.principal.clone(),
                                key: a.key.clone(),
                                obligations: a.obligations.as_slice().iter().cloned().collect(),
                            },
                        )
                    })
                    .collect();
                covered = chio_flow::verify_recovery_coverage(
                    &approval.intent,
                    &action.authorization_requirements,
                    action.basis,
                    &approval.coverage,
                    &assignments,
                    now,
                )
                .is_ok();
                if covered {
                    coverage_deadline = approval.coverage.as_slice().iter().fold(
                        approval.intent.expires_at_unix_ms.get(),
                        |deadline, proof| deadline.min(proof.body().expires_at_unix_ms.get()),
                    );
                }
            }
        }
        let mut facts = Vec::new();
        for (id, kind, target, satisfied, known, deadline) in [
            (
                "capability",
                ExplanationFactKind::Capability,
                ExplanationFactTargetV1::Intent { intent },
                live,
                true,
                if live {
                    cap_deadline.min(expires.get())
                } else {
                    expires.get()
                },
            ),
            (
                "policy",
                ExplanationFactKind::Policy,
                ExplanationFactTargetV1::Intent { intent },
                consistent
                    && record.control == WorkflowControlV1::Active
                    && !record.admission_closed,
                consistent,
                expires.get(),
            ),
            // The pinned operator recipient/effect contract is observed here.
            // No remote provider ACL lookup or permission claim is fabricated.
            (
                "recipient",
                ExplanationFactKind::DestinationAcl,
                ExplanationFactTargetV1::Destination {
                    destination: profile.recipient.clone(),
                },
                true,
                consistent,
                expires.get(),
            ),
            (
                "coverage",
                ExplanationFactKind::AuthorityCoverage,
                ExplanationFactTargetV1::Authority {
                    scope: profile.authority_scope,
                },
                covered,
                consistent,
                coverage_deadline.min(expires.get()),
            ),
        ] {
            let evidence = EvidenceRef::new(&format!("native:{id}")).map_err(invalid)?;
            facts.push(RecoveryExplanationFactV1 {
                id: ObservationId::new(id).map_err(invalid)?,
                scope: self.scope.clone(),
                object: evidence.clone(),
                source: ExplanationFactSource::NativeAuthority,
                fact: kind,
                target,
                integrity: ExplanationIntegrity::NativeOwned,
                label: context_label.clone(),
                observed_at_unix_ms: issued,
                expires_at_unix_ms: SafeInteger::new(deadline).map_err(invalid)?,
                state: if known {
                    ExplanationFactStateV1::FreshnessQualified {
                        evidence,
                        satisfied,
                    }
                } else {
                    ExplanationFactStateV1::Gap {
                        reason: ExplanationGap::Unavailable,
                    }
                },
            });
        }
        let snapshot = RecoverySnapshotV1 {
            schema: RecoverySnapshotSchema::V1,
            version: VersionV1,
            scope: self.scope.clone(),
            deployment_digest: record.deployment_digest,
            policy_digest: profile.policy_digest,
            contract_digest: profile.contract_digest,
            intent_digest: intent,
            context_label: context_label.clone(),
            influence: ExplanationInfluenceV1::Observed {
                basis: SourceDigest::from_bytes(
                    recovery_digest(
                        chio_core_types::recovery::RecoveryDigestDomain::Influence,
                        &observation.snapshot(),
                    )
                    .map_err(denied)?,
                ),
                integrity: ExplanationIntegrity::NativeOwned,
            },
            observed_at_unix_ms: issued,
            expires_at_unix_ms: expires,
            effect: record.effect,
            observations: BoundedList::new(facts).map_err(invalid)?,
        };
        let registry = RecoveryRemedyRegistryV1 {
            schema: RecoveryRemedyRegistrySchema::V1,
            version: VersionV1,
            scope: self.scope.clone(),
            deployment_digest: snapshot.deployment_digest,
            policy_digest: profile.policy_digest,
            contract_digest: profile.contract_digest,
            classification: context_label.clone(),
            templates: BoundedList::new(vec![RecoveryRemedyTemplateV1 {
                template_id: TemplateId::new("support-ticket-public-issue").map_err(invalid)?,
                kind: ExplanationRemedyKind::ExactApproval,
                family: profile.contract_digest,
                authority_scope: profile.authority_scope,
                destination: profile.recipient.clone(),
                disclosure_label: profile.target_label,
                classification: context_label,
                satisfies_task: true,
                requires_integrity: false,
                cost: ExplanationCostV1 {
                    approvals: SafeInteger::new(u64::from(!covered)).map_err(invalid)?,
                    irreversible_effects: SafeInteger::new(1).map_err(invalid)?,
                    budget_units: SafeInteger::new(1).map_err(invalid)?,
                    latency: ExplanationLatencyClass::Remote,
                    evidence: EvidenceRef::new("native:pinned-effect-contract").map_err(invalid)?,
                },
                requirements: NonEmptyBoundedList::new(
                    ["capability", "policy", "recipient", "coverage"]
                        .iter()
                        .map(|id| ObservationId::new(id))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(invalid)?,
                )
                .map_err(invalid)?,
            }])
            .map_err(invalid)?,
        };
        let audience = ExplanationAudience {
            recipient: &recipient,
            clearance: &assignment.preview_clearance,
            validity_ceiling_unix_ms: SafeInteger::new(
                capability
                    .expires_at
                    .checked_mul(1000)
                    .ok_or(RecoveryRuntimeError::Unavailable)?,
            )
            .map_err(invalid)?,
        };
        service.evaluate(snapshot, registry, audience)
    }

    fn recheck_explanation_audience(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        artifact: &ProtectedRecoveryExplanationV1,
        permission: RecoveryPermission,
    ) -> Result<InformationLabel, RecoveryRuntimeError> {
        let actor = self.explanation_actor(capability, permission)?;
        let profile = self
            .kernel
            .recovery_deployment(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let assignment = profile
            .actors
            .as_slice()
            .iter()
            .find(|a| a.principal == *actor.principal())
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?;
        if matches!(assignment.preview_clearance, InformationLabel::Top) {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        let record = self
            .kernel
            .read_recovery_workflow(&actor, workflow)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let observation = self
            .kernel
            .observe_recovery_source(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let source = self
            .flow
            .recovery_input_source(&record.seed, &profile.security_context, &observation)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        // A change during planning refuses the observed view. Native admission
        // still checks every basis afresh on a later resume.
        let source_label = record
            .action
            .as_ref()
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?
            .authorization_requirements
            .source_label
            .join_restrictions(&source)
            .unwrap_or(InformationLabel::Top);
        if source_label != artifact.snapshot.context_label
            || artifact.view.body().recipient.as_str() != actor.principal().as_str()
        {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        let basis = SourceDigest::from_bytes(
            recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::Influence,
                &observation.snapshot(),
            )
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?,
        );
        if assignment.preview_clearance != artifact.audience_clearance
            || artifact.snapshot.influence
                != (ExplanationInfluenceV1::Observed {
                    basis,
                    integrity: ExplanationIntegrity::NativeOwned,
                })
            || crate::recovery::materialize::now()? >= artifact.view.body().expires_at_unix_ms.get()
        {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        Ok(assignment.preview_clearance.clone())
    }
}
