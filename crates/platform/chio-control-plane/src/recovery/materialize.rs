use super::runtime::*;
use chio_core_types::recovery::{
    GrantVersionV2, RecoveryDigestDomain, RecoveryGrantBodyV2, RecoveryGrantSchema,
    SignedRecoveryGrantV2,
};
use chio_core_types::{canonical_json_bytes, sha256};
use chio_kernel::recovery::*;
use chio_security_types::ports::GrantId;
use chio_security_types::recovery::*;
use chio_security_types::{DeclassificationGrantBody, DeclassificationGrantClaims};

fn hash<T: serde::Serialize>(
    domain: RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], RecoveryRuntimeError> {
    recovery_digest(domain, value).map_err(|_| RecoveryRuntimeError::InvalidCommand)
}
pub(super) fn now() -> Result<u64, RecoveryRuntimeError> {
    if let Some(seconds) = chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
        return seconds
            .checked_mul(1000)
            .ok_or(RecoveryRuntimeError::Unavailable);
    }
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RecoveryRuntimeError::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| RecoveryRuntimeError::Unavailable)
}
pub(super) fn operation_key(id: &ContinuationId) -> String {
    format!("recovery:{}", id.as_str())
}
fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in bytes {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 15)] as char);
    }
    result
}
fn digest_bytes(hex: &str) -> Result<[u8; 32], RecoveryRuntimeError> {
    if hex.len() != 64 {
        return Err(RecoveryRuntimeError::Conflict);
    }
    let mut result = [0; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        fn nibble(byte: u8) -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            }
        }
        result[index] = nibble(pair[0])
            .and_then(|high| nibble(pair[1]).map(|low| (high << 4) | low))
            .ok_or(RecoveryRuntimeError::Conflict)?;
    }
    Ok(result)
}
impl RecoveryRuntime {
    pub(super) fn materialize(
        &self,
        actor: &AuthenticatedRecoveryActor,
        id: &WorkflowId,
    ) -> Result<(), RecoveryRuntimeError> {
        let record = self
            .kernel
            .read_recovery_workflow(actor, id)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let origin = record
            .origin
            .as_ref()
            .ok_or(RecoveryRuntimeError::Conflict)?;
        if record
            .action
            .as_ref()
            .is_some_and(|action| action.origin.as_ref() != Some(origin))
        {
            return Err(RecoveryRuntimeError::Conflict);
        }
        if record.action.is_some() {
            return self.attach_process_reservation(actor, id, &record);
        }
        let profile = self
            .kernel
            .recovery_deployment(&self.scope)
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        let key = operation_key(&record.continuation_id);
        let mut request = record.seed.clone();
        request.request_id = self
            .process
            .request_id(self.scope.process_id.as_str(), &key)
            .map_err(|_| RecoveryRuntimeError::Conflict)?;
        let identity = self
            .kernel
            .recovery_native_identity(&request, &profile.security_context)
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        let observation = self
            .kernel
            .observe_recovery_source(&self.scope)
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        let state = observation
            .snapshot()
            .ok_or(RecoveryRuntimeError::UnsupportedProfile)?;
        let source = self
            .flow
            .recovery_input_source(&request, &profile.security_context, &observation)
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        let semantics = request
            .recovery_review_projection()
            .canonical_semantics()
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        let ceiling = now()?
            .checked_add(MAX_RECOVERY_REVIEW_MS)
            .ok_or(RecoveryRuntimeError::Unavailable)?
            .min(
                request
                    .capability
                    .expires_at
                    .checked_mul(1000)
                    .ok_or(RecoveryRuntimeError::InvalidCommand)?,
            );
        let requirements = AuthorizationRequirementsV1 {
            schema: AuthorizationRequirementsSchema::V1,
            version: VersionV1,
            scope: self.scope.clone(),
            source_label: source.clone(),
            admitted_target: profile.target_label.clone(),
            source_join: SourceDigest::from_bytes(hash(RecoveryDigestDomain::Source, &source)?),
            influence_basis: SourceDigest::from_bytes(hash(
                RecoveryDigestDomain::Influence,
                state,
            )?),
            recipient: profile.recipient.clone(),
            purpose: profile.purpose.clone(),
            obligations: chio_flow::required_recovery_disclosure_obligations(
                &source,
                &profile.target_label,
            )
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?,
            issuer_scope: profile.authority_scope,
            validity_ceiling_unix_ms: SafeInteger::new(ceiling)
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            attachment_profile: profile.attachment_profile,
        };
        let action = ActionIntentV1 {
            schema: ActionIntentSchema::V1,
            version: VersionV1,
            origin: Some(
                record
                    .origin
                    .clone()
                    .ok_or(RecoveryRuntimeError::Conflict)?,
            ),
            scope: self.scope.clone(),
            workflow_id: record.workflow_id,
            step_id: record.step_id,
            continuation_id: record.continuation_id.clone(),
            request_id: RequestId::new(&request.request_id)
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            request_namespace: RequestNamespaceDigest::from_bytes(digest_bytes(
                identity.binding().request_namespace_digest().as_str(),
            )?),
            capability_id: chio_security_types::ports::RecordId::new(&request.capability.id)
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            capability_body: CapabilityBodyDigest::from_bytes(hash(
                RecoveryDigestDomain::CapabilityBody,
                &request.capability.signing_body(),
            )?),
            semantic_request: SemanticRequestDigest::from_bytes(
                *sha256(semantics.as_bytes()).as_bytes(),
            ),
            authorization_requirements: requirements,
            policy_digest: profile.policy_digest,
            contract_digest: profile.contract_digest,
            authority_scope: profile.authority_scope,
            basis: BasisDigest::from_bytes(hash(
                RecoveryDigestDomain::Basis,
                &(
                    state,
                    profile.policy_digest,
                    profile.contract_digest,
                    profile.authority_scope,
                ),
            )?),
            source_generation: SafeInteger::new(state.context_generation)
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            output_disposition: OutputDispositionDigest::from_bytes(hash(
                RecoveryDigestDomain::OutputDisposition,
                &("original-process", &self.scope, &profile.target_label),
            )?),
            isolation_lineage: IsolationLineageId::new(
                profile.security_context.as_v1().lineage_root_id().as_str(),
            )
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            isolation_epoch: SafeInteger::new(
                profile.security_context.as_v1().context_generation(),
            )
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
        };
        let preview = request
            .recovery_review_projection()
            .canonical_action_preview(&action)
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        if preview.as_bytes().len() > 32768 {
            return Err(RecoveryRuntimeError::InvalidCommand);
        }
        // Freeze time-dependent action bytes before crossing the process store.
        // A lost acknowledgement recovers those exact bytes on either side.
        let retained = self
            .kernel
            .materialize_recovery_action(actor, id, &action)
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        #[cfg(test)]
        super::test_cutpoint("action");
        self.attach_process_reservation(actor, id, &retained)
    }
    fn attach_process_reservation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        id: &WorkflowId,
        record: &RecoveryWorkflowRecordV1,
    ) -> Result<(), RecoveryRuntimeError> {
        let action = record
            .action
            .as_ref()
            .ok_or(RecoveryRuntimeError::Conflict)?;
        let reservation = self
            .process
            .reserve_recovery_call(
                self.scope.process_id.as_str(),
                &operation_key(&record.continuation_id),
                &record.continuation_id,
                IntentDigest::from_bytes(hash(RecoveryDigestDomain::ActionIntent, action)?),
                record.seed.server_id.as_str(),
            )
            .map_err(|_| RecoveryRuntimeError::Conflict)?;
        #[cfg(test)]
        super::test_cutpoint("reservation");
        let data = serde_json::from_slice(
            &canonical_json_bytes(&reservation).map_err(|_| RecoveryRuntimeError::Conflict)?,
        )
        .map_err(|_| RecoveryRuntimeError::Conflict)?;
        self.kernel
            .acknowledge_recovery_reservation(actor, id, &data, &self.process)
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        #[cfg(test)]
        super::test_cutpoint("reservation-attached");
        Ok(())
    }
    /// Return an exact authorized review document. Consumers must render the
    /// full canonical action and exact payload, without rewriting or truncation.
    pub fn review_document(
        &self,
        capability: &chio_core_types::capability::token::CapabilityToken,
        id: &WorkflowId,
    ) -> Result<RecoveryReviewDocumentV1, RecoveryRuntimeError> {
        let intent = self.approval_intent(capability, id)?;
        let actor = self
            .kernel
            .authenticate_recovery_actor(&self.scope, capability, RecoveryPermission::Approve)
            .map_err(super::authentication_error)?;
        let record = self
            .kernel
            .read_recovery_workflow(&actor, id)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let action = record.action.ok_or(RecoveryRuntimeError::Conflict)?;
        let preview = record
            .seed
            .recovery_review_projection()
            .canonical_action_preview(&action)
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        let bytes = preview.as_bytes();
        if intent.preview
            != recovery_review_digest(&action, &record.seed)
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?
        {
            return Err(RecoveryRuntimeError::Conflict);
        }
        let canonical_preview = ProtectedText::new(
            std::str::from_utf8(bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
        )
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        Ok(RecoveryReviewDocumentV1 {
            intent,
            canonical_preview,
        })
    }
    pub fn approval_intent(
        &self,
        capability: &chio_core_types::capability::token::CapabilityToken,
        id: &WorkflowId,
    ) -> Result<ApprovalIntentV1, RecoveryRuntimeError> {
        let actor = self
            .kernel
            .authenticate_recovery_actor(&self.scope, capability, RecoveryPermission::Approve)
            .map_err(super::authentication_error)?;
        self.validate_protected_mediation()?;
        let record = self
            .kernel
            .read_recovery_workflow(&actor, id)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        if let Some(review) = record.review {
            return Ok(review);
        }
        let action = record.action.ok_or(RecoveryRuntimeError::Conflict)?;
        let intent = IntentDigest::from_bytes(hash(RecoveryDigestDomain::ActionIntent, &action)?);
        let requirements = AuthorizationRequirementsDigest::from_bytes(hash(
            RecoveryDigestDomain::AuthorizationRequirements,
            &action.authorization_requirements,
        )?);
        let draft = ApprovalIntentV1 {
            schema: ApprovalIntentSchema::V1,
            version: VersionV1,
            scope: self.scope.clone(),
            approval_intent: ApprovalIntentRef::new(&format!(
                "approval:{}",
                hex(intent.as_bytes())
            ))
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            challenge: ChallengeId::new(&format!("challenge:{}", hex(intent.as_bytes())))
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            action_intent: intent,
            authorization_requirements: requirements,
            offer: OfferDigest::from_bytes(hash(
                RecoveryDigestDomain::Offer,
                &(intent, action.basis, &action.scope),
            )?),
            plan: PlanDigest::from_bytes(hash(
                RecoveryDigestDomain::Plan,
                &(intent, requirements),
            )?),
            preview: recovery_review_digest(&action, &record.seed)
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            recipient: action.authorization_requirements.recipient.clone(),
            purpose: action.authorization_requirements.purpose.clone(),
            obligations: action.authorization_requirements.obligations.clone(),
            reviewer: actor.principal().clone(),
            issued_at_unix_ms: SafeInteger::new(now()?)
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            expires_at_unix_ms: action.authorization_requirements.validity_ceiling_unix_ms,
        };
        let review = self
            .kernel
            .reserve_recovery_review(&actor, id, &draft)
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        #[cfg(test)]
        super::test_cutpoint("review");
        Ok(review)
    }
    pub(super) fn prepare_original(
        &self,
        actor: &AuthenticatedRecoveryActor,
        id: &WorkflowId,
    ) -> Result<chio_process::RecoveryCallReservation, RecoveryRuntimeError> {
        let record = self
            .kernel
            .read_recovery_workflow(actor, id)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let action = record
            .action
            .as_ref()
            .ok_or(RecoveryRuntimeError::Conflict)?;
        let intent = IntentDigest::from_bytes(hash(RecoveryDigestDomain::ActionIntent, action)?);
        let profile = self
            .kernel
            .recovery_deployment(&self.scope)
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        let reservation = self
            .process
            .reserve_recovery_call(
                self.scope.process_id.as_str(),
                &operation_key(&record.continuation_id),
                &record.continuation_id,
                intent,
                profile.server_id.as_str(),
            )
            .map_err(|_| RecoveryRuntimeError::Conflict)?;
        if record.envelope.is_some() {
            return Ok(reservation);
        }
        let approval = record
            .approval
            .as_ref()
            .ok_or(RecoveryRuntimeError::Conflict)?;
        let body = match record.issuance.clone() {
            Some(body) => body,
            None => {
                let assignments = profile
                    .coverage
                    .as_slice()
                    .iter()
                    .map(|assignment| {
                        (
                            assignment.issuer_id.clone(),
                            chio_flow::RecoveryAuthorityAssignment {
                                principal: assignment.principal.clone(),
                                key: assignment.key.clone(),
                                obligations: assignment
                                    .obligations
                                    .as_slice()
                                    .iter()
                                    .cloned()
                                    .collect(),
                            },
                        )
                    })
                    .collect();
                let coverage = chio_flow::verify_recovery_coverage(
                    &approval.intent,
                    &action.authorization_requirements,
                    action.basis,
                    &approval.coverage,
                    &assignments,
                    now()?,
                )
                .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
                let context = profile.security_context.as_v1();
                let issued = now()? / 1000;
                let mut expires = issued
                    .checked_add(MAX_RECOVERY_GRANT_SECONDS)
                    .ok_or(RecoveryRuntimeError::InvalidCommand)?
                    .min(record.seed.capability.expires_at)
                    .min(approval.intent.expires_at_unix_ms.get() / 1000);
                for proof in approval.coverage.as_slice() {
                    expires = expires.min(proof.body().expires_at_unix_ms.get() / 1000);
                }
                let claims = DeclassificationGrantBody::new(DeclassificationGrantClaims {
                    grant_id: GrantId::new(format!("grant:{}", hex(intent.as_bytes())))
                        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
                    capability_id: action.capability_id.clone(),
                    tenant_id: context.tenant_id().clone(),
                    subject_id: context.principal_id().clone(),
                    agent_id: chio_security_types::ports::RecordId::new(&record.seed.agent_id)
                        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
                    session_id: context.session_id().clone(),
                    source_label_hash: chio_flow::information_label_hash(
                        &action.authorization_requirements.source_label,
                    )
                    .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
                    target_label: profile.target_label.clone(),
                    destination_id: profile.recipient.clone(),
                    tool_name: profile.tool_name.clone(),
                    purpose: profile.purpose.clone(),
                    request_hash: chio_security_types::ports::Digest32::new(
                        *sha256(
                            &canonical_json_bytes(&record.seed.arguments)
                                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
                        )
                        .as_bytes(),
                    ),
                    issued_at_unix_seconds: issued,
                    expires_at_unix_seconds: expires,
                    authority_key_id: profile.aggregate_issuer_id.clone(),
                })
                .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
                RecoveryGrantBodyV2 {
                    schema: RecoveryGrantSchema::V2,
                    domain_version: GrantVersionV2,
                    claims,
                    recovery: RecoveryGrantBindingV1 {
                        schema: RecoveryGrantBindingSchema::V1,
                        version: VersionV1,
                        authority_domain: self.scope.authority_domain.clone(),
                        workflow_id: record.workflow_id.clone(),
                        step_id: record.step_id.clone(),
                        continuation_id: record.continuation_id.clone(),
                        process_id: self.scope.process_id.clone(),
                        request_namespace: action.request_namespace,
                        request_id: action.request_id.clone(),
                        action_intent: intent,
                        authorization_requirements: approval.intent.authorization_requirements,
                        selected_offer: approval.intent.offer,
                        approved_plan: approval.intent.plan,
                        policy_digest: action.policy_digest,
                        contract_digest: action.contract_digest,
                        authority_scope: action.authority_scope,
                        isolation_lineage: action.isolation_lineage.clone(),
                        isolation_epoch: action.isolation_epoch,
                        output_disposition: action.output_disposition,
                        coverage_digest: coverage.digest(),
                        approval_intent: approval.intent.approval_intent.clone(),
                        challenge: approval.intent.challenge.clone(),
                    },
                }
            }
        };
        let body = self
            .kernel
            .reserve_recovery_issuance(actor, id, &body)
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        #[cfg(test)]
        super::test_cutpoint("issuance");
        let signed = match record.signed_grant {
            Some(grant) => grant,
            None => {
                let signed = SignedRecoveryGrantV2::sign_with_backend(body, self.signer.as_ref())
                    .map_err(|_| RecoveryRuntimeError::Unavailable)?;
                #[cfg(test)]
                {
                    if std::env::var_os("CHIO_RECOVERY_CRASH_CHILD").is_some()
                        && std::env::var("CHIO_RECOVERY_CRASH_POINT")
                            .is_ok_and(|point| point == "signed")
                    {
                        let root = std::env::var_os("CHIO_RECOVERY_CRASH_ROOT")
                            .ok_or(RecoveryRuntimeError::Unavailable)?;
                        std::fs::write(
                            std::path::PathBuf::from(root).join("unacknowledged-signature.json"),
                            canonical_json_bytes(&signed)
                                .map_err(|_| RecoveryRuntimeError::Unavailable)?,
                        )
                        .map_err(|_| RecoveryRuntimeError::Unavailable)?;
                    }
                    super::test_cutpoint("signed");
                }
                self.kernel
                    .attach_recovery_signature(actor, id, &signed)
                    .map_err(|_| RecoveryRuntimeError::Unavailable)?;
                signed
            }
        };
        #[cfg(test)]
        super::test_cutpoint("signature-attached");
        let mut request = record.seed;
        request.declassification_grant = Some(signed.into());
        let bytes =
            canonical_json_bytes(&request).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        let (request_digest, binding_digest) = self
            .process
            .recovery_request_digests(
                self.scope.process_id.as_str(),
                reservation.operation_key(),
                &request,
            )
            .map_err(|_| RecoveryRuntimeError::Conflict)?;
        let identity = self
            .kernel
            .recovery_native_identity(&request, &profile.security_context)
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        let envelope = FinalizedRequestEnvelopeV1 {
            action_intent: intent,
            authorization_requirements: approval.intent.authorization_requirements,
            request: ProtectedText::new(
                std::str::from_utf8(&bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            )
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            process_request_digest: ProcessRequestDigest::from_bytes(digest_bytes(
                &request_digest,
            )?),
            process_binding_digest: ProcessCallBindingDigest::from_bytes(digest_bytes(
                &binding_digest,
            )?),
        };
        self.kernel
            .finalize_recovery_envelope(actor, id, &envelope, &identity)
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        #[cfg(test)]
        super::test_cutpoint("envelope");
        Ok(reservation)
    }
}
