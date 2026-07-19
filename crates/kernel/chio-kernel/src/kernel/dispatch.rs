//! `ChioKernel` guard evaluation, runtime admission, and tool dispatch.
//!
//! Holds parent-request continuation, guard execution, runtime admission
//! hook invocation, the tool-dispatch entrypoints, and child-receipt
//! recording.

use crate::budget_store::{
    BudgetAdmissionOperationBinding, BudgetReleaseHoldDecision, BudgetReverseHoldDecision,
};
use chio_log_redact::redacted;

use super::*;

const SECURITY_PRE_DISPATCH_GUARD_NAME: &str = "chio-security-pre-dispatch";
const SECURITY_PRE_DISPATCH_MISSING_CONTEXT_REASON: &str =
    "authoritative security context is missing at dispatch";
const SECURITY_PRE_DISPATCH_MISSING_HOOK_REASON: &str =
    "security pre-dispatch hook is not installed";
const SECURITY_PRE_DISPATCH_BINDING_REASON: &str =
    "security pre-dispatch commitment could not be derived";
const SECURITY_PRE_DISPATCH_REJECTION_REASON: &str = "security pre-dispatch hook rejected dispatch";
const SECURITY_DISPATCH_COMMITMENT_DOMAIN: &[u8] =
    b"chio.kernel.security-pre-dispatch.commitment.v2\0";

#[derive(serde::Serialize)]
struct SecurityDispatchContextBinding<'a> {
    schema: &'static str,
    context_version: u16,
    tenant_id: &'a str,
    session_id: &'a str,
    principal_id: &'a str,
    isolation_epoch_id: &'a str,
    lineage_root_id: &'a str,
    /// Immutable capability-bound isolation-incarnation generation.
    context_generation: u64,
    /// Mutable durable flow generation observed for this dispatch.
    flow_state_generation: Option<u64>,
}

fn security_pre_dispatch_denial(reason: &'static str) -> SecurityPreDispatchDenial {
    SecurityPreDispatchDenial {
        reason,
        evidence: GuardEvidence {
            guard_name: SECURITY_PRE_DISPATCH_GUARD_NAME.to_string(),
            verdict: false,
            details: Some(reason.to_string()),
        },
    }
}

pub(crate) fn derive_security_dispatch_commitment_id(
    canonical_request: &[u8],
    security_context: &SecurityInvocationContext,
) -> Result<chio_security_types::ports::RecordId, KernelError> {
    let context = security_context.as_v1();
    let binding = SecurityDispatchContextBinding {
        schema: "chio.kernel.security-dispatch-context.v2",
        context_version: security_context.version(),
        tenant_id: context.tenant_id().as_str(),
        session_id: context.session_id().as_str(),
        principal_id: context.principal_id().as_str(),
        isolation_epoch_id: context.isolation_epoch_id().as_str(),
        lineage_root_id: context.lineage_root_id().as_str(),
        context_generation: context.context_generation(),
        flow_state_generation: context.flow_state_generation(),
    };
    let canonical_context = canonical_json_bytes(&binding).map_err(|error| {
        KernelError::Internal(format!(
            "failed to canonicalize security dispatch context: {error}"
        ))
    })?;
    let request_len = u64::try_from(canonical_request.len()).map_err(|_| {
        KernelError::Internal("canonical security dispatch request is too large".to_string())
    })?;
    let context_len = u64::try_from(canonical_context.len()).map_err(|_| {
        KernelError::Internal("canonical security dispatch context is too large".to_string())
    })?;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(SECURITY_DISPATCH_COMMITMENT_DOMAIN);
    preimage.extend_from_slice(&request_len.to_be_bytes());
    preimage.extend_from_slice(canonical_request);
    preimage.extend_from_slice(&context_len.to_be_bytes());
    preimage.extend_from_slice(&canonical_context);
    chio_security_types::ports::RecordId::new(format!(
        "dispatch-commitment:{}",
        sha256_hex(&preimage)
    ))
    .map_err(|error| {
        KernelError::Internal(format!(
            "failed to construct security dispatch commitment identifier: {error}"
        ))
    })
}

pub(crate) struct GuardRunError {
    pub(crate) error: KernelError,
    pub(crate) evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
}

impl GuardRunError {
    fn new(error: KernelError, evidence: Vec<chio_core::receipt::metadata::GuardEvidence>) -> Self {
        Self { error, evidence }
    }
}

impl ChioKernel {
    /// Bind trusted-host security state to the request that will cross the
    /// connector boundary. This validation must run before receipt scoping,
    /// guard mutation, session inflight tracking, or any connector side effect.
    pub(crate) fn validate_security_invocation_context_binding(
        &self,
        request: &ToolCallRequest,
        security_context: Option<&SecurityInvocationContext>,
        authenticated_session_id: Option<&SessionId>,
    ) -> Result<(), KernelError> {
        let capability_binding = request.capability.security_binding().map_err(|error| {
            KernelError::GuardDenied(format!("capability security binding is invalid: {error}"))
        })?;
        let expected_workload = self.capability_authority.workload_binding();
        let Some(security_context) = security_context else {
            if capability_binding.is_some() || expected_workload.is_some() {
                return Err(KernelError::GuardDenied(
                    "security-bound capability requires an authoritative invocation context"
                        .to_string(),
                ));
            }
            return Ok(());
        };
        let context = security_context.as_v1();
        if context.principal_id().as_str() != request.agent_id.as_str() {
            return Err(KernelError::GuardDenied(
                "authoritative security context principal does not match the request agent"
                    .to_string(),
            ));
        }

        let expected_lineage_root = capability_binding
            .as_ref()
            .map(|binding| binding.lineage_id.as_str())
            .or_else(|| {
                self.capability_issuance_admission_authority
                    .is_none()
                    .then(|| {
                        request
                            .capability
                            .delegation_chain
                            .first()
                            .map_or(request.capability.id.as_str(), |link| {
                                link.capability_id.as_str()
                            })
                    })
            });
        if expected_lineage_root
            .is_some_and(|lineage_root| context.lineage_root_id().as_str() != lineage_root)
        {
            return Err(KernelError::GuardDenied(
                "authoritative security context lineage root does not match the request capability"
                    .to_string(),
            ));
        }

        if authenticated_session_id
            .is_some_and(|session_id| context.session_id().as_str() != session_id.as_str())
        {
            return Err(KernelError::GuardDenied(
                "authoritative security context does not match the authenticated session"
                    .to_string(),
            ));
        }
        match (capability_binding.as_ref(), expected_workload.as_ref()) {
            (Some(binding), Some(workload)) => {
                if binding.tenant_id != context.tenant_id().as_str()
                    || binding.lineage_id != context.lineage_root_id().as_str()
                    || binding.session_id != context.session_id().as_str()
                    || binding.principal_id != context.principal_id().as_str()
                    || binding.isolation_epoch_id != context.isolation_epoch_id().as_str()
                    || binding.context_generation != context.context_generation()
                    || binding.tenant_id != workload.tenant_id
                    || binding.workload_id != workload.workload_id
                    || binding.server_id != workload.server_id
                    || binding.workload_signer_public_key != workload.signer_public_key.to_hex()
                {
                    return Err(KernelError::GuardDenied(
                        "capability security binding does not match the live invocation and pinned workload identity"
                            .to_string(),
                    ));
                }
                if !request.capability.delegation_chain.is_empty() {
                    return Err(KernelError::GuardDenied(
                        "security-bound remote capabilities cannot be delegated".to_string(),
                    ));
                }
            }
            (Some(_), None) => {
                return Err(KernelError::GuardDenied(
                    "capability carries a workload binding but no workload authority is pinned"
                        .to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(KernelError::GuardDenied(
                    "pinned workload authority returned an unbound capability".to_string(),
                ));
            }
            (None, None) => {}
        }
        Ok(())
    }

    pub(crate) fn run_security_pre_dispatch_hook(
        &self,
        request: &ToolCallRequest,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<SecurityPreDispatchCommit, SecurityPreDispatchDenial> {
        let Some(security_context) = security_context else {
            return if self.security_pre_dispatch_policy == SecurityPreDispatchPolicy::Enforce {
                Err(security_pre_dispatch_denial(
                    SECURITY_PRE_DISPATCH_MISSING_CONTEXT_REASON,
                ))
            } else {
                Ok(SecurityPreDispatchCommit {
                    dispatch_outcome: None,
                    request_lifecycle: None,
                })
            };
        };
        let Some(hook) = self.security_pre_dispatch_hook.as_ref() else {
            return if self.security_pre_dispatch_policy == SecurityPreDispatchPolicy::Enforce {
                Err(security_pre_dispatch_denial(
                    SECURITY_PRE_DISPATCH_MISSING_HOOK_REASON,
                ))
            } else {
                Ok(SecurityPreDispatchCommit {
                    dispatch_outcome: None,
                    request_lifecycle: None,
                })
            };
        };
        let canonical_request = canonical_json_bytes(request).map_err(|error| {
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&error.to_string()),
                "security pre-dispatch request canonicalization failed"
            );
            security_pre_dispatch_denial(SECURITY_PRE_DISPATCH_BINDING_REASON)
        })?;
        let dispatch_commitment_id =
            derive_security_dispatch_commitment_id(&canonical_request, security_context).map_err(
                |error| {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&error.to_string()),
                        "security pre-dispatch commitment derivation failed"
                    );
                    security_pre_dispatch_denial(SECURITY_PRE_DISPATCH_BINDING_REASON)
                },
            )?;
        let context = SecurityPreDispatchContext {
            request,
            canonical_request: &canonical_request,
            security_context,
            dispatch_commitment_id: &dispatch_commitment_id,
        };
        let map_rejection = |error: KernelError| {
            warn!(
                request_id = %request.request_id,
                hook = hook.name(),
                reason = %redacted!(&error.to_string()),
                "security pre-dispatch hook rejected dispatch"
            );
            security_pre_dispatch_denial(SECURITY_PRE_DISPATCH_REJECTION_REASON)
        };
        let request_lifecycle = hook
            .acquire_request_lifecycle(&context)
            .map_err(&map_rejection)?;
        let dispatch_outcome = hook.commit(&context).map_err(map_rejection)?;
        Ok(SecurityPreDispatchCommit {
            dispatch_outcome,
            request_lifecycle,
        })
    }

    pub(crate) fn validate_parent_request_continuation(
        &self,
        request: &ToolCallRequest,
        parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        let child_request_id = RequestId::new(request.request_id.clone());
        self.with_session(&parent_context.session_id, |session| {
            session.validate_context(parent_context)?;
            session
                .validate_parent_request_lineage(&child_request_id, &parent_context.request_id)?;
            Ok(())
        })
    }

    pub(crate) fn has_local_receipt_id(&self, receipt_id: &str) -> Result<bool, KernelError> {
        // Store-authoritative: a durable store is a point lookup by id, not an
        // O(n) mirror scan. On a store MISS fall back to the local mirror below: a
        // store may implement append without point loads (for example an
        // append-only or remote store), so a receipt appended and mirrored locally
        // must still resolve. A store READ ERROR fails closed and PROPAGATES; only
        // a genuine miss (`Ok(None)`) falls through to the mirror, so a store
        // verification failure is never masked by a mirror hit.
        //
        // Boundary: if that append-only/remote store does not implement point
        // loads, the bounded mirror is the ONLY lookup source.
        // Once the mirror evicts a receipt past `receipt_mirror_capacity`, this
        // returns `Ok(false)` and the dependent call-chain claim is denied
        // (fail-closed, never a false allow). Such deployments must implement
        // `ReceiptStore::load_chio_receipt` so older parent receipts stay
        // point-loadable after eviction.
        if self.receipt_store.is_some() {
            if self
                .with_receipt_store(|store| Ok(store.load_chio_receipt(receipt_id)?))?
                .flatten()
                .is_some()
            {
                return Ok(true);
            }
            if self
                .with_receipt_store(|store| Ok(store.load_child_receipt(receipt_id)?))?
                .flatten()
                .is_some()
            {
                return Ok(true);
            }
            // Store miss: fall through to the local mirror scan.
        }
        // Local mirror scan (no store, or store missed).
        let chio_receipt_match = match self.receipt_log.lock() {
            Ok(log) => log.iter().any(|receipt| receipt.id == receipt_id),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .any(|receipt| receipt.id == receipt_id),
        };
        if chio_receipt_match {
            return Ok(true);
        }

        Ok(match self.child_receipt_log.lock() {
            Ok(log) => log.iter().any(|receipt| receipt.id == receipt_id),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .any(|receipt| receipt.id == receipt_id),
        })
    }

    pub(crate) fn local_receipt_artifact(
        &self,
        receipt_id: &str,
    ) -> Result<Option<LocalReceiptArtifact>, KernelError> {
        // Consult the durable store first; on a MISS fall back to the local
        // mirror (append-only / remote stores may not implement point loads, so
        // a receipt appended and mirrored locally must still resolve). A store
        // READ ERROR fails closed and PROPAGATES; only a genuine miss
        // (`Ok(None)`) falls through to the mirror, so a store verification
        // failure can never be accepted from the bounded mirror.
        if self.receipt_store.is_some() {
            if let Some(receipt) = self
                .with_receipt_store(|store| Ok(store.load_chio_receipt(receipt_id)?))?
                .flatten()
            {
                return Ok(Some(LocalReceiptArtifact::Tool(Box::new(receipt))));
            }
            if let Some(child) = self
                .with_receipt_store(|store| Ok(store.load_child_receipt(receipt_id)?))?
                .flatten()
            {
                return Ok(Some(LocalReceiptArtifact::Child(Box::new(child))));
            }
            // Store miss: fall through to the local mirror scan.
        }
        let tool_match = match self.receipt_log.lock() {
            Ok(log) => log
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Tool(Box::new(receipt))),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Tool(Box::new(receipt))),
        };
        if tool_match.is_some() {
            return Ok(tool_match);
        }

        Ok(match self.child_receipt_log.lock() {
            Ok(log) => log
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Child(Box::new(receipt))),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Child(Box::new(receipt))),
        })
    }

    pub(crate) fn verify_trusted_governed_continuation_signer(
        &self,
        token: &chio_core::capability::governance::CallChainContinuationToken,
    ) -> Result<bool, KernelError> {
        let signer = &token.signer;
        if self
            .config
            .ca_public_keys
            .iter()
            .any(|candidate| candidate == signer)
        {
            return Ok(true);
        }
        if self.authority_artifact_trust_resolver.is_some() {
            let artifact = canonical_json_bytes(&token.body())
                .map_err(|error| KernelError::Internal(error.to_string()))?;
            return self.verify_trusted_authority_artifact_signature(
                &artifact,
                signer,
                &token.signature,
            );
        }
        if *signer == self.public_key() {
            return Ok(true);
        }
        Ok(self
            .capability_authority
            .trusted_public_keys()
            .into_iter()
            .any(|candidate| candidate == *signer))
    }

    pub(crate) fn unwind_aborted_monetary_invocation(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Result<Option<BudgetReverseHoldDecision>, KernelError> {
        let charge = budget_mutation.charge_result();

        // For operation-owned admission this reversal first wins the shared
        // compensation-versus-dispatch CAS. Payment is a participant in that
        // operation and must not be released while dispatch can still win.
        let reversed = self.reverse_pre_execution_budget_mutation(cap, budget_mutation)?;

        if let (Some(charge), Some(authorization)) = (charge, payment_authorization) {
            let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "payment authorization present without configured adapter".to_string(),
                )
            })?;
            let unwind = || match (authorization.settled, charge.admission_operation.as_ref()) {
                (true, Some(binding)) => {
                    adapter.refund_for_operation(OperationPaymentRefundRequest {
                        operation_id: binding.operation_id(),
                        request_binding_hash: binding.request_binding_hash(),
                        transaction_id: &authorization.authorization_id,
                        amount_units: charge.cost_charged,
                        currency: &charge.currency,
                        reference: &request.request_id,
                    })
                }
                (true, None) => adapter.refund(
                    &authorization.authorization_id,
                    charge.cost_charged,
                    &charge.currency,
                    &request.request_id,
                ),
                (false, Some(binding)) => adapter.release_for_operation(
                    binding.operation_id(),
                    binding.request_binding_hash(),
                    &authorization.authorization_id,
                    &request.request_id,
                ),
                (false, None) => {
                    adapter.release(&authorization.authorization_id, &request.request_id)
                }
            };
            let unwind_result = unwind();
            let unwind_result = if charge.admission_operation.is_some() {
                unwind_result.or_else(|_| unwind())
            } else {
                unwind_result
            };
            if let Err(error) = unwind_result {
                return Err(KernelError::Internal(format!(
                    "failed to unwind payment after aborted tool invocation: {error}"
                )));
            }
        }

        Ok(reversed)
    }

    pub(crate) fn release_post_dispatch_monetary_invocation(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        charge_result: Option<&BudgetChargeResult>,
        payment_authorization: Option<&PaymentAuthorization>,
        retain_operation_owned_budget: bool,
    ) -> Result<Option<BudgetReleaseHoldDecision>, PostDispatchCleanupFailure> {
        if retain_operation_owned_budget {
            return Ok(None);
        }
        let Some(charge) = charge_result else {
            return Ok(None);
        };

        let failure = |step: &'static str, reason: String| {
            let mut hold_ids = vec![cap.id.clone(), charge.budget_hold_id.clone()];
            if let Some(authorization) = payment_authorization {
                hold_ids.push(authorization.authorization_id.clone());
            }
            PostDispatchCleanupFailure {
                step,
                reason,
                attempted_release_event_id: charge.release_event_id(),
                hold_ids,
            }
        };

        if let Some(authorization) = payment_authorization {
            let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                failure(
                    "payment_adapter_lookup",
                    "payment authorization present without configured adapter".to_string(),
                )
            })?;
            let payment_step = if authorization.settled {
                "payment_refund"
            } else {
                "payment_release"
            };
            let release_payment =
                || match (authorization.settled, charge.admission_operation.as_ref()) {
                    (true, Some(binding)) => {
                        adapter.refund_for_operation(OperationPaymentRefundRequest {
                            operation_id: binding.operation_id(),
                            request_binding_hash: binding.request_binding_hash(),
                            transaction_id: &authorization.authorization_id,
                            amount_units: charge.cost_charged,
                            currency: &charge.currency,
                            reference: &request.request_id,
                        })
                    }
                    (true, None) => adapter.refund(
                        &authorization.authorization_id,
                        charge.cost_charged,
                        &charge.currency,
                        &request.request_id,
                    ),
                    (false, Some(binding)) => adapter.release_for_operation(
                        binding.operation_id(),
                        binding.request_binding_hash(),
                        &authorization.authorization_id,
                        &request.request_id,
                    ),
                    (false, None) => {
                        adapter.release(&authorization.authorization_id, &request.request_id)
                    }
                };
            let release_result = release_payment();
            let release_result = if charge.admission_operation.is_some() {
                release_result.or_else(|_| release_payment())
            } else {
                release_result
            };
            if let Err(error) = release_result {
                return Err(failure(payment_step, redacted!(&error).to_string()));
            }
        }

        self.release_budget_charge(&cap.id, charge)
            .map(Some)
            .map_err(|error| failure("budget_hold_release", redacted!(&error).to_string()))
    }

    pub(crate) fn post_dispatch_cleanup_receipt_metadata(
        &self,
        base: Option<serde_json::Value>,
        charge: Option<&BudgetChargeResult>,
        cleanup: &Result<Option<BudgetReleaseHoldDecision>, PostDispatchCleanupFailure>,
    ) -> Option<serde_json::Value> {
        match (charge, cleanup) {
            (Some(charge), Ok(Some(released))) => self.merge_budget_receipt_metadata(
                base,
                self.budget_execution_receipt_metadata(charge, Some(("released", released))),
            ),
            (Some(charge), Ok(None)) => self.merge_budget_receipt_metadata(
                base,
                self.budget_execution_receipt_metadata(charge, None),
            ),
            (Some(charge), Err(failure)) => {
                let authorized = self.merge_budget_receipt_metadata(
                    base,
                    self.budget_execution_receipt_metadata(charge, None),
                );
                merge_metadata_objects(
                    authorized,
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "post_dispatch_cleanup_failed": true,
                            "post_dispatch_cleanup_faults": [{
                                "step": failure.step,
                                "reason": failure.reason,
                                "attempted_release_event_id": failure.attempted_release_event_id,
                                "hold_ids": failure.hold_ids,
                            }],
                        }
                    })),
                )
            }
            _ => base,
        }
    }

    pub(crate) fn record_observed_capability_snapshot(
        &self,
        capability: &CapabilityToken,
    ) -> Result<(), KernelError> {
        if self.capability_issuance_admission_authority.is_some() {
            return Err(KernelError::CapabilityIssuanceDenied(
                "authoritative tenant and lineage context is required for capability issuance"
                    .to_string(),
            ));
        }
        let parent_capability_id = capability
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        let _ = self.with_receipt_store(|store| {
            Ok(store.record_capability_snapshot(capability, parent_capability_id)?)
        })?;
        Ok(())
    }

    pub(crate) fn record_observed_capability_snapshot_for_dispatch(
        &self,
        capability: &CapabilityToken,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<(), KernelError> {
        let Some(authority) = self.capability_issuance_admission_authority.as_ref() else {
            return self.record_observed_capability_snapshot(capability);
        };
        let context = security_context.ok_or_else(|| {
            KernelError::CapabilityIssuanceDenied(
                "authoritative tenant and lineage context is required for capability issuance"
                    .to_string(),
            )
        })?;
        let context = context.as_v1();
        let parent_capability_id = capability
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        let already_admitted = self
            .with_receipt_store(|store| {
                store
                    .capability_snapshot_has_issuance_admission(
                        context.tenant_id(),
                        context.lineage_root_id(),
                        capability,
                        parent_capability_id,
                    )
                    .map_err(KernelError::from)
            })?
            .ok_or_else(|| {
                KernelError::CapabilityIssuanceDenied(
                    "durable receipt store is required for capability issuance admission"
                        .to_string(),
                )
            })?;
        if already_admitted {
            return Ok(());
        }
        let parent_capability_id = parent_capability_id
            .map(chio_security_types::ports::RecordId::new)
            .transpose()
            .map_err(|error| KernelError::CapabilityIssuanceDenied(error.to_string()))?;
        let query = chio_security_types::ports::IssuanceFreezeAdmissionQuery {
            tenant_id: context.tenant_id().clone(),
            lineage_id: context.lineage_root_id().clone(),
            operation: if parent_capability_id.is_some() {
                chio_security_types::ports::CapabilityIssuanceOperation::Delegate
            } else {
                chio_security_types::ports::CapabilityIssuanceOperation::Issue
            },
            parent_capability_id,
        };
        authority.authorize(&query).map_err(|error| {
            KernelError::CapabilityIssuanceDenied(format!(
                "active issuance freeze rejected capability admission: {error}"
            ))
        })?;
        let _ = self.with_receipt_store(|store| {
            Ok(store.record_capability_snapshot_with_issuance_admission(
                context.tenant_id(),
                context.lineage_root_id(),
                capability,
                query
                    .parent_capability_id
                    .as_ref()
                    .map(|parent| parent.as_str()),
            )?)
        })?;
        Ok(())
    }

    pub(crate) fn authorize_capability_issuance(
        &self,
        query: &chio_security_types::ports::IssuanceFreezeAdmissionQuery,
    ) -> Result<(), KernelError> {
        let Some(authority) = self.capability_issuance_admission_authority.as_ref() else {
            return Err(KernelError::CapabilityIssuanceDenied(
                "capability issuance admission authority is unavailable".to_string(),
            ));
        };
        authority.authorize(query).map_err(|error| {
            KernelError::CapabilityIssuanceDenied(format!(
                "active issuance freeze rejected capability admission: {error}"
            ))
        })
    }

    /// Verify a DPoP proof carried on the request against the capability.
    ///
    /// Fails closed: if no proof is present, or if the nonce store / config is
    /// absent (misconfigured kernel), or if verification fails, the call is denied.
    pub(crate) fn verify_dpop_for_request(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let proof = request.dpop_proof.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed(
                "grant requires DPoP proof but none was provided".to_string(),
            )
        })?;

        let nonce_store = self.dpop_nonce_store.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed(
                "kernel DPoP nonce store not configured".to_string(),
            )
        })?;

        let config = self.dpop_config.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed("kernel DPoP config not configured".to_string())
        })?;

        let args_bytes = canonical_json_bytes(&request.arguments).map_err(|e| {
            KernelError::DpopVerificationFailed(format!(
                "failed to serialize arguments for action hash: {e}"
            ))
        })?;
        let action_hash = sha256_hex(&args_bytes);

        dpop::verify_dpop_proof(
            proof,
            cap,
            &request.server_id,
            &request.tool_name,
            &action_hash,
            nonce_store,
            config,
        )
    }

    /// Verify a DPoP proof for non-mutating permission preview.
    ///
    /// This mirrors invocation DPoP policy and checks that the nonce store and
    /// config are installed, but deliberately avoids inserting the nonce so a
    /// later authoritative invocation can still spend it.
    pub fn verify_dpop_for_permission_preview(
        &self,
        proof: &dpop::DpopProof,
        cap: &CapabilityToken,
        expected_tool_server: &str,
        expected_tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(), KernelError> {
        if self.dpop_nonce_store.is_none() {
            return Err(KernelError::DpopVerificationFailed(
                "kernel DPoP nonce store not configured".to_string(),
            ));
        }

        let config = self.dpop_config.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed("kernel DPoP config not configured".to_string())
        })?;

        let args_bytes = canonical_json_bytes(arguments).map_err(|e| {
            KernelError::DpopVerificationFailed(format!(
                "failed to serialize arguments for action hash: {e}"
            ))
        })?;
        let action_hash = sha256_hex(&args_bytes);

        dpop::verify_dpop_proof_stateless(
            proof,
            cap,
            expected_tool_server,
            expected_tool_name,
            &action_hash,
            config,
        )
    }

    /// Run all registered guards. Fail-closed: any error from a guard is
    /// treated as a deny.
    pub(crate) fn run_guards(
        &self,
        request: &ToolCallRequest,
        scope: &ChioScope,
        session_filesystem_roots: Option<&[String]>,
        matched_grant_index: Option<usize>,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<Vec<chio_core::receipt::metadata::GuardEvidence>, GuardRunError> {
        let ctx = GuardContext {
            request,
            scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots,
            matched_grant_index,
            security_context,
        };

        let mut evidence = Vec::new();
        for guard in &self.guards {
            match guard.evaluate(&ctx) {
                Ok(decision) => {
                    evidence.extend(decision.evidence);
                    match decision.verdict {
                        Verdict::Allow => {
                            debug!(guard = guard.name(), "guard passed");
                        }
                        Verdict::Deny => {
                            return Err(GuardRunError::new(
                                KernelError::GuardDenied(format!(
                                    "guard \"{}\" denied the request",
                                    guard.name()
                                )),
                                evidence,
                            ));
                        }
                        Verdict::PendingApproval => {
                            // The `Guard` trait does not carry the HITL approval flow; that runs via
                            // `ApprovalGuard::evaluate`. A `Guard` returning `PendingApproval` is an
                            // unsupported state, so fail closed.
                            return Err(GuardRunError::new(
                                KernelError::GuardDenied(format!(
                                    "guard \"{}\" returned an unsupported approval verdict",
                                    guard.name()
                                )),
                                evidence,
                            ));
                        }
                    }
                }
                Err(e) => {
                    // Fail closed: guard errors are treated as denials.
                    return Err(GuardRunError::new(
                        KernelError::GuardDenied(format!(
                            "guard \"{}\" error (fail-closed): {e}",
                            guard.name()
                        )),
                        evidence,
                    ));
                }
            }
        }

        Ok(evidence)
    }

    pub(crate) fn run_runtime_admission_hook(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<&serde_json::Value>,
        now: u64,
        now_unix_ms: u64,
        matched_grant_index: Option<usize>,
    ) -> RuntimeAdmissionDecision {
        self.run_runtime_admission_hook_for_operation(
            request,
            extra_metadata,
            now,
            now_unix_ms,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn run_runtime_admission_hook_for_operation(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<&serde_json::Value>,
        now: u64,
        now_unix_ms: u64,
        matched_grant_index: Option<usize>,
        admission_operation: Option<&AdmissionOperation>,
    ) -> RuntimeAdmissionDecision {
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            let has_runtime_context = request
                .governed_intent
                .as_ref()
                .and_then(|intent| intent.as_tool_invocation())
                .and_then(|intent| intent.context.as_ref())
                .is_some_and(|context| {
                    context.get("chioAdmission").is_some()
                        || context.get("chioTreaty").is_some()
                        || context.get("chioSwarm").is_some()
                });
            if has_runtime_context {
                return RuntimeAdmissionDecision::deny(
                    "chio runtime admission hook is required for governed runtime requests",
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "accepted": false,
                            "failure_code": "runtime_admission_hook_missing"
                        }
                    })),
                );
            }
            if request.federated_origin_kernel_id.is_some() {
                return RuntimeAdmissionDecision::deny(
                    "chio treaty-bound runtime admission context missing",
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "accepted": false,
                            "failure_code": "missing_chio_treaty_context"
                        }
                    })),
                );
            }
            return RuntimeAdmissionDecision::allow(None);
        };
        let context = RuntimeAdmissionContext {
            request,
            extra_metadata,
            now_unix_secs: now,
            now_unix_ms,
            matched_grant_index,
            local_kernel_id: self.federation_local_kernel_id(),
            admission_operation_id: admission_operation.map(AdmissionOperation::operation_id),
            admission_request_binding_hash: admission_operation
                .map(AdmissionOperation::request_binding_hash),
        };
        let evaluation = if admission_operation.is_some() {
            hook.evaluate_before_operation_persist(&context)
        } else {
            hook.evaluate(&context)
        };
        let mut decision = match evaluation {
            Ok(decision) => decision,
            Err(error) => RuntimeAdmissionDecision::deny(
                format!(
                    "runtime admission hook \"{}\" error (fail-closed): {error}",
                    hook.name()
                ),
                Some(serde_json::json!({
                    "runtime_admission": {
                        "hook": hook.name(),
                        "accepted": false,
                        "failure_code": "runtime_admission_hook_error"
                    }
                })),
            ),
        };
        if let Some(operation) = admission_operation {
            decision.metadata = merge_metadata_objects(
                decision.metadata,
                Some(serde_json::json!({
                    "admission_operation": {
                        "operation_id": operation.operation_id(),
                        "request_binding_hash": operation.request_binding_hash(),
                        "runtime_evaluation": "pure_pre_persist"
                    }
                })),
            );
        }
        decision
    }

    pub(crate) fn release_runtime_admission_reservations(
        &self,
        metadata: Option<&serde_json::Value>,
    ) -> Result<(), KernelError> {
        let Some(metadata) = metadata else {
            return Ok(());
        };
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            return Ok(());
        };
        self.release_runtime_admission_metadata(hook.as_ref(), metadata)
    }

    /// Record, in receipt metadata, that runtime-admission reservations
    /// consumed at admission were deliberately NOT released because a tool
    /// side effect may have executed. The reserved ids are copied so an
    /// operator can locate and re-issue the burned lease/continuation from
    /// the signed receipt alone. Fail-closed: metadata without a
    /// `chio_runtime` block, or a `chio_runtime` block that carries no real
    /// reservation (no present, non-empty `reserved_*` id), is returned
    /// unchanged. Marking such metadata retained would claim a reservation was
    /// burned when there was nothing to recover, which misleads operators.
    pub(crate) fn mark_runtime_admission_reservations_retained_fail_closed(
        &self,
        metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let mut retained = serde_json::Map::new();
        {
            let Some(runtime) = metadata
                .as_ref()
                .and_then(|value| value.get("chio_runtime"))
                .and_then(serde_json::Value::as_object)
            else {
                return metadata;
            };
            // Copy across only the ids that name a REAL reservation: a present,
            // non-empty reserved lease/continuation id. A `chio_runtime` route
            // block that merely carries the key with no (or an empty) value had
            // nothing to burn.
            for (source, target) in [
                (
                    "reserved_destructive_lease_id",
                    "retained_destructive_lease_id",
                ),
                (
                    "reserved_treaty_continuation_id",
                    "retained_treaty_continuation_id",
                ),
                (
                    "reserved_swarm_continuation_id",
                    "retained_swarm_continuation_id",
                ),
            ] {
                if let Some(id) = runtime
                    .get(source)
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| !id.is_empty())
                {
                    retained.insert(target.to_string(), serde_json::json!(id));
                }
            }
            // Only mark retained when at least one real reservation was actually
            // retained. An observe-only admission or a metadata-only
            // `chio_runtime` route block has no `reserved_*` id to recover, so
            // it must not carry the fail-closed marker.
            if retained.is_empty() {
                return metadata;
            }
            retained.insert(
                "reservations_retained_fail_closed".to_string(),
                serde_json::Value::Bool(true),
            );
        }
        merge_metadata_objects(
            metadata,
            Some(serde_json::json!({ "chio_runtime": retained })),
        )
    }

    pub(crate) fn release_runtime_admission_reservations_for_pre_dispatch_denial(
        &self,
        metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let metadata_value = metadata?;
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            return Some(metadata_value);
        };

        match self.release_runtime_admission_metadata(hook.as_ref(), &metadata_value) {
            Ok(()) => Some(metadata_value),
            Err(error) => {
                let reason = error.to_string();
                warn!(
                    hook = hook.name(),
                    reason = %redacted!(&reason),
                    "runtime admission reservation release failed on pre-dispatch denial"
                );
                merge_metadata_objects(
                    Some(metadata_value),
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "reservation_release_failed": true,
                            "reservation_release_failure_reason": reason
                        }
                    })),
                )
            }
        }
    }

    fn release_runtime_admission_metadata(
        &self,
        hook: &dyn RuntimeAdmissionHook,
        metadata: &serde_json::Value,
    ) -> Result<(), KernelError> {
        let Some(operation) = metadata
            .get("admission_operation")
            .and_then(serde_json::Value::as_object)
        else {
            return hook.release_reserved(metadata);
        };
        if operation
            .get("runtime_evaluation")
            .and_then(serde_json::Value::as_str)
            == Some("pure_pre_persist")
        {
            return Ok(());
        }
        let operation_id = operation
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KernelError::Internal(
                    "runtime reservation metadata omitted admission operation_id".to_string(),
                )
            })?;
        let request_binding_hash = operation
            .get("request_binding_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KernelError::Internal(
                    "runtime reservation metadata omitted admission request_binding_hash"
                        .to_string(),
                )
            })?;
        let binding = BudgetAdmissionOperationBinding::new(
            operation_id.to_string(),
            request_binding_hash.to_string(),
        )?;
        hook.release_reserved_for_operation(
            binding.operation_id(),
            binding.request_binding_hash(),
            metadata,
        )
    }

    /// Forward the validated request and optionally report actual invocation cost.
    pub(crate) async fn dispatch_tool_call_with_cost(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        self.require_presented_execution_nonce(request, &request.capability)?;
        if !self.tool_servers.contains_key(&request.server_id) {
            return Err(KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            )));
        }
        let _security_dispatch_outcome = self
            .run_security_pre_dispatch_hook(request, None)
            .map_err(|denial| KernelError::GuardDenied(denial.reason.to_string()))?;
        self.dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary_grant)
            .await
    }

    pub(crate) async fn dispatch_tool_call_with_cost_after_nonce_check(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        let server = self.tool_servers.get(&request.server_id).ok_or_else(|| {
            KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
        })?;

        // Try streaming first regardless of monetary mode.
        //
        // Why the kernel cannot bound stream memory "as chunks arrive" at THIS
        // seam, and where the actual bounds live.
        //
        // `ToolServerConnection::invoke_stream` returns a FULLY MATERIALIZED
        // `ToolServerStreamResult` (which owns a `ToolCallStream { chunks: Vec<..>
        // }`). The connector is in-process trusted code that drains its transport
        // and builds the entire Vec BEFORE returning; the kernel receives control
        // only after materialization. There is no incremental per-chunk arrival at
        // this seam, so `push_chunk_bounded` cannot be driven here to bound the
        // stream as it accumulates. True accumulation-time bounding would require
        // changing the trait contract to a kernel-driven pull model (invoke_stream
        // yielding a chunk source the kernel pulls), a public runtime-API change
        // affecting every implementor; and even then a malicious in-process
        // connector could allocate before yielding. So the transient peak
        // allocation of a non-cooperating out-of-tree connector is a genuine
        // connector-trust-boundary limit, bounded only by the process RSS ceiling
        // (cgroup/ulimit).
        //
        // Layered bounds that DO apply:
        //   - Accumulation is bounded by the ACCUMULATOR. In-tree connectors cap
        //     it (A2A: `parse_sse_stream_with_limit`, MAX_SSE_TOTAL_BYTES = 1 MiB).
        //     `enforce_stream_byte_limit` / `push_chunk_bounded` (crate::runtime)
        //     are pub fail-closed Overloaded { StreamBytes / StreamChunks }
        //     primitives (bounding total bytes AND retained chunk count) so
        //     out-of-tree connector authors can bound their own invoke_stream.
        //   - Retained memory is bounded at finalize by `apply_stream_limits` /
        //     `truncate_stream_to_limits`: the stream is truncated to
        //     `max_stream_total_bytes` / `max_stream_chunks` and the receipt is
        //     marked incomplete,
        //     PRESERVING the charge-for-work-done and financial metadata on
        //     governed monetary streams (pinned by
        //     `governed_monetary_incomplete_receipt_keeps_financial_and_governed_metadata`
        //     and `streamed_tool_byte_limit_truncates_output_and_marks_receipt_incomplete`).
        //     A hard-deny (Err) here was deliberately reverted because it unwinds
        //     the monetary charge for an already-executed stream, so this seam
        //     does not hard-deny.
        if let Some(stream) = server
            .invoke_stream(&request.tool_name, request.arguments.clone(), None)
            .await?
        {
            return Ok((ToolServerOutput::Stream(stream), None));
        }

        if has_monetary_grant {
            let (value, cost) = server
                .invoke_with_cost(&request.tool_name, request.arguments.clone(), None)
                .await?;
            Ok((ToolServerOutput::Value(value), cost))
        } else {
            let value = server
                .invoke(&request.tool_name, request.arguments.clone(), None)
                .await?;
            Ok((ToolServerOutput::Value(value), None))
        }
    }

    /// Build a denial response, including FinancialReceiptMetadata when the
    pub(crate) fn record_child_receipts(
        &self,
        receipts: Vec<ChildRequestReceipt>,
    ) -> Result<(), KernelError> {
        for receipt in receipts {
            let receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
                KernelError::Internal("receipt store write lock poisoned".to_string())
            })?;
            self.with_receipt_store(|store| {
                Ok(store.append_child_receipt_returning_seq(&receipt)?)
            })?;
            drop(receipt_store_write);
            self.append_child_receipt_to_local_log(receipt);
        }
        Ok(())
    }

    pub(crate) fn append_chio_receipt_to_local_log(&self, receipt: ChioReceipt) {
        let append_once = |log: &mut ReceiptLog| {
            if !log.iter().any(|existing| existing.id == receipt.id) {
                log.append(receipt);
            }
        };
        match self.receipt_log.lock() {
            Ok(mut log) => append_once(&mut log),
            Err(poisoned) => append_once(&mut poisoned.into_inner()),
        }
    }

    fn append_child_receipt_to_local_log(&self, receipt: ChildRequestReceipt) {
        match self.child_receipt_log.lock() {
            Ok(mut log) => log.append(receipt),
            Err(poisoned) => poisoned.into_inner().append(receipt),
        }
    }
}
