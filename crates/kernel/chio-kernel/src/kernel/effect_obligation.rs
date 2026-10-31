//! One affine owner from the effect boundary through terminal commitment,
//! buffered evidence, or the original durable saga's custody.

use super::publication_sync::PublicationGuard;
use super::*;
use crate::kernel::admission_coordinator::{DurableToolReturn, DurableToolReturnContext};
use crate::kernel::credential_reservation::DispatchCredentialReservation;
use crate::kernel::responses::{PrepareToolOutputCostContext, PreparedResponse};

pub(super) mod evidence;
mod post_effect;
mod preparation;
pub(super) mod publication;
pub(super) mod recovery;
pub(super) mod runtime;

use evidence::EvidenceSlot;
use preparation::{fault_response, DischargeBinding};
pub(in crate::kernel) use preparation::{PostEffectPreparation, PreparedPostEffect};
use publication::{ReceiptAppendFailure, ReceiptCommit};
use recovery::{
    PendingChildReceipt, PendingPostEffectEvidence, PendingPostEffectRecord, PreparedFaultReceipt,
    UnknownChildAppend,
};

pub(in crate::kernel) type ObservedToolReturn =
    Result<((ToolServerOutput, Option<ToolInvocationCost>), Duration), KernelError>;

pub(in crate::kernel) struct PostEffectInputs<'a> {
    pub request: &'a ToolCallRequest,
    pub matched_grant_index: usize,
    pub budget: PreExecutionBudgetMutation,
    pub payment: Option<PaymentAuthorization>,
    pub metadata: Option<serde_json::Value>,
    pub evidence: crate::kernel::PreInvocationGuardOutput,
    pub payee: Option<VerifiedGovernedPayeeBinding>,
    pub admission: Option<DurableToolAdmission>,
    pub return_context: Option<DurableToolReturnContext>,
    pub credentials: DispatchCredentialReservation<'a>,
    pub security_outcome: Option<SecurityDispatchOutcomeHandle>,
    pub security_lifecycle: Option<SecurityRequestLifecycleHandle>,
    pub finding: crate::kernel::dispatch::VerifiedFindingDispatchAdmission,
    pub security_context: Option<&'a SecurityInvocationContext>,
    pub parent_context: Option<&'a OperationContext>,
    pub prepared: PreparedPostEffect,
}

struct ObligationParts<'a> {
    inputs: PostEffectInputs<'a>,
    children: Vec<PendingChildReceipt>,
    unknown_child: Option<UnknownChildAppend>,
}

pub(in crate::kernel) const URL_ELICITATION_AFTER_DISPATCH: &str =
    "tool server returned URL elicitation after dispatch; outcome is unknown";
pub(in crate::kernel) const TOOL_REPORTED_CANCELLATION_AFTER_DISPATCH: &str =
    "tool server reported cancellation after dispatch; outcome is unknown";
pub(in crate::kernel) const SESSION_CANCELLED_AFTER_DISPATCH: &str =
    "session request cancelled after dispatch; outcome is unknown";

impl ChioKernel {
    /// The cancellation reason for a dispatched session request. It comes from
    /// the cancellation the kernel holds for that request or for one of its
    /// nested children, never from the error a tool connection returned.
    pub(in crate::kernel) fn cancellation_reason_after_dispatch(
        &self,
        context: Option<&OperationContext>,
        request_id: &RequestId,
    ) -> String {
        context
            .and_then(|context| {
                self.with_session(&context.session_id, |session| {
                    Ok(if request_id == &context.request_id {
                        session
                            .inflight()
                            .get(request_id)
                            .filter(|request| request.cancellation_requested)
                            .map(|request| {
                                request
                                    .cancellation_reason
                                    .unwrap_or_else(|| SESSION_CANCELLED_AFTER_DISPATCH.to_owned())
                            })
                    } else {
                        session
                            .request_lineage(request_id)
                            .filter(|child| {
                                child.parent_request_id.as_ref() == Some(&context.request_id)
                            })
                            .and_then(|child| match child.terminal_state {
                                Some(OperationTerminalState::Cancelled { reason }) => Some(reason),
                                _ => None,
                            })
                    })
                })
                .ok()
                .flatten()
            })
            .unwrap_or_else(|| TOOL_REPORTED_CANCELLATION_AFTER_DISPATCH.to_owned())
    }
}

/// Why a dispatched call ended cancelled instead of with a known outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::kernel) enum PostDispatchCancellation {
    UrlElicitation,
    Request,
    HotPathDeadline,
}

impl PostDispatchCancellation {
    /// The closed code a client observes for this cancellation.
    pub(in crate::kernel) const fn code(self) -> ClientDenialCode {
        match self {
            Self::UrlElicitation => ClientDenialCode::SessionUnsupported,
            Self::Request => ClientDenialCode::RequestCancelled,
            Self::HotPathDeadline => ClientDenialCode::Overloaded,
        }
    }
}

/// The terminal refusal a dispatched call signs when its tool outcome is not
/// known. The reason is kernel-authored; tool-supplied text never reaches it.
pub(in crate::kernel) struct PostDispatchRefusal {
    pub(in crate::kernel) reason: String,
    pub(in crate::kernel) cancellation: Option<PostDispatchCancellation>,
    code: ClientDenialCode,
}

impl PostDispatchRefusal {
    /// The client code and signed detail: a cancellation or closed tool refusal
    /// reports its own code, any other unknown outcome `KernelUnavailable`.
    pub(in crate::kernel) fn denial(&self) -> Denial {
        Denial::new(self.code, self.reason.as_str())
    }

    pub(in crate::kernel) fn classify(
        kernel: &ChioKernel,
        context: Option<&OperationContext>,
        step: &str,
        error: &KernelError,
    ) -> Self {
        match error {
            KernelError::UrlElicitationsRequired { .. } => Self {
                reason: URL_ELICITATION_AFTER_DISPATCH.to_owned(),
                cancellation: Some(PostDispatchCancellation::UrlElicitation),
                code: PostDispatchCancellation::UrlElicitation.code(),
            },
            KernelError::RequestCancelled { request_id, .. } => Self {
                reason: kernel.cancellation_reason_after_dispatch(context, request_id),
                cancellation: Some(PostDispatchCancellation::Request),
                code: PostDispatchCancellation::Request.code(),
            },
            KernelError::HotPathDeadlineExceeded { stage, budget_ms } => Self {
                reason: format!("hot-path deadline exceeded at {stage}: budget {budget_ms}ms"),
                cancellation: Some(PostDispatchCancellation::HotPathDeadline),
                code: PostDispatchCancellation::HotPathDeadline.code(),
            },
            KernelError::ToolRefused(_) => Self {
                reason: error.to_string(),
                cancellation: None,
                code: error.client_denial_code(),
            },
            error => Self {
                reason: format!(
                    "dispatch outcome is unknown after {step}: {}",
                    error.report().code
                ),
                cancellation: None,
                code: ClientDenialCode::KernelUnavailable,
            },
        }
    }
}

#[must_use = "an executed call must retain one terminal owner"]
pub(in crate::kernel) struct PostEffectObligation<'a> {
    kernel: &'a ChioKernel,
    binding: DischargeBinding,
    parts: Option<Box<ObligationParts<'a>>>,
    submitted: Option<UnknownAppend>,
}

/// Fields and construction are private. A tool response or public kernel error
/// never establishes this evidence. The owning obligation performs the append.
#[must_use = "a discharged call still owes delivery"]
pub(in crate::kernel) struct Discharged<'a> {
    kernel: &'a ChioKernel,
    delivery: Option<Delivery<'a>>,
}

enum Delivery<'a> {
    Receipt(Box<ReceiptDelivery<'a>>),
    Durable(Box<DurableDelivery<'a>>),
    Terminal(Box<ToolCallResponse>),
    Buffered(Box<KernelError>),
    Saga(Box<KernelError>),
    OwnershipFailure(Box<KernelError>),
}

struct ReceiptDelivery<'a> {
    parts: Box<ObligationParts<'a>>,
    prepared: PreparedResponse,
    committed: ReceiptCommit,
    transition: PublicationGuard<'a>,
    returned: bool,
    deferred_error: Option<KernelError>,
}

struct DurableDelivery<'a> {
    request: &'a ToolCallRequest,
    admission: DurableToolAdmission,
    returned: DurableToolReturn,
    outcome: Option<SecurityDispatchOutcomeHandle>,
    lifecycle: Option<SecurityRequestLifecycleHandle>,
}

struct PostEffectError {
    step: &'static str,
    code: String,
    source: Box<KernelError>,
}

impl PostEffectError {
    fn at(step: &'static str, error: KernelError) -> Self {
        Self {
            step,
            code: error.report().code,
            source: Box::new(error),
        }
    }
}

#[derive(Clone)]
struct UnknownAppend {
    id: String,
    sha256: String,
    key: chio_core::PublicKey,
}

struct Undischarged<'a> {
    obligation: PostEffectObligation<'a>,
    error: PostEffectError,
    original: Option<UnknownAppend>,
}

impl<'a> PostEffectObligation<'a> {
    pub(in crate::kernel) fn enter(
        kernel: &'a ChioKernel,
        mut inputs: PostEffectInputs<'a>,
    ) -> Self {
        if let Some(outcome) = inputs.security_outcome.as_mut() {
            outcome.mark_dispatch_started();
        }
        Self {
            kernel,
            binding: inputs.prepared.binding.clone(),
            parts: Some(Box::new(ObligationParts {
                inputs,
                children: Vec::new(),
                unknown_child: None,
            })),
            submitted: None,
        }
    }

    pub(in crate::kernel) fn admission(&self) -> Option<&DurableToolAdmission> {
        self.parts
            .as_ref()
            .and_then(|parts| parts.inputs.admission.as_ref())
    }

    pub(in crate::kernel) fn nested_receipt_sinks(
        &mut self,
    ) -> Result<(&mut Vec<PendingChildReceipt>, &mut Option<EvidenceSlot>), KernelError> {
        let parts = self.parts.as_mut().ok_or_else(|| {
            KernelError::Internal("post-effect owner has no live child custody".into())
        })?;
        Ok((&mut parts.children, &mut parts.inputs.prepared.slot))
    }

    fn ownership_failure(self, step: &'static str) -> Discharged<'a> {
        let kernel = self.kernel;
        // Any still-live custody follows the same Drop handoff before this
        // diagnostic can leave the typed region. No receipt or saga success is
        // manufactured from an inconsistent internal state.
        drop(self);
        Discharged {
            kernel,
            delivery: Some(Delivery::OwnershipFailure(Box::new(KernelError::Internal(
                format!("post-effect ownership invariant failed at {step}; output withheld"),
            )))),
        }
    }

    fn commit_terminal_receipt(
        mut self,
        prepared: PreparedResponse,
        returned: bool,
        deferred_error: Option<KernelError>,
    ) -> Result<Discharged<'a>, Box<Undischarged<'a>>> {
        let kernel = self.kernel;
        let receipt = prepared.receipt();
        let Some(parts) = self.parts.as_ref() else {
            return Err(Box::new(Undischarged {
                obligation: self,
                error: PostEffectError::at(
                    "receipt_binding",
                    KernelError::Internal("post-effect owner lost its live custody".into()),
                ),
                original: None,
            }));
        };
        let capability = &parts.inputs.request.capability;
        let binding = &self.binding;
        if let Err(error) = binding.validate_receipt(receipt) {
            return Err(Box::new(Undischarged {
                obligation: self,
                error: PostEffectError::at("receipt_binding", error),
                original: None,
            }));
        }
        let canonical = match chio_core::canonical::canonical_json_bytes(receipt) {
            Ok(canonical) => canonical,
            Err(error) => {
                return Err(Box::new(Undischarged {
                    obligation: self,
                    error: PostEffectError::at(
                        "receipt_content",
                        KernelError::ReceiptSigningFailed(error.to_string()),
                    ),
                    original: None,
                }))
            }
        };
        let original = UnknownAppend {
            id: receipt.id.clone(),
            sha256: chio_core::crypto::sha256_hex(&canonical),
            key: receipt.kernel_key.clone(),
        };
        let transition = match kernel.lock_receipt_publication(false) {
            Ok(transition) => transition,
            Err(error) => {
                return Err(Box::new(Undischarged {
                    obligation: self,
                    error: PostEffectError::at("append", error),
                    original: None,
                }))
            }
        };
        let appended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if receipt.is_allowed() {
                kernel
                    .check_revocation(capability)
                    .map_err(ReceiptAppendFailure::Refused)?;
            }
            self.submitted = Some(original.clone());
            kernel.append_terminal_receipt_during_trace_transition(
                receipt,
                &transition,
                true,
                false,
            )
        }));
        let appended = match appended {
            Ok(result) => result,
            Err(_) => {
                let error = KernelError::Internal("terminal publication callback panicked".into());
                Err(if self.submitted.is_some() {
                    ReceiptAppendFailure::unknown(&receipt.id, error)
                } else {
                    ReceiptAppendFailure::Refused(error)
                })
            }
        };
        let committed = match appended {
            Ok(committed) => committed,
            Err(failure) => {
                drop(transition);
                let (error, original) = match failure {
                    ReceiptAppendFailure::Refused(error) => {
                        self.submitted = None;
                        (error, None)
                    }
                    ReceiptAppendFailure::OutcomeUnknown { source, .. } => (
                        KernelError::ReceiptAppendOutcomeUnknown {
                            receipt_id: receipt.id.clone(),
                            source: Box::new(source),
                        },
                        self.submitted.take(),
                    ),
                };
                return Err(Box::new(Undischarged {
                    obligation: self,
                    error: PostEffectError::at("append", error),
                    original,
                }));
            }
        };
        // Nothing fallible or extension-controlled runs between acknowledgement
        // and consuming this owner. Later projection and delivery cannot undo it.
        let Some(parts) = self.parts.take() else {
            return Err(Box::new(Undischarged {
                obligation: self,
                error: PostEffectError::at(
                    "append_acknowledgement",
                    KernelError::Internal("acknowledged receipt lost its live custody".into()),
                ),
                original: Some(original),
            }));
        };
        self.submitted = None;
        Ok(Discharged {
            kernel,
            delivery: Some(Delivery::Receipt(Box::new(ReceiptDelivery {
                parts,
                prepared,
                committed,
                transition,
                returned,
                deferred_error,
            }))),
        })
    }

    fn fail(mut self, error: PostEffectError, original: Option<UnknownAppend>) -> Discharged<'a> {
        let PostEffectError { step, code, source } = error;
        let source = *source;
        if original.is_some() {
            self.submitted.clone_from(&original);
        }
        if self.binding.operation_id.is_some() {
            let Some(mut parts) = self.parts.take() else {
                return self.ownership_failure("durable_fault_handoff");
            };
            let binding = parts.inputs.prepared.binding.clone();
            let mut terminal_response = None;
            let mut delivery_error = None;
            if let Some(admission) = parts.inputs.admission.as_ref() {
                // An existing tool outcome excludes a competing unknown terminal.
                let refusal = PostDispatchRefusal::classify(
                    self.kernel,
                    parts.inputs.parent_context,
                    step,
                    &source,
                );
                match self.kernel.terminalize_dispatch_committed_admission(
                    admission.operation(),
                    parts
                        .inputs
                        .prepared
                        .evaluation_timestamp
                        .saturating_mul(1_000),
                    parts.inputs.return_context.as_ref(),
                    super::admission_coordinator::DurableRefusalResponse {
                        denial: &refusal.denial(),
                        cancelled: refusal.cancellation.is_some(),
                        matched_grant_index: Some(parts.inputs.matched_grant_index),
                        metadata: self.kernel.ambiguous_dispatch_receipt_metadata(
                            &parts.inputs.budget,
                            parts.inputs.payment.as_ref(),
                            parts.inputs.metadata.clone(),
                        ),
                        verified_payee_binding: parts.inputs.payee.as_ref(),
                    },
                ) {
                    Ok(response) => terminal_response = Some(response),
                    Err(terminal_error) => {
                        tracing::warn!(request_id = %binding.request_id, code = %terminal_error.report().code,
                            audit_fault = "durable_unknown_terminal_pending",
                            "original saga retains its terminal obligation or recorded return");
                        if matches!(
                            &terminal_error,
                            KernelError::DeliveryFailedAfterReceipt { .. }
                        ) {
                            delivery_error = Some(terminal_error);
                        }
                    }
                }
            }
            buffer_durable_children(self.kernel, &mut parts);
            tracing::warn!(request_id = %binding.request_id, step, code = %code,
                audit_fault = "durable_post_effect_reconciliation", "durable saga retains terminal ownership");
            return Discharged {
                kernel: self.kernel,
                delivery: Some(match terminal_response {
                    // The terminal unknown outcome is persisted; the caller still
                    // receives the tool's URL elicitations to complete them.
                    Some(_) if matches!(&source, KernelError::UrlElicitationsRequired { .. }) => {
                        Delivery::Saga(Box::new(source))
                    }
                    Some(response) => Delivery::Terminal(Box::new(response)),
                    None => Delivery::Saga(Box::new(delivery_error.unwrap_or(source))),
                }),
            };
        }
        let Some(parts) = self.parts.as_mut() else {
            return self.ownership_failure("fault_preparation");
        };
        let Some(fault) = parts.inputs.prepared.fault.as_mut() else {
            return self.ownership_failure("reserved_fault_template");
        };
        let deferred_error =
            step == "credential_commit" || matches!(&source, KernelError::Clock(_));
        if step == "credential_commit" {
            fault.body.decision = Some(Decision::Cancelled {
                reason: "dispatch credential commit failed after tool execution".into(),
            });
            fault.body.metadata = merge_metadata_objects(
                fault.body.metadata.take(),
                Some(serde_json::json!({
                    "chio_runtime": {
                        (crate::kernel::runtime_field::DISPATCH_CREDENTIAL_RETENTION_OUTCOME_UNKNOWN): true,
                        (crate::kernel::runtime_field::PAYMENT_CREDENTIAL_DISPOSITION): "retention_outcome_unknown"
                    }
                })),
            );
        }
        fault.body.metadata = merge_metadata_objects(
            fault.body.metadata.take(),
            Some(serde_json::json!({
                "chio_runtime": { (crate::kernel::runtime_field::POST_EFFECT_FAULT): { "step": step, "code": code,
                    "original_receipt_id": original.as_ref().map(|identity| identity.id.as_str()) } }
            })),
        );
        if original.is_none() && parts.children.is_empty() {
            let signed = self
                .kernel
                .read_authority_time()
                .map_err(KernelError::from)
                .and_then(|now| {
                    fault.body.timestamp = now.as_secs();
                    fault.observe_fault_timestamp(now.get());
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if !self
                            .kernel
                            .signing_authority
                            .floor
                            .allowed_signing_algorithms()
                            .contains(&self.kernel.receipt_signing_public_key()?.algorithm())
                        {
                            return Err(KernelError::ReceiptSigningFailed(
                                "fault signer does not satisfy the boot floor".into(),
                            ));
                        }
                        chio_kernel_core::sign_receipt_with_handle(
                        fault.body.clone(),
                        self.kernel.signing_authority.backend.as_ref(),
                        chio_core::receipt::signing::ReceiptSigningHandle::from_content_preimage(
                            fault.canonical_content.clone(),
                        ),
                    )
                    .map_err(|_| {
                        KernelError::ReceiptSigningFailed("post-effect fault signing failed".into())
                    })
                    }))
                    .map_err(|_| {
                        KernelError::ReceiptSigningFailed(
                            "post-effect fault signer panicked".into(),
                        )
                    })?
                });
            if let Ok(receipt) = signed {
                let prepared = fault_response(receipt, &parts.inputs.request.request_id);
                match self.commit_terminal_receipt(
                    prepared,
                    false,
                    deferred_error.then_some(source),
                ) {
                    Ok(discharged) => return discharged,
                    Err(failed) => {
                        return failed
                            .obligation
                            .buffer(failed.original, *failed.error.source)
                    }
                }
            }
        }
        self.buffer(original, source)
    }

    fn buffer(mut self, original: Option<UnknownAppend>, source: KernelError) -> Discharged<'a> {
        if original.is_some() {
            self.submitted.clone_from(&original);
        }
        let Some(mut parts) = self.parts.take() else {
            return self.ownership_failure("buffer_handoff");
        };
        let Some((slot, fault)) = take_reserved_fault(&mut parts) else {
            self.parts = Some(parts);
            self.submitted = original;
            return self.ownership_failure("reserved_evidence_handoff");
        };
        let evidence = match original {
            Some(original) => PendingPostEffectEvidence::Unknown {
                receipt_id: original.id,
                receipt_sha256: original.sha256,
                kernel_key: original.key,
                fault,
            },
            None => PendingPostEffectEvidence::Unsigned { fault },
        };
        self.kernel.buffer_post_effect_evidence(
            slot,
            PendingPostEffectRecord {
                evidence,
                child_receipts: parts.children,
                unknown_child: parts.unknown_child,
            },
        );
        Discharged {
            kernel: self.kernel,
            delivery: Some(Delivery::Buffered(Box::new(source))),
        }
    }
}

fn take_reserved_fault(
    parts: &mut ObligationParts<'_>,
) -> Option<(EvidenceSlot, PreparedFaultReceipt)> {
    let fault = parts.inputs.prepared.fault.take()?;
    match parts.inputs.prepared.slot.take() {
        Some(slot) => Some((slot, fault)),
        None => {
            parts.inputs.prepared.fault = Some(fault);
            None
        }
    }
}

fn buffer_durable_children(kernel: &ChioKernel, parts: &mut ObligationParts<'_>) {
    if !parts.children.is_empty() {
        if let Some(slot) = parts.inputs.prepared.slot.take() {
            kernel.buffer_post_effect_evidence(
                slot,
                PendingPostEffectRecord {
                    evidence: PendingPostEffectEvidence::ChildrenOnly,
                    child_receipts: std::mem::take(&mut parts.children),
                    unknown_child: parts.unknown_child.take(),
                },
            );
        } else {
            tracing::warn!(request_id = %parts.inputs.request.request_id,
                child_receipts = parts.children.len(),
                audit_fault = "post_effect_child_evidence_slot_missing",
                "retained child evidence has no reserved recovery capacity");
        }
    }
}

impl Drop for PostEffectObligation<'_> {
    fn drop(&mut self) {
        let Some(mut parts) = self.parts.take() else {
            return;
        };
        // Transfer reserved capacity before invoking any infrastructure or host
        // callback. The supervised owner attempts the prebuilt fault receipt.
        let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.binding.operation_id.is_some() {
                buffer_durable_children(self.kernel, &mut parts);
                tracing::warn!(request_id = %parts.inputs.request.request_id,
                    audit_fault = "durable_post_effect_reconciliation_pending",
                    "dropped evaluation retains its original durable saga and reservations");
            } else if let Some((slot, fault)) = take_reserved_fault(&mut parts) {
                let evidence = match self.submitted.take() {
                    Some(original) => PendingPostEffectEvidence::Unknown {
                        receipt_id: original.id,
                        receipt_sha256: original.sha256,
                        kernel_key: original.key,
                        fault,
                    },
                    None => PendingPostEffectEvidence::Unsigned { fault },
                };
                self.kernel.buffer_post_effect_evidence(
                    slot,
                    PendingPostEffectRecord {
                        evidence,
                        child_receipts: std::mem::take(&mut parts.children),
                        unknown_child: parts.unknown_child.take(),
                    },
                );
            } else {
                tracing::warn!(request_id = %parts.inputs.request.request_id,
                    fault_template_reserved = parts.inputs.prepared.fault.is_some(),
                    evidence_slot_reserved = parts.inputs.prepared.slot.is_some(),
                    child_receipts = parts.children.len(),
                    audit_fault = "post_effect_reserved_evidence_missing",
                    "dropped post-effect owner has incomplete reserved evidence custody");
            }
        }));
        if guarded.is_err() {
            tracing::warn!(
                audit_fault = "post_effect_drop_owner_failed",
                "post-effect drop ownership transfer panicked"
            );
        }
    }
}

impl<'a> Discharged<'a> {
    pub(in crate::kernel) fn deliver(mut self) -> Result<ToolCallResponse, KernelError> {
        let delivery = self.delivery.take().ok_or_else(|| {
            KernelError::Internal("discharge has no remaining delivery custody".into())
        })?;
        match delivery {
            Delivery::OwnershipFailure(error) => Err(*error),
            Delivery::Buffered(source) | Delivery::Saga(source) => Err(*source),
            Delivery::Terminal(response) => Ok(*response),
            Delivery::Receipt(delivery) => {
                let ReceiptDelivery {
                    mut parts,
                    prepared,
                    committed,
                    transition,
                    returned,
                    deferred_error,
                } = *delivery;
                drop(parts.inputs.prepared.slot.take());
                let request = parts.inputs.request;
                let outcome = parts.inputs.security_outcome.take();
                let lifecycle = parts.inputs.security_lifecycle.take();
                let receipt_id = prepared.receipt().id.clone();
                let committed = self
                    .kernel
                    .project_acknowledged_receipt_during_trace_transition(
                        prepared.receipt(),
                        committed,
                        &transition,
                    );
                drop(transition);
                self.kernel
                    .finish_record_chio_receipt(prepared.receipt(), committed)?;
                if matches!(
                    prepared.record_mode(),
                    crate::kernel::responses::ReceiptRecordMode::WithFederation
                ) {
                    super::security_dispatch::receipt_delivery(
                        &receipt_id,
                        ReceiptDeliveryStep::Federation,
                        || {
                            self.kernel.apply_federation_cosign_for_admitted_request(
                                request,
                                prepared.receipt(),
                            )
                        },
                    )?;
                }
                if let Some(outcome) = outcome {
                    (if returned {
                        outcome.record_released()
                    } else {
                        outcome.record_outcome_unknown_after_dispatch()
                    })
                    .map_err(|source| {
                        KernelError::DeliveryFailedAfterReceipt {
                            receipt_id: receipt_id.clone(),
                            step: ReceiptDeliveryStep::SecurityOutcome,
                            source: Box::new(source),
                        }
                    })?;
                }
                if let Some(lifecycle) = lifecycle {
                    lifecycle.ensure_final_release().map_err(|source| {
                        KernelError::DeliveryFailedAfterReceipt {
                            receipt_id: receipt_id.clone(),
                            step: ReceiptDeliveryStep::SecurityRelease,
                            source: Box::new(source),
                        }
                    })?;
                }
                let response = prepared.finish_delivery(self.kernel, request)?;
                deferred_error.map_or(Ok(response), Err)
            }
            Delivery::Durable(delivery) => {
                let DurableDelivery {
                    request,
                    mut admission,
                    returned,
                    outcome,
                    lifecycle,
                } = *delivery;
                let response = self
                    .kernel
                    .finalize_durable_tool_return_with_security_release(
                        &mut admission,
                        request,
                        &returned,
                        lifecycle,
                    );
                match response {
                    Ok(response) => {
                        if let Some(outcome) = outcome {
                            outcome.record_released().map_err(|source| {
                                KernelError::DeliveryFailedAfterReceipt {
                                    receipt_id: response.receipt.id.clone(),
                                    step: ReceiptDeliveryStep::SecurityOutcome,
                                    source: Box::new(source),
                                }
                            })?;
                        }
                        Ok(response)
                    }
                    Err(error) => {
                        tracing::warn!(operation_id = %admission.operation_id(), code = %error.report().code,
                            audit_fault = "durable_post_effect_finalization_pending", "original durable return retains terminal ownership");
                        Err(error)
                    }
                }
            }
        }
    }
}

impl Drop for Discharged<'_> {
    fn drop(&mut self) {
        match self.delivery.take() {
            Some(Delivery::Receipt(delivery)) => {
                let ReceiptDelivery {
                    transition, parts, ..
                } = *delivery;
                // Extension disposal may re-enter kernel APIs. The committed
                // receipt stands; release ordering locks before any disposal.
                drop(transition);
                drop(parts);
            }
            Some(Delivery::Durable(delivery)) => {
                tracing::warn!(operation_id = %delivery.admission.operation_id(), audit_fault = "durable_post_effect_delivery_pending",
                    "undelivered return remains owned by its original durable saga");
            }
            _ => {}
        }
    }
}

pub(in crate::kernel) fn run_post_effect<'a>(
    obligation: PostEffectObligation<'a>,
    returned: ObservedToolReturn,
) -> Discharged<'a> {
    post_effect::run(obligation, returned)
}
