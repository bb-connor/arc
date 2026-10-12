//! One affine owner from the effect boundary through terminal commitment,
//! buffered evidence, or the original durable saga's custody.

use super::*;
use crate::kernel::admission_coordinator::{DurableToolReturn, DurableToolReturnContext};
use crate::kernel::credential_reservation::DispatchCredentialReservation;
use crate::kernel::responses::{PrepareToolOutputCostContext, PreparedResponse};
use std::sync::MutexGuard;

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
    pub evidence: Vec<GuardEvidence>,
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
    binding: DischargeBinding,
    delivery: Option<Delivery<'a>>,
}

enum Delivery<'a> {
    Receipt(Box<ReceiptDelivery<'a>>),
    Durable(Box<DurableDelivery<'a>>),
    Buffered,
    Saga,
    OwnershipFailure(Box<KernelError>),
}

struct ReceiptDelivery<'a> {
    parts: Box<ObligationParts<'a>>,
    prepared: PreparedResponse,
    committed: ReceiptCommit,
    original: UnknownAppend,
    transition: MutexGuard<'a, ()>,
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
}

impl PostEffectError {
    fn at(step: &'static str, error: &KernelError) -> Self {
        Self {
            step,
            code: error.report().code,
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
        let binding = self.binding.clone();
        // Any still-live custody follows the same Drop handoff before this
        // diagnostic can leave the typed region. No receipt or saga success is
        // manufactured from an inconsistent internal state.
        drop(self);
        Discharged {
            kernel,
            binding,
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
                    &KernelError::Internal("post-effect owner lost its live custody".into()),
                ),
                original: None,
            }));
        };
        let capability = &parts.inputs.request.capability;
        let binding = &self.binding;
        if let Err(error) = binding.validate_receipt(receipt) {
            return Err(Box::new(Undischarged {
                obligation: self,
                error: PostEffectError::at("receipt_binding", &error),
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
                        &KernelError::ReceiptSigningFailed(error.to_string()),
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
        let transition = match kernel.lock_runtime_trace_transition() {
            Ok(transition) => transition,
            Err(error) => {
                return Err(Box::new(Undischarged {
                    obligation: self,
                    error: PostEffectError::at("append", &error),
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
                    ReceiptAppendFailure::OutcomeUnknown { source, .. } => {
                        (source, self.submitted.take())
                    }
                };
                return Err(Box::new(Undischarged {
                    obligation: self,
                    error: PostEffectError::at("append", &error),
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
                    &KernelError::Internal("acknowledged receipt lost its live custody".into()),
                ),
                original: Some(original),
            }));
        };
        self.submitted = None;
        let binding = parts.inputs.prepared.binding.clone();
        Ok(Discharged {
            kernel,
            binding,
            delivery: Some(Delivery::Receipt(Box::new(ReceiptDelivery {
                parts,
                prepared,
                committed,
                original,
                transition,
                returned,
                deferred_error,
            }))),
        })
    }

    fn fail(mut self, error: PostEffectError, original: Option<UnknownAppend>) -> Discharged<'a> {
        if original.is_some() {
            self.submitted.clone_from(&original);
        }
        if self.binding.operation_id.is_some() {
            let Some(mut parts) = self.parts.take() else {
                return self.ownership_failure("durable_fault_handoff");
            };
            let binding = parts.inputs.prepared.binding.clone();
            buffer_durable_children(self.kernel, &mut parts);
            tracing::warn!(request_id = %binding.request_id, step = error.step, code = %error.code,
                audit_fault = "durable_post_effect_reconciliation", "durable saga retains terminal ownership");
            return Discharged {
                kernel: self.kernel,
                binding,
                delivery: Some(Delivery::Saga),
            };
        }
        let Some(parts) = self.parts.as_mut() else {
            return self.ownership_failure("fault_preparation");
        };
        let Some(fault) = parts.inputs.prepared.fault.as_mut() else {
            return self.ownership_failure("reserved_fault_template");
        };
        fault.body.metadata = merge_metadata_objects(
            fault.body.metadata.take(),
            Some(serde_json::json!({
                "chio_runtime": { "post_effect_fault": { "step": error.step, "code": error.code,
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
                    fault.body.metadata = merge_metadata_objects(
                        fault.body.metadata.take(),
                        Some(serde_json::json!({
                            "chio_runtime": { "post_effect_fault": { "observed_at": now.get() } }
                        })),
                    );
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if !self
                            .kernel
                            .signing_authority
                            .floor
                            .allowed_signing_algorithms()
                            .contains(&self.kernel.signing_authority.backend.algorithm())
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
                match self.commit_terminal_receipt(prepared, false, None) {
                    Ok(discharged) => return discharged,
                    Err(failed) => return failed.obligation.buffer(failed.original),
                }
            }
        }
        self.buffer(original)
    }

    fn buffer(mut self, original: Option<UnknownAppend>) -> Discharged<'a> {
        if original.is_some() {
            self.submitted.clone_from(&original);
        }
        let Some(mut parts) = self.parts.take() else {
            return self.ownership_failure("buffer_handoff");
        };
        let binding = parts.inputs.prepared.binding.clone();
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
            binding,
            delivery: Some(Delivery::Buffered),
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
    fn enforce_binding(mut self, expected: DischargeBinding) -> Self {
        if self.binding == expected {
            return self;
        }
        tracing::warn!(request_id = %expected.request_id, audit_fault = "post_effect_discharge_binding_mismatch",
            "discharged output does not match its original evaluation");
        match self.delivery.take() {
            Some(Delivery::Receipt(delivery)) => {
                let ReceiptDelivery {
                    mut parts,
                    original,
                    transition,
                    ..
                } = *delivery;
                drop(transition);
                let Some((slot, mut fault)) = take_reserved_fault(&mut parts) else {
                    let obligation = PostEffectObligation {
                        kernel: self.kernel,
                        binding: parts.inputs.prepared.binding.clone(),
                        parts: Some(parts),
                        submitted: Some(original),
                    };
                    let mut failed = obligation.ownership_failure("discharge_binding_custody");
                    failed.binding = expected;
                    return failed;
                };
                fault.body.metadata = merge_metadata_objects(
                    fault.body.metadata.take(),
                    Some(serde_json::json!({
                        "chio_runtime": { "post_effect_fault": { "step": "discharge_binding",
                            "code": "CHIO-KERNEL-POST-EFFECT-BINDING", "original_receipt_id": original.id } }
                    })),
                );
                self.kernel.buffer_post_effect_evidence(
                    slot,
                    PendingPostEffectRecord {
                        evidence: PendingPostEffectEvidence::Unknown {
                            receipt_id: original.id,
                            receipt_sha256: original.sha256,
                            kernel_key: original.key,
                            fault,
                        },
                        child_receipts: parts.children,
                        unknown_child: parts.unknown_child,
                    },
                );
                Self {
                    kernel: self.kernel,
                    binding: expected,
                    delivery: Some(Delivery::Buffered),
                }
            }
            Some(Delivery::Durable(_)) => Self {
                kernel: self.kernel,
                binding: expected,
                delivery: Some(Delivery::Saga),
            },
            Some(
                delivery @ (Delivery::Buffered | Delivery::Saga | Delivery::OwnershipFailure(_)),
            ) => {
                // Non-receipt discharges already transferred their evidence to
                // the buffer or durable saga. Withhold delivery on the mismatch.
                self.delivery = Some(delivery);
                self.binding = expected;
                self
            }
            None => Self {
                kernel: self.kernel,
                binding: expected,
                delivery: Some(Delivery::OwnershipFailure(Box::new(KernelError::Internal(
                    "discharge binding check lost its delivery custody; output withheld".into(),
                )))),
            },
        }
    }

    pub(in crate::kernel) fn deliver(mut self) -> Result<ToolCallResponse, KernelError> {
        let delivery = self.delivery.take().ok_or_else(|| {
            KernelError::Internal("discharge has no remaining delivery custody".into())
        })?;
        match delivery {
            Delivery::OwnershipFailure(error) => Err(*error),
            Delivery::Buffered => Err(KernelError::PostEffectFaultLatched {
                request_id: self.binding.request_id.clone(),
            }),
            Delivery::Saga => Err(match self.binding.operation_id.clone() {
                Some(operation_id) => KernelError::DurableOutcomePending { operation_id },
                None => {
                    KernelError::Internal("durable discharge lost its operation binding".into())
                }
            }),
            Delivery::Receipt(delivery) => {
                let ReceiptDelivery {
                    mut parts,
                    prepared,
                    committed,
                    original: _,
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
                        Err(KernelError::DurableOutcomePending {
                            operation_id: admission.operation_id().to_owned(),
                        })
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
    let expected = obligation.binding.clone();
    post_effect::run(obligation, returned).enforce_binding(expected)
}
