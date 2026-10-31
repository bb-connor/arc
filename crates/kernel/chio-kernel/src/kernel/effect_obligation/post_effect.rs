//! All fallible post-dispatch preparation returns to the same owning obligation.

use super::*;
use crate::kernel::receipt_identity::{with_identity_disposition, IdentityDisposition};

fn failure(step: &'static str, error: KernelError) -> PostEffectError {
    PostEffectError::at(step, error)
}

pub(super) fn run<'a>(
    mut obligation: PostEffectObligation<'a>,
    returned: ObservedToolReturn,
) -> Discharged<'a> {
    if let Err(error) = flush_children(&mut obligation) {
        return obligation.fail(error, None);
    }
    let known_return = returned.is_ok();
    if known_return || matches!(&returned, Err(KernelError::UrlElicitationsRequired { .. })) {
        let committed = obligation
            .parts
            .as_mut()
            .ok_or_else(|| {
                KernelError::Internal("post-effect owner lost its credential custody".into())
            })
            .and_then(|parts| parts.inputs.credentials.commit());
        if let Err(error) = committed {
            return obligation.fail(failure("credential_commit", error), None);
        }
    }
    if obligation.admission().is_some() {
        return record_durable_return(obligation, returned);
    }
    let (prepared, deferred_error) = match prepare_ordinary(&mut obligation, returned) {
        Ok(prepared) => prepared,
        Err(error) => return obligation.fail(error, None),
    };
    match obligation.commit_terminal_receipt(prepared, known_return, deferred_error) {
        Ok(discharged) => discharged,
        Err(failed) => failed.obligation.fail(failed.error, failed.original),
    }
}

fn flush_children(obligation: &mut PostEffectObligation<'_>) -> Result<(), PostEffectError> {
    let parts = obligation.parts.as_mut().ok_or_else(|| {
        failure(
            "child_receipt_flush",
            KernelError::Internal("post-effect owner lost its child custody".into()),
        )
    })?;
    while !parts.children.is_empty() {
        if let Some(PendingChildReceipt::Unsigned(body)) = parts.children.first() {
            let now = obligation
                .kernel
                .read_authority_time()
                .map_err(|error| failure("child_receipt_flush", error.into()))?;
            let body = ChildRequestReceiptBody {
                timestamp: now.as_secs(),
                ..body.clone()
            };
            let signed = ChildRequestReceipt::sign(body, &obligation.kernel.config.keypair)
                .map_err(|error| {
                    failure(
                        "child_receipt_flush",
                        KernelError::ReceiptSigningFailed(error.to_string()),
                    )
                })?;
            let first = parts.children.first_mut().ok_or_else(|| {
                failure(
                    "child_receipt_flush",
                    KernelError::Internal("child evidence queue lost its first entry".into()),
                )
            })?;
            *first = PendingChildReceipt::Signed(signed);
        }
        let Some(PendingChildReceipt::Signed(receipt)) = parts.children.first() else {
            return Err(failure(
                "child_receipt_flush",
                KernelError::Internal("child evidence was not signed".into()),
            ));
        };
        let canonical = chio_core::canonical::canonical_json_bytes(receipt).map_err(|error| {
            failure(
                "child_receipt_flush",
                KernelError::ReceiptSigningFailed(error.to_string()),
            )
        })?;
        let unknown = UnknownChildAppend {
            receipt_id: receipt.id.clone(),
            receipt_sha256: chio_core::crypto::sha256_hex(&canonical),
            kernel_key: receipt.kernel_key.clone(),
        };
        let write = obligation
            .kernel
            .publication_sync
            .receipts(false)
            .map_err(|error| failure("child_receipt_flush", error))?;
        if let Some(store) = obligation.kernel.receipt_store.as_ref() {
            // Once entered, the writer can still commit after a timeout or
            // callback panic. Preserve this exact child at the vector front.
            parts.unknown_child = Some(unknown);
            let appended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                store.append_child_receipt_with_timeout(
                    receipt,
                    obligation.kernel.config.deadlines.receipt_append_budget(),
                )
            }));
            match appended {
                Ok(result) => result
                    .map_err(|error| failure("child_receipt_flush", KernelError::from(error)))?,
                Err(_) => {
                    return Err(failure(
                        "child_receipt_flush",
                        KernelError::Internal("child receipt append callback panicked".into()),
                    ))
                }
            };
            parts.unknown_child = None;
        }
        let PendingChildReceipt::Signed(receipt) = parts.children.remove(0) else {
            return Err(failure(
                "child_receipt_flush",
                KernelError::Internal("acknowledged child lost its signed evidence".into()),
            ));
        };
        let mut log = obligation
            .kernel
            .child_receipt_log
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        log.append(receipt);
        drop(log);
        drop(write);
    }
    Ok(())
}

fn record_durable_return<'a>(
    mut obligation: PostEffectObligation<'a>,
    observed: ObservedToolReturn,
) -> Discharged<'a> {
    let ((output, reported_cost), elapsed) = match observed {
        Ok(observed) => observed,
        Err(error) => return obligation.fail(failure("transport_return", error), None),
    };
    let Some(parts) = obligation.parts.as_mut() else {
        return obligation.ownership_failure("durable_return");
    };
    let inputs = &mut parts.inputs;
    let Some(context) = inputs.return_context.as_ref() else {
        return obligation.fail(
            failure(
                "durable_return",
                KernelError::DurableAdmission(
                    "tool return lost its frozen dispatch context".into(),
                ),
            ),
            None,
        );
    };
    let now = match obligation.kernel.read_authority_time() {
        Ok(now) => now.get(),
        Err(error) => return obligation.fail(failure("authority_time", error.into()), None),
    };
    let Some(admission) = inputs.admission.as_mut() else {
        return obligation.ownership_failure("durable_admission");
    };
    let recorded = obligation.kernel.record_durable_tool_return(
        admission,
        DurableToolReturnInput {
            request: inputs.request,
            output: &output,
            reported_cost,
            context,
            elapsed,
            trusted_now_unix_ms: now,
        },
    );
    let returned = match recorded {
        Ok(returned) => returned,
        Err(error) => return obligation.fail(failure("durable_return", error), None),
    };
    // The atomic return commit makes the original saga authoritative. Its
    // finalizer owns settlement, security release and the terminal outbox.
    let Some(mut parts) = obligation.parts.take() else {
        return obligation.ownership_failure("durable_return_handoff");
    };
    let Some(admission) = parts.inputs.admission.take() else {
        obligation.parts = Some(parts);
        return obligation.ownership_failure("durable_admission_handoff");
    };
    let discharged = Discharged {
        kernel: obligation.kernel,
        delivery: Some(Delivery::Durable(Box::new(DurableDelivery {
            request: parts.inputs.request,
            admission,
            returned,
            outcome: parts.inputs.security_outcome.take(),
            lifecycle: parts.inputs.security_lifecycle.take(),
        }))),
    };
    obligation
        .kernel
        .reach_durable_finalization_cutpoint(DurableFinalizationCutpoint::ToolReturnRecorded);
    discharged
}

fn prepare_ordinary(
    obligation: &mut PostEffectObligation<'_>,
    observed: ObservedToolReturn,
) -> Result<(PreparedResponse, Option<KernelError>), PostEffectError> {
    let kernel = obligation.kernel;
    let parts = obligation.parts.as_mut().ok_or_else(|| {
        failure(
            "ordinary_finalization",
            KernelError::Internal("post-effect owner lost its preparation custody".into()),
        )
    })?;
    let inputs = &mut parts.inputs;
    // Ordinary value finalization keeps the admission-time receipt timestamp.
    let now = inputs.prepared.evaluation_timestamp;
    let metadata = merge_metadata_objects(
        inputs.metadata.clone(),
        Some(serde_json::json!({
        "receipt_context": { "request_namespace_digest": inputs.prepared.binding.namespace, "evaluation_id": inputs.prepared.binding.evaluation_id }
        })),
    );
    let metadata = with_identity_disposition(metadata, IdentityDisposition::Terminal);
    let prepared = kernel
        .with_pre_invocation_guard_output(&inputs.evidence, || match observed {
            Ok(((output, reported_cost), elapsed)) => {
                if let Err(denial) = kernel.revalidate_ordinary_recovery_status(
                    inputs.matched_grant_index,
                    inputs.request,
                    &inputs.finding,
                ) {
                    return kernel
                        .prepare_changed_ordinary_recovery_status(
                            inputs.request,
                            inputs.matched_grant_index,
                            &metadata,
                            &inputs.evidence,
                            inputs.payee.as_ref(),
                            &denial,
                        )
                        .map(|response| (response, None));
                }
                let metadata = crate::kernel::delivery_contract::attach_finding_recovery_metadata(
                    metadata,
                    inputs.finding.recovery_binding(),
                );
                crate::kernel::evaluation::evaluation_helpers::require_durable_finding_recovery(
                    inputs.finding.recovery_binding(),
                )?;
                kernel
                    .prepare_budgeted_tool_output_with_cost_and_metadata(
                        inputs.request,
                        output,
                        elapsed,
                        now,
                        inputs.matched_grant_index,
                        PrepareToolOutputCostContext {
                            charge_result: inputs.budget.charge_result(),
                            reported_cost: reported_cost.as_ref(),
                            payment_authorization: inputs.payment.as_ref(),
                            cap: &inputs.request.capability,
                            fault_progress: inputs.prepared.fault.as_mut(),
                        },
                        metadata,
                        inputs.payee.as_ref(),
                        inputs.security_context,
                    )
                    .map(|response| (response, None))
            }
            Err(error) => {
                let metadata = kernel.ambiguous_dispatch_receipt_metadata(
                    &inputs.budget,
                    inputs.payment.as_ref(),
                    metadata,
                );
                kernel.note_retained_ambiguous_hold(metadata.is_some() || inputs.payment.is_some());
                match error {
                    error @ KernelError::UrlElicitationsRequired { .. } => kernel
                        .prepare_cancelled_response_with_metadata_and_payee_binding(
                            inputs.request,
                            &PostDispatchRefusal::classify(
                                kernel,
                                inputs.parent_context,
                                "transport_return",
                                &error,
                            )
                            .denial(),
                            now,
                            Some(inputs.matched_grant_index),
                            RefusalReceiptMetadata::new(metadata, IdentityDisposition::Terminal),
                            inputs.payee.as_ref(),
                        )
                        .map(|response| (response, Some(error))),
                    KernelError::RequestCancelled { request_id, .. } => {
                        let reason = kernel
                            .cancellation_reason_after_dispatch(inputs.parent_context, &request_id);
                        if let Some(parent) = inputs
                            .parent_context
                            .filter(|parent| parent.request_id == request_id)
                        {
                            kernel.with_session_mut(&parent.session_id, |session| {
                                session.request_cancellation(&parent.request_id)?;
                                Ok(())
                            })?;
                        }
                        kernel
                            .prepare_cancelled_response_with_metadata_and_payee_binding(
                                inputs.request,
                                &Denial::new(PostDispatchCancellation::Request.code(), reason),
                                now,
                                Some(inputs.matched_grant_index),
                                RefusalReceiptMetadata::new(
                                    metadata,
                                    IdentityDisposition::Terminal,
                                ),
                                inputs.payee.as_ref(),
                            )
                            .map(|response| (response, None))
                    }
                    error @ KernelError::HotPathDeadlineExceeded { .. } => kernel
                        .prepare_cancelled_response_with_metadata_and_payee_binding(
                            inputs.request,
                            &PostDispatchRefusal::classify(
                                kernel,
                                inputs.parent_context,
                                "transport_return",
                                &error,
                            )
                            .denial(),
                            now,
                            Some(inputs.matched_grant_index),
                            RefusalReceiptMetadata::new(metadata, IdentityDisposition::Terminal),
                            inputs.payee.as_ref(),
                        )
                        .map(|response| (response, None)),
                    KernelError::RequestIncomplete(reason) => kernel
                        .prepare_incomplete_response_with_output_metadata_and_payee_binding(
                            inputs.request,
                            None,
                            &reason,
                            now,
                            Some(inputs.matched_grant_index),
                            RefusalReceiptMetadata::new(metadata, IdentityDisposition::Terminal),
                            inputs.payee.as_ref(),
                        )
                        .map(|response| (response, None)),
                    error => kernel
                        .prepare_deny_response_with_metadata_and_payee_binding(
                            inputs.request,
                            &Denial::from_error(&error),
                            now,
                            Some(inputs.matched_grant_index),
                            RefusalReceiptMetadata::new(metadata, IdentityDisposition::Terminal),
                            inputs.payee.as_ref(),
                        )
                        .map(|response| (response, None)),
                }
            }
        })
        .map_err(|error| failure("ordinary_finalization", error))?;
    if let Some(fault) = inputs.prepared.fault.as_mut() {
        fault.observe_economics(prepared.0.receipt().metadata.as_ref());
    }
    Ok(prepared)
}
