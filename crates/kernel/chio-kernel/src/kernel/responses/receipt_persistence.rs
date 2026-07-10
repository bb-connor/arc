use chio_core::receipt::kinds::TrustLevel;

use super::*;

/// A cost-bearing receipt may claim `TrustLevel::Mediated` only when it carries a
/// reconciled budget-authority hold. This is the sign-site fail-closed invariant
/// that turns `Mediated` from a stamp into earned proof.
pub(crate) fn require_earned_mediated_trust_level(
    metadata: Option<&serde_json::Value>,
    trust_level: TrustLevel,
) -> Result<(), KernelError> {
    if trust_level != TrustLevel::Mediated {
        return Ok(());
    }
    let Some(metadata) = metadata else {
        return Ok(());
    };
    let cost_bearing = metadata
        .get("financial")
        .and_then(|financial| financial.get("cost_charged"))
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|cost| cost > 0);
    if !cost_bearing {
        return Ok(());
    }
    let reconciled = metadata
        .get("budget_authority")
        .and_then(|block| block.get("terminal"))
        .and_then(|terminal| terminal.get("disposition"))
        .and_then(serde_json::Value::as_str)
        == Some("reconciled");
    // A prepaid spend under a grant with no budget ceiling carries no reconciled
    // budget hold: its cost is earned by an external settlement, not a mediated
    // hold, and such a receipt carries NO `budget_authority` block (the budget
    // layer took no charge). A fully settled prepayment (a `settled` status
    // carrying a payment reference) in that no-hold context is therefore earned
    // cost-bearing status. When a `budget_authority` (monetary-hold) context IS
    // present, the cost must be earned by that hold's `reconciled` terminal above,
    // not two free-form financial strings, so the carve-out is gated on the
    // absence of the hold context to keep this sign-site a structural proof. The
    // `financial` block is kernel-constructed and never merged from caller-supplied
    // metadata on any Mediated-signing path. Still fail closed when neither a
    // reconciled hold nor a settled no-ceiling prepayment backs the cost.
    let settled_prepayment = metadata.get("budget_authority").is_none()
        && metadata.get("financial").is_some_and(|financial| {
            financial
                .get("settlement_status")
                .and_then(serde_json::Value::as_str)
                == Some("settled")
                && financial
                    .get("payment_reference")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
        });
    if reconciled || settled_prepayment {
        Ok(())
    } else {
        Err(KernelError::ReceiptSigningFailed(
            "refusing to sign TrustLevel::Mediated for a cost-bearing receipt without a reconciled budget-authority hold or a settled prepayment".to_string(),
        ))
    }
}

impl ChioKernel {
    /// Build and sign a receipt from a `ReceiptParams` descriptor.
    pub(crate) fn build_and_sign_receipt(
        &self,
        params: ReceiptParams<'_>,
    ) -> Result<ChioReceipt, KernelError> {
        // Multi-tenant receipt isolation: resolve tenant_id for this receipt.
        // Precedence:
        //   1. An explicit override on `ReceiptParams` (currently unused).
        //   2. The request-keyed tenant context set by the evaluate path.
        //   3. The active scoped tenant context set by the evaluate path
        //      from `session.auth_context().enterprise_identity.tenant_id`.
        //
        // Tenant_id is never taken from a caller-provided field on the
        // request: allowing caller choice would defeat the isolation the
        // store-level WHERE clause enforces.
        let tenant_id = params
            .tenant_id
            .clone()
            .or_else(|| self.receipt_tenant_id_for_request(params.request_id))
            .or_else(current_scoped_receipt_tenant_id);

        let request_metadata = params.request_id.map(|request_id| {
            serde_json::json!({
                "receipt_context": {
                    "request_id": request_id,
                }
            })
        });
        let metadata = merge_metadata_objects(params.metadata, request_metadata);
        require_earned_mediated_trust_level(metadata.as_ref(), params.trust_level)?;

        let mut evidence = current_pre_invocation_guard_evidence();
        evidence.extend(current_post_invocation_guard_evidence());

        let body = ChioReceiptBody {
            id: next_receipt_id("rcpt"),
            timestamp: params.timestamp,
            capability_id: params.capability_id.to_string(),
            tool_server: params.server_id.to_string(),
            tool_name: params.tool_name.to_string(),
            action: params.action,
            decision: Some(params.decision),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: params.content_hash,
            policy_hash: self.config.policy_hash.clone(),
            evidence,
            metadata,
            trust_level: params.trust_level,
            tenant_id,
            kernel_key: self.config.keypair.public_key(),
            bbs_projection_version: None,
        };

        // WYSIWYS: bind the signature to the exact content this receipt's
        // `content_hash` was derived from. The handle recomputes
        // `sha256_hex(canonical_content)` and the signing primitive refuses to
        // sign if it disagrees with `body.content_hash`, closing the
        // render-A / sign-B hole on the production path. The
        // canonical_content is the same preimage `receipt_content_for_output`
        // hashed to produce `content_hash`.
        let handle = ReceiptSigningHandle::from_content_preimage(params.canonical_content);

        // Delegate the pure signing step to chio-kernel-core so the portable
        // TCB stays in one place. The full kernel still owns body construction
        // (tenant scope resolution, policy_hash injection, evidence assembly)
        // because those are std/tokio-aware concerns.
        //
        // Verified-core boundary note:
        // `formal/proof-manifest.toml` includes this shell method only for the
        // direct call into `chio_kernel_core::sign_receipt_with_handle`. Receipt
        // body assembly, metadata shaping, and persistence remain
        // operational-shell behavior outside the current bounded proof claim.
        let backend = chio_core::crypto::Ed25519Backend::new(self.config.keypair.clone());
        chio_kernel_core::sign_receipt_with_handle(body, &backend, handle).map_err(|error| {
            use chio_kernel_core::ReceiptSigningError;
            let message = match error {
                ReceiptSigningError::KernelKeyMismatch => {
                    "kernel signing key does not match receipt body kernel_key".to_string()
                }
                ReceiptSigningError::ContentHashMismatch {
                    recomputed,
                    claimed,
                } => format!(
                    "receipt content_hash mismatch: body claimed {claimed} but signer \
                     recomputed {recomputed} over the canonical content (WYSIWYS refused)"
                ),
                ReceiptSigningError::SigningFailed(reason) => reason,
            };
            KernelError::ReceiptSigningFailed(message)
        })
    }

    /// Record the receipt and drive the bilateral co-signing hook when the
    /// request crosses a federation boundary.
    ///
    /// Local durability happens before remote co-signing. A co-sign
    /// failure can abort the caller's response path, but it must never
    /// create an externally visible remote side effect before the local
    /// receipt state is durable.
    pub(crate) fn record_chio_receipt_with_federation(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        // Persistence uses the admission-time peer-key snapshot installed
        // by the evaluate path. Re-resolving freshness here is unsafe: the
        // tool has already executed, so a peer that expires mid-dispatch
        // must not skip dual-sign evidence for the side effect admitted
        // under the fresh snapshot.
        let request_admission = self.receipt_federation_admission_for_request(
            &request.request_id,
            request.federated_origin_kernel_id.as_deref(),
        );
        let thread_admission = current_scoped_receipt_federation_admission();
        let thread_admission = thread_admission.as_ref().filter(|admission| {
            admission.remote_kernel_id.as_deref() == request.federated_origin_kernel_id.as_deref()
        });
        let scoped_admission = request_admission.as_ref().or(thread_admission);
        self.record_chio_receipt(receipt)?;
        self.apply_federation_cosign(
            request,
            receipt,
            scoped_admission.and_then(|admission| admission.peer.as_ref()),
        )?;
        Ok(())
    }

    pub(super) fn record_chio_receipt_with_mode(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
        mode: ReceiptRecordMode,
    ) -> Result<(), KernelError> {
        match mode {
            ReceiptRecordMode::WithFederation => {
                self.record_chio_receipt_with_federation(request, receipt)
            }
            ReceiptRecordMode::LocalOnly => {
                self.record_chio_receipt_for_admitted_request_local_only(request, receipt)
            }
        }
    }

    fn record_chio_receipt_for_admitted_request_local_only(
        &self,
        _request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        // Persist the v1 deny receipt locally and
        // deliberately stop before the federation co-signature hook. The
        // runtime-admission deny path does not co-sign because the deny
        // decision is locally authoritative and may have been triggered
        // before any federation peer was contacted.
        self.record_chio_receipt(receipt)
    }

    pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
        // Scope the receipt-store write lock so it is released before the
        // settlement observer runs. Holding the mutex across
        // `run_settlement_observer` would serialize all concurrent receipt
        // persistence behind potentially I/O-bound hook latency; the observer
        // needs only a fully-persisted receipt, so the guard is dropped first.
        // Checkpoint construction runs on the store's writer actor, so this
        // critical section holds no checkpoint work.
        {
            let _receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
                KernelError::Internal("receipt store write lock poisoned".to_string())
            })?;
            self.with_receipt_store(|store| Ok(store.append_chio_receipt_returning_seq(receipt)?))?;
            self.append_chio_receipt_to_local_log(receipt.clone());
        }
        let _settlement_status = self.run_settlement_observer(receipt);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chio_core::receipt::kinds::TrustLevel;

    use super::*;

    #[test]
    fn signing_mediated_for_cost_bearing_grant_without_reconciled_hold_fails_closed() {
        // Refuse to stamp Mediated on a cost-bearing receipt that carries a
        // financial charge but no reconciled budget-authority hold.
        let metadata = serde_json::json!({
            "financial": { "cost_charged": 50, "grant_index": 0, "currency": "USD" }
            // no budget_authority.terminal.disposition == "reconciled"
        });
        let result = require_earned_mediated_trust_level(Some(&metadata), TrustLevel::Mediated);
        assert!(matches!(result, Err(KernelError::ReceiptSigningFailed(_))));
    }

    #[test]
    fn signing_mediated_for_cost_bearing_settled_prepayment_is_allowed() {
        // A prepaid spend with no budget ceiling carries no reconciled hold, but a
        // settled prepayment (settled status + payment reference) earns cost-bearing
        // Mediated status.
        let metadata = serde_json::json!({
            "financial": {
                "cost_charged": 100,
                "grant_index": 0,
                "currency": "USD",
                "settlement_status": "settled",
                "payment_reference": "sim-abc123"
            }
        });
        assert!(require_earned_mediated_trust_level(Some(&metadata), TrustLevel::Mediated).is_ok());
    }

    #[test]
    fn signing_mediated_settled_strings_under_a_hold_context_fails_closed() {
        // The settled-prepayment carve-out is only for a genuine no-monetary-ceiling
        // MustPrepay spend, which carries NO budget_authority block. A cost-bearing
        // receipt that DOES carry a budget-authority (monetary-hold) context must
        // earn Mediated through that hold's `reconciled` terminal, not two free-form
        // financial strings; a non-reconciled hold with settled strings fails closed.
        let metadata = serde_json::json!({
            "financial": {
                "cost_charged": 100,
                "grant_index": 0,
                "currency": "USD",
                "settlement_status": "settled",
                "payment_reference": "sim-abc123"
            },
            "budget_authority": { "terminal": { "disposition": "reversed" } }
        });
        let result = require_earned_mediated_trust_level(Some(&metadata), TrustLevel::Mediated);
        assert!(matches!(result, Err(KernelError::ReceiptSigningFailed(_))));
    }

    #[test]
    fn signing_mediated_for_cost_bearing_pending_prepayment_fails_closed() {
        // A cost-bearing Mediated receipt with neither a reconciled hold nor a
        // settled prepayment still fails closed.
        let metadata = serde_json::json!({
            "financial": {
                "cost_charged": 100,
                "grant_index": 0,
                "currency": "USD",
                "settlement_status": "pending",
                "payment_reference": "sim-abc123"
            }
        });
        let result = require_earned_mediated_trust_level(Some(&metadata), TrustLevel::Mediated);
        assert!(matches!(result, Err(KernelError::ReceiptSigningFailed(_))));
    }

    #[test]
    fn signing_mediated_with_reconciled_hold_is_allowed() {
        let metadata = serde_json::json!({
            "financial": { "cost_charged": 50, "grant_index": 0, "currency": "USD" },
            "budget_authority": { "terminal": { "disposition": "reconciled" } }
        });
        assert!(require_earned_mediated_trust_level(Some(&metadata), TrustLevel::Mediated).is_ok());
    }

    #[test]
    fn advisory_trust_level_never_requires_a_hold() {
        assert!(require_earned_mediated_trust_level(None, TrustLevel::Advisory).is_ok());
    }
}
