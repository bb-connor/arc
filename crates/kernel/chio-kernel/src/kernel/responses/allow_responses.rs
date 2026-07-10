use super::*;

/// The reserve-for-caller charge threaded into a preflight allow response: the
/// authorized hold to keep reserved (its id, grant currency, and the accounting
/// needed to reverse it if the reservation stamp fails). The TTL reaper deadline
/// is derived from the minted nonce's exact expiry inside the response builder
/// so a hold never expires before its own nonce.
pub(crate) struct ReservedHoldStamp<'a> {
    pub(crate) charge: &'a BudgetChargeResult,
}

impl ChioKernel {
    pub(crate) fn build_allow_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
        preminted_nonce: Option<Box<crate::execution_nonce::SignedExecutionNonce>>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;

        // Classify the call against the memory-provenance action conventions
        // and, for reads, look up the latest chain entry BEFORE the receipt
        // is signed so the provenance evidence rides in the signed metadata.
        // Writes append AFTER signing (see below) because the chain entry
        // needs the receipt id.
        let memory_action_kind = crate::memory_provenance::classify_memory_action(
            &request.tool_name,
            &request.arguments,
        );
        let memory_read_metadata = match memory_action_kind.as_ref() {
            Some(crate::memory_provenance::MemoryActionKind::Read { store, key }) => {
                self.resolve_memory_read_provenance_metadata(store, key)
            }
            _ => None,
        };
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;

        // Merge extra_metadata (e.g. "financial") into receipt_content.metadata.
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            memory_read_metadata,
        );

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Allow,
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata,
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_federation(request, &receipt)?;

        info!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            receipt_id = %receipt.id,
            "tool call allowed"
        );

        // For governed writes, append an entry to the provenance chain once
        // the receipt is signed. A failure here is fatal (fail-closed): we
        // do not want to acknowledge the write to the caller while silently
        // dropping provenance.
        if let Some(crate::memory_provenance::MemoryActionKind::Write { store, key }) =
            memory_action_kind.as_ref()
        {
            self.append_memory_provenance_for_write(
                store,
                key,
                &cap.id,
                &receipt.id,
                receipt.timestamp,
            )?;
        }

        // Use a pre-minted nonce when the caller already minted one (cost-bearing
        // allow paths that need the nonce id in the receipt metadata before signing).
        // Otherwise fall back to minting after the receipt is signed.
        let execution_nonce = match preminted_nonce {
            Some(nonce) => Some(nonce),
            None => self.mint_execution_nonce_for_allow(request, cap, &receipt)?,
        };

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: Some(output),
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce,
        })
    }

    pub(crate) fn build_execution_nonce_preflight_allow_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
        incomplete_reason: &str,
        reserved_hold: Option<ReservedHoldStamp<'_>>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(receipt_content.metadata, request_metadata),
                extra_metadata,
            ),
            receipt_attribution_metadata(cap, matched_grant_index),
        );

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Incomplete {
                reason: incomplete_reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata,
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        // Mint the nonce and stamp the reserved hold BEFORE persisting the
        // receipt. A failed stamp reverses the hold, so the receipt must not
        // already be recorded: a persisted `hold_disposition: reserved` receipt
        // with no terminal event standing over a reversed hold is a corrupted
        // audit view.
        let execution_nonce = self.mint_execution_nonce_for_allow_reserving(
            request,
            cap,
            &receipt,
            reserved_hold
                .as_ref()
                .map(|stamp| stamp.charge.budget_hold_id.as_str()),
        )?;

        // Stamp the reserved hold's TTL deadline from the minted nonce's exact
        // `expires_at` (not a separately sampled evaluation clock), so an
        // unreconciled reserved hold can never expire before its own nonce.
        // The grant currency is recorded here too, for reconcile-time validation.
        // Only the reserve-for-caller path supplies a stamp; the reverse-for-retry
        // preflight passes `None` and marks nothing.
        if let (Some(stamp), Some(nonce)) = (reserved_hold.as_ref(), execution_nonce.as_ref()) {
            let reserved_until = nonce.expires_at();
            if let Err(error) = self.with_budget_store(|store| {
                Ok(store.mark_hold_reserved(
                    stamp.charge.budget_hold_id.as_str(),
                    reserved_until,
                    stamp.charge.currency.as_str(),
                )?)
            }) {
                // The hold was authorized but the reservation stamp did not land.
                // The TTL reaper only settles stamped holds, so an unstamped open
                // hold would stay reserved forever, blocking later authorizations
                // on the grant. Reverse the hold and release the sibling-sum
                // headroom it was holding before surfacing the error, leaving no
                // committed exposure and no stranded parent budget. The receipt is
                // not yet persisted, so a reversed hold leaves no orphaned receipt.
                self.reverse_budget_charge(&cap.id, stamp.charge)?;
                self.release_admitted_capability_budget(cap)
                    .map_err(KernelError::DelegationInvalid)?;
                return Err(error);
            }
            // The stamp landed: keep the delegated child's sibling-sum share
            // admitted and remember it against the reserved hold so reconcile-by-
            // nonce or the TTL reaper releases the parent's headroom when it closes.
            self.record_reserved_sibling_share(stamp.charge.budget_hold_id.as_str(), cap);
        }

        // Persist the receipt only after the hold is successfully stamped, so a
        // stamp failure (which reverses the hold) leaves no reserved receipt.
        self.record_chio_receipt_with_federation(request, &receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Incomplete {
                reason: incomplete_reason.to_string(),
            },
            receipt,
            execution_nonce,
        })
    }

    /// Build receipt metadata describing the provenance record that governs
    /// the memory read identified by `(store, key)`.
    ///
    /// Returns `None` when no provenance store has been installed
    /// (backward-compatible no-op), and returns an `unverified` metadata
    /// object when the store is installed but the key has no chain
    /// entry OR the chain is tampered / unavailable. This is the
    /// fail-closed signal: the receipt explicitly records that the
    /// memory read was not backed by a provenance record.
    fn resolve_memory_read_provenance_metadata(
        &self,
        store: &str,
        key: &str,
    ) -> Option<serde_json::Value> {
        let chain = self.memory_provenance_store()?;

        let latest = match chain.latest_for_key(store, key) {
            Ok(entry) => entry,
            Err(error) => {
                warn!(
                    store = %store,
                    key = %key,
                    error = %redacted!(&error),
                    "memory provenance lookup failed; marking read unverified"
                );
                return Some(memory_read_unverified_metadata(
                    store,
                    key,
                    crate::memory_provenance::UnverifiedReason::StoreUnavailable,
                ));
            }
        };

        let Some(entry) = latest else {
            return Some(memory_read_unverified_metadata(
                store,
                key,
                crate::memory_provenance::UnverifiedReason::NoProvenance,
            ));
        };

        let verification = match chain.verify_entry(&entry.entry_id) {
            Ok(verification) => verification,
            Err(error) => {
                warn!(
                    store = %store,
                    key = %key,
                    entry_id = %entry.entry_id,
                    error = %redacted!(&error),
                    "memory provenance verification failed; marking read unverified"
                );
                return Some(memory_read_unverified_metadata(
                    store,
                    key,
                    crate::memory_provenance::UnverifiedReason::StoreUnavailable,
                ));
            }
        };

        match verification {
            crate::memory_provenance::ProvenanceVerification::Verified {
                entry,
                chain_digest,
            } => Some(serde_json::json!({
                "memory_provenance": {
                    "status": "verified",
                    "store": entry.store,
                    "key": entry.key,
                    "entry_id": entry.entry_id,
                    "capability_id": entry.capability_id,
                    "receipt_id": entry.receipt_id,
                    "written_at": entry.written_at,
                    "prev_hash": entry.prev_hash,
                    "hash": entry.hash,
                    "chain_digest": chain_digest,
                }
            })),
            crate::memory_provenance::ProvenanceVerification::Unverified { reason } => {
                Some(memory_read_unverified_metadata(store, key, reason))
            }
        }
    }

    /// Append a provenance entry for a governed memory write once the allow
    /// receipt is signed. Fails closed on chain-store errors.
    fn append_memory_provenance_for_write(
        &self,
        store: &str,
        key: &str,
        capability_id: &str,
        receipt_id: &str,
        written_at: u64,
    ) -> Result<(), KernelError> {
        let Some(chain) = self.memory_provenance_store() else {
            return Ok(());
        };
        chain
            .append(crate::memory_provenance::MemoryProvenanceAppend {
                store: store.to_string(),
                key: key.to_string(),
                capability_id: capability_id.to_string(),
                receipt_id: receipt_id.to_string(),
                written_at,
            })
            .map(|_| ())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "memory provenance append failed for store={store} key={key}: {error}"
                ))
            })
    }
}

fn memory_read_unverified_metadata(
    store: &str,
    key: &str,
    reason: crate::memory_provenance::UnverifiedReason,
) -> serde_json::Value {
    serde_json::json!({
        "memory_provenance": {
            "status": "unverified",
            "store": store,
            "key": key,
            "reason": reason.as_str(),
        }
    })
}
