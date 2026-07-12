use super::*;

use crate::receipt_store::{
    DispatchIntentHandle, DispatchIntentJournalMode, DispatchIntentReconciler,
    DispatchIntentRecord, DispatchIntentResolution, ReceiptStoreError, SideEffectClass,
};

/// Boot-time reconciler for intents that survived a restart: every orphan
/// becomes a durable dead-letter incident, because a side effect is never
/// blindly re-executed. A monetary orphan's incident names its rail (and the
/// rail authorization id when the crash happened after authorize) so an
/// operator can reconcile against the rail; a rail-querying reconciler can
/// replace this default to resolve monetary orphans automatically.
pub struct DefaultDispatchIntentReconciler;

impl DispatchIntentReconciler for DefaultDispatchIntentReconciler {
    fn resolve(
        &self,
        intent: &DispatchIntentRecord,
    ) -> Result<DispatchIntentResolution, ReceiptStoreError> {
        let detail = match (&intent.rail, &intent.rail_authorization_id) {
            (Some(rail), Some(authorization_id)) => format!(
                "outcome unknown after restart; rail={rail}; \
                 rail_authorization_id={authorization_id}"
            ),
            (Some(rail), None) => {
                format!("outcome unknown after restart; rail={rail}; query the rail")
            }
            _ => "outcome unknown after restart".to_string(),
        };
        Ok(DispatchIntentResolution::DeadLetter { detail })
    }
}

impl ChioKernel {
    /// Compute the side-effect class for this call and, unless it is
    /// read-only or the journal is off, durably commit a dispatch-intent row
    /// BEFORE the earliest possible effect (prepaid payment authorization, or
    /// tool dispatch). Returns the handle the terminal receipt sink consumes,
    /// or `None` when no intent was written.
    ///
    /// The write is bounded by the receipt-append budget: the pre-dispatch
    /// liveness gate denies an already-wedged writer, but a writer that
    /// passes the gate and then stalls must fail this call closed within
    /// budget rather than hang the evaluation before dispatch. Any failure
    /// maps to `KernelError::DispatchIntentPersistence`, and the caller
    /// reverses every pre-execution hold before denying.
    pub(crate) fn record_dispatch_intent_if_side_effecting(
        &self,
        request: &crate::runtime::ToolCallRequest,
        has_monetary: bool,
        now_unix_ms: u64,
    ) -> Result<Option<DispatchIntentHandle>, KernelError> {
        let mode = self.config.dispatch_intent_journal;
        if matches!(mode, DispatchIntentJournalMode::Off) {
            return Ok(None);
        }

        // The intent's tenant must be resolved EXACTLY as the terminal
        // receipt resolves it (request-scoped entry first, thread-local scope
        // only for callers outside a request scope): the consuming append
        // keys on the receipt's tenant, so any divergence here would strand
        // the intent after the side effect already ran. The request-scoped
        // entry is installed at the top of every evaluate path and is stable
        // across worker migration, unlike the thread-local.
        let tenant_id = self
            .receipt_tenant_id_for_request(Some(request.request_id.as_str()))
            .unwrap_or_else(current_scoped_receipt_tenant_id);

        // Class order: monetary wins, then the connection's read-only
        // annotation, else side-effecting. An unregistered server or
        // unannotated tool reads as NOT read-only, so unknown tools are
        // journaled (fail-safe), never silently skipped.
        let read_only = self
            .tool_servers
            .get(&request.server_id)
            .map(|connection| connection.tool_is_read_only(&request.tool_name))
            .unwrap_or(false);
        let class = if has_monetary {
            SideEffectClass::Monetary
        } else if read_only {
            SideEffectClass::ReadOnly
        } else {
            SideEffectClass::SideEffecting
        };
        // Read-only calls pay zero durable round trips unless the operator
        // opted into journaling every call.
        if matches!(class, SideEffectClass::ReadOnly)
            && !matches!(mode, DispatchIntentJournalMode::All)
        {
            return Ok(None);
        }

        // The same canonical parameter hash the eventual receipt commits, so
        // the consume can prove the intent matches the exact attested call.
        let action = chio_core::receipt::decision::ToolCallAction::from_parameters(
            request.arguments.clone(),
        )
        .map_err(|error| {
            KernelError::DispatchIntentPersistence(format!(
                "failed to canonicalize parameters for the dispatch intent: {error}"
            ))
        })?;
        let parameter_hash = action.parameter_hash;

        let rail = if has_monetary {
            self.payment_adapter
                .as_ref()
                .map(|adapter| adapter.rail_id().to_string())
        } else {
            None
        };
        let intent = DispatchIntentRecord {
            request_id: request.request_id.clone(),
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.to_string(),
            tool_name: request.tool_name.clone(),
            parameter_hash: parameter_hash.clone(),
            side_effect_class: class,
            monetary: has_monetary,
            rail,
            rail_authorization_id: None,
            tenant_id: tenant_id.clone(),
            created_at_unix_ms: now_unix_ms,
        };

        let budget = self.config.deadlines.receipt_append_budget();
        let recorded = self
            .with_receipt_store(|store| {
                Ok(store.record_dispatch_intent_with_timeout(&intent, budget)?)
            })
            .map_err(|error| KernelError::DispatchIntentPersistence(error.to_string()))?;
        if recorded.is_none() {
            // Journal enabled with no durable store attached: the intent
            // cannot outlive the process, so the guarantee cannot be honored.
            return Err(KernelError::DispatchIntentPersistence(
                "dispatch-intent journal is enabled but no durable receipt store is attached"
                    .to_string(),
            ));
        }
        Ok(Some(DispatchIntentHandle {
            request_id: request.request_id.clone(),
            parameter_hash,
            tenant_id,
        }))
    }
}
