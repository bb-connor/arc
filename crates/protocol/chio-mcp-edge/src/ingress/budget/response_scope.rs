//! Actor response provenance shares the original inbox accounting owner.

use super::*;

/// An opaque, monotonic origin within one accounting owner. It has no wire form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpRequestGeneration(u64);

impl McpRequestGeneration {
    pub(super) fn new(generation: u64) -> Self {
        Self(generation)
    }
}

/// A read-only response context for the single actor's uncloneable writer.
#[derive(Clone)]
pub struct McpResponseContext(IngressBudget);

impl McpResponseContext {
    pub(super) fn new(budget: IngressBudget) -> Self {
        Self(budget)
    }

    pub fn request_generation(&self) -> Result<Option<McpRequestGeneration>, AdapterError> {
        let state = self.0.state.lock().map_err(|_| self.0.lock_error())?;
        if let Some(failure) = &state.failure {
            return Err(failure.error());
        }
        Ok(state.response_generation)
    }
}

/// Retains actual actor origin across nested writes and restores the prior scope.
pub struct McpResponseScope {
    budget: IngressBudget,
    generation: McpRequestGeneration,
    previous: Option<McpRequestGeneration>,
}

pub(super) fn enter(
    budget: &IngressBudget,
    reservation: &FrameReservation,
) -> Result<McpResponseScope, AdapterError> {
    if !budget.owns_reservation(reservation) {
        return Err(AdapterError::IngressCapacity);
    }
    let mut state = budget.state.lock().map_err(|_| budget.lock_error())?;
    if let Some(failure) = &state.failure {
        return Err(failure.error());
    }
    let previous = state.response_generation;
    state.response_generation = Some(reservation.generation);
    Ok(McpResponseScope {
        budget: budget.clone(),
        generation: reservation.generation,
        previous,
    })
}

impl Drop for McpResponseScope {
    fn drop(&mut self) {
        let Ok(mut state) = self.budget.state.lock() else {
            self.budget
                .shutdown_requested
                .store(true, Ordering::Release);
            return;
        };
        if state.response_generation == Some(self.generation) {
            state.response_generation = self.previous;
        } else {
            drop(state);
            self.budget
                .fail("MCP actor response scope ownership was lost");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_foreign_reservation_cannot_supply_an_inbox_response_scope() -> Result<(), AdapterError> {
        let (sender, receiver) = crate::ingress::mcp_inbox();
        let (foreign_sender, _foreign_receiver) = crate::ingress::mcp_inbox();
        let foreign = foreign_sender.account(serde_json::json!({}))?;
        assert!(receiver.enter_response_scope(&foreign).is_err());
        assert_eq!(sender.response_context().request_generation()?, None);
        Ok(())
    }

    #[test]
    fn nested_response_scopes_restore_origin_and_release_accounting() -> Result<(), AdapterError> {
        let (sender, receiver) = crate::ingress::mcp_inbox();
        let old = sender.account(serde_json::json!({"id":1}))?;
        let new = sender.account(serde_json::json!({"id":1}))?;
        assert_ne!(old.request_generation(), new.request_generation());
        let context = sender.response_context();
        let old_scope = receiver.enter_response_scope(&old)?;
        assert_eq!(
            context.request_generation()?,
            Some(old.request_generation())
        );
        let new_scope = receiver.enter_response_scope(&new)?;
        assert_eq!(
            context.request_generation()?,
            Some(new.request_generation())
        );
        drop(new_scope);
        assert_eq!(
            context.request_generation()?,
            Some(old.request_generation())
        );
        drop(old_scope);
        assert_eq!(context.request_generation()?, None);
        drop(old);
        drop(new);
        assert_eq!(sender.usage()?, IngressUsage::default());
        Ok(())
    }

    #[test]
    fn exhausted_generation_refuses_without_counter_wrap_or_new_accounting(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = crate::ingress::mcp_inbox();
        let context = sender.response_context();
        let budget = &context.0;
        budget
            .state
            .lock()
            .map_err(|_| "budget state lock poisoned")?
            .next_generation = u64::MAX;
        assert!(matches!(
            sender.account(serde_json::json!({})),
            Err(AdapterError::IngressCapacity)
        ));
        assert_eq!(sender.usage()?, IngressUsage::default());
        assert_eq!(
            budget
                .state
                .lock()
                .map_err(|_| "budget state lock poisoned")?
                .next_generation,
            u64::MAX
        );
        assert_eq!(sender.response_context().request_generation()?, None);
        Ok(())
    }
}
