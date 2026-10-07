//! Exact, default-off predecessor input model for owning upgrade regressions.
use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;
use std::{
    collections::BTreeSet,
    sync::{Mutex, OnceLock},
};

const MAX_SELECTIONS: usize = 16;
const MAX_REQUEST_BYTES: usize = 262_144;
type Selection = (String, Vec<u8>);

fn selected_requests() -> &'static Mutex<BTreeSet<Selection>> {
    static REQUESTS: OnceLock<Mutex<BTreeSet<Selection>>> = OnceLock::new();
    REQUESTS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

pub(super) fn has_transient_credentials(request: &ToolCallRequest) -> bool {
    request.dpop_proof.is_some()
        || request.execution_nonce.is_some()
        || request.approval_token.is_some()
        || !request.approval_tokens.is_empty()
        || request.threshold_approval_proposal.is_some()
        || request.supplemental_authorization.is_some()
        || request.declassification_grant.is_some()
}

pub(super) fn request_bytes(
    request: &ToolCallRequest,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    // Original custody intentionally omits one-shot credentials. Reject their
    // presence here so matching never normalizes or strips request authority.
    if has_transient_credentials(request) {
        return Err(refused("legacy input fixture has transient credentials"));
    }
    let bytes = canonical_json_bytes(request).map_err(refused)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(refused("legacy input fixture request exceeds its bound"));
    }
    Ok(bytes)
}

/// Applies only to one exact request in one actual native authority store.
/// Dropping the guard restores the current independently verified input floor.
#[must_use]
pub struct ModeledLegacySemanticInputFloorGuard {
    selection: Selection,
}

impl Drop for ModeledLegacySemanticInputFloorGuard {
    fn drop(&mut self) {
        if let Ok(mut selected) = selected_requests().lock() {
            selected.remove(&self.selection);
        }
    }
}

fn reserve_selection(
    selected: &mut BTreeSet<Selection>,
    selection: Selection,
) -> Result<ModeledLegacySemanticInputFloorGuard, AdmissionOperationStoreError> {
    if selected.len() >= MAX_SELECTIONS || !selected.insert(selection.clone()) {
        return Err(refused("legacy input fixture is full or already selected"));
    }
    Ok(ModeledLegacySemanticInputFloorGuard { selection })
}

/// Only the owning native input writer may use this after retained original,
/// live native owner, current route and semantic source verification succeed.
pub(in crate::admission_operation_store) fn modeled_legacy_input_floor_selected(
    store_uuid: &str,
    original: &RetainedToolAdmissionRequestV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let Some(binding) = original.native_security_authority_binding() else {
        return Ok(false);
    };
    if binding.store_uuid().as_str() != store_uuid {
        return Ok(false);
    }
    let selected = selected_requests()
        .lock()
        .map_err(|_| refused("legacy input fixture registry unavailable"))?;
    if has_transient_credentials(original.request_for_revalidation())
        || !selected.iter().any(|(selected, _)| selected == store_uuid)
    {
        return Ok(false);
    }
    let selection = (
        store_uuid.to_owned(),
        request_bytes(original.request_for_revalidation())?,
    );
    Ok(selected.contains(&selection))
}

impl SqliteAdmissionOperationStore {
    /// Model the predecessor's classified native input join for one exact
    /// request. The owning writer still performs every current verifier and
    /// native authority check before considering this default-off fixture.
    pub fn modeled_legacy_semantic_input_floor_for_test(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ModeledLegacySemanticInputFloorGuard, AdmissionOperationStoreError> {
        let selection = (
            self.serving_owner.fence.store_uuid.clone(),
            request_bytes(request)?,
        );
        let mut selected = selected_requests()
            .lock()
            .map_err(|_| refused("legacy input fixture registry unavailable"))?;
        reserve_selection(&mut selected, selection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::{
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    };

    fn request() -> Result<ToolCallRequest, AdmissionOperationStoreError> {
        let signer = chio_core::Keypair::generate();
        let agent = chio_core::Keypair::generate();
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "fixture-capability".into(),
                issuer: signer.public_key(),
                subject: agent.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_000,
                expires_at: 2_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &signer,
        )
        .map_err(refused)?;
        serde_json::from_value(serde_json::json!({
            "request_id": "exact-request",
            "capability": capability,
            "server_id": "exact-server",
            "tool_name": "exact-tool",
            "agent_id": agent.public_key().to_hex(),
            "arguments": {"material": "exact-bytes"},
        }))
        .map_err(refused)
    }

    #[test]
    fn exact_request_selection_never_matches_another_store_or_request(
    ) -> Result<(), AdmissionOperationStoreError> {
        let request = request()?;
        let mut selected = BTreeSet::new();
        let exact = ("store-a".to_owned(), request_bytes(&request)?);
        let guard = reserve_selection(&mut selected, exact.clone())?;
        assert!(selected.contains(&exact));
        assert!(!selected.contains(&("store-b".to_owned(), exact.1.clone())));
        let mut foreign = request.clone();
        foreign.request_id = "foreign-request".into();
        assert!(!selected.contains(&(exact.0.clone(), request_bytes(&foreign)?)));
        foreign = request.clone();
        foreign.server_id = "foreign-server".into();
        assert!(!selected.contains(&(exact.0.clone(), request_bytes(&foreign)?)));
        foreign = request.clone();
        foreign.tool_name = "foreign-tool".into();
        assert!(!selected.contains(&(exact.0.clone(), request_bytes(&foreign)?)));
        foreign = request.clone();
        foreign.agent_id = "foreign-agent".into();
        assert!(!selected.contains(&(exact.0.clone(), request_bytes(&foreign)?)));
        foreign = request.clone();
        foreign.arguments = serde_json::json!({"material": "changed-bytes"});
        assert!(!selected.contains(&(exact.0.clone(), request_bytes(&foreign)?)));
        foreign = request.clone();
        foreign.capability = self::request()?.capability;
        assert!(!selected.contains(&(exact.0.clone(), request_bytes(&foreign)?)));
        foreign = request;
        foreign.federated_origin_kernel_id = Some("foreign-kernel".into());
        assert!(!selected.contains(&(exact.0.clone(), request_bytes(&foreign)?)));
        assert!(reserve_selection(&mut selected, exact).is_err());
        drop(guard);
        Ok(())
    }

    #[test]
    fn legacy_input_registry_is_bounded_and_dropping_a_guard_restores_current_behavior(
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut bounded = BTreeSet::new();
        let mut guards = Vec::new();
        for index in 0..MAX_SELECTIONS {
            guards.push(reserve_selection(
                &mut bounded,
                (format!("bounded-store-{index}"), vec![index as u8]),
            )?);
        }
        assert!(reserve_selection(&mut bounded, ("overflow-store".to_owned(), vec![0])).is_err());
        drop(guards);

        let exact = ("drop-control-store".to_owned(), b"exact-request".to_vec());
        let guard = {
            let mut selected = selected_requests()
                .lock()
                .map_err(|_| refused("legacy input fixture registry unavailable"))?;
            reserve_selection(&mut selected, exact.clone())?
        };
        assert!(selected_requests()
            .lock()
            .map_err(|_| refused("legacy input fixture registry unavailable"))?
            .contains(&exact));
        drop(guard);
        assert!(!selected_requests()
            .lock()
            .map_err(|_| refused("legacy input fixture registry unavailable"))?
            .contains(&exact));
        Ok(())
    }
}
