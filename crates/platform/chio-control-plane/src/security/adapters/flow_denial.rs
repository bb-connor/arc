use super::*;


pub(super) struct FlowDenialReceiptContext {
    tenant_id: TenantId,
    request_hash: Digest32,
    source_label_hash: Digest32,
    destination_label_hash: Digest32,
    occurred_at_unix_ms: u64,
    flow_transition_id: RecordId,
}

impl FlowDenialReceiptContext {
    pub(super) fn from_resolved(resolved: &ResolvedFlowRequest) -> Result<Self, FlowDenial> {
        let source_label = resolved
            .payload_label
            .join(&resolved.operator_input_floor)
            .and_then(|label| label.join(&resolved.state.principal_label))
            .and_then(|label| label.join(&resolved.state.lineage_label))
            .and_then(|label| label.join(&resolved.state.session_label))
            .map_err(|_| FlowDenial::StateOverflow)?;
        let source_label_hash =
            information_label_hash(&source_label).map_err(map_declassification_error)?;
        let destination_commitment = serde_json::json!({
            "destination_id": resolved.destination_id.as_str(),
            "manifest_clearance": &resolved.manifest.input_clearance,
            "policy_clearances": resolved.policy_clearances.as_slice(),
        });
        let destination_label_hash = digest(
            &chio_core::canonical_json_bytes(&destination_commitment)
                .map_err(|_| FlowDenial::InvalidManifest)?,
        );
        Ok(Self {
            tenant_id: resolved.state.key.tenant_id.clone(),
            request_hash: resolved.request_hash,
            source_label_hash,
            destination_label_hash,
            occurred_at_unix_ms: resolved.now_unix_ms,
            flow_transition_id: resolved.transition_id.clone(),
        })
    }

    pub(super) fn body(
        &self,
        policy: ActiveDefensePolicyBinding,
        denial: FlowDenial,
    ) -> Result<ActiveDefenseReceiptBody, FlowDenial> {
        let denial_code = flow_denial_code(denial)?;
        let transition_id = transition_id(
            "flow-denial-receipt",
            self.flow_transition_id.as_str().as_bytes(),
        )?;
        let guard_evidence_hash = digest(
            &chio_core::canonical_json_bytes(&serde_json::json!({
                "denial_code": denial_code.as_str(),
                "destination_label_hash": self.destination_label_hash.as_bytes(),
                "flow_transition_id": self.flow_transition_id.as_str(),
                "request_hash": self.request_hash.as_bytes(),
                "source_label_hash": self.source_label_hash.as_bytes(),
            }))
            .map_err(|_| FlowDenial::StateOverflow)?,
        );
        let event_id = event_id("flow-denial-event", transition_id.as_str().as_bytes())?;
        Ok(ActiveDefenseReceiptBody::FlowDenial(
            FlowDenialReceiptBody {
                header: active_defense_header(
                    self.occurred_at_unix_ms,
                    self.tenant_id.clone(),
                    transition_id,
                    Vec::new(),
                )?,
                policy,
                request_hash: self.request_hash,
                source_label_hash: self.source_label_hash,
                destination_label_hash: self.destination_label_hash,
                guard_evidence_hash,
                denial_code,
                event_id,
            },
        ))
    }
}

pub(super) fn flow_denial_code(denial: FlowDenial) -> Result<ErrorCode, FlowDenial> {
    let suffix = match denial {
        FlowDenial::StateOverflow => "state_overflow",
        FlowDenial::StateChanged => "state_changed",
        FlowDenial::InvalidManifest => "invalid_manifest",
        FlowDenial::DeclassificationBindingMismatch => "declassification_binding_mismatch",
        FlowDenial::DeclassificationPurposeDenied => "declassification_purpose_denied",
        FlowDenial::DeclassificationNotYetValid => "declassification_not_yet_valid",
        FlowDenial::DeclassificationExpired => "declassification_expired",
        FlowDenial::DeclassificationUntrustedAuthority => "declassification_untrusted_authority",
        FlowDenial::UnexpectedDeclassification => "unexpected_declassification",
        FlowDenial::DeclassificationReplay => "declassification_replay",
        FlowDenial::DeclassificationStoreFailure => "declassification_store_failure",
        FlowDenial::ClassifierFailure => "classifier_failure",
        FlowDenial::ClassifierBindingMismatch => "classifier_binding_mismatch",
        FlowDenial::MissingPolicyClearance => "missing_policy_clearance",
        FlowDenial::MissingManifestClearance => "missing_manifest_clearance",
        FlowDenial::TopSource => "top_source",
        FlowDenial::TopClearance => "top_clearance",
        FlowDenial::PolicyFlowViolation => "policy_flow_violation",
        FlowDenial::ManifestFlowViolation => "manifest_flow_violation",
    };
    ErrorCode::new(format!("flow.{suffix}")).map_err(|_| FlowDenial::StateOverflow)
}
