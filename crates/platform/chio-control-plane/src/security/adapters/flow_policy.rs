//! Shared read-only policy and classification. State custody belongs to the caller.

use super::*;

pub(super) struct FlowPolicyView<'a> {
    pub manifests: &'a VerifiedManifestRegistry,
    pub classifier: &'a dyn ClassificationPort,
    pub clock: &'a dyn SecurityClock,
    pub config: &'a FlowResolverConfig,
}

/// Inputs and exact verifier output from one resolution. Splitting this result
/// must not rerun classification or reload another manifest for its evidence.
pub(super) struct ResolvedFlowPolicy<'a> {
    pub request: ResolvedFlowRequest,
    pub classification: chio_flow::VerifiedClassification,
    pub admitted_security: &'a AdmittedToolSecurity,
    pub bridge: BridgeSecurityMetadata,
}

impl<'a> FlowPolicyView<'a> {
    pub(super) fn resolve_pre(
        &self,
        input: &FlowPreInvocationInput<'_>,
        state: FlowStateSnapshot,
    ) -> Result<ResolvedFlowRequest, FlowDenial> {
        self.resolve_pre_with_evidence(input, state)
            .map(|resolved| resolved.request)
    }

    pub(super) fn resolve_pre_with_evidence(
        &self,
        input: &FlowPreInvocationInput<'_>,
        state: FlowStateSnapshot,
    ) -> Result<ResolvedFlowPolicy<'a>, FlowDenial> {
        let key = flow_key(input.security_context);
        if state.key != key {
            return Err(FlowDenial::StateChanged);
        }
        let (security, bridge) = self
            .resolve_admitted_tool_security(&input.request.server_id, &input.request.tool_name)?;
        let manifest = bridge
            .flow()
            .cloned()
            .unwrap_or_else(non_egress_declaration);
        let (
            ClassificationRequest {
                request_id,
                payload: canonical_request,
                payload_digest,
                ..
            },
            classified,
        ) = self.classify_arguments(input)?;
        let complete_source = classified
            .label()
            .join(&self.config.operator_input_floor)
            .and_then(|label| label.join(&state.principal_label))
            .and_then(|label| label.join(&state.lineage_label))
            .and_then(|label| label.join(&state.session_label))
            .map_err(|_| FlowDenial::StateOverflow)?;
        let now_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|_| FlowDenial::StateChanged)?;
        let capability_id = RecordId::new(input.request.capability.id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let agent_id = RecordId::new(input.request.agent_id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let tool_name = RecordId::new(input.request.tool_name.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let destination_id = DestinationId::new(input.request.server_id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let purpose = match input.request.declassification_grant.as_ref() {
            Some(grant) => grant.body().purpose().clone(),
            None => DeclassificationPurpose::new("not-applicable")
                .map_err(|_| FlowDenial::InvalidManifest)?,
        };
        let declassification = input
            .request
            .declassification_grant
            .as_ref()
            .map(|grant| {
                verify_declassification(
                    grant,
                    &DeclassificationVerificationRequest {
                        capability_id: capability_id.clone(),
                        tenant_id: key.tenant_id.clone(),
                        subject_id: key.principal_id.clone(),
                        agent_id: agent_id.clone(),
                        session_id: key.session_id.clone(),
                        source_label: complete_source,
                        destination_id: destination_id.clone(),
                        tool_name: tool_name.clone(),
                        purpose: purpose.clone(),
                        policy_purposes: security.declassification_purposes().clone(),
                        manifest_purposes: manifest.declassification_purposes.clone(),
                        canonical_request: canonical_request.clone(),
                        now_unix_ms,
                        trusted_authorities: self
                            .config
                            .trusted_declassification_authorities
                            .clone(),
                    },
                )
                .map_err(map_declassification_error)
            })
            .transpose()?;
        let fence_expires_at_unix_ms = now_unix_ms
            .checked_add(self.config.fence_ttl_ms)
            .ok_or(FlowDenial::StateOverflow)?;
        let flow_transition_id = flow_transition_id(
            "flow-pre",
            &state.key,
            state.context_generation,
            &request_id,
            payload_digest,
        )?;
        let request = ResolvedFlowRequest {
            request_id,
            request_hash: canonical_request_hash(&canonical_request)
                .map_err(map_declassification_error)?,
            transition_id: flow_transition_id,
            state,
            payload_label: classified.label().clone(),
            operator_input_floor: self.config.operator_input_floor.clone(),
            runtime_egress: security.effective_egress(),
            capability_id,
            agent_id,
            tool_name,
            destination_id,
            purpose,
            effective_declassification_purposes: security.declassification_purposes().clone(),
            trusted_declassification_authorities: self
                .config
                .trusted_declassification_authorities
                .clone(),
            now_unix_ms,
            declassification,
            policy_clearances: BoundedVec::new(security.policy_clearances().to_vec())
                .map_err(|_| FlowDenial::InvalidManifest)?,
            manifest,
            fence_expires_at_unix_ms,
        };
        Ok(ResolvedFlowPolicy {
            request,
            classification: classified,
            admitted_security: security,
            bridge,
        })
    }

    /// Classify exact original arguments before budget capture. Manifest and
    /// bridge admission must succeed first. Inherited state is resolved only by
    /// the operation-owned physical writer, not by this policy-only view.
    pub(super) fn classified_input_label(
        &self,
        input: &FlowPreInvocationInput<'_>,
    ) -> Result<InformationLabel, FlowDenial> {
        self.resolve_admitted_tool_security(&input.request.server_id, &input.request.tool_name)?;
        let (_, classified) = self.classify_arguments(input)?;
        classified
            .label()
            .join(&self.config.operator_input_floor)
            .map_err(|_| FlowDenial::StateOverflow)
    }

    fn classify_arguments(
        &self,
        input: &FlowPreInvocationInput<'_>,
    ) -> Result<(ClassificationRequest, chio_flow::VerifiedClassification), FlowDenial> {
        let payload = canonical_body(&input.request.arguments)?;
        let request = ClassificationRequest {
            tenant_id: input.security_context.tenant_id().clone(),
            request_id: RequestId::new(input.request.request_id.clone())
                .map_err(|_| FlowDenial::InvalidManifest)?,
            payload_digest: digest(payload.as_bytes()),
            payload,
        };
        let classified = self
            .config
            .category_labels
            .classify(self.classifier, &request)
            .map_err(|_| FlowDenial::ClassifierFailure)?;
        Ok((request, classified))
    }

    pub(super) fn resolve_admitted_tool_security(
        &self,
        server_id: &str,
        tool_name: &str,
    ) -> Result<(&'a AdmittedToolSecurity, BridgeSecurityMetadata), FlowDenial> {
        let regular = Self::pair_admitted_security(
            self.manifests.tool_security(server_id, tool_name),
            self.manifests.bridge_security(server_id, tool_name),
        )?;
        let server_tool = Self::pair_admitted_security(
            self.manifests
                .tool_security_for_server_tool(server_id, tool_name),
            self.manifests
                .bridge_security_for_server_tool(server_id, tool_name),
        )?;
        let (security, bridge) = match (regular, server_tool) {
            (Some(pair), None) | (None, Some(pair)) => pair,
            (None, None) | (Some(_), Some(_)) => return Err(FlowDenial::InvalidManifest),
        };
        self.validate_bridge_security(server_id, tool_name, &bridge)?;
        Ok((security, bridge))
    }

    fn pair_admitted_security(
        security: Option<&AdmittedToolSecurity>,
        bridge: Option<BridgeSecurityMetadata>,
    ) -> Result<Option<(&AdmittedToolSecurity, BridgeSecurityMetadata)>, FlowDenial> {
        match (security, bridge) {
            (Some(security), Some(bridge)) => Ok(Some((security, bridge))),
            (None, None) => Ok(None),
            _ => Err(FlowDenial::InvalidManifest),
        }
    }

    fn validate_bridge_security(
        &self,
        server_id: &str,
        tool_name: &str,
        bridge: &BridgeSecurityMetadata,
    ) -> Result<(), FlowDenial> {
        self.manifests
            .validate_bridge_security(server_id, tool_name, bridge)
            .map_err(|_| FlowDenial::InvalidManifest)
    }
}
