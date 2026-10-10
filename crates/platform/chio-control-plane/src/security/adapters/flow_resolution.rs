use super::{
    append_active_defense_body, canonical_body, digest, flow_policy, prepare_pre_invocation,
    transition_id, ActiveDefensePolicyBinding, AdmittedToolSecurity, Arc, BTreeMap, BTreeSet,
    BridgeSecurityMetadata, CategoryLabelMap, ClassificationPort, ClassificationRequest, Clock,
    DeclassificationError, DeclassificationEvidenceCommitStore, DeclassificationEvidenceConfig,
    Digest32, ExactSecurityReceiptSink, FlowAdmission, FlowDenial, FlowDenialReceiptContext,
    FlowDispatchOutcomeRecorder, FlowJoinRequest, FlowPostInvocationInput,
    FlowPostInvocationResolver, FlowPreDispatchInput, FlowPreDispatchPort, FlowPreInvocationInput,
    FlowPreInvocationPort, FlowPreInvocationResolver, FlowReceiptEvidenceConfig,
    FlowResolverConfig, FlowStateKey, FlowStateSnapshot, FlowStateStore, InformationLabel,
    PersistentFlowResolver, PortResult, PostInvocationFlow, PublicKey, RecordId, RequestId,
    ResolvedFlowRequest, SecurityReceiptSink, VerifiedManifestRegistry,
};

impl FlowResolverConfig {
    pub fn new(
        operator_input_floor: InformationLabel,
        category_labels: CategoryLabelMap,
        trusted_declassification_authorities: BTreeMap<RecordId, PublicKey>,
        fence_ttl_ms: u64,
    ) -> Result<Self, FlowResolverConfigError> {
        if fence_ttl_ms == 0 {
            return Err(FlowResolverConfigError::ZeroFenceTtl);
        }
        Ok(Self {
            operator_input_floor,
            category_labels,
            trusted_declassification_authorities,
            fence_ttl_ms,
            declassification_evidence: None,
            receipt_evidence: None,
        })
    }

    pub fn with_declassification_evidence(
        mut self,
        store: Arc<dyn DeclassificationEvidenceCommitStore>,
        sink: Arc<dyn ExactSecurityReceiptSink>,
        policy: ActiveDefensePolicyBinding,
    ) -> PortResult<Self> {
        store.ensure_declassification_evidence_ready()?;
        sink.ensure_receipts_ready()?;
        store.seal_declassification_live_dispatch()?;
        self.declassification_evidence = Some(DeclassificationEvidenceConfig {
            store,
            sink,
            policy,
        });
        Ok(self)
    }

    #[must_use]
    pub fn with_receipt_evidence(
        mut self,
        sink: Arc<dyn SecurityReceiptSink>,
        policy: ActiveDefensePolicyBinding,
    ) -> Self {
        self.receipt_evidence = Some(FlowReceiptEvidenceConfig { sink, policy });
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FlowResolverConfigError {
    #[error("flow egress fence TTL must be nonzero")]
    ZeroFenceTtl,
}

impl PersistentFlowResolver {
    #[must_use]
    pub fn new(
        manifests: Arc<VerifiedManifestRegistry>,
        state: Arc<dyn FlowStateStore>,
        classifier: Arc<dyn ClassificationPort>,
        clock: Arc<dyn Clock>,
        config: FlowResolverConfig,
    ) -> Self {
        Self {
            manifests,
            state,
            classifier,
            clock,
            config,
        }
    }

    pub(super) fn resolve_pre(
        &self,
        input: &FlowPreInvocationInput<'_>,
        require_context_generation: bool,
    ) -> Result<ResolvedFlowRequest, FlowDenial> {
        let key = flow_key(input.security_context);
        let state = self.load_state(&key)?;
        if require_context_generation {
            let expected_flow_state_generation = input
                .security_context
                .flow_state_generation()
                .ok_or(FlowDenial::StateChanged)?;
            if state.context_generation != expected_flow_state_generation {
                return Err(FlowDenial::StateChanged);
            }
        }
        self.flow_policy().resolve_pre(input, state)
    }

    fn flow_policy(&self) -> flow_policy::FlowPolicyView<'_> {
        flow_policy::FlowPolicyView {
            manifests: &self.manifests,
            classifier: self.classifier.as_ref(),
            clock: self.clock.as_ref(),
            config: &self.config,
        }
    }

    pub(super) fn load_state(&self, key: &FlowStateKey) -> Result<FlowStateSnapshot, FlowDenial> {
        self.state
            .load(key)
            .map_err(|_| FlowDenial::StateChanged)?
            .ok_or(FlowDenial::StateChanged)
    }

    fn resolve_admitted_tool_security(
        &self,
        server_id: &str,
        tool_name: &str,
    ) -> Result<(&AdmittedToolSecurity, BridgeSecurityMetadata), FlowDenial> {
        self.flow_policy()
            .resolve_admitted_tool_security(server_id, tool_name)
    }

    pub(super) fn persist_admission(
        &self,
        admission: &FlowAdmission,
    ) -> Result<FlowStateSnapshot, FlowDenial> {
        self.state
            .join(&admission.taint_transition)
            .map_err(|_| FlowDenial::StateChanged)
    }
}

impl FlowPreInvocationResolver for PersistentFlowResolver {
    fn persist_observed_input(&self, observation: &FlowJoinRequest) -> Result<(), FlowDenial> {
        self.state
            .join(observation)
            .map(|_| ())
            .map_err(|_| FlowDenial::StateChanged)
    }

    fn resolve(
        &self,
        input: &FlowPreInvocationInput<'_>,
    ) -> Result<ResolvedFlowRequest, FlowDenial> {
        self.resolve_pre(input, true)
    }

    fn persist(&self, admission: &FlowAdmission) -> Result<(), FlowDenial> {
        self.persist_admission(admission).map(|_| ())
    }
}

impl FlowPreInvocationPort for PersistentFlowResolver {
    fn evaluate(&self, input: &FlowPreInvocationInput<'_>) -> Result<(), FlowDenial> {
        let resolved = self.resolve_pre(input, true)?;
        let receipt_context = self
            .config
            .receipt_evidence
            .as_ref()
            .map(|_| FlowDenialReceiptContext::from_resolved(&resolved))
            .transpose()?;
        let decision = self
            .persist_observed_input(&resolved.observed_input_taint())
            .and_then(|()| prepare_pre_invocation(resolved).map(|_| ()));
        if let Err(denial) = decision {
            if let Some(context) = receipt_context.as_ref() {
                self.attest_flow_denial(context, denial)?;
            }
        }
        decision
    }
}

impl PersistentFlowResolver {
    fn attest_flow_denial(
        &self,
        context: &FlowDenialReceiptContext,
        denial: FlowDenial,
    ) -> Result<(), FlowDenial> {
        let Some(receipt_evidence) = self.config.receipt_evidence.as_ref() else {
            return Ok(());
        };
        let body = context.body(receipt_evidence.policy.clone(), denial)?;
        append_active_defense_body(receipt_evidence.sink.as_ref(), &body)?;
        Ok(())
    }
}

impl FlowPreDispatchPort for PersistentFlowResolver {
    fn commit(
        &self,
        input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        let canonical_request = chio_core::canonical_json_bytes(input.request)
            .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
        if canonical_request.as_slice() != input.canonical_request {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        self.commit_dispatch(
            &FlowPreInvocationInput {
                security_context: input.security_context,
                request: input.request,
            },
            input.dispatch_commitment_id.clone(),
        )
    }
}

impl FlowPostInvocationResolver for PersistentFlowResolver {
    fn resolve(
        &self,
        input: &FlowPostInvocationInput<'_>,
    ) -> Result<PostInvocationFlow, FlowDenial> {
        let key = flow_key(input.security_context);
        let state = self.load_state(&key)?;
        let (security, bridge) = self
            .resolve_admitted_tool_security(&input.request.server_id, &input.request.tool_name)?;
        let canonical_response = canonical_body(input.response)?;
        let request_id = RequestId::new(input.request.request_id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let payload_digest = digest(canonical_response.as_bytes());
        let classified = self
            .config
            .category_labels
            .classify(
                self.classifier.as_ref(),
                &ClassificationRequest {
                    tenant_id: key.tenant_id.clone(),
                    request_id: request_id.clone(),
                    payload: chio_security_types::ports::ClassificationPayload::new(
                        canonical_response.into_bytes(),
                    )
                    .map_err(|_| FlowDenial::ClassifierFailure)?,
                    payload_digest,
                },
            )
            .map_err(|_| FlowDenial::ClassifierFailure)?;
        let flow_transition_id = flow_transition_id(
            "flow-post",
            &state.key,
            state.context_generation,
            &request_id,
            payload_digest,
        )?;
        Ok(PostInvocationFlow {
            request_id,
            payload_digest,
            state,
            classified,
            operator_output_floor: security.effective_output_floor().clone(),
            manifest: bridge
                .flow()
                .cloned()
                .unwrap_or_else(non_egress_declaration),
            transition_id: flow_transition_id,
        })
    }

    fn persist(&self, transition: &FlowJoinRequest) -> Result<(), FlowDenial> {
        self.state
            .join(transition)
            .map(|_| ())
            .map_err(|_| FlowDenial::StateChanged)
    }
}

pub(super) fn flow_key(context: &chio_kernel::SecurityInvocationContextV1) -> FlowStateKey {
    FlowStateKey {
        tenant_id: context.tenant_id().clone(),
        principal_id: context.principal_id().clone(),
        lineage_id: context.lineage_root_id().clone(),
        session_id: context.session_id().clone(),
        isolation_epoch_id: context.isolation_epoch_id().clone(),
    }
}

pub(super) fn flow_transition_id(
    domain: &str,
    key: &FlowStateKey,
    context_generation: u64,
    request_id: &RequestId,
    payload_digest: Digest32,
) -> Result<RecordId, FlowDenial> {
    let fields = [
        key.tenant_id.as_str().as_bytes(),
        key.principal_id.as_str().as_bytes(),
        key.lineage_id.as_str().as_bytes(),
        key.session_id.as_str().as_bytes(),
        key.isolation_epoch_id.as_str().as_bytes(),
        request_id.as_str().as_bytes(),
        payload_digest.as_bytes(),
    ];
    let mut binding = Vec::new();
    for field in fields {
        let length = u64::try_from(field.len()).map_err(|_| FlowDenial::StateOverflow)?;
        binding.extend_from_slice(&length.to_be_bytes());
        binding.extend_from_slice(field);
    }
    binding.extend_from_slice(&context_generation.to_be_bytes());
    transition_id(domain, &binding)
}

pub(super) fn non_egress_declaration() -> chio_manifest::ToolFlowDeclaration {
    chio_manifest::ToolFlowDeclaration {
        output_label: None,
        input_clearance: None,
        egress: false,
        declassification_purposes: BTreeSet::new(),
    }
}

pub(super) fn map_declassification_error(error: DeclassificationError) -> FlowDenial {
    match error {
        DeclassificationError::PurposeDenied => FlowDenial::DeclassificationPurposeDenied,
        DeclassificationError::NotYetValid => FlowDenial::DeclassificationNotYetValid,
        DeclassificationError::Expired => FlowDenial::DeclassificationExpired,
        DeclassificationError::UntrustedAuthority => FlowDenial::DeclassificationUntrustedAuthority,
        DeclassificationError::AlreadyConsumed => FlowDenial::DeclassificationReplay,
        DeclassificationError::StoreFailure => FlowDenial::DeclassificationStoreFailure,
        DeclassificationError::InvalidGrant
        | DeclassificationError::InvalidRequestRepresentation
        | DeclassificationError::BindingMismatch
        | DeclassificationError::InvalidSignature
        | DeclassificationError::TopSource
        | DeclassificationError::InvalidTarget
        | DeclassificationError::NoOpTarget => FlowDenial::DeclassificationBindingMismatch,
    }
}
