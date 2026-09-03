#[cfg(test)]
mod tests {
    use super::{FlowResolverConfig, PersistentFlowResolver, StructuredClassificationAdapter};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;

    use chio_core::capability::scope::ChioScope;
    use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
    use chio_core::crypto::Keypair;
    use chio_core_types::SignedDeclassificationGrant;
    use chio_data_guards::{
        ClassifierIdentity, RegexClassificationRule, RegexStructuredClassifier,
        StructuredClassificationError, StructuredClassificationResult, StructuredClassifier,
    };
    use chio_flow::{
        canonical_request_hash, evaluate_post_invocation, evaluate_pre_invocation,
        information_label_hash, CategoryLabelMap, DeclassificationDispatchOutcome,
    };
    use chio_kernel::{SecurityInvocationContextV1, ToolCallRequest};
    use chio_manifest::{
        sign_manifest, AuthoritativeToolPolicy, RuntimeToolTopology, ServerTool, ToolAnnotations,
        ToolDefinition, ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry,
        TOOL_MANIFEST_SCHEMA,
    };
    use chio_security_kernel::{
        FlowPostInvocationInput, FlowPostInvocationResolver, FlowPreDispatchInput,
        FlowPreDispatchPort, FlowPreInvocationInput, FlowPreInvocationPort,
        FlowPreInvocationResolver, SecurityClock,
    };
    use chio_security_types::flow::DeclassificationPurpose;
    use chio_security_types::ports::{
        derive_declassification_transition_id, CanonicalBody, ClassificationPort,
        ClassificationRequest, ClassificationResult, ClassifierId, ClassifierVersion,
        CommittedEgressFence, DeclassificationEvidenceCommitStore,
        DeclassificationEvidencePhase, DeclassificationEvidenceQuery,
        DeclassificationTransitionBinding, DeclassificationUseQuery, DeclassificationUseState,
        DestinationId, Digest32, EgressFence, EgressFenceCommit, EgressFenceRequest,
        ExactReceiptRecord, ExactSecurityReceiptSink, FlowJoinRequest, FlowStateKey,
        FlowStateSnapshot, FlowStateStore, GrantId, IsolationEpochTransition, LineageId,
        OpaqueReceiptRef, PortError, PortErrorKind, PortResult, ReceiptAppendRequest, RecordId,
        RequestId, SecurityReceiptSink, SessionId, TenantId,
    };
    use chio_security_types::{
        Compartment, DeclassificationGrantBody, DeclassificationGrantClaims, InformationLabel,
        PrincipalId,
    };
    use chio_store_sqlite::SqliteSecurityStateStore;
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn require_error<T>(result: PortResult<T>) -> chio_security_types::ports::PortError {
        match result {
            Ok(_) => panic!("classification unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn request(payload: &[u8]) -> ClassificationRequest {
        ClassificationRequest {
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            request_id: RequestId::new("classification-a")
                .unwrap_or_else(|error| panic!("request: {error}")),
            payload: CanonicalBody::new(payload.to_vec())
                .unwrap_or_else(|error| panic!("payload: {error}")),
            payload_digest: Digest32::new(*chio_core::sha256(payload).as_bytes()),
        }
    }

    #[test]
    fn adapter_preserves_identity_locations_and_payload_binding() {
        let classifier = RegexStructuredClassifier::new(
            "classifier.local",
            "1",
            vec![RegexClassificationRule::new("pii.email", "@", 9_000)
                .unwrap_or_else(|error| panic!("rule: {error}"))],
        )
        .unwrap_or_else(|error| panic!("classifier: {error}"));
        let adapter = StructuredClassificationAdapter::new(Arc::new(classifier));
        let request = request(b"a@b");
        let result = adapter
            .classify(&request)
            .unwrap_or_else(|error| panic!("classification: {error}"));
        assert_eq!(result.request_id, request.request_id);
        assert_eq!(result.payload_digest, request.payload_digest);
        assert_eq!(result.classifier_id.as_str(), "classifier.local");
        assert_eq!(result.classifier_version.as_str(), "1");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings.as_slice()[0].category.as_str(), "pii.email");
        assert_eq!(
            result.findings.as_slice()[0].byte_range,
            Some(chio_security_types::ports::ByteRange { start: 1, end: 2 })
        );
    }

    #[test]
    fn declared_request_digest_mismatch_fails_before_classification() {
        let classifier = RegexStructuredClassifier::new("classifier.local", "1", vec![])
            .unwrap_or_else(|error| panic!("classifier: {error}"));
        let adapter = StructuredClassificationAdapter::new(Arc::new(classifier));
        let mut request = request(b"payload");
        request.payload_digest = Digest32::new([9; 32]);
        let error = require_error(adapter.classify(&request));
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }

    struct WrongRepresentation;

    impl StructuredClassifier for WrongRepresentation {
        fn classify(
            &self,
            _: &[u8],
        ) -> Result<StructuredClassificationResult, StructuredClassificationError> {
            StructuredClassificationResult::from_payload(
                ClassifierIdentity::new("classifier.external", "1")?,
                b"other",
                vec![],
            )
        }
    }

    #[test]
    fn classifier_result_for_another_representation_fails_closed() {
        let adapter = StructuredClassificationAdapter::new(Arc::new(WrongRepresentation));
        let error = require_error(adapter.classify(&request(b"payload")));
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }

    #[test]
    fn declassification_transition_ids_bind_tenant_and_replay_exactly() {
        let tenant_a =
            TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant a: {error}"));
        let tenant_b =
            TenantId::new("tenant-b").unwrap_or_else(|error| panic!("tenant b: {error}"));
        let grant = GrantId::new("shared-grant").unwrap_or_else(|error| panic!("grant: {error}"));
        let request_hash = Digest32::new([17_u8; 32]);
        let request_id =
            RequestId::new("shared-request").unwrap_or_else(|error| panic!("request id: {error}"));
        let dispatch_id =
            RecordId::new("shared-dispatch").unwrap_or_else(|error| panic!("dispatch id: {error}"));
        let first_binding = DeclassificationTransitionBinding::Consumption {
            tenant_id: tenant_a.clone(),
            grant_id: grant.clone(),
            request_hash,
            request_id: request_id.clone(),
        };
        let first = derive_declassification_transition_id(&first_binding)
            .unwrap_or_else(|error| panic!("first transition: {error}"));
        let replay = derive_declassification_transition_id(&first_binding)
            .unwrap_or_else(|error| panic!("replay transition: {error}"));
        let other_tenant = derive_declassification_transition_id(
            &DeclassificationTransitionBinding::Consumption {
                tenant_id: tenant_b.clone(),
                grant_id: grant.clone(),
                request_hash,
                request_id: request_id.clone(),
            },
        )
        .unwrap_or_else(|error| panic!("other tenant transition: {error}"));
        assert_eq!(first, replay);
        assert_ne!(first, other_tenant);
        let outcome_a =
            derive_declassification_transition_id(&DeclassificationTransitionBinding::Released {
                tenant_id: tenant_a,
                grant_id: grant.clone(),
                request_hash,
                request_id: request_id.clone(),
                dispatch_commitment_id: dispatch_id.clone(),
            })
            .unwrap_or_else(|error| panic!("tenant a outcome transition: {error}"));
        let outcome_b =
            derive_declassification_transition_id(&DeclassificationTransitionBinding::Released {
                tenant_id: tenant_b,
                grant_id: grant,
                request_hash,
                request_id,
                dispatch_commitment_id: dispatch_id,
            })
            .unwrap_or_else(|error| panic!("tenant b outcome transition: {error}"));
        assert_ne!(outcome_a, outcome_b);
    }

    struct FixedClock(u64);

    impl SecurityClock for FixedClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            Ok(self.0)
        }
    }

    struct AdvancingClock {
        calls: AtomicUsize,
        first_unix_ms: u64,
    }

    impl AdvancingClock {
        fn new(first_unix_ms: u64) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                first_unix_ms,
            }
        }
    }

    impl SecurityClock for AdvancingClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            let elapsed = u64::try_from(self.calls.fetch_add(1, Ordering::SeqCst))
                .map_err(|_| PortError::unavailable())?;
            self.first_unix_ms
                .checked_add(elapsed)
                .ok_or_else(PortError::unavailable)
        }
    }

    struct CountingEmptyClassifier {
        calls: AtomicUsize,
    }

    impl CountingEmptyClassifier {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl ClassificationPort for CountingEmptyClassifier {
        fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ClassificationResult {
                tenant_id: request.tenant_id.clone(),
                request_id: request.request_id.clone(),
                payload_digest: request.payload_digest,
                classifier_id: ClassifierId::new("classifier.empty").map_err(PortError::from)?,
                classifier_version: ClassifierVersion::new("1").map_err(PortError::from)?,
                findings: chio_security_types::ports::BoundedVec::new(Vec::new())
                    .map_err(|_| PortError::invalid_data())?,
            })
        }
    }

    struct FakeFlowStore {
        snapshot: Mutex<FlowStateSnapshot>,
        acquired: AtomicUsize,
        committed: AtomicUsize,
        fail_join: bool,
    }

    impl FakeFlowStore {
        fn new(snapshot: FlowStateSnapshot) -> Self {
            Self {
                snapshot: Mutex::new(snapshot),
                acquired: AtomicUsize::new(0),
                committed: AtomicUsize::new(0),
                fail_join: false,
            }
        }

        fn with_join_failure(snapshot: FlowStateSnapshot) -> Self {
            Self {
                snapshot: Mutex::new(snapshot),
                acquired: AtomicUsize::new(0),
                committed: AtomicUsize::new(0),
                fail_join: true,
            }
        }
    }

    impl FlowStateStore for FakeFlowStore {
        fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
            let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
            Ok((snapshot.key == *key).then(|| snapshot.clone()))
        }

        fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
            if self.fail_join {
                return Err(PortError::unavailable());
            }
            let mut snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
            if snapshot.key != request.key {
                return Err(PortError::invalid_data());
            }
            snapshot.principal_label = snapshot
                .principal_label
                .join_restrictions(&request.principal_join)
                .map_err(|_| PortError::invalid_data())?;
            snapshot.lineage_label = snapshot
                .lineage_label
                .join_restrictions(&request.lineage_join)
                .map_err(|_| PortError::invalid_data())?;
            snapshot.session_label = snapshot
                .session_label
                .join_restrictions(&request.session_join)
                .map_err(|_| PortError::invalid_data())?;
            snapshot.context_generation = snapshot
                .context_generation
                .checked_add(1)
                .ok_or_else(PortError::invalid_data)?;
            Ok(snapshot.clone())
        }

        fn open_isolation_epoch(
            &self,
            _: &IsolationEpochTransition,
        ) -> PortResult<FlowStateSnapshot> {
            Err(PortError::invalid_data())
        }

        fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence> {
            let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
            if snapshot.key != request.key
                || snapshot.context_generation != request.expected_context_generation
            {
                return Err(PortError::conflict());
            }
            self.acquired.fetch_add(1, Ordering::SeqCst);
            Ok(EgressFence {
                fence_id: RecordId::new("fence-a").map_err(PortError::from)?,
                key: request.key.clone(),
                request_id: request.request_id.clone(),
                request_hash: request.request_hash,
                context_generation: request.expected_context_generation,
                expires_at_unix_ms: request.expires_at_unix_ms,
            })
        }

        fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()> {
            let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
            if snapshot.key == fence.key && snapshot.context_generation == fence.context_generation
            {
                Ok(())
            } else {
                Err(PortError::conflict())
            }
        }

        fn commit_egress_fence(
            &self,
            commitment: &EgressFenceCommit,
        ) -> PortResult<CommittedEgressFence> {
            self.validate_egress_fence(&commitment.fence)?;
            self.committed.fetch_add(1, Ordering::SeqCst);
            Ok(CommittedEgressFence {
                fence_id: commitment.fence.fence_id.clone(),
                request_id: commitment.fence.request_id.clone(),
                request_hash: commitment.fence.request_hash,
                context_generation: commitment.fence.context_generation,
                dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
                committed_at_unix_ms: commitment.committed_at_unix_ms,
            })
        }
    }

    #[derive(Default)]
    struct RecordingSecurityReceipts {
        bodies: Mutex<Vec<chio_core::receipt::security::ActiveDefenseReceiptBody>>,
        records: Mutex<BTreeMap<OpaqueReceiptRef, ExactReceiptRecord>>,
    }

    #[derive(Default)]
    struct ToggleSecurityReceipts {
        inner: RecordingSecurityReceipts,
        rejecting: AtomicBool,
    }

    struct RejectingSecurityReceipts;

    impl RecordingSecurityReceipts {
        fn bodies(&self) -> Vec<chio_core::receipt::security::ActiveDefenseReceiptBody> {
            self.bodies
                .lock()
                .unwrap_or_else(|_| panic!("security receipt lock"))
                .clone()
        }
    }

    impl SecurityReceiptSink for RecordingSecurityReceipts {
        fn ensure_receipts_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
            let body = serde_json::from_slice(request.canonical_body.as_bytes())
                .map_err(|_| PortError::invalid_data())?;
            let canonical =
                chio_core::canonical_json_bytes(request).map_err(|_| PortError::invalid_data())?;
            let exact = ExactReceiptRecord {
                receipt: request.clone(),
                durable_record_hash: Digest32::new(*chio_core::sha256(&canonical).as_bytes()),
            };
            let mut records = self.records.lock().map_err(|_| PortError::unavailable())?;
            if let Some(existing) = records.get(&request.evidence_id) {
                return if existing == &exact {
                    Ok(request.evidence_id.clone())
                } else {
                    Err(PortError::conflict())
                };
            }
            records.insert(request.evidence_id.clone(), exact);
            self.bodies
                .lock()
                .map_err(|_| PortError::unavailable())?
                .push(body);
            Ok(request.evidence_id.clone())
        }
    }

    impl ExactSecurityReceiptSink for RecordingSecurityReceipts {
        fn load_exact(
            &self,
            evidence_id: &OpaqueReceiptRef,
        ) -> PortResult<Option<ExactReceiptRecord>> {
            Ok(self
                .records
                .lock()
                .map_err(|_| PortError::unavailable())?
                .get(evidence_id)
                .cloned())
        }
    }

    impl SecurityReceiptSink for ToggleSecurityReceipts {
        fn ensure_receipts_ready(&self) -> PortResult<()> {
            self.inner.ensure_receipts_ready()
        }

        fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
            if self.rejecting.load(Ordering::Acquire) {
                Err(PortError::unavailable())
            } else {
                self.inner.sign_and_append(request)
            }
        }
    }

    impl ExactSecurityReceiptSink for ToggleSecurityReceipts {
        fn load_exact(
            &self,
            evidence_id: &OpaqueReceiptRef,
        ) -> PortResult<Option<ExactReceiptRecord>> {
            if self.rejecting.load(Ordering::Acquire) {
                Err(PortError::unavailable())
            } else {
                self.inner.load_exact(evidence_id)
            }
        }
    }

    impl SecurityReceiptSink for RejectingSecurityReceipts {
        fn ensure_receipts_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn sign_and_append(&self, _: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
            Err(PortError::unavailable())
        }
    }

    impl ExactSecurityReceiptSink for RejectingSecurityReceipts {
        fn load_exact(&self, _: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>> {
            Err(PortError::unavailable())
        }
    }

    fn flow_key() -> FlowStateKey {
        FlowStateKey {
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            principal_id: PrincipalId::new("principal-a")
                .unwrap_or_else(|error| panic!("principal: {error}")),
            lineage_id: LineageId::new("lineage-a")
                .unwrap_or_else(|error| panic!("lineage: {error}")),
            session_id: SessionId::new("session-a")
                .unwrap_or_else(|error| panic!("session: {error}")),
            isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("epoch-a")
                .unwrap_or_else(|error| panic!("epoch: {error}")),
        }
    }

    fn flow_snapshot(generation: u64) -> FlowStateSnapshot {
        FlowStateSnapshot {
            key: flow_key(),
            principal_label: InformationLabel::bottom(),
            lineage_label: InformationLabel::bottom(),
            session_label: InformationLabel::bottom(),
            context_generation: generation,
        }
    }

    fn flow_registry() -> Arc<VerifiedManifestRegistry> {
        let signer = Keypair::from_seed(&[73; 32]);
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "server-a".to_string(),
            name: "Flow server".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "send".to_string(),
                description: "Send".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "object"})),
                pricing: None,
                annotations: ToolAnnotations {
                    read_only: false,
                    destructive: false,
                    idempotent: true,
                    requires_approval: false,
                    estimated_duration_ms: None,
                },
                latency_hint: None,
                flow: Some(ToolFlowDeclaration::public_egress()),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = sign_manifest(&manifest, &signer)
            .unwrap_or_else(|error| panic!("sign manifest: {error}"));
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
            .unwrap_or_else(|error| panic!("register manifest: {error}"));
        Arc::new(registry)
    }

    fn server_tool_flow_registry() -> Arc<VerifiedManifestRegistry> {
        let signer = Keypair::from_seed(&[72; 32]);
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "server-a".to_string(),
            name: "Anthropic flow server".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "send".to_string(),
                description: "Regular control tool".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "object"})),
                pricing: None,
                annotations: ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: true,
                    requires_approval: false,
                    estimated_duration_ms: None,
                },
                latency_hint: None,
                flow: None,
            }],
            server_tools: vec![ServerTool::Bash],
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = sign_manifest(&manifest, &signer)
            .unwrap_or_else(|error| panic!("sign server-tool manifest: {error}"));
        let server_tool_policy = AuthoritativeToolPolicy::new(
            vec![InformationLabel::bottom()],
            restricted_label(),
            BTreeSet::new(),
        )
        .unwrap_or_else(|error| panic!("server-tool policy: {error}"));
        let policies = BTreeMap::from([
            ("send".to_string(), AuthoritativeToolPolicy::public_only()),
            (ServerTool::Bash.as_str().to_string(), server_tool_policy),
        ]);
        let topologies = BTreeMap::from([
            ("send".to_string(), RuntimeToolTopology::local()),
            (
                ServerTool::Bash.as_str().to_string(),
                RuntimeToolTopology::remote(),
            ),
        ]);
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register(signed, &signer.public_key(), &policies, &topologies)
            .unwrap_or_else(|error| panic!("register server-tool manifest: {error}"));
        Arc::new(registry)
    }

    fn restricted_label() -> InformationLabel {
        InformationLabel::try_known(
            BTreeMap::new(),
            BTreeSet::from([Compartment::new("restricted")
                .unwrap_or_else(|error| panic!("compartment: {error}"))]),
        )
        .unwrap_or_else(|error| panic!("label: {error}"))
    }

    fn declassification_registry(
        purpose: &DeclassificationPurpose,
    ) -> Arc<VerifiedManifestRegistry> {
        let signer = Keypair::from_seed(&[73; 32]);
        let flow = ToolFlowDeclaration::new(
            None,
            Some(InformationLabel::bottom()),
            true,
            BTreeSet::from([purpose.clone()]),
        )
        .unwrap_or_else(|error| panic!("flow: {error}"));
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "server-a".to_string(),
            name: "Flow server".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "send".to_string(),
                description: "Send".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "object"})),
                pricing: None,
                annotations: ToolAnnotations {
                    read_only: false,
                    destructive: false,
                    idempotent: true,
                    requires_approval: false,
                    estimated_duration_ms: None,
                },
                latency_hint: None,
                flow: Some(flow),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = sign_manifest(&manifest, &signer)
            .unwrap_or_else(|error| panic!("sign manifest: {error}"));
        let policy = AuthoritativeToolPolicy::new(
            vec![InformationLabel::bottom()],
            InformationLabel::bottom(),
            BTreeSet::from([purpose.clone()]),
        )
        .unwrap_or_else(|error| panic!("policy: {error}"));
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register(
                signed,
                &signer.public_key(),
                &BTreeMap::from([("send".to_string(), policy)]),
                &BTreeMap::from([("send".to_string(), RuntimeToolTopology::remote())]),
            )
            .unwrap_or_else(|error| panic!("register manifest: {error}"));
        Arc::new(registry)
    }

    fn flow_request() -> ToolCallRequest {
        let keypair = Keypair::from_seed(&[74; 32]);
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "capability-a".to_string(),
                issuer: keypair.public_key(),
                subject: keypair.public_key(),
                scope: ChioScope::default(),
                issued_at: 1,
                expires_at: u64::MAX,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &keypair,
        )
        .unwrap_or_else(|error| panic!("capability: {error}"));
        ToolCallRequest {
            request_id: "request-a".to_string(),
            capability,
            tool_name: "send".to_string(),
            server_id: "server-a".to_string(),
            agent_id: "agent-a".to_string(),
            arguments: serde_json::json!({"safe": true}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        }
    }

    fn server_tool_flow_request() -> ToolCallRequest {
        let mut request = flow_request();
        request.tool_name = "bash_20241022".to_string();
        request
    }

    fn declassifying_flow_request(
        authority: &Keypair,
        purpose: &DeclassificationPurpose,
    ) -> ToolCallRequest {
        let mut request = flow_request();
        let canonical = CanonicalBody::new(
            chio_core::canonical_json_bytes(&request.arguments)
                .unwrap_or_else(|error| panic!("canonical request: {error}")),
        )
        .unwrap_or_else(|error| panic!("canonical body: {error}"));
        let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            capability_id: RecordId::new("capability-a")
                .unwrap_or_else(|error| panic!("capability: {error}")),
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            subject_id: PrincipalId::new("principal-a")
                .unwrap_or_else(|error| panic!("subject: {error}")),
            agent_id: RecordId::new("agent-a").unwrap_or_else(|error| panic!("agent: {error}")),
            session_id: SessionId::new("session-a")
                .unwrap_or_else(|error| panic!("session: {error}")),
            source_label_hash: information_label_hash(&restricted_label())
                .unwrap_or_else(|error| panic!("source label hash: {error}")),
            target_label: InformationLabel::bottom(),
            destination_id: DestinationId::new("server-a")
                .unwrap_or_else(|error| panic!("destination: {error}")),
            tool_name: RecordId::new("send").unwrap_or_else(|error| panic!("tool: {error}")),
            purpose: purpose.clone(),
            request_hash: canonical_request_hash(&canonical)
                .unwrap_or_else(|error| panic!("request hash: {error}")),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            authority_key_id: RecordId::new("authority-a")
                .unwrap_or_else(|error| panic!("authority: {error}")),
        })
        .unwrap_or_else(|error| panic!("grant body: {error}"));
        request.declassification_grant = Some(
            SignedDeclassificationGrant::sign(body, authority)
                .unwrap_or_else(|error| panic!("sign grant: {error}")),
        );
        request
    }

    fn flow_config() -> FlowResolverConfig {
        FlowResolverConfig::new(
            InformationLabel::bottom(),
            CategoryLabelMap::new(
                ClassifierId::new("classifier.empty")
                    .unwrap_or_else(|error| panic!("classifier: {error}")),
                ClassifierVersion::new("1")
                    .unwrap_or_else(|error| panic!("classifier version: {error}")),
                BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("category map: {error}")),
            BTreeMap::new(),
            10_000,
        )
        .unwrap_or_else(|error| panic!("flow config: {error}"))
    }

    fn declassifying_evidence_flow_config(
        authority: &Keypair,
        declassification_store: Arc<dyn DeclassificationEvidenceCommitStore>,
        receipt_sink: Arc<dyn ExactSecurityReceiptSink>,
    ) -> FlowResolverConfig {
        FlowResolverConfig::new(
            restricted_label(),
            CategoryLabelMap::new(
                ClassifierId::new("classifier.empty")
                    .unwrap_or_else(|error| panic!("classifier: {error}")),
                ClassifierVersion::new("1")
                    .unwrap_or_else(|error| panic!("classifier version: {error}")),
                BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("category map: {error}")),
            BTreeMap::from([(
                RecordId::new("authority-a").unwrap_or_else(|error| panic!("authority: {error}")),
                authority.public_key(),
            )]),
            10_000,
        )
        .unwrap_or_else(|error| panic!("flow config: {error}"))
        .with_declassification_evidence(declassification_store, receipt_sink, receipt_policy())
        .unwrap_or_else(|error| panic!("declassification evidence config: {error}"))
    }

    fn receipt_policy() -> chio_core::receipt::security::ActiveDefensePolicyBinding {
        chio_core::receipt::security::ActiveDefensePolicyBinding {
            policy_version: RecordId::new("flow-policy-v1")
                .unwrap_or_else(|error| panic!("policy version: {error}")),
            policy_hash: Digest32::new([91; 32]),
        }
    }

    #[test]
    fn production_flow_denial_path_emits_closed_native_receipt_from_resolved_runtime_facts() {
        let receipts = Arc::new(RecordingSecurityReceipts::default());
        let config = FlowResolverConfig::new(
            restricted_label(),
            CategoryLabelMap::new(
                ClassifierId::new("classifier.empty")
                    .unwrap_or_else(|error| panic!("classifier: {error}")),
                ClassifierVersion::new("1")
                    .unwrap_or_else(|error| panic!("classifier version: {error}")),
                BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("category map: {error}")),
            BTreeMap::new(),
            10_000,
        )
        .unwrap_or_else(|error| panic!("flow config: {error}"))
        .with_receipt_evidence(
            receipts.clone() as Arc<dyn SecurityReceiptSink>,
            receipt_policy(),
        );
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(FixedClock(150_000)),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = flow_request();

        assert_eq!(
            FlowPreInvocationPort::evaluate(
                &resolver,
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
            ),
            Err(chio_flow::FlowDenial::PolicyFlowViolation)
        );
        let bodies = receipts.bodies();
        assert_eq!(bodies.len(), 1);
        let chio_core::receipt::security::ActiveDefenseReceiptBody::FlowDenial(body) = &bodies[0]
        else {
            panic!("flow denial must emit a flow-denial body");
        };
        assert_eq!(body.header.tenant_id.as_str(), "tenant-a");
        assert_eq!(body.request_hash.as_bytes().len(), 32);
        assert_eq!(body.denial_code.as_str(), "flow.policy_flow_violation");
    }

    #[test]
    fn production_flow_denial_path_surfaces_receipt_persistence_failure() {
        let config = FlowResolverConfig::new(
            restricted_label(),
            CategoryLabelMap::new(
                ClassifierId::new("classifier.empty")
                    .unwrap_or_else(|error| panic!("classifier: {error}")),
                ClassifierVersion::new("1")
                    .unwrap_or_else(|error| panic!("classifier version: {error}")),
                BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("category map: {error}")),
            BTreeMap::new(),
            10_000,
        )
        .unwrap_or_else(|error| panic!("flow config: {error}"))
        .with_receipt_evidence(Arc::new(RejectingSecurityReceipts), receipt_policy());
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(FixedClock(150_000)),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = flow_request();

        assert_eq!(
            FlowPreInvocationPort::evaluate(
                &resolver,
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
            ),
            Err(chio_flow::FlowDenial::DeclassificationStoreFailure)
        );
    }

    #[test]
    fn production_declassification_path_attests_consumption_and_exact_dispatch_outcome() {
        let authority = Keypair::from_seed(&[75; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let declassification_store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("declassification.sqlite"))
                .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
        );
        let receipts = Arc::new(RecordingSecurityReceipts::default());
        let config = declassifying_evidence_flow_config(
            &authority,
            declassification_store as Arc<dyn DeclassificationEvidenceCommitStore>,
            receipts.clone() as Arc<dyn ExactSecurityReceiptSink>,
        );
        let resolver = PersistentFlowResolver::new(
            declassification_registry(&purpose),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(FixedClock(150_000)),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = declassifying_flow_request(&authority, &purpose);
        let mut outcome = resolver
            .commit_dispatch(
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
                RecordId::new("dispatch-receipt-test")
                    .unwrap_or_else(|error| panic!("dispatch: {error}")),
            )
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
            .unwrap_or_else(|| panic!("declassification outcome recorder"));
        outcome
            .record(DeclassificationDispatchOutcome::Released)
            .unwrap_or_else(|error| panic!("record released outcome: {error}"));

        let bodies = receipts.bodies();
        assert_eq!(bodies.len(), 2);
        let chio_core::receipt::security::ActiveDefenseReceiptBody::DeclassificationConsumption(
            consumed,
        ) = &bodies[0]
        else {
            panic!("first declassification receipt must attest consumption");
        };
        let chio_core::receipt::security::ActiveDefenseReceiptBody::DeclassificationOutcome(
            released,
        ) = &bodies[1]
        else {
            panic!("second declassification receipt must attest outcome");
        };
        assert_eq!(consumed.grant_id, released.grant_id);
        assert_eq!(consumed.grant_hash, released.grant_hash);
        assert_eq!(consumed.request_hash, released.request_hash);
        assert_eq!(
            released.header.prior_receipt_ids.as_slice(),
            [bodies[0]
                .evidence_id()
                .unwrap_or_else(|error| panic!("consumption evidence id: {error}"))]
        );
        assert_eq!(released.to_state, DeclassificationUseState::Released);
    }

    #[test]
    fn production_declassification_path_attests_live_unknown_dispatch_outcome() {
        let authority = Keypair::from_seed(&[80; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("unknown-dispatch.sqlite"))
                .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
        );
        let receipts = Arc::new(RecordingSecurityReceipts::default());
        let config = declassifying_evidence_flow_config(
            &authority,
            store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
            receipts.clone() as Arc<dyn ExactSecurityReceiptSink>,
        );
        let resolver = PersistentFlowResolver::new(
            declassification_registry(&purpose),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(FixedClock(150_000)),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = declassifying_flow_request(&authority, &purpose);
        let mut outcome = resolver
            .commit_dispatch(
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
                RecordId::new("unknown-dispatch-receipt-test")
                    .unwrap_or_else(|error| panic!("dispatch: {error}")),
            )
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
            .unwrap_or_else(|| panic!("declassification outcome recorder"));
        outcome
            .record(DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch)
            .unwrap_or_else(|error| panic!("record unknown dispatch outcome: {error}"));

        let bodies = receipts.bodies();
        assert_eq!(bodies.len(), 2);
        bodies[1]
            .validate()
            .unwrap_or_else(|error| panic!("validate unknown-outcome receipt: {error:?}"));
        let chio_core::receipt::security::ActiveDefenseReceiptBody::DeclassificationOutcome(
            unknown,
        ) = &bodies[1]
        else {
            panic!("second declassification receipt must attest unknown outcome");
        };
        assert_eq!(unknown.to_state, DeclassificationUseState::OutcomeUnknown);
        assert_eq!(
            unknown.header.prior_receipt_ids.as_slice(),
            [bodies[0]
                .evidence_id()
                .unwrap_or_else(|error| panic!("consumption evidence id: {error}"))]
        );

        let use_record = store
            .load_declassification_use(&DeclassificationUseQuery {
                tenant_id: TenantId::new("tenant-a")
                    .unwrap_or_else(|error| panic!("tenant: {error}")),
                grant_id: GrantId::new("grant-a")
                    .unwrap_or_else(|error| panic!("grant: {error}")),
            })
            .unwrap_or_else(|error| panic!("load unknown use: {error:?}"))
            .unwrap_or_else(|| panic!("unknown use missing"));
        assert_eq!(use_record.state, DeclassificationUseState::OutcomeUnknown);
        let evidence = store
            .load_declassification_evidence(&DeclassificationEvidenceQuery {
                tenant_id: use_record.tenant_id,
                grant_id: use_record.grant_id,
                phase: DeclassificationEvidencePhase::Outcome,
            })
            .unwrap_or_else(|error| panic!("load unknown outcome evidence: {error:?}"))
            .unwrap_or_else(|| panic!("unknown outcome evidence missing"));
        assert!(matches!(
            evidence.transition_binding,
            DeclassificationTransitionBinding::OutcomeUnknownAfterDispatch { .. }
        ));
    }

    #[test]
    fn consumption_sink_failure_durably_terminalizes_at_failure_time() {
        let authority = Keypair::from_seed(&[76; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("sink-failure.sqlite"))
                .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
        );
        let config = declassifying_evidence_flow_config(
            &authority,
            store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
            Arc::new(RejectingSecurityReceipts) as Arc<dyn ExactSecurityReceiptSink>,
        );
        let clock = Arc::new(AdvancingClock::new(150_000));
        let resolver = PersistentFlowResolver::new(
            declassification_registry(&purpose),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            clock.clone(),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = declassifying_flow_request(&authority, &purpose);

        assert!(matches!(
            resolver.commit_dispatch(
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
                RecordId::new("sink-failure-dispatch")
                    .unwrap_or_else(|error| panic!("dispatch: {error}")),
            ),
            Err(chio_flow::FlowDenial::DeclassificationStoreFailure)
        ));
        let use_record = store
            .load_declassification_use(&DeclassificationUseQuery {
                tenant_id: TenantId::new("tenant-a")
                    .unwrap_or_else(|error| panic!("tenant: {error}")),
                grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            })
            .unwrap_or_else(|error| panic!("load terminal use: {error:?}"))
            .unwrap_or_else(|| panic!("terminal use missing"));
        assert_eq!(use_record.state, DeclassificationUseState::DispatchFailed);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn pre_dispatch_state_failure_durably_terminalizes_at_failure_time() {
        let authority = Keypair::from_seed(&[77; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("state-failure.sqlite"))
                .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
        );
        let receipts = Arc::new(RecordingSecurityReceipts::default());
        let config = declassifying_evidence_flow_config(
            &authority,
            store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
            receipts as Arc<dyn ExactSecurityReceiptSink>,
        );
        let clock = Arc::new(AdvancingClock::new(150_000));
        let resolver = PersistentFlowResolver::new(
            declassification_registry(&purpose),
            Arc::new(FakeFlowStore::with_join_failure(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            clock.clone(),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = declassifying_flow_request(&authority, &purpose);

        assert!(matches!(
            resolver.commit_dispatch(
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
                RecordId::new("state-failure-dispatch")
                    .unwrap_or_else(|error| panic!("dispatch: {error}")),
            ),
            Err(chio_flow::FlowDenial::StateChanged)
        ));
        let use_record = store
            .load_declassification_use(&DeclassificationUseQuery {
                tenant_id: TenantId::new("tenant-a")
                    .unwrap_or_else(|error| panic!("tenant: {error}")),
                grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            })
            .unwrap_or_else(|error| panic!("load terminal use: {error:?}"))
            .unwrap_or_else(|| panic!("terminal use missing"));
        assert_eq!(use_record.state, DeclassificationUseState::DispatchFailed);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn outcome_sink_failure_leaves_a_durable_terminal_outcome() {
        let authority = Keypair::from_seed(&[78; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("outcome-sink-failure.sqlite"))
                .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
        );
        let receipts = Arc::new(ToggleSecurityReceipts::default());
        let config = declassifying_evidence_flow_config(
            &authority,
            store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
            receipts.clone() as Arc<dyn ExactSecurityReceiptSink>,
        );
        let clock = Arc::new(AdvancingClock::new(150_000));
        let resolver = PersistentFlowResolver::new(
            declassification_registry(&purpose),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            clock.clone(),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = declassifying_flow_request(&authority, &purpose);
        let mut recorder = resolver
            .commit_dispatch(
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
                RecordId::new("outcome-sink-failure-dispatch")
                    .unwrap_or_else(|error| panic!("dispatch: {error}")),
            )
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
            .unwrap_or_else(|| panic!("outcome recorder missing"));
        receipts.rejecting.store(true, Ordering::Release);

        assert!(matches!(
            recorder.record(DeclassificationDispatchOutcome::Released),
            Err(chio_flow::FlowDenial::DeclassificationStoreFailure)
        ));
        let use_record = store
            .load_declassification_use(&DeclassificationUseQuery {
                tenant_id: TenantId::new("tenant-a")
                    .unwrap_or_else(|error| panic!("tenant: {error}")),
                grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            })
            .unwrap_or_else(|error| panic!("load terminal use: {error:?}"))
            .unwrap_or_else(|| panic!("terminal use missing"));
        assert_eq!(use_record.state, DeclassificationUseState::Released);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn outcome_store_failure_leaves_reconciliation_required() {
        let authority = Keypair::from_seed(&[79; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("outcome-store-failure.sqlite");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
        );
        let receipts = Arc::new(RecordingSecurityReceipts::default());
        let config = declassifying_evidence_flow_config(
            &authority,
            store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
            receipts as Arc<dyn ExactSecurityReceiptSink>,
        );
        let clock = Arc::new(AdvancingClock::new(150_000));
        let resolver = PersistentFlowResolver::new(
            declassification_registry(&purpose),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            clock.clone(),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = declassifying_flow_request(&authority, &purpose);
        let mut recorder = resolver
            .commit_dispatch(
                &FlowPreInvocationInput {
                    security_context: &context,
                    request: &request,
                },
                RecordId::new("outcome-store-failure-dispatch")
                    .unwrap_or_else(|error| panic!("dispatch: {error}")),
            )
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
            .unwrap_or_else(|| panic!("outcome recorder missing"));
        Connection::open(&path)
            .and_then(|connection| {
                connection.execute_batch(
                    r#"
                    CREATE TRIGGER test_reject_declassification_terminalization
                    BEFORE UPDATE OF state ON security_declassification_uses
                    WHEN OLD.state = 'consumed_pending_dispatch'
                    BEGIN
                        SELECT RAISE(ABORT, 'test terminalization failure');
                    END;
                    "#,
                )
            })
            .unwrap_or_else(|error| panic!("install terminalization failure: {error}"));

        assert!(matches!(
            recorder.record(DeclassificationDispatchOutcome::Released),
            Err(chio_flow::FlowDenial::DeclassificationStoreFailure)
        ));
        let use_record = store
            .load_declassification_use(&DeclassificationUseQuery {
                tenant_id: TenantId::new("tenant-a")
                    .unwrap_or_else(|error| panic!("tenant: {error}")),
                grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            })
            .unwrap_or_else(|error| panic!("load stranded use: {error:?}"))
            .unwrap_or_else(|| panic!("stranded use missing"));
        assert_eq!(
            use_record.state,
            DeclassificationUseState::ConsumedPendingDispatch
        );
        assert_eq!(clock.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn persistent_flow_resolver_binds_verified_manifest_state_and_final_bytes() {
        let store = Arc::new(FakeFlowStore::new(flow_snapshot(7)));
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            store.clone(),
            classifier.clone(),
            Arc::new(FixedClock(150_000)),
            flow_config(),
        );
        let key = flow_key();
        let security_context = SecurityInvocationContextV1::new(
            key.tenant_id.clone(),
            key.session_id.clone(),
            key.principal_id.clone(),
            key.isolation_epoch_id.clone(),
            key.lineage_id.clone(),
            7,
        )
        .with_flow_state_generation(7);
        let request = flow_request();
        let pre = FlowPreInvocationInput {
            security_context: &security_context,
            request: &request,
        };
        let admission = evaluate_pre_invocation(
            FlowPreInvocationResolver::resolve(&resolver, &pre)
                .unwrap_or_else(|error| panic!("resolve pre: {error}")),
        )
        .unwrap_or_else(|error| panic!("evaluate pre: {error}"));
        FlowPreInvocationResolver::persist(&resolver, &admission)
            .unwrap_or_else(|error| panic!("persist pre: {error}"));
        resolver
            .commit_dispatch(
                &pre,
                RecordId::new("dispatch-a").unwrap_or_else(|error| panic!("dispatch: {error}")),
            )
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"));

        let response = serde_json::json!({"delivered": true});
        let post = FlowPostInvocationInput {
            security_context: &security_context,
            request: &request,
            response: &response,
        };
        let transition = evaluate_post_invocation(
            FlowPostInvocationResolver::resolve(&resolver, &post)
                .unwrap_or_else(|error| panic!("resolve post: {error}")),
        )
        .unwrap_or_else(|error| panic!("evaluate post: {error}"));
        FlowPostInvocationResolver::persist(&resolver, &transition)
            .unwrap_or_else(|error| panic!("persist post: {error}"));

        assert_eq!(classifier.calls.load(Ordering::SeqCst), 3);
        assert_eq!(store.acquired.load(Ordering::SeqCst), 1);
        assert_eq!(store.committed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn persistent_flow_resolver_accepts_exact_server_tool_in_pre_and_post_stages() {
        let registry = server_tool_flow_registry();
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = PersistentFlowResolver::new(
            registry.clone(),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            classifier.clone(),
            Arc::new(FixedClock(150_000)),
            flow_config(),
        );
        let key = flow_key();
        let security_context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = server_tool_flow_request();
        let pre = FlowPreInvocationResolver::resolve(
            &resolver,
            &FlowPreInvocationInput {
                security_context: &security_context,
                request: &request,
            },
        )
        .unwrap_or_else(|error| panic!("resolve server-tool pre flow: {error}"));
        assert!(pre.runtime_egress);
        assert_eq!(
            pre.policy_clearances.as_slice(),
            &[InformationLabel::bottom()]
        );
        assert!(!pre.manifest.egress);

        let response = serde_json::json!({"status": "complete"});
        let post = FlowPostInvocationResolver::resolve(
            &resolver,
            &FlowPostInvocationInput {
                security_context: &security_context,
                request: &request,
                response: &response,
            },
        )
        .unwrap_or_else(|error| panic!("resolve server-tool post flow: {error}"));
        assert_eq!(post.operator_output_floor, restricted_label());
        assert!(!post.manifest.egress);
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 2);

        let exact_sidecar = registry
            .bridge_security_for_server_tool("server-a", "bash_20241022")
            .unwrap_or_else(|| panic!("server-tool sidecar must be admitted"));
        assert_eq!(exact_sidecar.server_id(), Some("server-a"));
        assert_eq!(exact_sidecar.tool_name(), Some("bash"));
        assert!(exact_sidecar.effective_egress());
        registry
            .validate_bridge_security("server-a", "bash_20241022", &exact_sidecar)
            .unwrap_or_else(|error| panic!("exact server-tool sidecar must validate: {error}"));

        let mut forged_value = serde_json::to_value(exact_sidecar)
            .unwrap_or_else(|error| panic!("serialize server-tool sidecar: {error}"));
        forged_value["manifest_digest"] = serde_json::json!("forged-manifest-digest");
        let forged = serde_json::from_value(forged_value)
            .unwrap_or_else(|error| panic!("deserialize forged server-tool sidecar: {error}"));
        assert!(registry
            .validate_bridge_security("server-a", "bash_20241022", &forged)
            .is_err());
    }

    #[test]
    fn persistent_flow_resolver_rejects_server_tool_coordinate_mismatches_pre_and_post() {
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = PersistentFlowResolver::new(
            server_tool_flow_registry(),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            classifier.clone(),
            Arc::new(FixedClock(150_000)),
            flow_config(),
        );
        let key = flow_key();
        let security_context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let response = serde_json::json!({"status": "complete"});

        for (server_id, tool_name) in [
            ("server-a", "text_editor_20241022"),
            ("server-b", "bash_20241022"),
        ] {
            let mut request = server_tool_flow_request();
            request.server_id = server_id.to_string();
            request.tool_name = tool_name.to_string();
            assert!(matches!(
                FlowPreInvocationResolver::resolve(
                    &resolver,
                    &FlowPreInvocationInput {
                        security_context: &security_context,
                        request: &request,
                    },
                ),
                Err(chio_flow::FlowDenial::InvalidManifest)
            ));
            assert!(matches!(
                FlowPostInvocationResolver::resolve(
                    &resolver,
                    &FlowPostInvocationInput {
                        security_context: &security_context,
                        request: &request,
                        response: &response,
                    },
                ),
                Err(chio_flow::FlowDenial::InvalidManifest)
            ));
        }
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pre_dispatch_port_commits_the_authoritative_fence_for_exact_kernel_bytes() {
        let store = Arc::new(FakeFlowStore::new(flow_snapshot(7)));
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            store.clone(),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(FixedClock(150_000)),
            flow_config(),
        );
        let key = flow_key();
        let security_context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = flow_request();
        let canonical_request = chio_core::canonical_json_bytes(&request)
            .unwrap_or_else(|error| panic!("canonical request: {error}"));
        let dispatch_commitment_id = RecordId::new("dispatch-a")
            .unwrap_or_else(|error| panic!("dispatch commitment: {error}"));

        FlowPreDispatchPort::commit(
            &resolver,
            &FlowPreDispatchInput {
                security_context: &security_context,
                request: &request,
                canonical_request: &canonical_request,
                dispatch_commitment_id: &dispatch_commitment_id,
            },
        )
        .unwrap_or_else(|error| panic!("pre-dispatch commit: {error}"));

        assert_eq!(store.acquired.load(Ordering::SeqCst), 1);
        assert_eq!(store.committed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pre_dispatch_port_rejects_bytes_from_another_request_before_classification() {
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            classifier.clone(),
            Arc::new(FixedClock(150_000)),
            flow_config(),
        );
        let key = flow_key();
        let security_context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = flow_request();
        let other_request = {
            let mut value = request.clone();
            value.arguments = serde_json::json!({"safe": false});
            value
        };
        let other_bytes = chio_core::canonical_json_bytes(&other_request)
            .unwrap_or_else(|error| panic!("canonical other request: {error}"));
        let dispatch_commitment_id = RecordId::new("dispatch-a")
            .unwrap_or_else(|error| panic!("dispatch commitment: {error}"));

        assert!(matches!(
            FlowPreDispatchPort::commit(
                &resolver,
                &FlowPreDispatchInput {
                    security_context: &security_context,
                    request: &request,
                    canonical_request: &other_bytes,
                    dispatch_commitment_id: &dispatch_commitment_id,
                },
            ),
            Err(chio_flow::FlowDenial::DeclassificationBindingMismatch)
        ));
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn flow_transition_identity_binds_the_canonical_payload() {
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            Arc::new(FakeFlowStore::new(flow_snapshot(7))),
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(FixedClock(150_000)),
            flow_config(),
        );
        let key = flow_key();
        let security_context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let first = flow_request();
        let mut second = flow_request();
        second.arguments = serde_json::json!({"safe": false});
        let first_input = FlowPreInvocationInput {
            security_context: &security_context,
            request: &first,
        };
        let second_input = FlowPreInvocationInput {
            security_context: &security_context,
            request: &second,
        };
        let first_admission = evaluate_pre_invocation(
            FlowPreInvocationResolver::resolve(&resolver, &first_input)
                .unwrap_or_else(|error| panic!("first resolve: {error}")),
        )
        .unwrap_or_else(|error| panic!("first admission: {error}"));
        let second_admission = evaluate_pre_invocation(
            FlowPreInvocationResolver::resolve(&resolver, &second_input)
                .unwrap_or_else(|error| panic!("second resolve: {error}")),
        )
        .unwrap_or_else(|error| panic!("second admission: {error}"));

        assert_ne!(
            first_admission.taint_transition.transition_id,
            second_admission.taint_transition.transition_id
        );
    }

    #[test]
    fn stale_authoritative_generation_denies_before_classification() {
        let store = Arc::new(FakeFlowStore::new(flow_snapshot(8)));
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = PersistentFlowResolver::new(
            flow_registry(),
            store,
            classifier.clone(),
            Arc::new(FixedClock(150_000)),
            flow_config(),
        );
        let key = flow_key();
        let security_context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(7);
        let request = flow_request();
        let input = FlowPreInvocationInput {
            security_context: &security_context,
            request: &request,
        };
        assert_eq!(
            FlowPreInvocationResolver::resolve(&resolver, &input),
            Err(chio_flow::FlowDenial::StateChanged)
        );
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
    }
}
