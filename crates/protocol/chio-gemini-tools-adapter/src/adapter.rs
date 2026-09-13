//! Adapter implementation that mediates Google Gemini `generateContent`
//! tool-use traffic through the Chio kernel. Pinned upstream API version:
//! `v1beta` (see [`transport::GEMINI_API_VERSION`]).
//!
//! Gemini surfaces tool calls as `functionCall` parts inside the model's
//! `Content` payload. Tool results travel back as `functionResponse` parts
//! on the user turn. The adapter's [`lift_batch`](GeminiAdapter::lift_batch)
//! lifts every `functionCall` into a [`chio_tool_call_fabric::ToolInvocation`]
//! and [`lower_function_response`](GeminiAdapter::lower_function_response)
//! lowers a kernel verdict back into a [`FunctionResponsePart`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use crate::{response, streaming, transport};
use chio_core::canonical::canonical_json_bytes;
use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderError, ProviderId, ProviderRequest, Redaction,
    ToolInvocation, ToolResult, VerdictResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

pub use crate::native::{FunctionCallPart, FunctionResponsePart};
pub use crate::transport::{
    GeminiTransport, Transport, GEMINI_API_KEY_ENV, GEMINI_API_VERSION,
    GEMINI_GENERATE_CONTENT_HOST,
};

/// Configuration for the Gemini adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeminiAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`GEMINI_API_VERSION`].
    pub api_version: String,
    /// Google Cloud project identifier that scopes Gemini tool calls. Stamped
    /// into the [`Principal::GeminiProject`] provenance slot.
    pub project_id: String,
}

impl GeminiAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`GEMINI_API_VERSION`].
    pub fn new(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        public_key: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            server_name: server_name.into(),
            server_version: server_version.into(),
            public_key: public_key.into(),
            api_version: GEMINI_API_VERSION.to_string(),
            project_id: project_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct GeminiAdapter {
    config: GeminiAdapterConfig,
    transport: Arc<dyn Transport>,
    admitted_security: Option<BTreeMap<String, chio_manifest::BridgeSecurityMetadata>>,
}

impl GeminiAdapter {
    /// Build a raw provider projection from a config and transport handle.
    ///
    /// This constructor has no manifest authority. Use
    /// [`Self::new_with_registry`] before lifted calls enter an evaluator.
    pub fn new(config: GeminiAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self {
            config,
            transport,
            admitted_security: None,
        }
    }

    /// Build an adapter bound to one verified, policy-admitted Chio server.
    pub fn new_with_registry(
        config: GeminiAdapterConfig,
        transport: Arc<dyn Transport>,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, GeminiAdapterError> {
        let manifest = registry
            .verified_manifest(&config.server_id)
            .map(|signed| &signed.manifest)
            .ok_or_else(|| GeminiAdapterError::RegistryManifestUnavailable {
                server_id: config.server_id.clone(),
            })?;
        if manifest.name != config.server_name
            || manifest.version != config.server_version
            || manifest.public_key != config.public_key
        {
            return Err(GeminiAdapterError::ConfigManifestMismatch {
                server_id: config.server_id.clone(),
            });
        }

        let mut admitted_security = BTreeMap::new();
        for tool in &manifest.tools {
            let security = registry
                .bridge_security(&config.server_id, &tool.name)
                .filter(chio_manifest::BridgeSecurityMetadata::has_registry_coordinates)
                .ok_or_else(|| GeminiAdapterError::RegistrySecurityUnavailable {
                    server_id: config.server_id.clone(),
                    tool_name: tool.name.clone(),
                })?;
            admitted_security.insert(tool.name.clone(), security);
        }

        Ok(Self {
            config,
            transport,
            admitted_security: Some(admitted_security),
        })
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Gemini
    }

    /// Pinned upstream API version (always [`GEMINI_API_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &GeminiAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    pub(crate) fn ensure_supported_api_version(&self) -> Result<(), ProviderError> {
        if self.config.api_version != GEMINI_API_VERSION {
            return Err(ProviderError::Malformed(format!(
                "Gemini adapter supports only API version {GEMINI_API_VERSION}; configured {}",
                self.config.api_version
            )));
        }
        let transport_api_version = self.transport.api_version();
        if transport_api_version != GEMINI_API_VERSION {
            return Err(ProviderError::Malformed(format!(
                "Gemini adapter supports only API version {GEMINI_API_VERSION}; transport advertised {transport_api_version}"
            )));
        }
        Ok(())
    }

    fn bridge_security_for_tool(
        &self,
        tool_name: &str,
    ) -> Result<Option<chio_manifest::BridgeSecurityMetadata>, ProviderError> {
        let Some(bindings) = &self.admitted_security else {
            return Ok(None);
        };
        bindings.get(tool_name).cloned().map(Some).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "registry-bound Gemini lift has no admitted security sidecar for tool `{tool_name}`"
            ))
        })
    }

    /// Proxy a non-streaming Gemini `generateContent` request and lift the
    /// response.
    ///
    /// `request_body` is the native Gemini `generateContent` JSON (`contents`,
    /// `tools.functionDeclarations`). The transport POSTs it to
    /// `/v1beta/models/<model>:generateContent` with the API key carried as the
    /// `?key=` query parameter, and the buffered response is fed straight into
    /// [`lift_batch`](Self::lift_batch). Transport-layer failures are mapped into
    /// the [`ProviderError`] taxonomy so a failed request never reads as an empty
    /// success.
    pub async fn generate_content(
        &self,
        model: &str,
        request_body: &[u8],
    ) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let response = self
            .transport
            .send_generate_content(model, request_body)
            .await?;
        self.lift_batch(response)
    }

    /// Proxy a streaming Gemini `streamGenerateContent` request and gate the SSE
    /// response.
    ///
    /// `request_body` is the native Gemini `generateContent` JSON. The buffered
    /// SSE body is gated frame-by-frame through `evaluate` by
    /// [`gate_sse_stream`](Self::gate_sse_stream) before any bytes are forwarded.
    pub async fn generate_content_stream<F>(
        &self,
        model: &str,
        request_body: &[u8],
        evaluate: F,
    ) -> Result<streaming::GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        let body = self
            .transport
            .send_generate_content_stream(model, request_body)
            .await?;
        self.gate_sse_stream(&body, evaluate)
    }

    /// Lift every Gemini `functionCall` part in a non-streaming
    /// `generateContent` response payload.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let calls = response::function_calls(raw)?;
        if calls.is_empty() {
            return Err(ProviderError::Malformed(
                "Gemini generateContent payload did not contain functionCall parts".to_string(),
            ));
        }
        calls
            .iter()
            .map(|call| self.invocation_from_function_call(call))
            .collect()
    }

    pub(crate) fn invocation_from_function_call(
        &self,
        call: &FunctionCallPart,
    ) -> Result<ToolInvocation, ProviderError> {
        self.ensure_supported_api_version()?;
        validate_function_call(call)?;
        let bridge_security = self.bridge_security_for_tool(&call.name)?;
        let arguments = canonical_json_bytes(&call.args).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Gemini functionCall args failed canonical JSON encoding: {error}"
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Gemini,
            tool_name: call.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Gemini,
                request_id: format!("gemini_{}_call", call.name),
                api_version: self.config.api_version.clone(),
                principal: Principal::GeminiProject {
                    project_id: self.config.project_id.clone(),
                },
                received_at: SystemTime::now(),
            },
            bridge_security,
        })
    }

    /// Lower a kernel verdict and tool result into a
    /// [`FunctionResponsePart`].
    pub fn lower_function_response(
        &self,
        function_name: &str,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<FunctionResponsePart, ProviderError> {
        self.ensure_supported_api_version()?;
        let function_name = non_empty_str(function_name, "functionResponse.name")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                lower_allow_function_response(function_name, result, &redactions)
            }
            VerdictResult::Deny { reason, .. } => {
                lower_deny_function_response(function_name, &reason)
            }
        }
    }
}

impl chio_provider_adapter_core::Provider for GeminiAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum GeminiAdapterError {
    /// Bubbled up from the transport layer.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    /// A provider-layer failure surfaced while proxying a request.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The configured server has no admitted signed manifest.
    #[error("verified manifest registry has no Gemini server {server_id}")]
    RegistryManifestUnavailable { server_id: String },
    /// Runtime configuration must identify exactly the admitted publisher surface.
    #[error("Gemini adapter config does not match admitted manifest for {server_id}")]
    ConfigManifestMismatch { server_id: String },
    /// A verified tool did not retain registry-admitted bridge metadata.
    #[error(
        "verified manifest registry has no admitted security sidecar for Gemini tool {server_id}/{tool_name}"
    )]
    RegistrySecurityUnavailable {
        server_id: String,
        tool_name: String,
    },
}

fn validate_function_call(call: &FunctionCallPart) -> Result<(), ProviderError> {
    non_empty_str(&call.name, "functionCall name")?;
    if !call.args.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "Gemini functionCall `{}` args were not a JSON object",
            call.name
        )));
    }
    Ok(())
}

fn parse_value(bytes: &[u8]) -> Result<Value, ProviderError> {
    serde_json::from_slice(bytes).map_err(|error| {
        ProviderError::Malformed(format!("tool result was not JSON bytes: {error}"))
    })
}

fn apply_redactions(
    mut value: Value,
    redactions: &[Redaction],
    context: &str,
) -> Result<Value, ProviderError> {
    for redaction in redactions {
        if redaction.path.is_empty() {
            value = Value::String(redaction.replacement.clone());
            continue;
        }
        if !redaction.path.starts_with('/') {
            return Err(ProviderError::Malformed(format!(
                "{context} redaction path `{}` is not a JSON Pointer",
                redaction.path
            )));
        }
        let target = value.pointer_mut(&redaction.path).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "{context} redaction path `{}` did not resolve",
                redaction.path
            ))
        })?;
        *target = Value::String(redaction.replacement.clone());
    }
    Ok(value)
}

fn lower_allow_function_response(
    function_name: &str,
    result: ToolResult,
    redactions: &[Redaction],
) -> Result<FunctionResponsePart, ProviderError> {
    let value = parse_value(&result.0)?;
    let value = apply_redactions(value, redactions, "Gemini functionResponse")?;
    Ok(FunctionResponsePart::new(function_name, value))
}

fn lower_deny_function_response(
    function_name: &str,
    reason: &DenyReason,
) -> Result<FunctionResponsePart, ProviderError> {
    Ok(FunctionResponsePart::new(
        function_name,
        deny_payload(reason),
    ))
}

fn deny_payload(reason: &DenyReason) -> Value {
    let text = match reason {
        DenyReason::PolicyDeny { rule_id } => format!("policy_deny: {rule_id}"),
        DenyReason::GuardDeny { guard_id, detail } => {
            format!("guard_deny: {guard_id}: {detail}")
        }
        DenyReason::CapabilityExpired => "capability_expired".to_string(),
        DenyReason::PrincipalUnknown => "principal_unknown".to_string(),
        DenyReason::BudgetExceeded => "budget_exceeded".to_string(),
    };
    json!({ "error": text })
}

fn non_empty_str<'a>(value: &'a str, field: &str) -> Result<&'a str, ProviderError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ProviderError::Malformed(format!(
            "Gemini {field} must not be empty"
        )));
    }
    if trimmed != value {
        return Err(ProviderError::Malformed(format!(
            "Gemini {field} must not contain surrounding whitespace"
        )));
    }
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use chio_core::Keypair;
    use chio_manifest::{
        RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
        VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
    };
    use serde_json::json;

    fn config() -> GeminiAdapterConfig {
        GeminiAdapterConfig::new(
            "gemini-1",
            "Gemini generateContent",
            "0.1.0",
            "deadbeef",
            "proj_chio_demo",
        )
    }

    fn config_with_api_version(api_version: &str) -> GeminiAdapterConfig {
        let mut cfg = config();
        cfg.api_version = api_version.to_string();
        cfg
    }

    fn function_call_payload() -> Value {
        json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}
                    ]
                }
            }]
        })
    }

    fn function_call_stream() -> Vec<u8> {
        let payload = function_call_payload();
        let mut sse = Vec::new();
        sse.extend_from_slice(b"data: ");
        sse.extend_from_slice(&serde_json::to_vec(&payload).unwrap());
        sse.extend_from_slice(b"\n\n");
        sse
    }

    fn raw_payload(value: Value) -> ProviderRequest {
        ProviderRequest(serde_json::to_vec(&value).unwrap())
    }

    fn admitted_registry(
        tool_name: &str,
    ) -> (
        GeminiAdapterConfig,
        VerifiedManifestRegistry,
        ToolFlowDeclaration,
    ) {
        let signer = Keypair::from_seed(&[62; 32]);
        let config = GeminiAdapterConfig::new(
            "gemini-1",
            "Gemini generateContent",
            "0.1.0",
            signer.public_key().to_hex(),
            "proj_chio_demo",
        );
        let flow = ToolFlowDeclaration::public_egress();
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: None,
            version: config.server_version.clone(),
            tools: vec![ToolDefinition {
                name: tool_name.to_string(),
                description: "Admitted Gemini tool".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations {
                    read_only: false,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: None,
                flow: Some(flow.clone()),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &signer).unwrap();
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
            .unwrap();
        (config, registry, flow)
    }

    fn admitted_adapter(tool_name: &str) -> (GeminiAdapter, ToolFlowDeclaration) {
        let (config, registry, flow) = admitted_registry(tool_name);
        let adapter = GeminiAdapter::new_with_registry(
            config,
            Arc::new(transport::MockTransport::new()),
            &registry,
        )
        .unwrap();
        (adapter, flow)
    }

    struct DriftedTransport {
        called: Arc<AtomicBool>,
    }

    impl DriftedTransport {
        fn new(called: Arc<AtomicBool>) -> Self {
            Self { called }
        }
    }

    #[async_trait::async_trait]
    impl transport::Transport for DriftedTransport {
        fn api_version(&self) -> &str {
            "v1alpha"
        }

        async fn send_generate_content(
            &self,
            _model: &str,
            _body: &[u8],
        ) -> Result<ProviderRequest, ProviderError> {
            self.called.store(true, Ordering::SeqCst);
            Ok(raw_payload(function_call_payload()))
        }

        async fn send_generate_content_stream(
            &self,
            _model: &str,
            _body: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            self.called.store(true, Ordering::SeqCst);
            Ok(function_call_stream())
        }
    }

    fn allow_verdict() -> VerdictResult {
        VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
        }
    }

    fn assert_api_version_drift(error: ProviderError) {
        match error {
            ProviderError::Malformed(message) => {
                assert!(message.contains("Gemini adapter supports only API version v1beta"));
                assert!(message.contains("v1alpha"));
            }
            other => panic!("expected Malformed API version drift, got {other:?}"),
        }
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, GEMINI_API_VERSION);
        assert_eq!(cfg.api_version, "v1beta");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport));
        assert_eq!(adapter.provider(), ProviderId::Gemini);
        assert_eq!(adapter.api_version(), "v1beta");
    }

    #[test]
    fn registry_bound_lift_preserves_exact_flow_sidecar() {
        let (adapter, expected_flow) = admitted_adapter("get_weather");
        let invocation = adapter
            .lift_batch(raw_payload(function_call_payload()))
            .unwrap()
            .remove(0);

        let security = invocation
            .bridge_security
            .as_ref()
            .expect("registry-bound lift retains security");
        assert!(security.has_registry_coordinates());
        assert_eq!(
            canonical_json_bytes(security.flow().expect("flow sidecar")).unwrap(),
            canonical_json_bytes(&expected_flow).unwrap()
        );
    }

    #[test]
    fn registry_bound_constructor_rejects_missing_server() {
        let (mut config, registry, _) = admitted_registry("get_weather");
        config.server_id = "missing-gemini".to_string();

        let error = match GeminiAdapter::new_with_registry(
            config,
            Arc::new(transport::MockTransport::new()),
            &registry,
        ) {
            Ok(_) => panic!("missing admitted server must fail closed"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            GeminiAdapterError::RegistryManifestUnavailable { .. }
        ));
    }

    #[test]
    fn registry_bound_constructor_rejects_config_mismatch() {
        let (mut config, registry, _) = admitted_registry("get_weather");
        config.server_version = "9.9.9".to_string();

        let error = match GeminiAdapter::new_with_registry(
            config,
            Arc::new(transport::MockTransport::new()),
            &registry,
        ) {
            Ok(_) => panic!("config identity mismatch must fail closed"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            GeminiAdapterError::ConfigManifestMismatch { .. }
        ));
    }

    #[test]
    fn registry_bound_lift_rejects_unknown_tool_sidecar() {
        let (adapter, _) = admitted_adapter("get_weather");
        let payload = json!({
            "functionCall": {
                "name": "send_email",
                "args": {}
            }
        });

        let error = adapter
            .lift_batch(raw_payload(payload))
            .expect_err("unknown tool must not inherit an admitted sidecar");

        assert!(error.to_string().contains(
            "registry-bound Gemini lift has no admitted security sidecar for tool `send_email`"
        ));
    }

    #[test]
    fn raw_projection_cannot_enter_stream_evaluator() {
        let adapter = GeminiAdapter::new(config(), Arc::new(transport::MockTransport::new()));
        let evaluated = std::cell::Cell::new(false);

        let error = adapter
            .gate_sse_stream(&function_call_stream(), |_invocation| {
                evaluated.set(true);
                Ok(allow_verdict())
            })
            .expect_err("raw projection must not be execution-ready");

        assert!(error
            .to_string()
            .contains("requires a registry-admitted security sidecar"));
        assert!(!evaluated.get());
    }

    #[tokio::test]
    async fn generate_content_rejects_api_version_drift_before_transport_call() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_generate_content_response(serde_json::to_vec(&function_call_payload()).unwrap());
        let adapter = GeminiAdapter::new(config_with_api_version("v1alpha"), mock.clone());

        let err = adapter
            .generate_content("gemini-1.5-pro", b"{\"contents\":[]}")
            .await
            .expect_err("drifted Gemini API version must fail before transport");

        assert_api_version_drift(err);
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn generate_content_rejects_transport_api_version_drift_before_send() {
        let called = Arc::new(AtomicBool::new(false));
        let transport = Arc::new(DriftedTransport::new(called.clone()));
        let adapter = GeminiAdapter::new(config(), transport);

        let err = adapter
            .generate_content("gemini-1.5-pro", b"{\"contents\":[]}")
            .await
            .expect_err("drifted Gemini transport API version must fail before send");

        assert_api_version_drift(err);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn generate_content_stream_rejects_api_version_drift_before_transport_call() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_generate_content_response(function_call_stream());
        let adapter = GeminiAdapter::new(config_with_api_version("v1alpha"), mock.clone());

        let err = adapter
            .generate_content_stream("gemini-1.5-pro", b"{\"contents\":[]}", |_invocation| {
                Ok(allow_verdict())
            })
            .await
            .expect_err("drifted Gemini API version must fail before stream transport");

        assert_api_version_drift(err);
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn generate_content_stream_rejects_transport_api_version_drift_before_send() {
        let called = Arc::new(AtomicBool::new(false));
        let transport = Arc::new(DriftedTransport::new(called.clone()));
        let adapter = GeminiAdapter::new(config(), transport);

        let err = adapter
            .generate_content_stream("gemini-1.5-pro", b"{\"contents\":[]}", |_invocation| {
                Ok(allow_verdict())
            })
            .await
            .expect_err("drifted Gemini stream transport API version must fail before send");

        assert_api_version_drift(err);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn lift_batch_rejects_api_version_drift_before_provenance_stamp() {
        let adapter = GeminiAdapter::new(
            config_with_api_version("v1alpha"),
            Arc::new(transport::MockTransport::new()),
        );

        let err = adapter
            .lift_batch(raw_payload(function_call_payload()))
            .expect_err("drifted Gemini API version must fail before provenance stamping");

        assert_api_version_drift(err);
    }

    #[test]
    fn gate_sse_stream_rejects_api_version_drift_before_evaluator() {
        let adapter = GeminiAdapter::new(
            config_with_api_version("v1alpha"),
            Arc::new(transport::MockTransport::new()),
        );
        let evaluated = std::cell::Cell::new(false);

        let err = adapter
            .gate_sse_stream(&function_call_stream(), |_invocation| {
                evaluated.set(true);
                Ok(allow_verdict())
            })
            .expect_err("drifted Gemini API version must fail before stream evaluation");

        assert_api_version_drift(err);
        assert!(!evaluated.get());
    }

    #[test]
    fn invocation_from_function_call_rejects_api_version_drift_before_provenance_stamp() {
        let adapter = GeminiAdapter::new(
            config_with_api_version("v1alpha"),
            Arc::new(transport::MockTransport::new()),
        );
        let call = FunctionCallPart::new("get_weather", json!({"city": "Paris"}));

        let err = adapter
            .invocation_from_function_call(&call)
            .expect_err("drifted Gemini API version must fail before provenance stamping");

        assert_api_version_drift(err);
    }

    #[test]
    fn lower_function_response_rejects_api_version_drift() {
        let adapter = GeminiAdapter::new(
            config_with_api_version("v1alpha"),
            Arc::new(transport::MockTransport::new()),
        );

        let err = adapter
            .lower_function_response(
                "get_weather",
                allow_verdict(),
                ToolResult(b"{\"temp\":18}".to_vec()),
            )
            .expect_err("drifted Gemini API version must fail before lowering");

        assert_api_version_drift(err);
    }

    #[test]
    fn lift_batch_extracts_function_call_parts() {
        let cfg = config();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "Let me check the forecast."},
                        {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}
                    ]
                }
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let invocations = adapter.lift_batch(raw).unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
    }

    #[test]
    fn lift_batch_rejects_malformed_envelope_before_outer_function_calls() {
        let cfg = config();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "body": 42,
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}
                    ]
                }
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter.lift_batch(raw).unwrap_err();

        assert!(err.to_string().contains("envelope field `body`"));
    }

    #[test]
    fn lift_batch_maps_prompt_feedback_safety_block_to_content_policy() {
        let cfg = config();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "promptFeedback": {
                "blockReason": "SAFETY",
                "safetyRatings": []
            }
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter
            .lift_batch(raw)
            .expect_err("Gemini safety block must fail closed as content policy");

        assert!(matches!(err, ProviderError::ContentPolicy(_)));
        assert!(err.to_string().contains("SAFETY"));
    }

    #[test]
    fn lift_batch_maps_candidate_safety_finish_reason_to_content_policy() {
        let cfg = config();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "candidates": [{
                "finishReason": "SAFETY",
                "content": { "parts": [] }
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter
            .lift_batch(raw)
            .expect_err("Gemini candidate safety finish reason must fail closed");

        assert!(matches!(err, ProviderError::ContentPolicy(_)));
        assert!(err.to_string().contains("SAFETY"));
    }

    #[test]
    fn lift_batch_rejects_function_call_name_with_surrounding_whitespace() {
        let cfg = config();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "functionCall": {
                "name": " get_weather ",
                "args": {}
            }
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter
            .lift_batch(raw)
            .expect_err("whitespace-padded function name must fail closed");

        assert!(err
            .to_string()
            .contains("functionCall name must not contain surrounding whitespace"));
    }

    #[test]
    fn lower_function_response_allow() {
        let cfg = config();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_demo".into()),
        };
        let result = ToolResult(b"{\"temp\":18}".to_vec());
        let part = adapter
            .lower_function_response("get_weather", verdict, result)
            .unwrap();
        assert_eq!(part.name, "get_weather");
    }

    #[test]
    fn lower_allow_function_response_helper_applies_redactions() {
        let part = lower_allow_function_response(
            "get_weather",
            ToolResult(br#"{"token":"secret","ok":true}"#.to_vec()),
            &[Redaction {
                path: "/token".to_string(),
                replacement: "[redacted]".to_string(),
            }],
        )
        .unwrap();

        assert_eq!(part.name, "get_weather");
        assert_eq!(part.response, json!({"token": "[redacted]", "ok": true}));
    }

    #[tokio::test]
    async fn generate_content_proxies_request_and_lifts_tool_calls() {
        let cfg = config();
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_generate_content_response(
            serde_json::to_vec(&json!({
                "candidates": [{
                    "content": {
                        "parts": [
                            {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}
                        ]
                    }
                }]
            }))
            .unwrap(),
        );
        let adapter = GeminiAdapter::new(cfg, mock.clone());
        let request = b"{\"contents\":[],\"tools\":[]}";
        let invocations = adapter
            .generate_content("gemini-1.5-pro", request)
            .await
            .unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "/v1beta/models/gemini-1.5-pro:generateContent");
        assert_eq!(calls[0].1, request);
    }

    #[tokio::test]
    async fn generate_content_propagates_upstream_status_error() {
        let cfg = config();
        let mock = transport::MockTransport::new();
        mock.push_error(
            chio_provider_adapter_core::http::HttpTransportError::Status {
                code: 503,
                body: "service unavailable".to_string(),
            },
        );
        let adapter = GeminiAdapter::new(cfg, Arc::new(mock));
        let err = adapter
            .generate_content("gemini-1.5-pro", b"{}")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Upstream5xx { status: 503, .. }
        ));
    }

    #[tokio::test]
    async fn generate_content_stream_gates_function_call_frames() {
        let mock = Arc::new(transport::MockTransport::new());
        let sse = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"Paris\"}}}]}}]}\n\n";
        mock.push_generate_content_response(sse.as_bytes().to_vec());
        let (config, registry, _) = admitted_registry("get_weather");
        let adapter = GeminiAdapter::new_with_registry(config, mock.clone(), &registry).unwrap();
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_stream".into()),
        };
        let gated = adapter
            .generate_content_stream("gemini-1.5-pro", b"{\"contents\":[]}", |_invocation| {
                Ok(verdict.clone())
            })
            .await
            .unwrap();
        assert_eq!(gated.invocations.len(), 1);
        assert_eq!(gated.invocations[0].tool_name, "get_weather");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0,
            "/v1beta/models/gemini-1.5-pro:streamGenerateContent?alt=sse"
        );
    }
}
