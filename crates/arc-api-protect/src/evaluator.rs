//! Request evaluator: matches routes, checks capabilities, signs receipts.

use std::collections::HashMap;
use std::sync::Arc;

use arc_core_types::crypto::{Keypair, PublicKey};
use arc_core_types::receipt::GuardEvidence;
use arc_http_core::{
    ArcHttpRequest, AuthMethod, CallerIdentity, HttpAuthority, HttpAuthorityError,
    HttpAuthorityEvaluation, HttpAuthorityInput, HttpAuthorityPolicy, HttpMethod, HttpReceipt,
    Verdict,
};
use arc_kernel::ApprovalStore;
use arc_openapi::PolicyDecision;
use serde_json::Value;

/// Evaluated result for a single HTTP request.
pub struct EvaluationResult {
    pub verdict: Verdict,
    pub receipt: HttpReceipt,
    pub evidence: Vec<GuardEvidence>,
}

/// Route information extracted from the OpenAPI spec.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub pattern: String,
    pub method: HttpMethod,
    pub operation_id: Option<String>,
    pub policy: PolicyDecision,
}

/// The request evaluator holds the loaded route table and shared HTTP authority.
pub struct RequestEvaluator {
    routes: Vec<RouteEntry>,
    authority: HttpAuthority,
}

impl RequestEvaluator {
    pub fn new(routes: Vec<RouteEntry>, keypair: Keypair, policy_hash: String) -> Self {
        Self::new_with_trusted_capability_issuers(routes, keypair, policy_hash, Vec::new())
    }

    pub fn new_with_trusted_capability_issuers(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Self {
        Self {
            routes,
            authority: HttpAuthority::new_with_approval_store_and_trusted_issuers(
                keypair,
                policy_hash,
                Arc::new(arc_kernel::InMemoryApprovalStore::new()),
                trusted_capability_issuers,
            ),
        }
    }

    pub fn new_with_approval_store(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
    ) -> Self {
        Self::new_with_approval_store_and_trusted_capability_issuers(
            routes,
            keypair,
            policy_hash,
            approval_store,
            Vec::new(),
        )
    }

    pub fn new_with_approval_store_and_trusted_capability_issuers(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Self {
        Self {
            routes,
            authority: HttpAuthority::new_with_approval_store_and_trusted_issuers(
                keypair,
                policy_hash,
                approval_store,
                trusted_capability_issuers,
            ),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn approval_store(&self) -> Arc<dyn ApprovalStore> {
        self.authority.approval_store()
    }

    /// Evaluate an incoming HTTP request against the route table.
    pub fn evaluate(
        &self,
        method: HttpMethod,
        path: &str,
        query: &HashMap<String, String>,
        headers: &HashMap<String, String>,
        body_hash: Option<String>,
        body_length: u64,
    ) -> Result<EvaluationResult, crate::error::ProtectError> {
        let request_id = uuid::Uuid::now_v7().to_string();
        let caller = extract_caller(headers);
        let (route_pattern, matched_policy) = self.match_route(method, path);
        let result = self.authority.evaluate(HttpAuthorityInput {
            request_id,
            method,
            route_pattern,
            path,
            query,
            caller,
            body_hash,
            body_length,
            session_id: None,
            capability_id_hint: None,
            presented_capability: extract_presented_capability(headers, query),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            policy: policy_mode(matched_policy),
        })?;
        Ok(result.into())
    }

    /// Evaluate a fully normalized sidecar request.
    pub fn evaluate_arc_request(
        &self,
        request: ArcHttpRequest,
        presented_capability: Option<&str>,
    ) -> Result<EvaluationResult, crate::error::ProtectError> {
        let ArcHttpRequest {
            request_id,
            method,
            path,
            query,
            headers,
            caller,
            body_hash,
            body_length,
            session_id,
            capability_id,
            tool_server,
            tool_name,
            arguments,
            ..
        } = request;
        let (route_pattern, matched_policy) = self.match_route(method, &path);
        let raw_capability =
            presented_capability.or_else(|| extract_presented_capability(&headers, &query));
        let arguments = arguments.unwrap_or(Value::Null);
        let result = self.authority.evaluate(HttpAuthorityInput {
            request_id,
            method,
            route_pattern,
            path: &path,
            query: &query,
            caller,
            body_hash,
            body_length,
            session_id,
            capability_id_hint: capability_id.as_deref(),
            presented_capability: raw_capability,
            requested_tool_server: tool_server.as_deref(),
            requested_tool_name: tool_name.as_deref(),
            requested_arguments: Some(&arguments),
            policy: policy_mode(matched_policy),
        })?;
        Ok(result.into())
    }

    /// Match a request path against the route table.
    /// Returns (matched_pattern, policy). Falls back to a catch-all.
    fn match_route(&self, method: HttpMethod, path: &str) -> (String, PolicyDecision) {
        // Try exact pattern match first, then prefix match.
        for route in &self.routes {
            if route.method == method && path_matches_pattern(path, &route.pattern) {
                return (route.pattern.clone(), route.policy);
            }
        }

        // Fallback: use method-based default policy.
        let pattern = path.to_string();
        let policy = if method.is_safe() {
            PolicyDecision::SessionAllow
        } else {
            PolicyDecision::DenyByDefault
        };
        (pattern, policy)
    }
}

fn extract_presented_capability<'a>(
    headers: &'a HashMap<String, String>,
    query: &'a HashMap<String, String>,
) -> Option<&'a str> {
    headers
        .get("x-arc-capability")
        .or_else(|| headers.get("X-Arc-Capability"))
        .map(String::as_str)
        .or_else(|| query.get("arc_capability").map(String::as_str))
}

fn policy_mode(policy: PolicyDecision) -> HttpAuthorityPolicy {
    match policy {
        PolicyDecision::SessionAllow => HttpAuthorityPolicy::SessionAllow,
        PolicyDecision::DenyByDefault => HttpAuthorityPolicy::DenyByDefault,
    }
}

impl RequestEvaluator {
    pub fn finalize_receipt(
        &self,
        decision_receipt: &HttpReceipt,
        response_status: u16,
    ) -> Result<HttpReceipt, crate::error::ProtectError> {
        self.authority
            .finalize_decision_receipt(decision_receipt, response_status)
            .map_err(Into::into)
    }
}

impl From<HttpAuthorityEvaluation> for EvaluationResult {
    fn from(value: HttpAuthorityEvaluation) -> Self {
        Self {
            verdict: value.verdict,
            receipt: value.receipt,
            evidence: value.evidence,
        }
    }
}

impl From<HttpAuthorityError> for crate::error::ProtectError {
    fn from(value: HttpAuthorityError) -> Self {
        match value {
            HttpAuthorityError::CallerIdentity(message)
            | HttpAuthorityError::ContentHash(message)
            | HttpAuthorityError::Kernel(message) => Self::Evaluation(message),
            HttpAuthorityError::PendingApproval {
                approval_id,
                kernel_receipt_id,
            } => Self::PendingApproval {
                approval_id,
                kernel_receipt_id,
            },
            HttpAuthorityError::ReceiptSign(message) => Self::ReceiptSign(message),
        }
    }
}

/// Simple path pattern matcher supporting {param} placeholders.
fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let path_segments: Vec<&str> = path.split('/').collect();
    let pattern_segments: Vec<&str> = pattern.split('/').collect();

    if path_segments.len() != pattern_segments.len() {
        return false;
    }

    path_segments
        .iter()
        .zip(pattern_segments.iter())
        .all(|(p, pat)| pat.starts_with('{') && pat.ends_with('}') || p == pat)
}

/// Extract caller identity from HTTP headers.
fn extract_caller(headers: &HashMap<String, String>) -> CallerIdentity {
    // Check for Authorization: Bearer <token>
    if let Some(auth) = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))
    {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            let token_hash = arc_core_types::sha256_hex(token.as_bytes());
            return CallerIdentity {
                subject: format!("bearer:{}", &token_hash[..16]),
                auth_method: AuthMethod::Bearer { token_hash },
                verified: false,
                tenant: None,
                agent_id: None,
            };
        }
    }

    // Check for API key headers
    for key_header in &["x-api-key", "X-Api-Key", "X-API-Key"] {
        if let Some(key_value) = headers.get(*key_header) {
            let key_hash = arc_core_types::sha256_hex(key_value.as_bytes());
            return CallerIdentity {
                subject: format!("apikey:{}", &key_hash[..16]),
                auth_method: AuthMethod::ApiKey {
                    key_name: key_header.to_string(),
                    key_hash,
                },
                verified: false,
                tenant: None,
                agent_id: None,
            };
        }
    }

    CallerIdentity::anonymous()
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core_types::capability::{
        ArcScope, CapabilityToken, CapabilityTokenBody, Operation, ToolGrant,
    };
    use arc_http_core::{
        http_status_scope, ARC_DECISION_RECEIPT_ID_KEY, ARC_HTTP_STATUS_SCOPE_DECISION,
        ARC_HTTP_STATUS_SCOPE_FINAL,
    };

    fn signed_capability_token_json(issuer: &Keypair, id: &str) -> String {
        signed_capability_token_json_with_scope(issuer, id, ArcScope::default())
    }

    fn signed_capability_token_json_with_scope(
        issuer: &Keypair,
        id: &str,
        scope: ArcScope,
    ) -> String {
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope,
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("token should sign");
        serde_json::to_string(&token).expect("token should serialize")
    }

    #[test]
    fn path_matching() {
        assert!(path_matches_pattern("/pets/42", "/pets/{petId}"));
        assert!(path_matches_pattern("/pets", "/pets"));
        assert!(!path_matches_pattern("/pets/42/toys", "/pets/{petId}"));
        assert!(!path_matches_pattern("/dogs/42", "/pets/{petId}"));
    }

    #[test]
    fn extract_bearer_caller() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer mytoken123".to_string());
        let caller = extract_caller(&headers);
        assert!(caller.subject.starts_with("bearer:"));
        assert!(matches!(caller.auth_method, AuthMethod::Bearer { .. }));
    }

    #[test]
    fn extract_anonymous_caller() {
        let headers = HashMap::new();
        let caller = extract_caller(&headers);
        assert_eq!(caller.subject, "anonymous");
    }

    #[test]
    fn evaluate_get_allowed() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator = RequestEvaluator::new(routes, keypair.clone(), "test-policy".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Get,
                "/pets",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .unwrap();
        assert!(result.verdict.is_allowed());
        assert!(result.receipt.verify_signature().unwrap());
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_arc_request_denies_capability_for_different_tool_identity() {
        let keypair = Keypair::generate();
        let evaluator = RequestEvaluator::new(vec![], keypair.clone(), "test-policy".to_string());
        let capability = signed_capability_token_json_with_scope(
            &keypair,
            "cap-tool-scope",
            ArcScope {
                grants: vec![ToolGrant {
                    server_id: "math".to_string(),
                    tool_name: "double".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ArcScope::default()
            },
        );

        let mut request = ArcHttpRequest::new(
            "req-sidecar-tool-mismatch".to_string(),
            HttpMethod::Post,
            "/arc/tools/math/increment".to_string(),
            "/arc/tools/math/increment".to_string(),
            CallerIdentity::anonymous(),
        );
        request.tool_server = Some("math".to_string());
        request.tool_name = Some("increment".to_string());
        request.arguments = Some(serde_json::json!({ "value": 1 }));
        request.body_hash = Some("tool-body".to_string());
        request.body_length = 1;

        let result = evaluator
            .evaluate_arc_request(request, Some(&capability))
            .unwrap();

        assert!(result.verdict.is_denied());
        assert_eq!(
            result.receipt.evidence[0].details.as_deref(),
            Some("capability does not authorize tool increment on server math")
        );
    }

    #[test]
    fn evaluate_arc_request_allows_capability_from_configured_external_issuer() {
        let signer = Keypair::generate();
        let external_issuer = Keypair::generate();
        let evaluator = RequestEvaluator::new_with_trusted_capability_issuers(
            vec![],
            signer,
            "test-policy".to_string(),
            vec![external_issuer.public_key()],
        );
        let capability = signed_capability_token_json(&external_issuer, "cap-external");

        let mut request = ArcHttpRequest::new(
            "req-external-issuer".to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            CallerIdentity::anonymous(),
        );
        request.body_hash = Some("body".to_string());
        request.body_length = 1;

        let result = evaluator
            .evaluate_arc_request(request, Some(&capability))
            .unwrap();

        assert!(result.verdict.is_allowed());
        assert_eq!(
            result.receipt.capability_id.as_deref(),
            Some("cap-external")
        );
    }

    #[test]
    fn evaluate_post_denied_without_capability() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }];
        let evaluator = RequestEvaluator::new(routes, keypair.clone(), "test-policy".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Post,
                "/pets",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .unwrap();
        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.response_status, 403);
        assert!(result.receipt.verify_signature().unwrap());
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_post_allowed_with_capability() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }];
        let evaluator = RequestEvaluator::new(routes, keypair.clone(), "test-policy".to_string());

        let mut headers = HashMap::new();
        headers.insert(
            "X-Arc-Capability".to_string(),
            signed_capability_token_json(&keypair, "cap-123"),
        );

        let result = evaluator
            .evaluate(
                HttpMethod::Post,
                "/pets",
                &HashMap::new(),
                &headers,
                None,
                0,
            )
            .unwrap();
        assert!(result.verdict.is_allowed());
        assert_eq!(result.receipt.capability_id.as_deref(), Some("cap-123"));
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn finalize_receipt_rebinds_status_and_links_decision_receipt() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator = RequestEvaluator::new(routes, keypair, "test-policy".to_string());

        let decision = evaluator
            .evaluate(
                HttpMethod::Get,
                "/pets",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .unwrap()
            .receipt;
        let final_receipt = evaluator.finalize_receipt(&decision, 204).unwrap();

        assert_ne!(final_receipt.id, decision.id);
        assert_eq!(final_receipt.response_status, 204);
        assert_eq!(
            http_status_scope(final_receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_FINAL)
        );
        assert_eq!(
            final_receipt
                .metadata
                .as_ref()
                .and_then(|meta| meta.get(ARC_DECISION_RECEIPT_ID_KEY))
                .and_then(|value| value.as_str()),
            Some(decision.id.as_str())
        );
        assert!(final_receipt.verify_signature().unwrap());
    }

    #[test]
    fn path_matching_trailing_slash_mismatch() {
        // Trailing slash should NOT match if pattern has no trailing slash
        assert!(!path_matches_pattern("/pets/", "/pets"));
        assert!(!path_matches_pattern("/pets", "/pets/"));
    }

    #[test]
    fn path_matching_double_slashes() {
        // Double slashes produce empty segments, should not match normal paths
        assert!(!path_matches_pattern("//pets", "/pets"));
    }

    #[test]
    fn path_matching_case_sensitivity() {
        // Path matching should be case-sensitive
        assert!(!path_matches_pattern("/Pets", "/pets"));
        assert!(path_matches_pattern("/Pets", "/Pets"));
    }

    #[test]
    fn path_matching_multiple_params() {
        assert!(path_matches_pattern(
            "/orgs/123/members/456",
            "/orgs/{orgId}/members/{memberId}"
        ));
        assert!(!path_matches_pattern(
            "/orgs/123/members",
            "/orgs/{orgId}/members/{memberId}"
        ));
    }

    #[test]
    fn path_matching_root() {
        assert!(path_matches_pattern("/", "/"));
        assert!(!path_matches_pattern("/pets", "/"));
    }

    #[test]
    fn extract_api_key_caller() {
        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), "my-api-key-value".to_string());
        let caller = extract_caller(&headers);
        assert!(caller.subject.starts_with("apikey:"));
        assert!(matches!(caller.auth_method, AuthMethod::ApiKey { .. }));
    }

    #[test]
    fn evaluate_with_body_hash() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/data".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("getData".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator = RequestEvaluator::new(routes, keypair, "test-policy".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Get,
                "/data",
                &HashMap::new(),
                &HashMap::new(),
                Some("bodyhash123".to_string()),
                1024,
            )
            .unwrap();
        assert!(result.verdict.is_allowed());
        assert!(result.receipt.verify_signature().unwrap());
    }

    #[test]
    fn fallback_policy_for_unmatched_route() {
        let keypair = Keypair::generate();
        let evaluator = RequestEvaluator::new(vec![], keypair, "test-policy".to_string());

        // GET to unknown route should still be allowed (safe method)
        let result = evaluator
            .evaluate(
                HttpMethod::Get,
                "/unknown",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .unwrap();
        assert!(result.verdict.is_allowed());

        // DELETE to unknown route should be denied (side-effect method)
        let result = evaluator
            .evaluate(
                HttpMethod::Delete,
                "/unknown",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .unwrap();
        assert!(result.verdict.is_denied());
    }

    #[test]
    fn evaluate_invalid_capability_denied_fail_closed() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }];
        let evaluator = RequestEvaluator::new(routes, keypair, "test-policy".to_string());
        let mut headers = HashMap::new();
        headers.insert("X-Arc-Capability".to_string(), "not-json".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Post,
                "/pets",
                &HashMap::new(),
                &headers,
                None,
                0,
            )
            .unwrap();

        assert!(result.verdict.is_denied());
        assert!(result.receipt.capability_id.as_deref().is_none());
    }

    #[test]
    fn evaluate_query_parameters_affect_content_hash() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/search".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("search".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator = RequestEvaluator::new(routes, keypair, "test-policy".to_string());
        let mut query_a = HashMap::new();
        query_a.insert("q".to_string(), "cats".to_string());
        let mut query_b = HashMap::new();
        query_b.insert("q".to_string(), "dogs".to_string());

        let result_a = evaluator
            .evaluate(
                HttpMethod::Get,
                "/search",
                &query_a,
                &HashMap::new(),
                None,
                0,
            )
            .unwrap();
        let result_b = evaluator
            .evaluate(
                HttpMethod::Get,
                "/search",
                &query_b,
                &HashMap::new(),
                None,
                0,
            )
            .unwrap();

        assert_ne!(result_a.receipt.content_hash, result_b.receipt.content_hash);
    }
}
