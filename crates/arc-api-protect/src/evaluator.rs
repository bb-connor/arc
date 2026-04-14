//! Request evaluator: matches routes, checks capabilities, signs receipts.

use std::collections::HashMap;

use arc_core_types::crypto::Keypair;
use arc_core_types::receipt::GuardEvidence;
use arc_http_core::{
    ArcHttpRequest, AuthMethod, CallerIdentity, HttpMethod, HttpReceipt, HttpReceiptBody, Verdict,
};
use arc_openapi::PolicyDecision;

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

/// The request evaluator holds the loaded route table and kernel keypair.
pub struct RequestEvaluator {
    routes: Vec<RouteEntry>,
    keypair: Keypair,
    policy_hash: String,
}

impl RequestEvaluator {
    pub fn new(routes: Vec<RouteEntry>, keypair: Keypair, policy_hash: String) -> Self {
        Self {
            routes,
            keypair,
            policy_hash,
        }
    }

    /// Evaluate an incoming HTTP request against the route table.
    pub fn evaluate(
        &self,
        method: HttpMethod,
        path: &str,
        headers: &HashMap<String, String>,
        body_hash: Option<String>,
        body_length: u64,
    ) -> Result<EvaluationResult, crate::error::ProtectError> {
        let request_id = uuid::Uuid::now_v7().to_string();
        let caller = extract_caller(headers);
        let (route_pattern, matched_policy) = self.match_route(method, path);

        let mut evidence = Vec::new();

        // Determine verdict based on policy.
        let verdict = match matched_policy {
            PolicyDecision::SessionAllow => {
                evidence.push(GuardEvidence {
                    guard_name: "DefaultPolicyGuard".to_string(),
                    verdict: true,
                    details: Some("safe method, session-scoped allow".to_string()),
                });
                Verdict::Allow
            }
            PolicyDecision::DenyByDefault => {
                // Check for capability token in headers.
                let cap_header = headers
                    .get("x-arc-capability")
                    .or_else(|| headers.get("X-Arc-Capability"));
                match cap_header {
                    Some(_token) => {
                        // In a full implementation, validate the token against
                        // the kernel's capability authority. For now, the
                        // presence of a token is sufficient to allow.
                        evidence.push(GuardEvidence {
                            guard_name: "CapabilityGuard".to_string(),
                            verdict: true,
                            details: Some("capability token presented".to_string()),
                        });
                        Verdict::Allow
                    }
                    None => {
                        evidence.push(GuardEvidence {
                            guard_name: "CapabilityGuard".to_string(),
                            verdict: false,
                            details: Some(
                                "side-effect route requires X-Arc-Capability header".to_string(),
                            ),
                        });
                        Verdict::deny(
                            "side-effect route requires a capability token",
                            "CapabilityGuard",
                        )
                    }
                }
            }
        };

        let response_status = if verdict.is_allowed() { 200 } else { 403 };

        let caller_identity_hash = caller.identity_hash().map_err(|e| {
            crate::error::ProtectError::ReceiptSign(format!("failed to hash caller identity: {e}"))
        })?;

        let request = ArcHttpRequest {
            request_id: request_id.clone(),
            method,
            route_pattern: route_pattern.clone(),
            path: path.to_string(),
            query: HashMap::new(),
            headers: HashMap::new(), // Don't store raw headers in receipt
            caller,
            body_hash: body_hash.clone(),
            body_length,
            session_id: None,
            capability_id: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let content_hash = request.content_hash().map_err(|e| {
            crate::error::ProtectError::ReceiptSign(format!("failed to compute content hash: {e}"))
        })?;

        let receipt_id = uuid::Uuid::now_v7().to_string();
        let body = HttpReceiptBody {
            id: receipt_id,
            request_id,
            route_pattern,
            method,
            caller_identity_hash,
            session_id: None,
            verdict: verdict.clone(),
            evidence: evidence.clone(),
            response_status,
            timestamp: request.timestamp,
            content_hash,
            policy_hash: self.policy_hash.clone(),
            capability_id: None,
            metadata: None,
            kernel_key: self.keypair.public_key(),
        };

        let receipt = HttpReceipt::sign(body, &self.keypair)
            .map_err(|e| crate::error::ProtectError::ReceiptSign(format!("signing failed: {e}")))?;

        Ok(EvaluationResult {
            verdict,
            receipt,
            evidence,
        })
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
        let evaluator = RequestEvaluator::new(routes, keypair, "test-policy".to_string());

        let result = evaluator
            .evaluate(HttpMethod::Get, "/pets", &HashMap::new(), None, 0)
            .unwrap();
        assert!(result.verdict.is_allowed());
        assert!(result.receipt.verify_signature().unwrap());
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
        let evaluator = RequestEvaluator::new(routes, keypair, "test-policy".to_string());

        let result = evaluator
            .evaluate(HttpMethod::Post, "/pets", &HashMap::new(), None, 0)
            .unwrap();
        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.response_status, 403);
        assert!(result.receipt.verify_signature().unwrap());
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
        let evaluator = RequestEvaluator::new(routes, keypair, "test-policy".to_string());

        let mut headers = HashMap::new();
        headers.insert("X-Arc-Capability".to_string(), "cap-token-123".to_string());

        let result = evaluator
            .evaluate(HttpMethod::Post, "/pets", &headers, None, 0)
            .unwrap();
        assert!(result.verdict.is_allowed());
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
            .evaluate(HttpMethod::Get, "/unknown", &HashMap::new(), None, 0)
            .unwrap();
        assert!(result.verdict.is_allowed());

        // DELETE to unknown route should be denied (side-effect method)
        let result = evaluator
            .evaluate(HttpMethod::Delete, "/unknown", &HashMap::new(), None, 0)
            .unwrap();
        assert!(result.verdict.is_denied());
    }
}
