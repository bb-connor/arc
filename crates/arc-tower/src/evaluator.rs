//! Request evaluator for the ARC tower middleware.
//!
//! Contains the core evaluation logic: matching routes, checking capabilities,
//! and signing receipts.

use std::collections::HashMap;
use std::sync::Arc;

use arc_core_types::crypto::Keypair;
use arc_core_types::receipt::GuardEvidence;
use arc_http_core::{
    ArcHttpRequest, CallerIdentity, HttpMethod, HttpReceipt, HttpReceiptBody, Verdict,
};

use crate::error::ArcTowerError;
use crate::identity::IdentityExtractor;

/// Result of evaluating an HTTP request.
pub struct EvaluationResult {
    /// The kernel's verdict.
    pub verdict: Verdict,
    /// Signed receipt for the evaluation.
    pub receipt: HttpReceipt,
    /// Per-guard evidence collected during evaluation.
    pub evidence: Vec<GuardEvidence>,
}

/// Route pattern resolver function type.
pub type RouteResolver = fn(&str, &str) -> String;

/// Default route resolver returns the raw path.
fn default_route_resolver(_method: &str, path: &str) -> String {
    path.to_string()
}

/// ARC request evaluator. Holds the kernel keypair and policy configuration.
pub struct ArcEvaluator {
    keypair: Arc<Keypair>,
    policy_hash: String,
    identity_extractor: IdentityExtractor,
    route_resolver: RouteResolver,
    /// When true, sidecar errors allow the request through (fail-open).
    /// Default is false (fail-closed).
    fail_open: bool,
}

impl ArcEvaluator {
    /// Create a new evaluator with the given keypair and policy hash.
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            keypair: Arc::new(keypair),
            policy_hash,
            identity_extractor: crate::identity::extract_identity,
            route_resolver: default_route_resolver,
            fail_open: false,
        }
    }

    /// Set a custom identity extractor.
    #[must_use]
    pub fn with_identity_extractor(mut self, extractor: IdentityExtractor) -> Self {
        self.identity_extractor = extractor;
        self
    }

    /// Set a custom route resolver.
    #[must_use]
    pub fn with_route_resolver(mut self, resolver: RouteResolver) -> Self {
        self.route_resolver = resolver;
        self
    }

    /// Set fail-open mode (allow requests when evaluation fails).
    #[must_use]
    pub fn with_fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    /// Whether this evaluator is configured for fail-open.
    pub fn is_fail_open(&self) -> bool {
        self.fail_open
    }

    /// Get the identity extractor function.
    pub fn identity_extractor(&self) -> IdentityExtractor {
        self.identity_extractor
    }

    /// Get the route resolver function.
    pub fn route_resolver(&self) -> RouteResolver {
        self.route_resolver
    }

    /// Evaluate an HTTP request, producing a verdict and signed receipt.
    pub fn evaluate(
        &self,
        method: &str,
        path: &str,
        caller: CallerIdentity,
        headers: &http::HeaderMap,
        body_hash: Option<String>,
        body_length: u64,
    ) -> Result<EvaluationResult, ArcTowerError> {
        let http_method = parse_method(method)?;
        let route_pattern = (self.route_resolver)(method, path);
        let request_id = uuid::Uuid::now_v7().to_string();

        let mut evidence = Vec::new();

        // Determine verdict based on method safety and capability token.
        let verdict = if http_method.is_safe() {
            evidence.push(GuardEvidence {
                guard_name: "DefaultPolicyGuard".to_string(),
                verdict: true,
                details: Some("safe method, session-scoped allow".to_string()),
            });
            Verdict::Allow
        } else {
            // Check for capability token.
            let has_capability = headers.get("x-arc-capability").is_some()
                || headers.get("X-Arc-Capability").is_some();
            if has_capability {
                evidence.push(GuardEvidence {
                    guard_name: "CapabilityGuard".to_string(),
                    verdict: true,
                    details: Some("capability token presented".to_string()),
                });
                Verdict::Allow
            } else {
                evidence.push(GuardEvidence {
                    guard_name: "CapabilityGuard".to_string(),
                    verdict: false,
                    details: Some("side-effect route requires X-Arc-Capability header".to_string()),
                });
                Verdict::deny(
                    "side-effect route requires a capability token",
                    "CapabilityGuard",
                )
            }
        };

        let response_status = if verdict.is_allowed() { 200 } else { 403 };

        let caller_identity_hash = caller
            .identity_hash()
            .map_err(|e| ArcTowerError::IdentityExtraction(format!("hash failed: {e}")))?;

        let arc_request = ArcHttpRequest {
            request_id: request_id.clone(),
            method: http_method,
            route_pattern: route_pattern.clone(),
            path: path.to_string(),
            query: HashMap::new(),
            headers: HashMap::new(),
            caller,
            body_hash: body_hash.clone(),
            body_length,
            session_id: None,
            capability_id: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let content_hash = arc_request
            .content_hash()
            .map_err(|e| ArcTowerError::Evaluation(format!("content hash failed: {e}")))?;

        let receipt_id = uuid::Uuid::now_v7().to_string();
        let body = HttpReceiptBody {
            id: receipt_id,
            request_id,
            route_pattern,
            method: http_method,
            caller_identity_hash,
            session_id: None,
            verdict: verdict.clone(),
            evidence: evidence.clone(),
            response_status,
            timestamp: arc_request.timestamp,
            content_hash,
            policy_hash: self.policy_hash.clone(),
            capability_id: None,
            metadata: None,
            kernel_key: self.keypair.public_key(),
        };

        let receipt = HttpReceipt::sign(body, &self.keypair)
            .map_err(|e| ArcTowerError::ReceiptSign(format!("signing failed: {e}")))?;

        Ok(EvaluationResult {
            verdict,
            receipt,
            evidence,
        })
    }
}

impl Clone for ArcEvaluator {
    fn clone(&self) -> Self {
        Self {
            keypair: Arc::clone(&self.keypair),
            policy_hash: self.policy_hash.clone(),
            identity_extractor: self.identity_extractor,
            route_resolver: self.route_resolver,
            fail_open: self.fail_open,
        }
    }
}

/// Parse an HTTP method string into the arc-http-core HttpMethod enum.
fn parse_method(method: &str) -> Result<HttpMethod, ArcTowerError> {
    match method.to_uppercase().as_str() {
        "GET" => Ok(HttpMethod::Get),
        "POST" => Ok(HttpMethod::Post),
        "PUT" => Ok(HttpMethod::Put),
        "PATCH" => Ok(HttpMethod::Patch),
        "DELETE" => Ok(HttpMethod::Delete),
        "HEAD" => Ok(HttpMethod::Head),
        "OPTIONS" => Ok(HttpMethod::Options),
        other => Err(ArcTowerError::Evaluation(format!(
            "unsupported HTTP method: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_safe_method_allowed() {
        let keypair = Keypair::generate();
        let evaluator = ArcEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();

        let result = evaluator
            .evaluate("GET", "/pets", caller, &headers, None, 0)
            .unwrap_or_else(|e| panic!("evaluation failed: {e}"));

        assert!(result.verdict.is_allowed());
        assert!(result
            .receipt
            .verify_signature()
            .unwrap_or_else(|e| panic!("verify failed: {e}")));
    }

    #[test]
    fn evaluate_unsafe_method_denied_without_capability() {
        let keypair = Keypair::generate();
        let evaluator = ArcEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();

        let result = evaluator
            .evaluate("POST", "/pets", caller, &headers, None, 0)
            .unwrap_or_else(|e| panic!("evaluation failed: {e}"));

        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.response_status, 403);
        assert!(result
            .receipt
            .verify_signature()
            .unwrap_or_else(|e| panic!("verify failed: {e}")));
    }

    #[test]
    fn evaluate_unsafe_method_allowed_with_capability() {
        let keypair = Keypair::generate();
        let evaluator = ArcEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-arc-capability",
            http::HeaderValue::from_static("cap-123"),
        );

        let result = evaluator
            .evaluate("POST", "/pets", caller, &headers, None, 0)
            .unwrap_or_else(|e| panic!("evaluation failed: {e}"));

        assert!(result.verdict.is_allowed());
    }

    #[test]
    fn evaluate_invalid_method() {
        let keypair = Keypair::generate();
        let evaluator = ArcEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();

        let err = evaluator.evaluate("FOOBAR", "/pets", caller, &headers, None, 0);
        assert!(err.is_err());
    }

    #[test]
    fn evaluator_clone() {
        let keypair = Keypair::generate();
        let evaluator = ArcEvaluator::new(keypair, "test-policy".to_string());
        let cloned = evaluator.clone();

        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();

        let r1 = evaluator
            .evaluate("GET", "/test", caller.clone(), &headers, None, 0)
            .unwrap_or_else(|e| panic!("r1 failed: {e}"));
        let r2 = cloned
            .evaluate("GET", "/test", caller, &headers, None, 0)
            .unwrap_or_else(|e| panic!("r2 failed: {e}"));

        // Both should produce valid receipts with the same kernel key.
        assert!(r1.verdict.is_allowed());
        assert!(r2.verdict.is_allowed());
        assert_eq!(r1.receipt.kernel_key, r2.receipt.kernel_key);
    }
}
