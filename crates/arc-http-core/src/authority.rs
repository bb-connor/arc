use std::collections::HashMap;
use std::sync::Arc;

use arc_core_types::capability::CapabilityToken;
use arc_core_types::crypto::Keypair;
use arc_core_types::receipt::GuardEvidence;
use thiserror::Error;

use crate::{
    http_status_metadata_decision, http_status_metadata_final, ArcHttpRequest, CallerIdentity,
    HttpMethod, HttpReceipt, HttpReceiptBody, Verdict,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpAuthorityPolicy {
    SessionAllow,
    DenyByDefault,
}

#[derive(Clone)]
pub struct HttpAuthority {
    keypair: Arc<Keypair>,
    policy_hash: String,
}

impl std::fmt::Debug for HttpAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuthority")
            .field("policy_hash", &self.policy_hash)
            .finish_non_exhaustive()
    }
}

pub struct HttpAuthorityInput<'a> {
    pub request_id: String,
    pub method: HttpMethod,
    pub route_pattern: String,
    pub path: &'a str,
    pub query: &'a HashMap<String, String>,
    pub caller: CallerIdentity,
    pub body_hash: Option<String>,
    pub body_length: u64,
    pub session_id: Option<String>,
    pub capability_id_hint: Option<&'a str>,
    pub presented_capability: Option<&'a str>,
    pub policy: HttpAuthorityPolicy,
}

#[derive(Debug, Clone)]
pub struct PreparedHttpEvaluation {
    pub verdict: Verdict,
    pub evidence: Vec<GuardEvidence>,
    pub request_id: String,
    pub route_pattern: String,
    pub http_method: HttpMethod,
    pub caller_identity_hash: String,
    pub content_hash: String,
    pub session_id: Option<String>,
    pub capability_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpAuthorityEvaluation {
    pub verdict: Verdict,
    pub receipt: HttpReceipt,
    pub evidence: Vec<GuardEvidence>,
}

#[derive(Debug, Error)]
pub enum HttpAuthorityError {
    #[error("failed to hash caller identity: {0}")]
    CallerIdentity(String),

    #[error("failed to compute content hash: {0}")]
    ContentHash(String),

    #[error("failed to sign receipt: {0}")]
    ReceiptSign(String),
}

impl HttpAuthority {
    #[must_use]
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            keypair: Arc::new(keypair),
            policy_hash,
        }
    }

    pub fn evaluate(
        &self,
        input: HttpAuthorityInput<'_>,
    ) -> Result<HttpAuthorityEvaluation, HttpAuthorityError> {
        let prepared = self.prepare(input)?;
        let receipt = self.sign_decision_receipt(&prepared)?;
        Ok(HttpAuthorityEvaluation {
            verdict: prepared.verdict.clone(),
            receipt,
            evidence: prepared.evidence.clone(),
        })
    }

    pub fn prepare(
        &self,
        input: HttpAuthorityInput<'_>,
    ) -> Result<PreparedHttpEvaluation, HttpAuthorityError> {
        let mut evidence = Vec::new();
        let capability_id = match resolve_capability_id(
            input.capability_id_hint,
            input.presented_capability,
        ) {
            Ok(capability_id) => capability_id,
            Err(error) => {
                evidence.push(GuardEvidence {
                    guard_name: "CapabilityGuard".to_string(),
                    verdict: false,
                    details: Some(error.clone()),
                });
                let verdict = Verdict::deny(&error, "CapabilityGuard");
                return self.build_prepared(input, verdict, evidence, None);
            }
        };

        let verdict = evaluate_policy(input.policy, &capability_id, &mut evidence);
        self.build_prepared(input, verdict, evidence, capability_id)
    }

    pub fn sign_decision_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        self.sign_receipt(
            prepared,
            decision_status(&prepared.verdict),
            Some(http_status_metadata_decision()),
        )
    }

    pub fn finalize_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
        response_status: u16,
        decision_receipt_id: Option<&str>,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        self.sign_receipt(
            prepared,
            response_status,
            Some(http_status_metadata_final(decision_receipt_id)),
        )
    }

    pub fn finalize_decision_receipt(
        &self,
        decision_receipt: &HttpReceipt,
        response_status: u16,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        let mut body = decision_receipt.body();
        let decision_receipt_id = body.id.clone();
        body.id = uuid::Uuid::now_v7().to_string();
        body.response_status = response_status;
        body.timestamp = chrono::Utc::now().timestamp() as u64;
        body.metadata = Some(http_status_metadata_final(Some(&decision_receipt_id)));
        HttpReceipt::sign(body, self.keypair.as_ref())
            .map_err(|e| HttpAuthorityError::ReceiptSign(e.to_string()))
    }

    fn build_prepared(
        &self,
        input: HttpAuthorityInput<'_>,
        verdict: Verdict,
        evidence: Vec<GuardEvidence>,
        capability_id: Option<String>,
    ) -> Result<PreparedHttpEvaluation, HttpAuthorityError> {
        let caller_identity_hash = input
            .caller
            .identity_hash()
            .map_err(|e| HttpAuthorityError::CallerIdentity(e.to_string()))?;

        let arc_request = ArcHttpRequest {
            request_id: input.request_id.clone(),
            method: input.method,
            route_pattern: input.route_pattern.clone(),
            path: input.path.to_string(),
            query: input.query.clone(),
            headers: HashMap::new(),
            caller: input.caller,
            body_hash: input.body_hash,
            body_length: input.body_length,
            session_id: input.session_id.clone(),
            capability_id: capability_id.clone(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let content_hash = arc_request
            .content_hash()
            .map_err(|e| HttpAuthorityError::ContentHash(e.to_string()))?;

        Ok(PreparedHttpEvaluation {
            verdict,
            evidence,
            request_id: input.request_id,
            route_pattern: input.route_pattern,
            http_method: input.method,
            caller_identity_hash,
            content_hash,
            session_id: input.session_id,
            capability_id,
        })
    }

    fn sign_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
        response_status: u16,
        metadata: Option<serde_json::Value>,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        let body = HttpReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            request_id: prepared.request_id.clone(),
            route_pattern: prepared.route_pattern.clone(),
            method: prepared.http_method,
            caller_identity_hash: prepared.caller_identity_hash.clone(),
            session_id: prepared.session_id.clone(),
            verdict: prepared.verdict.clone(),
            evidence: prepared.evidence.clone(),
            response_status,
            timestamp: chrono::Utc::now().timestamp() as u64,
            content_hash: prepared.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            capability_id: prepared.capability_id.clone(),
            metadata,
            kernel_key: self.keypair.public_key(),
        };

        HttpReceipt::sign(body, self.keypair.as_ref())
            .map_err(|e| HttpAuthorityError::ReceiptSign(e.to_string()))
    }
}

fn decision_status(verdict: &Verdict) -> u16 {
    match verdict {
        Verdict::Allow => 200,
        Verdict::Deny { http_status, .. } => *http_status,
        Verdict::Cancel { .. } | Verdict::Incomplete { .. } => 500,
    }
}

fn evaluate_policy(
    policy: HttpAuthorityPolicy,
    capability_id: &Option<String>,
    evidence: &mut Vec<GuardEvidence>,
) -> Verdict {
    match policy {
        HttpAuthorityPolicy::SessionAllow => {
            evidence.push(GuardEvidence {
                guard_name: "DefaultPolicyGuard".to_string(),
                verdict: true,
                details: Some("safe method, session-scoped allow".to_string()),
            });
            Verdict::Allow
        }
        HttpAuthorityPolicy::DenyByDefault => match capability_id {
            Some(_) => {
                evidence.push(GuardEvidence {
                    guard_name: "CapabilityGuard".to_string(),
                    verdict: true,
                    details: Some("valid capability token presented".to_string()),
                });
                Verdict::Allow
            }
            None => {
                evidence.push(GuardEvidence {
                    guard_name: "CapabilityGuard".to_string(),
                    verdict: false,
                    details: Some(
                        "side-effect route requires a valid capability token".to_string(),
                    ),
                });
                Verdict::deny(
                    "side-effect route requires a capability token",
                    "CapabilityGuard",
                )
            }
        },
    }
}

fn validate_capability_token(raw: &str) -> Result<CapabilityToken, String> {
    let token: CapabilityToken =
        serde_json::from_str(raw).map_err(|e| format!("invalid capability token: {e}"))?;
    let signature_valid = token
        .verify_signature()
        .map_err(|e| format!("capability signature verification failed: {e}"))?;
    if !signature_valid {
        return Err("capability signature verification failed".to_string());
    }
    token
        .validate_time(chrono::Utc::now().timestamp() as u64)
        .map_err(|e| format!("invalid capability token: {e}"))?;
    Ok(token)
}

fn resolve_capability_id(
    capability_id_hint: Option<&str>,
    presented_capability: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(raw_capability) = presented_capability else {
        return Ok(None);
    };

    let token = validate_capability_token(raw_capability)?;
    if let Some(hint) = capability_id_hint {
        if hint != token.id {
            return Err("capability_id does not match the presented capability token".to_string());
        }
    }
    Ok(Some(token.id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core_types::capability::{ArcScope, CapabilityTokenBody};
    use crate::{http_status_scope, AuthMethod, ARC_DECISION_RECEIPT_ID_KEY, ARC_HTTP_STATUS_SCOPE_DECISION, ARC_HTTP_STATUS_SCOPE_FINAL};

    fn valid_capability_token_json(id: &str) -> String {
        let issuer = Keypair::generate();
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope: ArcScope::default(),
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .unwrap();
        serde_json::to_string(&token).unwrap()
    }

    fn caller() -> CallerIdentity {
        CallerIdentity {
            subject: "tester".to_string(),
            auth_method: AuthMethod::Anonymous,
            verified: false,
            tenant: None,
            agent_id: None,
        }
    }

    fn authority() -> HttpAuthority {
        HttpAuthority::new(Keypair::generate(), "policy-hash".to_string())
    }

    #[test]
    fn safe_policy_allows_without_capability() {
        let query = HashMap::new();
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-1".to_string(),
                method: HttpMethod::Get,
                route_pattern: "/pets".to_string(),
                path: "/pets",
                query: &query,
                caller: caller(),
                body_hash: None,
                body_length: 0,
                session_id: None,
                capability_id_hint: None,
                presented_capability: None,
                policy: HttpAuthorityPolicy::SessionAllow,
            })
            .unwrap();

        assert!(result.verdict.is_allowed());
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn deny_by_default_requires_capability() {
        let query = HashMap::new();
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-2".to_string(),
                method: HttpMethod::Post,
                route_pattern: "/pets".to_string(),
                path: "/pets",
                query: &query,
                caller: caller(),
                body_hash: Some("abc".to_string()),
                body_length: 3,
                session_id: None,
                capability_id_hint: None,
                presented_capability: None,
                policy: HttpAuthorityPolicy::DenyByDefault,
            })
            .unwrap();

        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.response_status, 403);
    }

    #[test]
    fn valid_capability_allows_deny_by_default() {
        let query = HashMap::new();
        let capability = valid_capability_token_json("cap-123");
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-3".to_string(),
                method: HttpMethod::Patch,
                route_pattern: "/pets/{petId}".to_string(),
                path: "/pets/42",
                query: &query,
                caller: caller(),
                body_hash: Some("def".to_string()),
                body_length: 3,
                session_id: Some("session-1".to_string()),
                capability_id_hint: None,
                presented_capability: Some(&capability),
                policy: HttpAuthorityPolicy::DenyByDefault,
            })
            .unwrap();

        assert!(result.verdict.is_allowed());
        assert_eq!(result.receipt.capability_id.as_deref(), Some("cap-123"));
        assert_eq!(result.receipt.session_id.as_deref(), Some("session-1"));
    }

    #[test]
    fn capability_hint_mismatch_becomes_denial() {
        let query = HashMap::new();
        let capability = valid_capability_token_json("cap-123");
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-4".to_string(),
                method: HttpMethod::Put,
                route_pattern: "/pets/42".to_string(),
                path: "/pets/42",
                query: &query,
                caller: caller(),
                body_hash: None,
                body_length: 0,
                session_id: None,
                capability_id_hint: Some("cap-other"),
                presented_capability: Some(&capability),
                policy: HttpAuthorityPolicy::DenyByDefault,
            })
            .unwrap();

        assert!(result.verdict.is_denied());
        assert!(result.receipt.capability_id.is_none());
    }

    #[test]
    fn finalized_receipt_links_decision_receipt() {
        let query = HashMap::new();
        let shared = authority();
        let decision = shared
            .evaluate(HttpAuthorityInput {
                request_id: "req-5".to_string(),
                method: HttpMethod::Get,
                route_pattern: "/pets".to_string(),
                path: "/pets",
                query: &query,
                caller: caller(),
                body_hash: None,
                body_length: 0,
                session_id: None,
                capability_id_hint: None,
                presented_capability: None,
                policy: HttpAuthorityPolicy::SessionAllow,
            })
            .unwrap()
            .receipt;
        let final_receipt = shared.finalize_decision_receipt(&decision, 204).unwrap();

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
                .and_then(|metadata| metadata.get(ARC_DECISION_RECEIPT_ID_KEY))
                .and_then(serde_json::Value::as_str),
            Some(decision.id.as_str())
        );
    }
}
