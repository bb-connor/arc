//! `oauth_introspection`: an opaque access token presented as a bearer at
//! the edge and verified through RFC 7662 token introspection.
//!
//! The token is posted to the `introspection_url` of the one provider record
//! the `oauth_introspection` rules reference, with the edge's own client
//! credentials as HTTP Basic. The response must say `active: true` and carry
//! `exp`; `iss`, when present, equals the record issuer, and when the record
//! lists audiences some `aud` is among them. The principal and tenant come
//! from the record's subject mapping over the response members. The
//! evidence is the digest of the response bytes, and the replay key is the
//! digest of the token bytes. A response carrying `cnf` refuses: no sender
//! proof reaches this verifier.

use async_trait::async_trait;
use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::{HttpsUrl, Sha256Digest};
use chio_core::sha256;
use chio_egress_contract::{
    client_builder_with_contract, send_with_contract, ContractClient, HttpEgressContract,
};
use serde_json::{Map, Value};

use super::super::claims::{
    audience_in, mapped_identity, required_seconds, scope_values, seconds, string,
};
use super::super::error::RootExchangeError;
use super::super::evidence::AnchorEvidence;
use super::super::exchange::{check_record, MatchInput, RootExchange};
use super::super::provider::ProviderRecord;
use super::super::replay::{ReplayKey, ReplayNamespace};
use super::sender;

const KIND: AnchorKind = AnchorKind::OauthIntrospection;

/// Upper bound on an introspection response body.
pub const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 64 * 1024;

/// Posts a token to an RFC 7662 introspection endpoint and returns the
/// exact response body of a successful response.
#[async_trait]
pub trait TokenIntrospector: Send + Sync {
    async fn introspect(
        &self,
        endpoint: &HttpsUrl,
        token: &str,
    ) -> Result<Vec<u8>, RootExchangeError>;
}

/// The production introspector: every request goes through the
/// `HttpEgressContract`, authenticated with the edge's own client
/// credentials (`--auth-introspection-client-id` and
/// `CHIO_MCP_AUTH_INTROSPECTION_CLIENT_SECRET`).
pub struct HttpTokenIntrospector {
    contract: HttpEgressContract,
    client: ContractClient,
    client_id: String,
    client_secret: String,
}

impl HttpTokenIntrospector {
    pub fn new(
        contract: HttpEgressContract,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, RootExchangeError> {
        let client = client_builder_with_contract(&contract)
            .build()
            .map_err(|error| RootExchangeError::IntrospectionUnavailable(error.to_string()))?;
        Ok(Self {
            contract,
            client,
            client_id,
            client_secret,
        })
    }
}

#[async_trait]
impl TokenIntrospector for HttpTokenIntrospector {
    async fn introspect(
        &self,
        endpoint: &HttpsUrl,
        token: &str,
    ) -> Result<Vec<u8>, RootExchangeError> {
        let unavailable = |error: String| RootExchangeError::IntrospectionUnavailable(error);
        let request = self
            .client
            .post(endpoint.as_str())
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("token", token)])
            .build()
            .map_err(|error| unavailable(error.to_string()))?;
        let response = send_with_contract(&self.contract, &self.client, request)
            .await
            .map_err(|error| unavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(unavailable(format!("status {}", response.status())));
        }
        Ok(response.body().to_vec())
    }
}

/// The one provider record the `oauth_introspection` rules reference,
/// pinned before any token or credential is sent to it: every referencing
/// rule must find it registered under its own id, enabled, of the
/// `oauth_introspection` kind and with the identity digest the rule pins.
/// Two distinct records refuse: an opaque token names no issuer to choose
/// between them.
fn introspection_record(exchange: &RootExchange) -> Result<&ProviderRecord, RootExchangeError> {
    let mut chosen: Option<&ProviderRecord> = None;
    for rule in &exchange.policy.policy().rules {
        if rule.match_.anchor_kind != KIND {
            continue;
        }
        let Some(record_id) = rule.match_.provider_record_id.as_ref() else {
            return Err(RootExchangeError::KindNotExchanged(KIND));
        };
        let record = exchange
            .providers
            .get(record_id.as_str())
            .ok_or_else(|| RootExchangeError::ProviderRecordMissing(record_id.to_string()))?;
        if &record.identity().provider_id != record_id {
            return Err(RootExchangeError::ProviderRecordInvalid {
                record: record_id.to_string(),
                reason: "registered under another provider_id".to_owned(),
            });
        }
        check_record(rule, record, KIND)?;
        match chosen {
            Some(seen) if seen.identity().provider_id != record.identity().provider_id => {
                return Err(RootExchangeError::IntrospectionRecordAmbiguous);
            }
            _ => chosen = Some(record),
        }
    }
    chosen.ok_or(RootExchangeError::RuleMatchCount { matched: 0 })
}

/// Verify the opaque bearer `token` at `now` (Unix seconds).
pub async fn verify(
    exchange: &RootExchange,
    token: &str,
    now: u64,
    introspector: &dyn TokenIntrospector,
) -> Result<AnchorEvidence, RootExchangeError> {
    let record = introspection_record(exchange)?;
    let identity = record.identity();
    let provider_id = identity.provider_id.as_str();
    let endpoint = identity.introspection_url.as_ref().ok_or_else(|| {
        RootExchangeError::ProviderRecordInvalid {
            record: provider_id.to_owned(),
            reason: "record has no introspection_url".to_owned(),
        }
    })?;
    let body = introspector.introspect(endpoint, token).await?;
    if body.len() > MAX_INTROSPECTION_RESPONSE_BYTES {
        return Err(RootExchangeError::IntrospectionInvalid(
            "response exceeds the size bound",
        ));
    }
    let response: Map<String, Value> =
        crate::input::document(&body, MAX_INTROSPECTION_RESPONSE_BYTES).map_err(|_| {
            RootExchangeError::IntrospectionInvalid("response is not a duplicate-free JSON object")
        })?;
    match response.get("active") {
        Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) => return Err(RootExchangeError::IntrospectionInactive),
        _ => {
            return Err(RootExchangeError::IntrospectionInvalid(
                "active is not a boolean",
            ))
        }
    }
    let issuer = identity.issuer.as_str();
    if string(&response, "iss")?.is_some_and(|iss| iss != issuer) {
        return Err(RootExchangeError::IssuerMismatch);
    }
    if !identity.audiences.is_empty() && !audience_in(&response, &identity.audiences) {
        return Err(RootExchangeError::AudienceMismatch);
    }
    let response_scope = scope_values(&response)?;
    let (rule, _) = exchange.match_rule(MatchInput {
        kind: KIND,
        issuer,
        alg: None,
        claims: &response,
        scope_values: &response_scope,
        provider_id: Some(provider_id),
    })?;
    let skew = rule.max_clock_skew_secs.unwrap_or(0);
    let exp = required_seconds(&response, "exp")?;
    if now >= exp.saturating_add(skew) {
        return Err(RootExchangeError::AssertionExpired);
    }
    if seconds(&response, "nbf")?.is_some_and(|nbf| nbf > now.saturating_add(skew)) {
        return Err(RootExchangeError::AssertionNotYetValid);
    }
    let iat = required_seconds(&response, "iat")?;
    if iat > now.saturating_add(skew) {
        return Err(RootExchangeError::AssertionIssuedInFuture);
    }
    if exp <= iat {
        return Err(RootExchangeError::ClaimInvalid("exp"));
    }
    sender::refuse_bound(&response)?;
    let (principal, tenant) = mapped_identity(&response, identity)?;
    let token_digest = Sha256Digest::from_hash(sha256(token.as_bytes()));
    Ok(AnchorEvidence {
        kind: KIND,
        replay_key: ReplayKey {
            namespace: ReplayNamespace::Assertion(KIND),
            issuer: issuer.to_owned(),
            id: format!("token:{token_digest}"),
        },
        issuer: issuer.to_owned(),
        principal,
        tenant,
        token_iat: iat,
        token_exp: exp,
        jws: None,
        artifact_digest: Some(Sha256Digest::from_hash(sha256(&body))),
        request_digest: token_digest,
        scope_values: response_scope,
        claims: response,
        provider_id: Some(provider_id.to_owned()),
        scope_bound: None,
        holder: None,
    })
}
