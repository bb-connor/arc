//! Bearer JWTs verified against the pinned keys of a provider record.

use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::Sha256Digest;
use chio_core::sha256;
use serde_json::{Map, Value};

use super::super::claims::{audience_in, check_times, mapped_identity, required_string};
use super::super::error::RootExchangeError;
use super::super::evidence::{AnchorEvidence, JwsEvidence};
use super::super::exchange::{check_record, MatchInput, RootExchange};
use super::super::jws::{CompactJws, VerifiedJws, VerifyingKey};
use super::super::key_lookup::IdpKeyLookup;
use super::super::replay::{ReplayKey, ReplayNamespace};
use super::sender;

/// Reads the scope values of a bearer JWT's claims.
pub(super) type ScopeValues = fn(&Map<String, Value>) -> Result<Vec<String>, RootExchangeError>;

/// Derives the replay id from verified claims and the digest of the token bytes.
pub(super) type ReplayId =
    fn(&Map<String, Value>, &Sha256Digest) -> Result<String, RootExchangeError>;

/// How a bearer JWT of one kind names its scope values and its replay id.
pub(super) struct BearerJwsKind {
    pub(super) kind: AnchorKind,
    pub(super) scope_values: ScopeValues,
    pub(super) replay_id: ReplayId,
}

/// Verify `token` as a bearer JWT of `spec.kind` at `now`.
///
/// The one rule the unverified claims match selects the provider record and
/// the clock skew. The signature verifies against the record's key for
/// `kid`; then `iss` equals the record issuer, some `aud` is in the
/// record's audiences, and the time rules hold. A token carrying `cnf`
/// refuses: no sender proof reaches this verifier.
pub(super) async fn verify(
    exchange: &RootExchange,
    spec: &BearerJwsKind,
    token: &str,
    now: u64,
    keys: &dyn IdpKeyLookup,
) -> Result<AnchorEvidence, RootExchangeError> {
    let jws = CompactJws::parse(token)?;
    let unverified_scope = (spec.scope_values)(jws.claims())?;
    let (rule, record) = exchange.match_rule(MatchInput {
        kind: spec.kind,
        issuer: required_string(jws.claims(), "iss")?,
        alg: Some(jws.header().alg),
        claims: jws.claims(),
        scope_values: &unverified_scope,
        provider_id: None,
    })?;
    let record = record.ok_or(RootExchangeError::KindNotExchanged(spec.kind))?;
    check_record(rule, record, spec.kind)?;
    let resolved = keys
        .resolve(
            record.identity(),
            jws.header().kid.as_str(),
            jws.header().alg,
            now,
        )
        .await?;
    let key = VerifyingKey::from_jwk(&resolved.jwk).ok_or(RootExchangeError::IdpKeyUnusable)?;
    let jws: VerifiedJws = jws.verify_with(&key)?;
    let claims = jws.claims();
    let identity = record.identity();
    let issuer = required_string(claims, "iss")?;
    if issuer != identity.issuer.as_str() {
        return Err(RootExchangeError::IssuerMismatch);
    }
    if !audience_in(claims, &identity.audiences) {
        return Err(RootExchangeError::AudienceMismatch);
    }
    let (iat, exp) = check_times(claims, now, rule.max_clock_skew_secs.unwrap_or(0))?;
    sender::refuse_bound(claims)?;
    let (principal, tenant) = mapped_identity(claims, identity)?;
    let token_digest = Sha256Digest::from_hash(sha256(token.as_bytes()));
    Ok(AnchorEvidence {
        kind: spec.kind,
        replay_key: ReplayKey {
            namespace: ReplayNamespace::Assertion(spec.kind),
            issuer: issuer.to_owned(),
            id: (spec.replay_id)(claims, &token_digest)?,
        },
        issuer: issuer.to_owned(),
        principal,
        tenant,
        token_iat: iat,
        token_exp: exp,
        jws: Some(JwsEvidence {
            key_snapshot_digest: resolved.snapshot_digest,
            kid: jws.header().kid.clone(),
            alg: jws.header().alg,
        }),
        artifact_digest: Some(*jws.artifact_digest()),
        request_digest: token_digest,
        scope_values: (spec.scope_values)(claims)?,
        claims: claims.clone(),
        provider_id: Some(identity.provider_id.to_string()),
        scope_bound: None,
        holder: None,
    })
}
