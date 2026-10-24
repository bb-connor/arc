//! The ID-JAG root exchange: from an authenticated token request to a
//! prepared anchored root.

use std::collections::{BTreeMap, BTreeSet};

use chio_core::canonical_json_bytes;
use chio_core::capability::anchor::{AnchorKind, RootAnchor};
use chio_core::capability::scope::{ChioScope, ToolGrant};
use chio_core::capability::token::CapabilityTokenBody;
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::rng::Rng;
use chio_core::root_authority::{
    ClaimMode, ClaimValue, DelegationAnchor, DelegationAnchorFields, DelegationContext,
    DelegationContextFields, DelegationExchange, HolderClass, LoadedRootPolicy, MatchClaims,
    ProviderRecordKind, RecordedClaims, RootAuthorityShapeError, RootPolicyRule, SaltRef,
    SaltedCommitment, Sha256Digest, Text, Uri, CHIO_DELEGATION_CONTEXT_SCHEMA,
};
use chio_core::Sha256State;
use serde_json::{Map, Value};

use super::client_auth::{authenticate_client, ClientAuthContext, ClientRegistry};
use super::error::RootExchangeError;
use super::grant::IdJagGrant;
use super::id_jag::{verify_id_jag_claims, IdJagAudience, IdJagTiming, VerifiedIdJag};
use super::jws::{CompactJws, VerifyingKey};
use super::key_lookup::IdpKeyLookup;
use super::provider::ProviderRecord;
use super::replay::{ExchangeReplayStore, ReplayBinding, ReplayKey, ReplayNamespace};

const SUBJECT_COMMITMENT_DOMAIN: &[u8] = b"chio.delegation-context.subject.v1\0";
const TENANT_COMMITMENT_DOMAIN: &[u8] = b"chio.delegation-context.tenant.v1\0";
const CLAIM_COMMITMENT_DOMAIN: &[u8] = b"chio.delegation-context.claim.v1\0";

/// Configuration of the exchange inside the provider's `serve-http` process.
pub struct RootExchange {
    pub policy: LoadedRootPolicy,
    /// Provider records by `provider_id`.
    pub providers: BTreeMap<String, ProviderRecord>,
    pub clients: ClientRegistry,
    /// The pinned exchange key that signs the root and is recorded in the context.
    pub exchange_key: PublicKey,
    /// The local authorization server issuer.
    pub authorization_server: String,
    /// The token endpoint URL client assertions name as `aud`.
    pub token_endpoint: String,
    /// The advertised protected resource.
    pub protected_resource: String,
    /// Clock skew admitted on client assertions.
    pub client_assertion_skew_secs: u64,
}

/// Collaborators of one exchange.
#[derive(Clone, Copy)]
pub struct ExchangeServices<'a> {
    pub keys: &'a dyn IdpKeyLookup,
    pub replay: &'a dyn ExchangeReplayStore,
    /// Randomness for salts, edge-session subject keys and capability
    /// identifiers. Every draw happens before the ID-JAG replay bind, so a
    /// failed draw denies the exchange with the ID-JAG unbound.
    pub entropy: &'a (dyn Rng + Send + Sync),
}

/// One salted opening the disclosure store keeps under `salt_ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextOpening {
    pub salt_ref: SaltRef,
    pub salt: [u8; 32],
    pub value: Value,
}

/// An anchored root ready to sign: the unsigned root body, its anchor, the
/// delegation context it is bound to and the openings of every commitment.
///
/// It is not a capability. Issuing it needs `root_anchor` as a signed member
/// of the capability body, so the unsigned body never leaves this module;
/// callers read its members only.
#[derive(Debug, Clone)]
pub struct PreparedAnchoredRoot {
    pub(super) body: CapabilityTokenBody,
    anchor: RootAnchor,
    context: DelegationContext,
    openings: Vec<ContextOpening>,
    replay_key: ReplayKey,
    holder: HolderClass,
    response_scope: Option<String>,
}

impl PreparedAnchoredRoot {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.body.id
    }
    #[must_use]
    pub fn issuer(&self) -> &PublicKey {
        &self.body.issuer
    }
    #[must_use]
    pub fn subject(&self) -> &PublicKey {
        &self.body.subject
    }
    #[must_use]
    pub fn scope(&self) -> &ChioScope {
        &self.body.scope
    }
    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.body.issued_at
    }
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.body.expires_at
    }
    #[must_use]
    pub fn anchor(&self) -> &RootAnchor {
        &self.anchor
    }
    #[must_use]
    pub fn context(&self) -> &DelegationContext {
        &self.context
    }
    #[must_use]
    pub fn openings(&self) -> &[ContextOpening] {
        &self.openings
    }
    #[must_use]
    pub fn replay_key(&self) -> &ReplayKey {
        &self.replay_key
    }
    #[must_use]
    pub fn holder(&self) -> HolderClass {
        self.holder
    }
    /// The `scope` the token response carries (RFC 6749 section 5.1): the
    /// identity-provider scope values that contribute a grant to the root,
    /// present when they differ from the requested scope.
    #[must_use]
    pub fn response_scope(&self) -> Option<&str> {
        self.response_scope.as_deref()
    }
}

fn random<const N: usize>(entropy: &dyn Rng) -> Result<[u8; N], RootExchangeError> {
    let mut bytes = [0_u8; N];
    entropy
        .fill_bytes(&mut bytes)
        .map_err(|_| RootExchangeError::EntropyUnavailable)?;
    Ok(bytes)
}

fn commitment(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut state = Sha256State::new();
    state.update(domain);
    for part in parts {
        state.update(part);
    }
    Sha256Digest::from_hash(state.finalize())
}

fn salt_ref(value: &str) -> Result<SaltRef, RootExchangeError> {
    SaltRef::new(value).map_err(|error| RootExchangeError::Canonicalization(error.to_string()))
}

/// Whether the token satisfies the rule's `match.claims`. A string claim
/// must equal a listed value; every `scope` value must be listed.
fn claims_match(
    rule_claims: Option<&MatchClaims>,
    token: &Map<String, Value>,
    scope_values: &[String],
) -> bool {
    let Some(rule_claims) = rule_claims else {
        return true;
    };
    let listed = |allowed: &[Text], value: &str| allowed.iter().any(|item| item.as_str() == value);
    let string_claims = [
        ("client_id", &rule_claims.client_id),
        ("sub", &rule_claims.sub),
        ("resource", &rule_claims.resource),
        ("azp", &rule_claims.azp),
        ("appid", &rule_claims.appid),
        ("oid", &rule_claims.oid),
        ("tid", &rule_claims.tid),
    ];
    let strings_hold = string_claims.iter().all(|(name, allowed)| match allowed {
        None => true,
        Some(allowed) => {
            matches!(token.get(*name), Some(Value::String(value)) if listed(allowed, value))
        }
    });
    let scope_holds = rule_claims.scope.as_ref().is_none_or(|allowed| {
        !scope_values.is_empty() && scope_values.iter().all(|value| listed(allowed, value))
    });
    strings_hold && scope_holds
}

/// `ceiling_scope` restricted to the tools the IdP scope values project to,
/// and the scope values that contribute at least one of its grants. A
/// projection target is one `server/tool` pair; a ceiling grant covers it
/// when each side is equal or `*`, and is issued narrowed to that pair.
fn effective_scope<'a>(
    rule: &RootPolicyRule,
    scope_values: &'a [String],
) -> Result<(ChioScope, Vec<&'a str>), RootExchangeError> {
    let projection = rule
        .idp_scope_projection
        .as_ref()
        .ok_or(RootExchangeError::ScopeNotProjected)?;
    let mut projected: Vec<(&str, BTreeSet<(&str, &str)>)> = Vec::new();
    for value in scope_values {
        let targets = projection
            .get(value)
            .ok_or(RootExchangeError::ScopeNotProjected)?;
        let mut pairs = BTreeSet::new();
        for target in targets {
            let pair = target
                .as_str()
                .split_once('/')
                .filter(|(server, tool)| {
                    !server.is_empty() && !tool.is_empty() && !tool.contains('/')
                })
                .ok_or(RootExchangeError::ProjectionTargetMalformed)?;
            pairs.insert(pair);
        }
        projected.push((value.as_str(), pairs));
    }
    let covers = |pattern: &str, value: &str| pattern == "*" || pattern == value;
    let covered = |grant: &ToolGrant, (server, tool): (&str, &str)| {
        covers(&grant.server_id, server) && covers(&grant.tool_name, tool)
    };
    let tools: BTreeSet<(&str, &str)> = projected
        .iter()
        .flat_map(|(_, pairs)| pairs.iter().copied())
        .collect();
    let mut grants: Vec<ToolGrant> = Vec::new();
    for grant in &rule.ceiling_scope.grants {
        for &(server, tool) in &tools {
            if covered(grant, (server, tool)) {
                let mut narrowed = grant.clone();
                narrowed.server_id = server.to_owned();
                narrowed.tool_name = tool.to_owned();
                grants.push(narrowed);
            }
        }
    }
    if grants.is_empty() {
        return Err(RootExchangeError::EmptyEffectiveScope);
    }
    let granted_values = projected
        .iter()
        .filter(|(_, pairs)| {
            pairs.iter().any(|pair| {
                rule.ceiling_scope
                    .grants
                    .iter()
                    .any(|grant| covered(grant, *pair))
            })
        })
        .map(|(value, _)| *value)
        .collect();
    Ok((
        ChioScope {
            grants,
            ..ChioScope::default()
        },
        granted_values,
    ))
}

/// The assertion scope values the root is built from: all of them, or the
/// requested ones. A requested value the assertion does not carry refuses.
fn selected_scope_values(
    assertion: &[String],
    requested: Option<&[String]>,
) -> Result<Vec<String>, RootExchangeError> {
    let Some(requested) = requested else {
        return Ok(assertion.to_vec());
    };
    let mut selected: Vec<String> = Vec::new();
    for value in requested {
        if !assertion.contains(value) {
            return Err(RootExchangeError::RequestedScopeExceedsAssertion);
        }
        if !selected.contains(value) {
            selected.push(value.clone());
        }
    }
    Ok(selected)
}

fn recorded_claim_value(
    name: &'static str,
    verified: &VerifiedIdJag,
) -> Result<Value, RootExchangeError> {
    if name == "scope" {
        if verified.scope_values.is_empty() {
            return Err(RootExchangeError::RecordedClaimMissing(name));
        }
        return Ok(Value::Array(
            verified
                .scope_values
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ));
    }
    verified
        .claims
        .get(name)
        .cloned()
        .ok_or(RootExchangeError::RecordedClaimMissing(name))
}

fn plain_claim(name: &'static str, value: &Value) -> Result<ClaimValue, RootExchangeError> {
    let text = |value: &Value| match value {
        Value::String(value) => Text::new(value.as_str()).ok(),
        _ => None,
    };
    match value {
        Value::Array(items) => items
            .iter()
            .map(text)
            .collect::<Option<Vec<_>>>()
            .filter(|items| items.len() <= 64)
            .map(ClaimValue::List),
        other => text(other).map(ClaimValue::Plain),
    }
    .ok_or(RootExchangeError::ClaimInvalid(name))
}

fn record_claims(
    rule: &RootPolicyRule,
    verified: &VerifiedIdJag,
    entropy: &dyn Rng,
    openings: &mut Vec<ContextOpening>,
) -> Result<RecordedClaims, RootExchangeError> {
    let mut recorded = RecordedClaims::default();
    for (name, mode) in rule.recorded_claims.entries() {
        let Some(mode) = mode else {
            continue;
        };
        let value = recorded_claim_value(name, verified)?;
        let claim = match mode {
            ClaimMode::Plain => plain_claim(name, &value)?,
            ClaimMode::Committed => {
                let salt = random::<32>(entropy)?;
                let canonical = canonical_json_bytes(&value)
                    .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
                let reference = salt_ref(&format!("anchor.claims.{name}"))?;
                let commit = commitment(
                    CLAIM_COMMITMENT_DOMAIN,
                    &[name.as_bytes(), &[0], &salt, &canonical],
                );
                openings.push(ContextOpening {
                    salt_ref: reference.clone(),
                    salt,
                    value,
                });
                ClaimValue::Committed(SaltedCommitment {
                    commit,
                    salt_ref: reference,
                })
            }
        };
        let slot = match name {
            "client_id" => &mut recorded.client_id,
            "scope" => &mut recorded.scope,
            "sub" => &mut recorded.sub,
            "aud" => &mut recorded.aud,
            "resource" => &mut recorded.resource,
            "azp" => &mut recorded.azp,
            "appid" => &mut recorded.appid,
            "oid" => &mut recorded.oid,
            "tid" => &mut recorded.tid,
            _ => {
                return Err(RootExchangeError::Canonicalization(format!(
                    "claim `{name}` has no recorded slot"
                )))
            }
        };
        *slot = Some(claim);
    }
    Ok(recorded)
}

fn salted(
    domain: &[u8],
    reference: &str,
    value: &str,
    entropy: &dyn Rng,
    openings: &mut Vec<ContextOpening>,
) -> Result<SaltedCommitment, RootExchangeError> {
    let salt = random::<32>(entropy)?;
    let reference = salt_ref(reference)?;
    openings.push(ContextOpening {
        salt_ref: reference.clone(),
        salt,
        value: Value::String(value.to_owned()),
    });
    Ok(SaltedCommitment {
        commit: commitment(domain, &[&salt, value.as_bytes()]),
        salt_ref: reference,
    })
}

impl RootExchange {
    /// Run the exchange for one ID-JAG token request at `now` (Unix seconds).
    ///
    /// `sender_key` is the `cnf.chioSenderKey` the client proved; without it
    /// the root is held by the edge session. Nothing is persisted except the
    /// spent client-assertion and ID-JAG replay keys; the ID-JAG key is bound
    /// only after every other check and conversion has succeeded.
    pub async fn exchange_id_jag(
        &self,
        grant: &IdJagGrant,
        sender_key: Option<&PublicKey>,
        now: u64,
        services: ExchangeServices<'_>,
    ) -> Result<PreparedAnchoredRoot, RootExchangeError> {
        self.policy
            .check_valid_at(now)
            .map_err(|_| RootExchangeError::PolicyOutOfForce)?;
        if !self.policy.lists_exchange_key(&self.exchange_key) {
            return Err(RootExchangeError::ExchangeKeyNotListed);
        }
        if grant
            .resource()
            .is_some_and(|resource| resource != self.protected_resource)
        {
            return Err(RootExchangeError::ResourceMismatch);
        }
        let client = authenticate_client(
            &self.clients,
            grant.client_credentials(),
            ClientAuthContext {
                token_endpoint: &self.token_endpoint,
                now,
                max_clock_skew_secs: self.client_assertion_skew_secs,
            },
            services.replay,
        )?;

        let jws = CompactJws::parse(grant.id_jag())?;
        let (rule, record) = self.match_rule(&jws)?;
        let provider_id = record.identity().provider_id.as_str();
        if !record.enabled() {
            return Err(RootExchangeError::ProviderRecordDisabled(
                provider_id.to_owned(),
            ));
        }
        if record.identity().kind != ProviderRecordKind::OidcJwks {
            return Err(RootExchangeError::ProviderRecordInvalid {
                record: provider_id.to_owned(),
                reason: "record kind is not oidc_jwks".to_owned(),
            });
        }
        if Some(record.identity_digest()) != rule.match_.provider_identity_digest.as_ref() {
            return Err(RootExchangeError::ProviderIdentityMismatch(
                provider_id.to_owned(),
            ));
        }
        let resolved = services
            .keys
            .resolve(
                record.identity(),
                jws.header().kid.as_str(),
                jws.header().alg,
                now,
            )
            .await?;
        let key = VerifyingKey::from_jwk(&resolved.jwk).ok_or(RootExchangeError::IdpKeyUnusable)?;
        let jws = jws.verify_with(&key)?;
        let skew = rule.max_clock_skew_secs.unwrap_or(0);
        let verified = verify_id_jag_claims(
            &jws,
            record.identity(),
            IdJagAudience {
                authorization_server: &self.authorization_server,
                protected_resource: &self.protected_resource,
            },
            &client.client_id,
            IdJagTiming {
                now,
                max_clock_skew_secs: skew,
                max_assertion_lifetime_secs: rule.max_assertion_lifetime().unwrap_or(0),
            },
        )?;

        let holder = if sender_key.is_some() {
            HolderClass::Caller
        } else {
            HolderClass::EdgeSession
        };
        if !rule.holder_classes.contains(&holder) {
            return Err(RootExchangeError::HolderClassNotAllowed(holder));
        }
        let scope_values = selected_scope_values(&verified.scope_values, grant.requested_scope())?;
        let (scope, granted_values) = effective_scope(rule, &scope_values)?;
        if holder == HolderClass::EdgeSession
            && rule
                .ceiling_scope
                .grants
                .iter()
                .chain(&scope.grants)
                .any(|grant| grant.dpop_required == Some(true))
        {
            return Err(RootExchangeError::ProofRequiredGrantForEdgeSession);
        }
        let expires_at = now
            .saturating_add(rule.capability_ttl())
            .min(verified.exp)
            .min(self.policy.policy().valid_until);
        if expires_at <= now {
            return Err(RootExchangeError::RootLifetimeEmpty);
        }

        let mut openings = Vec::new();
        let claims = record_claims(rule, &verified, services.entropy, &mut openings)?;
        let replay_key = ReplayKey {
            namespace: ReplayNamespace::Assertion(AnchorKind::OauthIdJag),
            issuer: verified.issuer.clone(),
            id: verified.jti.clone(),
        };
        let subject = match sender_key {
            Some(key) => key.clone(),
            None => Keypair::from_seed(&random::<32>(services.entropy)?).public_key(),
        };
        let subject_commitment = salted(
            SUBJECT_COMMITMENT_DOMAIN,
            "anchor.sub",
            &verified.principal,
            services.entropy,
            &mut openings,
        )?;
        let tenant_commitment = salted(
            TENANT_COMMITMENT_DOMAIN,
            "anchor.tenant",
            &verified.tenant,
            services.entropy,
            &mut openings,
        )?;
        let canonical =
            |error: chio_core::Error| RootExchangeError::Canonicalization(error.to_string());
        let effective_root_scope_hash = Sha256Digest::of_scope(&scope).map_err(canonical)?;
        let issuer = Uri::new(verified.issuer.as_str())
            .map_err(|_| RootExchangeError::ClaimInvalid("iss"))?;
        let shape =
            |error: RootAuthorityShapeError| RootExchangeError::Canonicalization(error.to_string());
        let anchor_fields = DelegationAnchorFields {
            kind: AnchorKind::OauthIdJag,
            issuer,
            provider_record_id: Some(record.identity().provider_id.clone()),
            provider_identity_digest: Some(*record.identity_digest()),
            key_snapshot_digest: Some(resolved.snapshot_digest),
            kid: Some(verified.kid.clone()),
            alg: Some(verified.alg),
            artifact_digest: Some(*jws.artifact_digest()),
            artifact_retained: false,
            replay_key_digest: replay_key.digest(),
            token_iat: verified.iat,
            token_exp: verified.exp,
            subject: subject_commitment,
            tenant: tenant_commitment,
            claims,
        };
        let context = DelegationContext::new(DelegationContextFields {
            schema: CHIO_DELEGATION_CONTEXT_SCHEMA.to_owned(),
            anchor: DelegationAnchor::new(anchor_fields).map_err(shape)?,
            exchange: DelegationExchange {
                exchange_key: self.exchange_key.clone(),
                exchanged_at: now,
                request_digest: *grant.request_digest(),
                holder,
            },
            root_policy_rule_id: rule.rule_id.clone(),
            effective_root_scope_hash,
        })
        .map_err(shape)?;
        let anchor = RootAnchor {
            kind: AnchorKind::OauthIdJag,
            context_digest: context.digest().map_err(canonical)?,
            root_policy_digest: *self.policy.digest(),
            anchored_at: now,
            assertion_exp: verified.exp,
        };
        let body = CapabilityTokenBody {
            id: format!("cap_{}", hex_lower(&random::<16>(services.entropy)?)),
            issuer: self.exchange_key.clone(),
            subject,
            scope,
            issued_at: now,
            expires_at,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        };
        let granted: BTreeSet<&str> = granted_values.iter().copied().collect();
        let requested: Option<BTreeSet<&str>> = grant
            .requested_scope()
            .map(|values| values.iter().map(String::as_str).collect());
        let response_scope =
            (requested.as_ref() != Some(&granted)).then(|| granted_values.join(" "));
        match services
            .replay
            .bind(&replay_key, verified.exp.saturating_add(skew), now)
            .map_err(RootExchangeError::ReplayStoreUnavailable)?
        {
            ReplayBinding::Bound => {}
            ReplayBinding::AlreadyBound => return Err(RootExchangeError::AssertionReplay),
        }
        Ok(PreparedAnchoredRoot {
            body,
            anchor,
            context,
            openings,
            replay_key,
            holder,
            response_scope,
        })
    }

    /// The one `oauth_id_jag` rule whose provider record issues the token
    /// and whose `match` members hold. A rule whose provider record is
    /// missing or registered under another id cannot match; that fault is
    /// reported only when no usable rule matches.
    fn match_rule(
        &self,
        jws: &CompactJws,
    ) -> Result<(&RootPolicyRule, &ProviderRecord), RootExchangeError> {
        let issuer = super::claims::required_string(jws.claims(), "iss")?;
        let scope_values = super::claims::scope_values(jws.claims())?;
        let mut matched = Vec::new();
        let mut unusable = None;
        for rule in &self.policy.policy().rules {
            if rule.match_.anchor_kind != AnchorKind::OauthIdJag {
                continue;
            }
            let Some(record_id) = rule.match_.provider_record_id.as_ref() else {
                unusable.get_or_insert(RootExchangeError::KindNotExchanged(AnchorKind::OauthIdJag));
                continue;
            };
            let Some(record) = self.providers.get(record_id.as_str()) else {
                unusable.get_or_insert(RootExchangeError::ProviderRecordMissing(
                    record_id.to_string(),
                ));
                continue;
            };
            if &record.identity().provider_id != record_id {
                unusable.get_or_insert(RootExchangeError::ProviderRecordInvalid {
                    record: record_id.to_string(),
                    reason: "registered under another provider_id".to_owned(),
                });
                continue;
            }
            let alg_allowed = rule
                .match_
                .allowed_algs
                .as_ref()
                .is_some_and(|algs| algs.contains(&jws.header().alg));
            if record.identity().issuer.as_str() == issuer
                && alg_allowed
                && claims_match(rule.match_.claims.as_ref(), jws.claims(), &scope_values)
            {
                matched.push((rule, record));
            }
        }
        match (matched.as_slice(), unusable) {
            ([single], _) => Ok(*single),
            ([], Some(fault)) => Err(fault),
            _ => Err(RootExchangeError::RuleMatchCount {
                matched: matched.len(),
            }),
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
