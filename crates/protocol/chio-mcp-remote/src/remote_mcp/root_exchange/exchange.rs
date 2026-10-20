//! The ID-JAG root exchange: from an authenticated token request to a
//! prepared anchored root.

use std::collections::{BTreeMap, BTreeSet};

use chio_core::canonical_json_bytes;
use chio_core::capability::anchor::{AnchorKind, RootAnchor};
use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::CapabilityTokenBody;
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::root_authority::{
    ClaimMode, ClaimValue, DelegationAnchor, DelegationAnchorFields, DelegationContext,
    DelegationContextFields, DelegationExchange, HolderClass, Identifier, LoadedRootPolicy,
    MatchClaims, ProviderRecordKind, RecordedClaims, RootAuthorityShapeError, RootPolicyRule,
    SaltRef, SaltedCommitment, Sha256Digest, Text, Uri, CHIO_DELEGATION_CONTEXT_SCHEMA,
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

/// Cryptographically secure randomness for salts, edge-session subject keys
/// and capability identifiers.
pub trait ExchangeEntropy: Send + Sync {
    fn fill(&self, dest: &mut [u8]);
}

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
    pub entropy: &'a dyn ExchangeEntropy,
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
/// of the capability body.
#[derive(Debug, Clone)]
pub struct PreparedAnchoredRoot {
    pub body: CapabilityTokenBody,
    pub anchor: RootAnchor,
    pub context: DelegationContext,
    pub openings: Vec<ContextOpening>,
    pub replay_key: ReplayKey,
    pub holder: HolderClass,
}

fn random<const N: usize>(entropy: &dyn ExchangeEntropy) -> [u8; N] {
    let mut bytes = [0_u8; N];
    entropy.fill(&mut bytes);
    bytes
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

/// `ceiling_scope` restricted to the tools the IdP scope values project to.
fn effective_scope(
    rule: &RootPolicyRule,
    scope_values: &[String],
) -> Result<ChioScope, RootExchangeError> {
    let projection = rule
        .idp_scope_projection
        .as_ref()
        .ok_or(RootExchangeError::ScopeNotProjected)?;
    let mut tools: BTreeSet<&str> = BTreeSet::new();
    for value in scope_values {
        let projected = projection
            .get(value)
            .ok_or(RootExchangeError::ScopeNotProjected)?;
        tools.extend(projected.iter().map(Identifier::as_str));
    }
    let grants: Vec<_> = rule
        .ceiling_scope
        .grants
        .iter()
        .filter(|grant| tools.contains(format!("{}/{}", grant.server_id, grant.tool_name).as_str()))
        .cloned()
        .collect();
    if grants.is_empty() {
        return Err(RootExchangeError::EmptyEffectiveScope);
    }
    Ok(ChioScope {
        grants,
        ..ChioScope::default()
    })
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
    entropy: &dyn ExchangeEntropy,
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
                let salt = random::<32>(entropy);
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
            _ => &mut recorded.tid,
        };
        *slot = Some(claim);
    }
    Ok(recorded)
}

fn salted(
    domain: &[u8],
    reference: &str,
    value: &str,
    entropy: &dyn ExchangeEntropy,
    openings: &mut Vec<ContextOpening>,
) -> Result<SaltedCommitment, RootExchangeError> {
    let salt = random::<32>(entropy);
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

        let jws = CompactJws::parse(&grant.id_jag)?;
        let (rule, record) = self.match_rule(&jws)?;
        let provider_id = record.identity.provider_id.as_str();
        if !record.enabled {
            return Err(RootExchangeError::ProviderRecordDisabled(
                provider_id.to_owned(),
            ));
        }
        if record.identity.kind != ProviderRecordKind::OidcJwks {
            return Err(RootExchangeError::ProviderRecordInvalid {
                record: provider_id.to_owned(),
                reason: "record kind is not oidc_jwks".to_owned(),
            });
        }
        if Some(&record.identity_digest) != rule.match_.provider_identity_digest.as_ref() {
            return Err(RootExchangeError::ProviderIdentityMismatch(
                provider_id.to_owned(),
            ));
        }
        let resolved = services
            .keys
            .resolve(
                &record.identity,
                jws.header.kid.as_str(),
                jws.header.alg,
                now,
            )
            .await?;
        let key = VerifyingKey::from_jwk(&resolved.jwk).ok_or(RootExchangeError::IdpKeyUnusable)?;
        jws.verify_with(&key)?;
        let skew = rule.max_clock_skew_secs.unwrap_or(0);
        let verified = verify_id_jag_claims(
            &jws,
            &record.identity,
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
        let scope = effective_scope(rule, &verified.scope_values)?;
        if holder == HolderClass::EdgeSession
            && scope
                .grants
                .iter()
                .any(|grant| grant.dpop_required == Some(true))
        {
            return Err(RootExchangeError::ProofRequiredGrantForEdgeSession);
        }
        let expires_at = now.saturating_add(rule.capability_ttl()).min(verified.exp);
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
            None => Keypair::from_seed(&random::<32>(services.entropy)).public_key(),
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
            provider_record_id: Some(record.identity.provider_id.clone()),
            provider_identity_digest: Some(record.identity_digest),
            key_snapshot_digest: Some(resolved.snapshot_digest),
            kid: Some(verified.kid.clone()),
            alg: Some(verified.alg),
            artifact_digest: Some(jws.artifact_digest),
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
                request_digest: grant.request_digest,
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
            id: format!("cap_{}", hex_lower(&random::<16>(services.entropy))),
            issuer: self.exchange_key.clone(),
            subject,
            scope,
            issued_at: now,
            expires_at,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        };
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
        })
    }

    /// The one `oauth_id_jag` rule whose provider record issues the token
    /// and whose `match` members hold.
    fn match_rule(
        &self,
        jws: &CompactJws,
    ) -> Result<(&RootPolicyRule, &ProviderRecord), RootExchangeError> {
        let issuer = super::claims::required_string(&jws.claims, "iss")?;
        let scope_values = super::claims::scope_values(&jws.claims)?;
        let mut matched = Vec::new();
        for rule in &self.policy.policy().rules {
            if rule.match_.anchor_kind != AnchorKind::OauthIdJag {
                continue;
            }
            let record_id = rule
                .match_
                .provider_record_id
                .as_ref()
                .ok_or(RootExchangeError::KindNotExchanged(AnchorKind::OauthIdJag))?;
            let record = self
                .providers
                .get(record_id.as_str())
                .ok_or_else(|| RootExchangeError::ProviderRecordMissing(record_id.to_string()))?;
            let alg_allowed = rule
                .match_
                .allowed_algs
                .as_ref()
                .is_some_and(|algs| algs.contains(&jws.header.alg));
            if record.identity.issuer.as_str() == issuer
                && alg_allowed
                && claims_match(rule.match_.claims.as_ref(), &jws.claims, &scope_values)
            {
                matched.push((rule, record));
            }
        }
        match matched.as_slice() {
            [single] => Ok(*single),
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
