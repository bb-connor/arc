//! `chio.root-policy.v1`: the provider-signed rules that admit anchored roots.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::capability::anchor::{AnchorKind, ROOT_POLICY_DIGEST_DOMAIN};
use crate::capability::scope::ChioScope;
use crate::crypto::{PublicKey, Signature};

use super::claims::{MatchClaims, RecordedClaimModes};
use super::delegation_context::HolderClass;
use super::jwk::JwsAlgorithm;
use super::wire::{
    canonical_public_key, canonical_public_keys, canonical_signature, check_items, check_nul_free,
    check_schema, check_unique, validated_type, Identifier, Sha256Digest,
};
use super::RootAuthorityShapeError;

pub const CHIO_ROOT_POLICY_SCHEMA: &str = "chio.root-policy.v1";

/// Root lifetime bound applied when a rule omits `capability_ttl_secs`.
pub const DEFAULT_CAPABILITY_TTL_SECS: u64 = 300;

/// Assertion lifetime bound applied when a rule omits `max_assertion_lifetime_secs`.
pub const DEFAULT_MAX_ASSERTION_LIFETIME_SECS: u64 = 300;

const MAX_RULE_SECS: u64 = 86_400;
const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// What a token must satisfy for a rule to match. Its `iss` must equal the
/// issuer of the named provider record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicyMatch {
    pub anchor_kind: AnchorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_identity_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_algs: Option<Vec<JwsAlgorithm>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<MatchClaims>,
}

/// The members of [`RootPolicyRule`]; [`RootPolicyRule::new`] validates them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicyRuleFields {
    pub rule_id: Identifier,
    #[serde(rename = "match")]
    pub match_: RootPolicyMatch,
    /// Identity-provider scope value to the `server/tool` names it projects to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idp_scope_projection: Option<BTreeMap<String, Vec<Identifier>>>,
    pub ceiling_scope: ChioScope,
    pub ceiling_scope_hash: Sha256Digest,
    pub recorded_claims: RecordedClaimModes,
    pub holder_classes: Vec<HolderClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_assertion_lifetime_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clock_skew_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_idp_artifact: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_value: Option<Identifier>,
}

validated_type!(
    /// One anchor rule.
    #[derive(Debug, Clone)]
    RootPolicyRule(RootPolicyRuleFields)
);

fn check_secs(
    field: &'static str,
    value: Option<u64>,
    min: u64,
    max: u64,
) -> Result<(), RootAuthorityShapeError> {
    match value {
        Some(actual) if actual < min || actual > max => Err(RootAuthorityShapeError::Range {
            field,
            min,
            max,
            actual,
        }),
        _ => Ok(()),
    }
}

impl RootPolicyRuleFields {
    pub fn validate(&self) -> Result<(), RootAuthorityShapeError> {
        let kind_value = self.match_.anchor_kind;
        let kind = kind_value.as_str();
        let presence = |field: &'static str, present: bool, wanted: bool| match (present, wanted) {
            (false, true) => Err(RootAuthorityShapeError::RequiredFor { field, kind }),
            (true, false) => Err(RootAuthorityShapeError::ForbiddenFor { field, kind }),
            _ => Ok(()),
        };
        let provider_backed = kind_value.is_provider_backed();
        presence(
            "match.provider_record_id",
            self.match_.provider_record_id.is_some(),
            provider_backed,
        )?;
        presence(
            "match.provider_identity_digest",
            self.match_.provider_identity_digest.is_some(),
            provider_backed,
        )?;
        if !provider_backed {
            presence(
                "match.allowed_algs",
                self.match_.allowed_algs.is_some(),
                false,
            )?;
            presence(
                "idp_scope_projection",
                self.idp_scope_projection.is_some(),
                false,
            )?;
        }
        if kind_value.is_jws_verified() {
            presence(
                "match.allowed_algs",
                self.match_.allowed_algs.is_some(),
                true,
            )?;
        }
        if kind_value == AnchorKind::OauthIntrospection {
            presence(
                "match.allowed_algs",
                self.match_.allowed_algs.is_some(),
                false,
            )?;
        }
        let static_bearer = kind_value == AnchorKind::OperatorStaticBearer;
        presence("principal", self.principal.is_some(), static_bearer)?;
        presence("tenant_value", self.tenant_value.is_some(), static_bearer)?;
        if kind_value.is_entra() {
            presence(
                "max_assertion_lifetime_secs",
                self.max_assertion_lifetime_secs.is_some(),
                false,
            )?;
        } else {
            let entra_only = self.recorded_claims.entra_only_claim().or_else(|| {
                self.match_
                    .claims
                    .as_ref()
                    .and_then(MatchClaims::entra_only_claim)
            });
            if let Some(field) = entra_only {
                return Err(RootAuthorityShapeError::ForbiddenFor { field, kind });
            }
        }
        if kind_value != AnchorKind::OauthIdJag {
            presence(
                "retain_idp_artifact",
                self.retain_idp_artifact.is_some(),
                false,
            )?;
        }
        if let Some(algs) = &self.match_.allowed_algs {
            check_items("match.allowed_algs", algs.len(), 1, 10)?;
            check_unique("match.allowed_algs", algs)?;
        }
        if let Some(claims) = &self.match_.claims {
            claims.validate()?;
        }
        if let Some(projection) = &self.idp_scope_projection {
            check_items("idp_scope_projection", projection.len(), 0, 256)?;
            for (scope_value, tools) in projection {
                check_nul_free("idp_scope_projection", scope_value, 128)?;
                check_items("idp_scope_projection", tools.len(), 0, 256)?;
            }
        }
        check_items("holder_classes", self.holder_classes.len(), 1, 2)?;
        check_unique("holder_classes", &self.holder_classes)?;
        check_secs(
            "capability_ttl_secs",
            self.capability_ttl_secs,
            1,
            MAX_RULE_SECS,
        )?;
        check_secs(
            "max_assertion_lifetime_secs",
            self.max_assertion_lifetime_secs,
            1,
            MAX_RULE_SECS,
        )?;
        check_secs(
            "max_clock_skew_secs",
            self.max_clock_skew_secs,
            0,
            MAX_CLOCK_SKEW_SECS,
        )
    }
}

impl RootPolicyRule {
    /// The root lifetime bound in seconds.
    #[must_use]
    pub fn capability_ttl(&self) -> u64 {
        self.capability_ttl_secs
            .unwrap_or(DEFAULT_CAPABILITY_TTL_SECS)
    }

    /// The assertion lifetime bound; `None` for kinds whose lifetime the
    /// identity provider sets.
    #[must_use]
    pub fn max_assertion_lifetime(&self) -> Option<u64> {
        if self.match_.anchor_kind.is_entra() {
            return None;
        }
        Some(
            self.max_assertion_lifetime_secs
                .unwrap_or(DEFAULT_MAX_ASSERTION_LIFETIME_SECS),
        )
    }

    /// SHA-256 of the canonical `ceiling_scope`.
    pub fn compute_ceiling_scope_hash(&self) -> crate::error::Result<Sha256Digest> {
        Sha256Digest::of_scope(&self.ceiling_scope)
    }
}

/// The only disclosure default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureDefault {
    Committed,
}

/// RFC 6901 pointers that may appear in plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineFields {
    pub inline_fields: Vec<String>,
}

impl InlineFields {
    fn validate(&self) -> Result<(), RootAuthorityShapeError> {
        check_items("inline_fields", self.inline_fields.len(), 0, 64)?;
        check_unique("inline_fields", &self.inline_fields)?;
        for pointer in &self.inline_fields {
            if pointer.chars().count() > 256 || !is_json_pointer(pointer) {
                return Err(RootAuthorityShapeError::Pattern {
                    field: "inline_fields",
                    expected: "a non-empty RFC 6901 JSON pointer of at most 256 characters",
                });
            }
        }
        Ok(())
    }
}

/// `^(/([^~/]|~[01])*)+$`.
fn is_json_pointer(pointer: &str) -> bool {
    let Some(rest) = pointer.strip_prefix('/') else {
        return false;
    };
    let mut characters = rest.chars();
    while let Some(character) = characters.next() {
        if character == '~' && !matches!(characters.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

/// Inline fields of one tool's parameters and result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDisclosure {
    pub parameters: InlineFields,
    pub result: InlineFields,
}

/// The members of [`RootPolicyDisclosure`]; [`RootPolicyDisclosure::new`] validates them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicyDisclosureFields {
    pub default: DisclosureDefault,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<BTreeMap<String, ToolDisclosure>>,
}

validated_type!(
    /// The receipt disclosure policy. A tool not listed is fully committed.
    #[derive(Debug, Clone, PartialEq, Eq)]
    RootPolicyDisclosure(RootPolicyDisclosureFields)
);

impl RootPolicyDisclosureFields {
    pub fn validate(&self) -> Result<(), RootAuthorityShapeError> {
        let Some(tools) = &self.tools else {
            return Ok(());
        };
        check_items("disclosure.tools", tools.len(), 0, 1024)?;
        for (tool, disclosure) in tools {
            let well_formed = tool.chars().count() <= 256
                && !tool.contains('\0')
                && tool
                    .split_once('/')
                    .is_some_and(|(server, name)| !server.is_empty() && !name.is_empty());
            if !well_formed {
                return Err(RootAuthorityShapeError::Pattern {
                    field: "disclosure.tools",
                    expected: "server/tool of at most 256 characters without NUL",
                });
            }
            disclosure.parameters.validate()?;
            disclosure.result.validate()?;
        }
        Ok(())
    }
}

impl RootPolicyDisclosure {
    /// Whether any tool admits plaintext fields.
    #[must_use]
    pub fn has_tool_entries(&self) -> bool {
        self.tools.as_ref().is_some_and(|tools| !tools.is_empty())
    }
}

/// The members of [`RootPolicy`]; [`RootPolicy::new`] validates them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicyFields {
    pub schema: String,
    pub policy_id: Identifier,
    #[serde(deserialize_with = "canonical_public_key")]
    pub policy_key: PublicKey,
    #[serde(deserialize_with = "canonical_public_keys")]
    pub exchange_keys: Vec<PublicKey>,
    pub rules: Vec<RootPolicyRule>,
    pub disclosure: RootPolicyDisclosure,
    pub valid_from: u64,
    pub valid_until: u64,
    #[serde(deserialize_with = "canonical_signature")]
    pub signature: Signature,
}

validated_type!(
    /// `chio.root-policy.v1`, signed by the provider's policy key.
    #[derive(Debug, Clone)]
    RootPolicy(RootPolicyFields)
);

/// Every policy member except `signature`.
#[derive(Serialize)]
pub struct RootPolicySigningBody<'a> {
    pub schema: &'a str,
    pub policy_id: &'a Identifier,
    pub policy_key: &'a PublicKey,
    pub exchange_keys: &'a [PublicKey],
    pub rules: &'a [RootPolicyRule],
    pub disclosure: &'a RootPolicyDisclosure,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl RootPolicyFields {
    pub fn validate(&self) -> Result<(), RootAuthorityShapeError> {
        check_schema(&self.schema, CHIO_ROOT_POLICY_SCHEMA)?;
        check_items("exchange_keys", self.exchange_keys.len(), 1, 16)?;
        check_unique("exchange_keys", &self.exchange_keys)?;
        check_items("rules", self.rules.len(), 1, 64)
    }
}

impl RootPolicy {
    #[must_use]
    pub fn signing_body(&self) -> RootPolicySigningBody<'_> {
        RootPolicySigningBody {
            schema: &self.schema,
            policy_id: &self.policy_id,
            policy_key: &self.policy_key,
            exchange_keys: &self.exchange_keys,
            rules: &self.rules,
            disclosure: &self.disclosure,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        }
    }

    /// `SHA-256("chio.root-policy.v1\0" || canonical_json(signing body))`.
    pub fn digest(&self) -> crate::error::Result<Sha256Digest> {
        let canonical = canonical_json_bytes(&self.signing_body())?;
        Ok(Sha256Digest::of_domain(
            ROOT_POLICY_DIGEST_DOMAIN,
            &canonical,
        ))
    }

    /// Apply every load rule against the pinned policy key at `now` (Unix seconds).
    pub fn load(
        self,
        pinned_policy_key: &PublicKey,
        now: u64,
    ) -> Result<LoadedRootPolicy, RootPolicyLoadError> {
        if &self.policy_key != pinned_policy_key {
            return Err(RootPolicyLoadError::PolicyKeyNotPinned);
        }
        let verified = self
            .policy_key
            .verify_canonical_strict(&self.signing_body(), &self.signature)
            .map_err(|error| RootPolicyLoadError::Canonicalization(error.to_string()))?;
        if !verified {
            return Err(RootPolicyLoadError::InvalidSignature);
        }
        if self.valid_from >= self.valid_until {
            return Err(RootPolicyLoadError::EmptyValidityWindow);
        }
        if self.exchange_keys.iter().any(PublicKey::is_weak_ed25519) {
            return Err(RootPolicyLoadError::WeakExchangeKey);
        }
        if self.exchange_keys.contains(&self.policy_key) {
            return Err(RootPolicyLoadError::PolicyKeyIsExchangeKey);
        }
        if self.disclosure.has_tool_entries() {
            return Err(RootPolicyLoadError::InlineDisclosureUnsupported);
        }
        let mut static_bearer_rules = 0_usize;
        for (index, rule) in self.rules.iter().enumerate() {
            let rule_id = || rule.rule_id.as_str().to_string();
            if self
                .rules
                .iter()
                .take(index)
                .any(|earlier| earlier.rule_id == rule.rule_id)
            {
                return Err(RootPolicyLoadError::DuplicateRuleId { rule_id: rule_id() });
            }
            if rule.match_.anchor_kind == AnchorKind::EntraAgentId {
                return Err(RootPolicyLoadError::UnsupportedAnchorKind {
                    rule_id: rule_id(),
                    kind: AnchorKind::EntraAgentId,
                });
            }
            if rule.retain_idp_artifact == Some(true) {
                return Err(RootPolicyLoadError::ArtifactRetentionUnsupported {
                    rule_id: rule_id(),
                });
            }
            if rule.match_.anchor_kind == AnchorKind::OperatorStaticBearer {
                static_bearer_rules += 1;
                if static_bearer_rules > 1 {
                    return Err(RootPolicyLoadError::DuplicateStaticBearerRule);
                }
            }
            let computed = rule
                .compute_ceiling_scope_hash()
                .map_err(|error| RootPolicyLoadError::Canonicalization(error.to_string()))?;
            if computed != rule.ceiling_scope_hash {
                return Err(RootPolicyLoadError::CeilingScopeHashMismatch { rule_id: rule_id() });
            }
        }
        let digest = self
            .digest()
            .map_err(|error| RootPolicyLoadError::Canonicalization(error.to_string()))?;
        let loaded = LoadedRootPolicy {
            policy: self,
            digest,
        };
        loaded.check_valid_at(now)?;
        Ok(loaded)
    }
}

/// A root policy that passed every load rule. Only [`RootPolicy::load`] builds one.
#[derive(Debug, Clone)]
pub struct LoadedRootPolicy {
    policy: RootPolicy,
    digest: Sha256Digest,
}

impl LoadedRootPolicy {
    #[must_use]
    pub fn policy(&self) -> &RootPolicy {
        &self.policy
    }

    /// The `root_policy_digest` every root minted under this policy names.
    #[must_use]
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    #[must_use]
    pub fn rule(&self, rule_id: &Identifier) -> Option<&RootPolicyRule> {
        self.policy
            .rules
            .iter()
            .find(|rule| &rule.rule_id == rule_id)
    }

    #[must_use]
    pub fn lists_exchange_key(&self, key: &PublicKey) -> bool {
        self.policy.exchange_keys.contains(key)
    }

    /// The policy is in force for `valid_from <= now < valid_until`.
    pub fn check_valid_at(&self, now: u64) -> Result<(), RootPolicyLoadError> {
        if now < self.policy.valid_from {
            return Err(RootPolicyLoadError::NotYetValid {
                valid_from: self.policy.valid_from,
            });
        }
        if now >= self.policy.valid_until {
            return Err(RootPolicyLoadError::Expired {
                valid_until: self.policy.valid_until,
            });
        }
        Ok(())
    }
}

/// Why a root policy refuses to load or is out of force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootPolicyLoadError {
    PolicyKeyNotPinned,
    InvalidSignature,
    EmptyValidityWindow,
    NotYetValid { valid_from: u64 },
    Expired { valid_until: u64 },
    InlineDisclosureUnsupported,
    DuplicateRuleId { rule_id: String },
    DuplicateStaticBearerRule,
    UnsupportedAnchorKind { rule_id: String, kind: AnchorKind },
    ArtifactRetentionUnsupported { rule_id: String },
    CeilingScopeHashMismatch { rule_id: String },
    WeakExchangeKey,
    PolicyKeyIsExchangeKey,
    Canonicalization(String),
}

impl fmt::Display for RootPolicyLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyKeyNotPinned => {
                formatter.write_str("root policy key differs from the pinned policy key")
            }
            Self::InvalidSignature => formatter.write_str("root policy signature is invalid"),
            Self::EmptyValidityWindow => {
                formatter.write_str("root policy valid_from is not before valid_until")
            }
            Self::NotYetValid { valid_from } => {
                write!(formatter, "root policy is not valid before {valid_from}")
            }
            Self::Expired { valid_until } => {
                write!(formatter, "root policy expired at {valid_until}")
            }
            Self::InlineDisclosureUnsupported => {
                formatter.write_str("root policy lists inline disclosure tools")
            }
            Self::DuplicateRuleId { rule_id } => {
                write!(formatter, "root policy repeats rule `{rule_id}`")
            }
            Self::DuplicateStaticBearerRule => {
                formatter.write_str("root policy has more than one operator_static_bearer rule")
            }
            Self::UnsupportedAnchorKind { rule_id, kind } => write!(
                formatter,
                "root policy rule `{rule_id}` uses unsupported anchor kind {}",
                kind.as_str()
            ),
            Self::ArtifactRetentionUnsupported { rule_id } => write!(
                formatter,
                "root policy rule `{rule_id}` retains identity-provider artifacts"
            ),
            Self::CeilingScopeHashMismatch { rule_id } => write!(
                formatter,
                "root policy rule `{rule_id}` ceiling_scope_hash does not match ceiling_scope"
            ),
            Self::WeakExchangeKey => {
                formatter.write_str("root policy lists a weak Ed25519 exchange key")
            }
            Self::PolicyKeyIsExchangeKey => {
                formatter.write_str("root policy key is also listed as an exchange key")
            }
            Self::Canonicalization(error) => {
                write!(formatter, "root policy canonicalization failed: {error}")
            }
        }
    }
}

impl core::error::Error for RootPolicyLoadError {}
