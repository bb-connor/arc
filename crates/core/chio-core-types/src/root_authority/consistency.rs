//! Consistency of a root capability with a `root_anchor`, a delegation
//! context and the loaded root policy. Every check is offline and takes no
//! clock.
//!
//! These checks authenticate nothing. The anchor and the context are unsigned
//! inputs here, so a substituted anchor and context that agree with each
//! other and with the root pass. Authenticating the pairing needs the anchor
//! read from the signed capability body.

use alloc::string::{String, ToString};
use core::fmt;

use crate::capability::anchor::{AnchorKind, RootAnchor};
use crate::capability::token::CapabilityToken;
use crate::crypto::PublicKey;

use super::delegation_context::{DelegationContext, HolderClass};
use super::root_policy::{LoadedRootPolicy, RootPolicyRule};
use super::wire::Sha256Digest;

/// The root, its anchor and the evidence it is checked against.
#[derive(Debug, Clone, Copy)]
pub struct RootConsistencyInput<'a> {
    pub root: &'a CapabilityToken,
    pub anchor: &'a RootAnchor,
    pub context: &'a DelegationContext,
    pub policy: &'a LoadedRootPolicy,
    /// The `cnf.chioSenderKey` the presenter proved, if any.
    pub sender_key: Option<&'a PublicKey>,
}

/// Why a root disagrees with its anchor, context or policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootConsistencyError {
    NotARoot,
    RootPolicyDigestMismatch,
    ContextDigestMismatch,
    AnchorKindMismatch,
    AssertionExpMismatch,
    AnchoredAtMismatch,
    ExpiresAfterAssertion { expires_at: u64, assertion_exp: u64 },
    StaticBearerExpiryMismatch { expires_at: u64, assertion_exp: u64 },
    InvertedAssertionWindow { token_iat: u64, token_exp: u64 },
    AlgorithmNotAllowed,
    StaticBearerScopeNotCeiling,
    ExchangeKeyMismatch,
    ExchangeKeyNotListed,
    ScopeHashMismatch,
    UnknownRule,
    RuleKindMismatch,
    HolderClassNotAllowed { holder: HolderClass },
    SenderKeyMissing,
    SubjectNotSenderKey,
    SenderKeyOnEdgeSession,
    ProofRequiredGrantOnEdgeSession,
    ProviderMismatch,
    ScopeExceedsCeiling,
    LifetimeExceedsRule { lifetime: u64, capability_ttl: u64 },
    AssertionLifetimeExceedsRule { lifetime: u64, max: u64 },
    RecordedClaimsMismatch { claim: &'static str },
    ArtifactRetentionMismatch,
    Canonicalization(String),
}

impl fmt::Display for RootConsistencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotARoot => {
                formatter.write_str("anchored root carries delegation or attenuation")
            }
            Self::RootPolicyDigestMismatch => {
                formatter.write_str("root_anchor names a root policy other than the loaded one")
            }
            Self::ContextDigestMismatch => formatter
                .write_str("root_anchor context_digest does not match the delegation context"),
            Self::AnchorKindMismatch => {
                formatter.write_str("root_anchor kind differs from the delegation context kind")
            }
            Self::AssertionExpMismatch => {
                formatter.write_str("root_anchor assertion_exp differs from anchor.token_exp")
            }
            Self::AnchoredAtMismatch => {
                formatter.write_str("root_anchor anchored_at differs from exchange.exchanged_at")
            }
            Self::ExpiresAfterAssertion {
                expires_at,
                assertion_exp,
            } => write!(
                formatter,
                "root expires_at {expires_at} exceeds assertion_exp {assertion_exp}"
            ),
            Self::StaticBearerExpiryMismatch {
                expires_at,
                assertion_exp,
            } => write!(
                formatter,
                "operator_static_bearer root expires_at {expires_at} differs from assertion_exp {assertion_exp}"
            ),
            Self::InvertedAssertionWindow {
                token_iat,
                token_exp,
            } => write!(
                formatter,
                "anchor token_iat {token_iat} is after token_exp {token_exp}"
            ),
            Self::AlgorithmNotAllowed => {
                formatter.write_str("anchor alg is not in the root policy rule allowed_algs")
            }
            Self::StaticBearerScopeNotCeiling => formatter
                .write_str("operator_static_bearer root scope differs from the rule ceiling_scope"),
            Self::ExchangeKeyMismatch => {
                formatter.write_str("root issuer differs from exchange.exchange_key")
            }
            Self::ExchangeKeyNotListed => {
                formatter.write_str("root issuer is not a root policy exchange key")
            }
            Self::ScopeHashMismatch => {
                formatter.write_str("root scope hash differs from effective_root_scope_hash")
            }
            Self::UnknownRule => {
                formatter.write_str("delegation context names no rule of the loaded root policy")
            }
            Self::RuleKindMismatch => {
                formatter.write_str("root policy rule anchor_kind differs from the anchor kind")
            }
            Self::HolderClassNotAllowed { holder } => write!(
                formatter,
                "holder class {} is not allowed by the root policy rule",
                holder.as_str()
            ),
            Self::SenderKeyMissing => {
                formatter.write_str("caller root presented without a sender key")
            }
            Self::SubjectNotSenderKey => {
                formatter.write_str("caller root subject differs from the presented sender key")
            }
            Self::SenderKeyOnEdgeSession => {
                formatter.write_str("edge_session root presented with a sender key")
            }
            Self::ProofRequiredGrantOnEdgeSession => {
                formatter.write_str("edge_session root carries a proof-required grant")
            }
            Self::ProviderMismatch => formatter
                .write_str("delegation context provider record differs from the root policy rule"),
            Self::ScopeExceedsCeiling => {
                formatter.write_str("root scope exceeds the root policy rule ceiling_scope")
            }
            Self::LifetimeExceedsRule {
                lifetime,
                capability_ttl,
            } => write!(
                formatter,
                "root lifetime {lifetime}s exceeds capability_ttl_secs {capability_ttl}"
            ),
            Self::AssertionLifetimeExceedsRule { lifetime, max } => write!(
                formatter,
                "assertion lifetime {lifetime}s exceeds max_assertion_lifetime_secs {max}"
            ),
            Self::RecordedClaimsMismatch { claim } => write!(
                formatter,
                "recorded claim `{claim}` differs from the root policy rule recorded_claims"
            ),
            Self::ArtifactRetentionMismatch => formatter.write_str(
                "artifact_retained differs from the root policy rule retain_idp_artifact",
            ),
            Self::Canonicalization(error) => {
                write!(formatter, "anchored root canonicalization failed: {error}")
            }
        }
    }
}

impl core::error::Error for RootConsistencyError {}

fn require(holds: bool, error: RootConsistencyError) -> Result<(), RootConsistencyError> {
    if holds {
        Ok(())
    } else {
        Err(error)
    }
}

/// Check that a depth-0 root agrees with `anchor`, `context` and `policy`.
/// Signature, issuer trust and time-window checks belong to the capability
/// verifier; the pairing of `anchor` with `root` is not authenticated.
pub fn check_root_consistency(input: RootConsistencyInput<'_>) -> Result<(), RootConsistencyError> {
    let RootConsistencyInput {
        root,
        anchor,
        context,
        policy,
        sender_key,
    } = input;
    let canonicalization =
        |error: crate::Error| RootConsistencyError::Canonicalization(error.to_string());

    require(
        root.delegation_chain.is_empty() && !root.requires_chain_binding(),
        RootConsistencyError::NotARoot,
    )?;
    require(
        &anchor.root_policy_digest == policy.digest(),
        RootConsistencyError::RootPolicyDigestMismatch,
    )?;
    require(
        context.digest().map_err(canonicalization)? == anchor.context_digest,
        RootConsistencyError::ContextDigestMismatch,
    )?;
    require(
        anchor.kind == context.anchor.kind,
        RootConsistencyError::AnchorKindMismatch,
    )?;
    require(
        anchor.assertion_exp == context.anchor.token_exp,
        RootConsistencyError::AssertionExpMismatch,
    )?;
    require(
        anchor.anchored_at == context.exchange.exchanged_at,
        RootConsistencyError::AnchoredAtMismatch,
    )?;
    require(
        root.expires_at <= anchor.assertion_exp,
        RootConsistencyError::ExpiresAfterAssertion {
            expires_at: root.expires_at,
            assertion_exp: anchor.assertion_exp,
        },
    )?;
    if anchor.kind == AnchorKind::OperatorStaticBearer {
        require(
            root.expires_at == anchor.assertion_exp,
            RootConsistencyError::StaticBearerExpiryMismatch {
                expires_at: root.expires_at,
                assertion_exp: anchor.assertion_exp,
            },
        )?;
    }
    require(
        context.anchor.token_iat <= context.anchor.token_exp,
        RootConsistencyError::InvertedAssertionWindow {
            token_iat: context.anchor.token_iat,
            token_exp: context.anchor.token_exp,
        },
    )?;
    require(
        root.issuer == context.exchange.exchange_key,
        RootConsistencyError::ExchangeKeyMismatch,
    )?;
    require(
        policy.lists_exchange_key(&root.issuer),
        RootConsistencyError::ExchangeKeyNotListed,
    )?;
    let scope_digest = Sha256Digest::of_scope(&root.scope).map_err(canonicalization)?;
    require(
        scope_digest == context.effective_root_scope_hash,
        RootConsistencyError::ScopeHashMismatch,
    )?;

    let rule = policy
        .rule(&context.root_policy_rule_id)
        .ok_or(RootConsistencyError::UnknownRule)?;
    require(
        rule.match_.anchor_kind == anchor.kind,
        RootConsistencyError::RuleKindMismatch,
    )?;
    if let Some(alg) = context.anchor.alg {
        require(
            rule.match_
                .allowed_algs
                .as_ref()
                .is_some_and(|allowed| allowed.contains(&alg)),
            RootConsistencyError::AlgorithmNotAllowed,
        )?;
    }
    check_holder(root, context.exchange.holder, rule, sender_key)?;
    require(
        context.anchor.provider_record_id == rule.match_.provider_record_id
            && context.anchor.provider_identity_digest == rule.match_.provider_identity_digest,
        RootConsistencyError::ProviderMismatch,
    )?;
    require(
        root.scope.is_subset_of(&rule.ceiling_scope),
        RootConsistencyError::ScopeExceedsCeiling,
    )?;
    if anchor.kind == AnchorKind::OperatorStaticBearer {
        require(
            scope_digest == rule.ceiling_scope_hash,
            RootConsistencyError::StaticBearerScopeNotCeiling,
        )?;
    }
    let lifetime = root.expires_at.saturating_sub(root.issued_at);
    require(
        lifetime <= rule.capability_ttl(),
        RootConsistencyError::LifetimeExceedsRule {
            lifetime,
            capability_ttl: rule.capability_ttl(),
        },
    )?;
    if anchor.kind == AnchorKind::OauthIdJag {
        if let Some(max) = rule.max_assertion_lifetime() {
            let lifetime = context
                .anchor
                .token_exp
                .saturating_sub(context.anchor.token_iat);
            require(
                lifetime <= max,
                RootConsistencyError::AssertionLifetimeExceedsRule { lifetime, max },
            )?;
        }
    }
    check_recorded_claims(context, rule)?;
    require(
        context.anchor.artifact_retained == rule.retain_idp_artifact.unwrap_or(false),
        RootConsistencyError::ArtifactRetentionMismatch,
    )
}

fn check_holder(
    root: &CapabilityToken,
    holder: HolderClass,
    rule: &RootPolicyRule,
    sender_key: Option<&PublicKey>,
) -> Result<(), RootConsistencyError> {
    require(
        rule.holder_classes.contains(&holder),
        RootConsistencyError::HolderClassNotAllowed { holder },
    )?;
    match (holder, sender_key) {
        (HolderClass::Caller, Some(key)) => require(
            &root.subject == key,
            RootConsistencyError::SubjectNotSenderKey,
        ),
        (HolderClass::Caller, None) => Err(RootConsistencyError::SenderKeyMissing),
        (HolderClass::EdgeSession, Some(_)) => Err(RootConsistencyError::SenderKeyOnEdgeSession),
        (HolderClass::EdgeSession, None) => require(
            !rule
                .ceiling_scope
                .grants
                .iter()
                .chain(&root.scope.grants)
                .any(|grant| grant.dpop_required == Some(true)),
            RootConsistencyError::ProofRequiredGrantOnEdgeSession,
        ),
    }
}

fn check_recorded_claims(
    context: &DelegationContext,
    rule: &RootPolicyRule,
) -> Result<(), RootConsistencyError> {
    let recorded = context.anchor.claims.entries();
    let modes = rule.recorded_claims.entries();
    for ((claim, value), (_, mode)) in recorded.into_iter().zip(modes) {
        let consistent = match (value, mode) {
            (None, None) => true,
            (Some(value), Some(mode)) => value.mode() == *mode,
            _ => false,
        };
        require(
            consistent,
            RootConsistencyError::RecordedClaimsMismatch { claim },
        )?;
    }
    Ok(())
}
