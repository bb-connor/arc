//! Depth-0 verification of exchange-issued anchored roots.

use core::fmt;

use chio_core_types::capability::anchor::RootAnchor;
use chio_core_types::root_authority::{
    check_root_binding, DelegationContext, HolderClass, Identifier, LoadedRootPolicy,
    RootBindingError, RootBindingInput, RootPolicyLoadError, Sha256Digest,
};

use super::*;

/// A pinned exchange key and the loaded root policy that lists it.
#[derive(Debug, Clone, Copy)]
pub struct AnchoredTrustRoot<'a> {
    exchange_key: &'a PublicKey,
    policy: &'a LoadedRootPolicy,
}

/// Why an anchored root is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchoredRootError {
    /// The pinned exchange key is not among the policy's `exchange_keys`.
    ExchangeKeyNotInPolicy,
    /// The root is not signed by the pinned exchange key.
    IssuerNotExchangeKey,
    /// The loaded policy is outside its validity window.
    PolicyOutOfForce(RootPolicyLoadError),
    /// Signature, crypto floor or time-window refusal.
    Capability(CapabilityError),
    /// A root-anchor, delegation-context or policy binding fails.
    Binding(RootBindingError),
    /// The clock could not be read.
    Clock(String),
}

impl fmt::Display for AnchoredRootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExchangeKeyNotInPolicy => {
                formatter.write_str("pinned exchange key is not listed by the root policy")
            }
            Self::IssuerNotExchangeKey => {
                formatter.write_str("anchored root is not signed by the pinned exchange key")
            }
            Self::PolicyOutOfForce(error) => write!(formatter, "{error}"),
            Self::Capability(error) => write!(formatter, "anchored root refused: {error:?}"),
            Self::Binding(error) => write!(formatter, "{error}"),
            Self::Clock(error) => write!(formatter, "clock unavailable: {error}"),
        }
    }
}

/// A root that verified against its anchor, delegation context and root policy.
#[derive(Debug, Clone)]
pub struct VerifiedAnchoredRoot {
    capability: VerifiedCapability,
    anchor: RootAnchor,
    exchange_key: PublicKey,
    rule_id: Identifier,
    holder: HolderClass,
    effective_root_scope_hash: Sha256Digest,
}

impl VerifiedAnchoredRoot {
    #[must_use]
    pub fn capability(&self) -> &VerifiedCapability {
        &self.capability
    }
    #[must_use]
    pub fn anchor(&self) -> &RootAnchor {
        &self.anchor
    }
    #[must_use]
    pub fn rule_id(&self) -> &Identifier {
        &self.rule_id
    }
    #[must_use]
    pub fn holder(&self) -> HolderClass {
        self.holder
    }
    #[must_use]
    pub fn effective_root_scope_hash(&self) -> &Sha256Digest {
        &self.effective_root_scope_hash
    }
}

/// The W1.1 trust-root scope hash of the verified root, for its exchange key only.
impl TrustRootResolver for VerifiedAnchoredRoot {
    fn trust_root_scope_hash(&self, issuer: &PublicKey) -> Option<ScopeHash> {
        (issuer == &self.exchange_key).then(|| self.effective_root_scope_hash.to_bare_hex())
    }
}

impl<'a> AnchoredTrustRoot<'a> {
    /// Pin `exchange_key`, which the loaded policy must list.
    pub fn new(
        exchange_key: &'a PublicKey,
        policy: &'a LoadedRootPolicy,
    ) -> Result<Self, AnchoredRootError> {
        if !policy.lists_exchange_key(exchange_key) {
            return Err(AnchoredRootError::ExchangeKeyNotInPolicy);
        }
        Ok(Self {
            exchange_key,
            policy,
        })
    }

    /// Verify a root presented alone (`ancestors: []`).
    ///
    /// `sender_key` is the `cnf.chioSenderKey` the presenter proved, if any.
    pub fn verify_root(
        &self,
        root: &CapabilityToken,
        anchor: &RootAnchor,
        context: &DelegationContext,
        sender_key: Option<&PublicKey>,
        clock: &dyn Clock,
        crypto_floor: CapabilityCryptoFloor,
    ) -> Result<VerifiedAnchoredRoot, AnchoredRootError> {
        let now = clock
            .unix_millis()
            .map_err(|error| AnchoredRootError::Clock(error.to_string()))?
            .as_secs();
        self.policy
            .check_valid_at(now)
            .map_err(AnchoredRootError::PolicyOutOfForce)?;
        if &root.issuer != self.exchange_key {
            return Err(AnchoredRootError::IssuerNotExchangeKey);
        }
        let capability = verify_capability_base(
            root,
            core::slice::from_ref(self.exchange_key),
            clock,
            crypto_floor,
            false,
            false,
        )
        .map_err(AnchoredRootError::Capability)?;
        check_root_binding(RootBindingInput {
            root,
            anchor,
            context,
            policy: self.policy,
            sender_key,
        })
        .map_err(AnchoredRootError::Binding)?;
        Ok(VerifiedAnchoredRoot {
            capability,
            anchor: anchor.clone(),
            exchange_key: self.exchange_key.clone(),
            rule_id: context.root_policy_rule_id.clone(),
            holder: context.exchange.holder,
            effective_root_scope_hash: context.effective_root_scope_hash,
        })
    }
}
