//! Typed refusals of the root exchange.

use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::HolderClass;

/// The OAuth error a refusal answers with at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    UnsupportedGrantType,
    TemporarilyUnavailable,
    ServerError,
}

impl OAuthErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::ServerError => "server_error",
        }
    }
}

/// A sender binding of the presented token that the request does not meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderConstraintFailure {
    /// The token is confirmed by a Chio sender key, which needs a DPoP proof.
    DpopUnavailable,
    /// The `cnf` member is outside the closed confirmation profile.
    Confirmation,
    /// The request's mTLS certificate is not the one the token names.
    Mtls,
    /// The request's runtime attestation is not the one the token names.
    Attestation,
}

impl SenderConstraintFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DpopUnavailable => "dpop_unavailable",
            Self::Confirmation => "confirmation",
            Self::Mtls => "mtls",
            Self::Attestation => "attestation",
        }
    }
}

/// Why an exchange cannot be built from its configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootExchangeConfigError {
    #[error(
        "rule `{rule_id}` is an oidc_jwt rule whose provider record has a Microsoft Entra issuer"
    )]
    EntraIssuerOnOidcRule { rule_id: String },
    #[error(
        "rule `{rule_id}` is an entra_jwt rule whose provider record issuer is not tenant-specific"
    )]
    IssuerNotTenantSpecific { rule_id: String },
    #[error("the exchange key is not listed in the loaded root policy")]
    ExchangeKeyNotListed,
}

/// Why a token request yields no anchored root.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootExchangeError {
    #[error("token request is malformed: {0}")]
    MalformedRequest(&'static str),
    #[error("unsupported grant_type")]
    UnsupportedGrantType,
    #[error("unsupported subject_token_type")]
    UnsupportedSubjectTokenType,
    #[error("unsupported requested_token_type")]
    UnsupportedRequestedTokenType,
    #[error("requested scope is not a space-delimited list of scope tokens")]
    RequestedScopeMalformed,

    #[error("client authenticates with more than one method")]
    ClientAuthenticationAmbiguous,
    #[error("client authentication is missing")]
    ClientAssertionMissing,
    #[error("client_assertion_type is not jwt-bearer")]
    ClientAssertionTypeUnsupported,
    #[error("client is not a registered confidential client")]
    ClientNotConfidential,
    #[error("client assertion is invalid: {0}")]
    ClientAssertionInvalid(&'static str),
    #[error("client assertion is not an admissible compact JWS: {0}")]
    ClientAssertionMalformed(Box<RootExchangeError>),
    #[error("client assertion signature is invalid")]
    ClientAssertionSignatureInvalid,
    #[error("client assertion jti was already used")]
    ClientAssertionReplay,

    #[error("assertion is not a well-formed compact JWS: {0}")]
    MalformedJws(&'static str),
    #[error("JWS header member `{0}` is not allowed")]
    ForbiddenHeaderMember(&'static str),
    #[error("JWS alg is not admitted")]
    AlgorithmNotAdmitted,
    #[error("JWS kid is missing")]
    KidMissing,
    #[error("assertion typ is not the ID-JAG media type")]
    TypMismatch,
    #[error("kid is not in the provider key set")]
    UnknownKid,
    #[error("signing key does not admit the token alg")]
    KeyAlgorithmMismatch,
    #[error("assertion signature is invalid")]
    SignatureInvalid,

    #[error("identity-provider key is unusable")]
    IdpKeyUnusable,
    #[error("identity-provider keys are unavailable: {0}")]
    KeysUnavailable(String),

    #[error("provider record `{0}` is missing")]
    ProviderRecordMissing(String),
    #[error("provider record `{0}` is disabled")]
    ProviderRecordDisabled(String),
    #[error("provider record `{record}` is invalid: {reason}")]
    ProviderRecordInvalid { record: String, reason: String },
    #[error("provider record `{0}` identity differs from the root policy rule")]
    ProviderIdentityMismatch(String),

    #[error("assertion claim `{0}` is missing")]
    ClaimMissing(&'static str),
    #[error("assertion claim `{0}` is invalid")]
    ClaimInvalid(&'static str),
    #[error("assertion issuer is not the provider record issuer")]
    IssuerMismatch,
    #[error("assertion audience is not the local authorization server")]
    AudienceMismatch,
    #[error("assertion client_id differs from the authenticated client")]
    ClientIdMismatch,
    #[error("assertion resource is not the protected resource")]
    ResourceMismatch,
    #[error("assertion has expired")]
    AssertionExpired,
    #[error("assertion is issued in the future")]
    AssertionIssuedInFuture,
    #[error("assertion is not yet valid")]
    AssertionNotYetValid,
    #[error("assertion lifetime {lifetime}s exceeds {max}s")]
    AssertionLifetimeTooLong { lifetime: u64, max: u64 },
    #[error("assertion jti was already exchanged")]
    AssertionReplay,
    #[error("static bearer token is not the configured token")]
    StaticBearerMismatch,
    #[error("introspected token is not active")]
    IntrospectionInactive,
    #[error("token introspection is unavailable: {0}")]
    IntrospectionUnavailable(String),
    #[error("token introspection response is invalid: {0}")]
    IntrospectionInvalid(&'static str),
    #[error("more than one provider record serves token introspection")]
    IntrospectionRecordAmbiguous,
    #[error("request does not meet the token's sender constraint: {}", .0.as_str())]
    SenderConstraintUnmet(SenderConstraintFailure),
    #[error("re-exchange requests scope or resource beyond the subject token")]
    ReExchangeWidens,
    #[error("re-exchange client is not the client the subject token was issued to")]
    ReExchangeClientMismatch,
    #[error("operator root request is malformed: {0}")]
    OperatorRootRequestMalformed(&'static str),
    #[error("operator root request names no tenant_value")]
    OperatorRootRequestMissingTenant,
    #[error("operator root request signature does not verify under the operator key")]
    OperatorRootRequestSignatureInvalid,

    #[error("root policy is out of force")]
    PolicyOutOfForce,
    #[error("{matched} root policy rules match; exactly one is required")]
    RuleMatchCount { matched: usize },
    #[error("requested scope exceeds the assertion scope")]
    RequestedScopeExceedsAssertion,
    #[error("scope value is absent from the rule projection")]
    ScopeNotProjected,
    #[error("idp_scope_projection target is not one server/tool pair")]
    ProjectionTargetMalformed,
    #[error("effective root scope is empty")]
    EmptyEffectiveScope,
    #[error("holder class {} is not allowed by the rule", .0.as_str())]
    HolderClassNotAllowed(HolderClass),
    #[error("holder class {} is not the one the request names", .0.as_str())]
    RequestedHolderMismatch(HolderClass),
    #[error("requested root scope exceeds the rule ceiling")]
    ScopeExceedsCeiling,
    #[error("edge_session root would carry a proof-required grant")]
    ProofRequiredGrantForEdgeSession,
    #[error("recorded claim `{0}` is absent from the assertion")]
    RecordedClaimMissing(&'static str),
    #[error("root would expire at or before now")]
    RootLifetimeEmpty,
    #[error("anchor kind {} is not exchanged here", .0.as_str())]
    KindNotExchanged(AnchorKind),

    #[error("entropy source failed")]
    EntropyUnavailable,
    #[error("replay store is unavailable: {0}")]
    ReplayStoreUnavailable(String),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

impl RootExchangeError {
    /// The OAuth error code the token endpoint answers with. Faults of the
    /// provider's own configuration or services are `server_error` or
    /// `temporarily_unavailable`, never a judgement on the client's grant.
    #[must_use]
    pub fn oauth_error(&self) -> OAuthErrorCode {
        match self {
            Self::MalformedRequest(_)
            | Self::UnsupportedSubjectTokenType
            | Self::UnsupportedRequestedTokenType
            | Self::ClientAuthenticationAmbiguous
            | Self::OperatorRootRequestMalformed(_)
            | Self::OperatorRootRequestMissingTenant
            | Self::OperatorRootRequestSignatureInvalid
            | Self::RequestedHolderMismatch(_) => OAuthErrorCode::InvalidRequest,
            Self::UnsupportedGrantType => OAuthErrorCode::UnsupportedGrantType,
            Self::ClientAssertionMissing
            | Self::ClientAssertionTypeUnsupported
            | Self::ClientNotConfidential
            | Self::ClientAssertionInvalid(_)
            | Self::ClientAssertionMalformed(_)
            | Self::ClientAssertionSignatureInvalid
            | Self::ClientAssertionReplay => OAuthErrorCode::InvalidClient,
            Self::MalformedJws(_)
            | Self::ForbiddenHeaderMember(_)
            | Self::AlgorithmNotAdmitted
            | Self::KidMissing
            | Self::TypMismatch
            | Self::UnknownKid
            | Self::KeyAlgorithmMismatch
            | Self::SignatureInvalid
            | Self::ClaimMissing(_)
            | Self::ClaimInvalid(_)
            | Self::IssuerMismatch
            | Self::AudienceMismatch
            | Self::ClientIdMismatch
            | Self::ResourceMismatch
            | Self::AssertionExpired
            | Self::AssertionIssuedInFuture
            | Self::AssertionNotYetValid
            | Self::AssertionLifetimeTooLong { .. }
            | Self::AssertionReplay
            | Self::StaticBearerMismatch
            | Self::IntrospectionInactive
            | Self::SenderConstraintUnmet(_)
            | Self::ReExchangeClientMismatch
            | Self::RuleMatchCount { .. }
            | Self::HolderClassNotAllowed(_)
            | Self::ProofRequiredGrantForEdgeSession
            | Self::RecordedClaimMissing(_)
            | Self::RootLifetimeEmpty => OAuthErrorCode::InvalidGrant,
            Self::RequestedScopeMalformed
            | Self::RequestedScopeExceedsAssertion
            | Self::ScopeExceedsCeiling
            | Self::ReExchangeWidens
            | Self::ScopeNotProjected
            | Self::EmptyEffectiveScope => OAuthErrorCode::InvalidScope,
            Self::ProjectionTargetMalformed => OAuthErrorCode::ServerError,
            Self::KeysUnavailable(_)
            | Self::ReplayStoreUnavailable(_)
            | Self::IntrospectionUnavailable(_) => OAuthErrorCode::TemporarilyUnavailable,
            Self::IdpKeyUnusable
            | Self::ProviderRecordMissing(_)
            | Self::ProviderRecordDisabled(_)
            | Self::ProviderRecordInvalid { .. }
            | Self::ProviderIdentityMismatch(_)
            | Self::PolicyOutOfForce
            | Self::KindNotExchanged(_)
            | Self::IntrospectionInvalid(_)
            | Self::IntrospectionRecordAmbiguous
            | Self::EntropyUnavailable
            | Self::Canonicalization(_) => OAuthErrorCode::ServerError,
        }
    }

    /// The `error_description` a client may see. `server_error` and
    /// `temporarily_unavailable` carry none, so no configuration or backend
    /// detail reaches the client.
    #[must_use]
    pub fn client_description(&self) -> Option<String> {
        match self.oauth_error() {
            OAuthErrorCode::ServerError | OAuthErrorCode::TemporarilyUnavailable => None,
            _ => Some(self.to_string()),
        }
    }
}
