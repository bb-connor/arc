//! Portable reputation credentials and Agent Passport verification for Chio.
//!
//! The native Chio passport format remains intentionally simple:
//! - credentials are canonically JSON-signed with Ed25519
//! - issuer and subject identities currently remain `did:chio` identifiers
//! - a passport is an unsigned bundle of independently verifiable credentials
//! - verification is pure and requires no kernel or storage dependency
//!
//! Chio also ships a narrower standards-native projection lane for external
//! OID4VCI-style issuance. That path remains derived from the native passport
//! artifact rather than replacing it as the source of truth.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use chio_fincred::*;

const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";
const CHIO_CREDENTIAL_CONTEXT_V1: &str = "https://chio.world/credentials/v1";
const VC_TYPE: &str = "VerifiableCredential";
const REPUTATION_ATTESTATION_TYPE: &str = "ChioReputationAttestation";
const PASSPORT_SCHEMA: &str = "chio.agent-passport.v1";
const PASSPORT_VERIFIER_POLICY_SCHEMA: &str = "chio.passport-verifier-policy.v1";
const PASSPORT_PRESENTATION_CHALLENGE_SCHEMA: &str =
    "chio.agent-passport-presentation-challenge.v1";
const PASSPORT_PRESENTATION_RESPONSE_SCHEMA: &str = "chio.agent-passport-presentation-response.v1";
const CROSS_ISSUER_PORTFOLIO_SCHEMA: &str = "chio.cross-issuer-portfolio.v1";
const CROSS_ISSUER_TRUST_PACK_SCHEMA: &str = "chio.cross-issuer-trust-pack.v1";
const CROSS_ISSUER_MIGRATION_SCHEMA: &str = "chio.cross-issuer-migration.v1";
const PROOF_TYPE: &str = "Ed25519Signature2020";
const PROOF_PURPOSE: &str = "assertionMethod";
const PRESENTATION_PROOF_PURPOSE: &str = "authentication";

fn is_supported_passport_schema(schema: &str) -> bool {
    schema == PASSPORT_SCHEMA
}

fn is_supported_passport_verifier_policy_schema(schema: &str) -> bool {
    schema == PASSPORT_VERIFIER_POLICY_SCHEMA
}

fn is_supported_passport_presentation_challenge_schema(schema: &str) -> bool {
    schema == PASSPORT_PRESENTATION_CHALLENGE_SCHEMA
}

fn is_supported_passport_presentation_response_schema(schema: &str) -> bool {
    schema == PASSPORT_PRESENTATION_RESPONSE_SCHEMA
}

mod jwt_decode;

pub mod trust_tier;
pub use trust_tier::{
    synthesize_trust_tier, TrustTier, TRUST_TIER_ATTESTED_MIN, TRUST_TIER_PREMIER_MIN,
    TRUST_TIER_VERIFIED_MIN,
};

// libFuzzer entry-point module, enabled only when the `fuzz` feature is
// turned on by the standalone `chio-fuzz` workspace at `../../fuzz`.
#[cfg(feature = "fuzz")]
pub mod fuzz;
pub use artifact::{
    AttestationWindow, ChioCredentialEvidence, CredentialError, CredentialProof,
    EnterpriseIdentityProvenance, ReputationCredential, ReputationCredentialSubject,
    UnsignedReputationCredential,
};
pub use challenge::{
    build_agent_passport, create_passport_presentation_challenge,
    create_passport_presentation_challenge_with_reference, evaluate_agent_passport,
    issue_reputation_credential, issue_reputation_credential_with_enterprise_identity,
    passport_artifact_id, present_agent_passport, verify_agent_passport,
    verify_passport_presentation_challenge, verify_reputation_credential,
    PassportPresentationChallenge, PassportPresentationChallengeArgs, PassportPresentationOptions,
    PassportPresentationResponse, PassportPresentationVerification, PresentationProof,
};
pub use cross_issuer::{
    create_signed_cross_issuer_migration, create_signed_cross_issuer_trust_pack,
    evaluate_cross_issuer_portfolio, verify_cross_issuer_portfolio,
    verify_signed_cross_issuer_migration, verify_signed_cross_issuer_trust_pack,
    CreateSignedCrossIssuerMigrationArgs, CrossIssuerPortfolio, CrossIssuerPortfolioEntry,
    CrossIssuerPortfolioEntryEvaluation, CrossIssuerPortfolioEntryKind,
    CrossIssuerPortfolioEntryVerification, CrossIssuerPortfolioEvaluation,
    CrossIssuerPortfolioVerification, CrossIssuerTrustPackPolicy, SignedCrossIssuerMigration,
    SignedCrossIssuerMigrationBody, SignedCrossIssuerTrustPack, SignedCrossIssuerTrustPackBody,
};
pub use discovery::{
    create_signed_public_discovery_transparency, create_signed_public_issuer_discovery,
    create_signed_public_verifier_discovery, ensure_signed_public_discovery_transparency_active,
    ensure_signed_public_issuer_discovery_active, ensure_signed_public_verifier_discovery_active,
    verify_signed_public_discovery_transparency, verify_signed_public_issuer_discovery,
    verify_signed_public_verifier_discovery, PublicDiscoveryEntryKind,
    PublicDiscoveryImportGuardrails, PublicDiscoveryTransparencyEntry,
    SignedPublicDiscoveryTransparency, SignedPublicDiscoveryTransparencyBody,
    SignedPublicDiscoveryTransparencyInput, SignedPublicIssuerDiscovery,
    SignedPublicIssuerDiscoveryBody, SignedPublicIssuerDiscoveryInput,
    SignedPublicVerifierDiscovery, SignedPublicVerifierDiscoveryBody,
    SignedPublicVerifierDiscoveryInput, CHIO_PUBLIC_DISCOVERY_TRANSPARENCY_SCHEMA,
    CHIO_PUBLIC_ISSUER_DISCOVERY_SCHEMA, CHIO_PUBLIC_VERIFIER_DISCOVERY_SCHEMA,
};
pub use financial::*;
pub use oid4vci::{
    build_oid4vci_passport_offer, default_oid4vci_passport_issuer_metadata,
    default_oid4vci_passport_issuer_metadata_with_signing_key,
    default_oid4vci_passport_issuer_metadata_with_status_distribution,
    Oid4vciChioCredentialContext, Oid4vciChioCredentialProfile, Oid4vciChioIssuerProfile,
    Oid4vciChioOfferContext, Oid4vciChioPassportStatusReference,
    Oid4vciChioPortableCredentialProfile, Oid4vciCredentialConfiguration,
    Oid4vciCredentialIssuerMetadata, Oid4vciCredentialOffer, Oid4vciCredentialRequest,
    Oid4vciCredentialResponse, Oid4vciOfferGrants, Oid4vciPreAuthorizedGrant, Oid4vciTokenRequest,
    Oid4vciTokenResponse, Oid4vciTxCode, CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID,
    CHIO_PASSPORT_OID4VCI_FORMAT, OID4VCI_ISSUER_METADATA_PATH, OID4VCI_PASSPORT_CREDENTIAL_PATH,
    OID4VCI_PASSPORT_OFFERS_PATH, OID4VCI_PASSPORT_TOKEN_PATH, OID4VCI_PRE_AUTHORIZED_GRANT_TYPE,
};
pub use oid4vp::{
    build_oid4vp_request_transport, build_wallet_exchange_descriptor_for_oid4vp,
    inspect_chio_passport_sd_jwt_vc_unverified, inspect_oid4vp_direct_post_response,
    respond_to_oid4vp_request, sign_oid4vp_request_object, verify_oid4vp_direct_post_response,
    verify_oid4vp_direct_post_response_with_any_issuer_key, verify_signed_oid4vp_request_object,
    verify_signed_oid4vp_request_object_with_any_key, Oid4vpDcqlQuery, Oid4vpDescriptorMap,
    Oid4vpDirectPostResponseClaims, Oid4vpPresentationSubmission, Oid4vpPresentationVerification,
    Oid4vpRequestObject, Oid4vpRequestTransport, Oid4vpRequestedCredential, Oid4vpVerifierMetadata,
    WalletExchangeDescriptor, WalletExchangeReplayAnchors, WalletExchangeTransactionState,
    WalletExchangeTransactionStatus, WalletExchangeTransportMode,
    CHIO_WALLET_EXCHANGE_DESCRIPTOR_PROFILE, OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI,
    OID4VP_OPENID4VP_SCHEME, OID4VP_REQUEST_OBJECT_TYP, OID4VP_RESPONSE_MODE_DIRECT_POST_JWT,
    OID4VP_RESPONSE_OBJECT_TYP, OID4VP_RESPONSE_TYPE_VP_TOKEN, OID4VP_VERIFIER_METADATA_PATH,
};
pub use passport::{
    AgentPassport, CredentialPolicyEvaluation, PassportLifecycleRecord,
    PassportLifecycleResolution, PassportLifecycleState, PassportPolicyEvaluation,
    PassportStatusDistribution, PassportVerification, PassportVerifierPolicy,
    PassportVerifierPolicyReference, SignedPassportVerifierPolicy,
    SignedPassportVerifierPolicyBody,
};
pub use portable_jwt_vc::{
    build_chio_passport_jwt_vc_json_type_metadata, issue_chio_passport_jwt_vc_json,
    verify_chio_passport_jwt_vc_json, ChioPassportJwtVcJsonEnvelope,
    ChioPassportJwtVcJsonTypeMetadata, ChioPassportJwtVcJsonVerification,
    CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_JWT_VC_JSON_FORMAT,
    CHIO_PASSPORT_JWT_VC_JSON_TYPE, CHIO_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH,
};
pub use portable_reputation::{
    build_portable_negative_event_artifact, build_portable_reputation_summary_artifact,
    evaluate_portable_reputation, PortableNegativeEventArtifact, PortableNegativeEventEvidenceKind,
    PortableNegativeEventEvidenceReference, PortableNegativeEventIssueRequest,
    PortableNegativeEventKind, PortableReputationEvaluation, PortableReputationEvaluationRequest,
    PortableReputationFinding, PortableReputationFindingCode, PortableReputationSummaryArtifact,
    PortableReputationSummaryArtifactContext, PortableReputationSummaryIssueRequest,
    PortableReputationWeightingProfile, SignedPortableNegativeEvent,
    SignedPortableReputationSummary, PORTABLE_NEGATIVE_EVENT_SCHEMA,
    PORTABLE_REPUTATION_SUMMARY_SCHEMA,
};
pub use portable_sd_jwt::{
    build_chio_passport_portable_projection, build_chio_passport_sd_jwt_type_metadata,
    build_portable_issuer_jwks, build_portable_jwks, issue_chio_passport_sd_jwt_vc,
    verify_chio_passport_sd_jwt_vc, ChioPassportPortableProjection, ChioPassportSdJwtVcEnvelope,
    ChioPassportSdJwtVcTypeMetadata, ChioPassportSdJwtVcUnverified,
    ChioPassportSdJwtVcVerification, Oid4vciIssuedCredential, PortableEd25519Jwk,
    PortableEd25519JwkSetEntry, PortableJwkSet,
    CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_SD_JWT_VC_FORMAT,
    CHIO_PASSPORT_SD_JWT_VC_TYPE, CHIO_PASSPORT_SD_JWT_VC_TYPE_METADATA_PATH, OID4VCI_JWKS_PATH,
};
pub use presentation::{
    respond_to_passport_presentation_challenge, verify_passport_presentation_response,
    verify_passport_presentation_response_with_policy,
};
pub use registry::{
    create_signed_passport_verifier_policy, ensure_signed_passport_verifier_policy_active,
    verify_signed_passport_verifier_policy,
};

mod artifact;
mod challenge;
mod cross_issuer;
mod discovery;
mod financial;
mod oid4vci;
mod oid4vp;
mod passport;
mod policy;
mod portable_jwt_vc;
mod portable_reputation;
mod portable_sd_jwt;
mod presentation;
mod registry;
#[cfg(test)]
mod tests;
