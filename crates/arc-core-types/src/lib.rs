//! Shared ARC substrate types extracted from `arc-core`.
//!
//! This crate holds the protocol-wide types that should remain stable while
//! heavier domain crates split away from the compatibility facade.

pub mod canonical;
pub mod capability;
pub mod crypto;
pub mod error;
pub mod hashing;
pub mod manifest;
pub mod merkle;
pub mod message;
pub mod oracle;
pub mod receipt;
pub mod runtime_attestation;
pub mod session;

pub use canonical::{canonical_json_bytes, canonical_json_string, canonicalize};
pub use capability::{
    canonicalize_attestation_verifier, validate_attenuation, validate_delegation_chain, ArcScope,
    Attenuation, AttestationTrustError, AttestationTrustPolicy, AttestationTrustRule,
    CapabilityToken, CapabilityTokenBody, Constraint, ContentReviewTier, DelegationLink,
    DelegationLinkBody, GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedAutonomyContext, GovernedAutonomyTier, GovernedCallChainContext,
    GovernedCommerceContext, GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote,
    MeteredSettlementMode, ModelMetadata, ModelSafetyTier, MonetaryAmount, Operation, PromptGrant,
    ResolvedRuntimeAssurance, ResourceGrant, RuntimeAssuranceTier, RuntimeAttestationEvidence,
    SqlOperationClass, ToolGrant, WorkloadCredentialKind, WorkloadIdentity, WorkloadIdentityError,
    WorkloadIdentityScheme,
};
pub use crypto::{
    sha256_hex, Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
#[cfg(feature = "fips")]
pub use crypto::{P256Backend, P384Backend};
pub use error::{Error, Result};
pub use hashing::{sha256, Hash};
pub use manifest::{
    PricingModel, ToolAnnotations, ToolDefinition, ToolManifest, ToolManifestBody, ToolPricing,
};
pub use merkle::{leaf_hash, node_hash, MerkleProof, MerkleTree};
pub use message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
pub use oracle::{OracleConversionEvidence, ARC_ORACLE_CONVERSION_EVIDENCE_SCHEMA};
pub use receipt::{
    ArcReceipt, ArcReceiptBody, ChildRequestReceipt, ChildRequestReceiptBody, Decision,
    FinancialReceiptMetadata, GovernedApprovalReceiptMetadata, GovernedAutonomyReceiptMetadata,
    GovernedCommerceReceiptMetadata, GovernedTransactionReceiptMetadata, GuardEvidence,
    MeteredBillingReceiptMetadata, MeteredUsageEvidenceReceiptMetadata, ReceiptAttributionMetadata,
    RuntimeAssuranceReceiptMetadata, SettlementStatus, SignedExportEnvelope, ToolCallAction,
    TrustLevel,
};
pub use runtime_attestation::{
    verifier_family_for_attestation_schema, AttestationVerifierFamily,
    AWS_NITRO_ATTESTATION_SCHEMA, AWS_NITRO_VERIFIER_ADAPTER, AZURE_MAA_ATTESTATION_SCHEMA,
    AZURE_MAA_VERIFIER_ADAPTER, ENTERPRISE_VERIFIER_ADAPTER,
    ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
    GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
};
pub use session::{
    ArcIdentityAssertion, CompleteOperation, CompletionArgument, CompletionReference,
    CompletionResult, CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, ElicitationAction, EnterpriseFederationMethod, EnterpriseIdentityContext,
    GetPromptOperation, NormalizedRoot, OAuthBearerFederatedClaims, OAuthBearerSessionAuthInput,
    OperationContext, OperationKind, OperationTerminalState, ProgressToken, PromptArgument,
    PromptDefinition, PromptMessage, PromptResult, ReadResourceOperation, RequestId,
    RequestOwnershipSnapshot, ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
    ResourceUriClassification, RootDefinition, SamplingMessage, SamplingTool, SamplingToolChoice,
    SessionAuthContext, SessionAuthMethod, SessionId, SessionOperation, SessionTransport,
    StreamOwner, TaskOwnershipSnapshot, ToolCallOperation, WorkOwner,
};

/// Opaque agent identifier. In practice this is a hex-encoded Ed25519 public key
/// or a SPIFFE URI, but the core treats it as an opaque string.
pub type AgentId = String;

/// Opaque tool server identifier.
pub type ServerId = String;

/// UUIDv7 capability identifier (time-ordered).
pub type CapabilityId = String;
