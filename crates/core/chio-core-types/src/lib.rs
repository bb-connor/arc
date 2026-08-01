//! Core Chio protocol types: capabilities, receipts, crypto primitives, and
//! canonical JSON. This crate is `no_std + alloc` compatible; heavier domain
//! crates (`chio-core`, `chio-appraisal`, etc.) re-export these types with
//! additional features layered on top.
//!
//! # no_std support
//!
//! The crate is `no_std + alloc` by source: under `--no-default-features`
//! every module compiles against `core` and `alloc` only. This is the
//! foundation that lets `chio-kernel-core` cross-compile to
//! `wasm32-unknown-unknown` and other embedded targets. The default `std`
//! feature re-enables `std`-backed error impls via `thiserror`, along with
//! the `std` feature on every transitive dependency.
//!
//! # Generated wire bindings
//!
//! Schema-derived Rust bindings live under `src/_generated/` as regenerate-only
//! artifacts. They are not re-exported from this crate root: the stable public
//! API is the hand-maintained no_std-compatible protocol modules below.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

pub mod canonical;
pub mod capability;
pub mod crypto;
pub mod declassification;
pub mod delegation_receipt;
pub mod economic_continuity;
pub mod error;
pub mod hashing;
pub mod loaded_weights;
pub mod manifest;
pub mod merkle;
pub mod message;
pub mod oracle;
pub mod partition_escrow;
pub mod plan;
#[cfg(feature = "pq")]
pub mod pq;
pub mod provider_attempt;
pub mod receipt;
pub mod runtime_attestation;
mod schema_binding;
pub mod security_event;
pub mod session;
pub mod signed_artifact;
mod signer_binding;
mod store_fence;

#[cfg(test)]
#[path = "economic_continuity_anchor_tests.rs"]
mod economic_continuity_anchor_tests;
#[cfg(test)]
#[path = "economic_continuity_tests.rs"]
mod economic_continuity_tests;

pub use canonical::{
    canonical_json_bytes, canonical_json_bytes_from_str, canonical_json_string,
    canonical_json_string_from_str, canonicalize, CanonicalBytes, CanonicalJsonWitness,
};
pub use crypto::{
    sha256_hex, Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
    SigningOutcome,
};
#[cfg(feature = "pq")]
pub use crypto::{HybridBackend, MlDsa65Backend};
#[cfg(feature = "fips")]
pub use crypto::{P256Backend, P384Backend};
pub use declassification::{SignedDeclassificationGrant, DECLASSIFICATION_GRANT_SIGNATURE_DOMAIN};
pub use delegation_receipt::{DelegationReceipt, ScopeAttenuation};
pub use economic_continuity::{
    CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
pub use error::{Error, Result};
pub use hashing::{sha256, Hash};
pub use loaded_weights::{
    loaded_weights_hash_of, loaded_weights_hash_of_chunks, LoadedWeights, LoadedWeightsUnavailable,
};
pub use manifest::{
    DeclassificationPurpose, LatencyHint, PricingModel, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolFlowValidationError, ToolManifest, ToolManifestBody, ToolPricing,
};
pub use merkle::{leaf_hash, node_hash, MerkleProof, MerkleTree};
pub use message::{
    AgentMessage, KernelMessage, OpaqueSupplementalAuthorization, ToolCallError, ToolCallResult,
    MAX_SUPPLEMENTAL_AUTHORIZATION_BYTES, MAX_SUPPLEMENTAL_AUTHORIZATION_REFERENCE_BYTES,
};
pub use oracle::{OracleConversionEvidence, CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA};
pub use partition_escrow::{
    verify_partition_escrow_allocation_set, verify_partition_escrow_allocation_set_structure,
    verify_partition_escrow_quota_commitment, PartitionEscrowAllocation,
    PartitionEscrowAllocationPlan, PartitionEscrowAllocationPlanBinding,
    PartitionEscrowAllocationSetBody, PartitionEscrowAllocationVerificationContext,
    PartitionEscrowQuota, PartitionEscrowQuotaCommitmentBody, PartitionEscrowQuotaSourceBinding,
    PartitionEscrowValidationError, SignedPartitionEscrowAllocationSet,
    SignedPartitionEscrowQuotaCommitment, StructurallyVerifiedPartitionEscrowAllocation,
    VerifiedPartitionEscrowAllocation, VerifiedPartitionEscrowQuotaCertificate,
    MAX_PARTITION_ESCROW_ALLOCATIONS, MAX_PARTITION_ESCROW_IDENTIFIER_BYTES,
    PARTITION_ESCROW_ALLOCATION_PLAN_DIGEST_DOMAIN, PARTITION_ESCROW_ALLOCATION_SET_DIGEST_DOMAIN,
    PARTITION_ESCROW_ALLOCATION_SET_SCHEMA, PARTITION_ESCROW_ALLOCATION_SIGNATURE_DOMAIN,
    PARTITION_ESCROW_QUOTA_AUTHORITY_BINDING_DOMAIN,
    PARTITION_ESCROW_QUOTA_COMMITMENT_DIGEST_DOMAIN, PARTITION_ESCROW_QUOTA_COMMITMENT_SCHEMA,
    PARTITION_ESCROW_QUOTA_COMMITMENT_SIGNATURE_DOMAIN, PARTITION_ESCROW_QUOTA_DESCRIPTOR_DOMAIN,
    PARTITION_ESCROW_QUOTA_KEY_DOMAIN,
};
pub use plan::{
    PlanEvaluationRequest, PlanEvaluationResponse, PlanVerdict, PlannedToolCall, PlannedToolCallId,
    StepVerdict, StepVerdictKind,
};
pub use runtime_attestation::{
    verifier_family_for_attestation_schema, AttestationVerifierFamily,
    AWS_NITRO_ATTESTATION_SCHEMA, AWS_NITRO_VERIFIER_ADAPTER, AZURE_MAA_ATTESTATION_SCHEMA,
    AZURE_MAA_VERIFIER_ADAPTER, ENTERPRISE_VERIFIER_ADAPTER,
    ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
    GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
};
pub use security_event::{SignedSecurityEvent, SECURITY_EVENT_SIGNATURE_DOMAIN};
pub use session::{
    ChioIdentityAssertion, CompleteOperation, CompletionArgument, CompletionReference,
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
pub use signed_artifact::{
    built_in_signed_artifact_registry, is_supported_signed_artifact_schema,
    validate_signed_artifact_schema, SignedArtifactSchemaEntry, CHIO_ANCHOR_BATCH_V1_SCHEMA,
    CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA, CHIO_ANCHOR_INCLUSION_PROOF_V2_SCHEMA,
    CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA, CHIO_ANCHOR_PROOF_BUNDLE_V2_SCHEMA,
    CHIO_BROKER_AUDIT_COMPARISON_V1_SCHEMA, CHIO_BROKER_AUDIT_RUNNER_AUTHORIZATION_V1_SCHEMA,
    CHIO_BUDGET_SNAPSHOT_ANCHOR_PROVENANCE_V1_SCHEMA, CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA,
    CHIO_CREDIT_FACILITY_BIND_V1_SCHEMA, CHIO_ENTERPRISE_MIGRATION_CANARY_EVIDENCE_V1_SCHEMA,
    CHIO_ENTERPRISE_MIGRATION_CUTOVER_ATTESTATION_V1_SCHEMA,
    CHIO_FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_V1_SCHEMA, CHIO_FACTOR_ASSIGNMENT_AGREEMENT_V1_SCHEMA,
    CHIO_FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_V1_SCHEMA,
    CHIO_FACTOR_ASSIGNMENT_NOT_APPLIED_V1_SCHEMA,
    CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_V1_SCHEMA, CHIO_FROST_AUTHORIZATION_V1_SCHEMA,
    CHIO_FROST_EPOCH_CHECKPOINT_V1_SCHEMA, CHIO_FROST_ROSTER_V1_SCHEMA,
    CHIO_OUTCOME_CONTRACTUAL_ZERO_V1_SCHEMA, CHIO_OUTCOME_DELIVERY_ACKNOWLEDGEMENT_V1_SCHEMA,
    CHIO_OUTCOME_DELIVERY_CHECKPOINT_V1_SCHEMA, CHIO_OUTCOME_DELIVERY_NONACCEPTANCE_V1_SCHEMA,
    CHIO_OUTCOME_ELIGIBILITY_V1_SCHEMA, CHIO_OUTCOME_OUTPUT_PROVENANCE_V1_SCHEMA,
    CHIO_OUTCOME_PREDICATE_V1_SCHEMA, CHIO_OUTCOME_PRICING_V1_SCHEMA, CHIO_OUTCOME_SLA_V1_SCHEMA,
    CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA, CHIO_TOOL_MANIFEST_V2_SCHEMA,
    CHIO_TRANSACTION_CLAIM_SET_V1_SCHEMA, KNOWN_SIGNED_ARTIFACT_SCHEMAS,
};
pub use store_fence::StoreMutationFence;

/// Opaque agent identifier: hex-encoded Ed25519 public key or SPIFFE URI
/// accepted; the core performs no structural validation.
pub type AgentId = alloc::string::String;

/// Opaque tool server identifier.
pub type ServerId = alloc::string::String;

/// Opaque capability identifier carried exactly as signed.
pub type CapabilityId = alloc::string::String;
