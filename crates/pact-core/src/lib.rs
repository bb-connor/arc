//! # pact-core
//!
//! Shared vocabulary for the PACT protocol. This crate defines the fundamental
//! types that flow between all PACT components: capability tokens, tool grants,
//! scopes, receipts, and canonical JSON serialization helpers.
//!
//! Nothing in this crate performs I/O or depends on a runtime. It is a pure
//! data-and-crypto crate suitable for use in WASM, embedded, and no-std
//! (with alloc) environments.

pub mod canonical;
pub mod capability;
pub mod crypto;
pub mod error;
pub mod hashing;
pub mod manifest;
pub mod merkle;
pub mod message;
pub mod receipt;
pub mod session;

pub use canonical::{canonical_json_bytes, canonical_json_string, canonicalize};
pub use capability::{
    Attenuation, CapabilityToken, CapabilityTokenBody, Constraint, DelegationLink,
    DelegationLinkBody, MonetaryAmount, Operation, PactScope, PromptGrant, ResourceGrant,
    ToolGrant,
};
pub use crypto::{sha256_hex, Keypair, PublicKey, Signature};
pub use error::Error;
pub use hashing::{sha256, Hash};
pub use manifest::{ToolAnnotations, ToolDefinition, ToolManifest, ToolManifestBody};
pub use merkle::{MerkleProof, MerkleTree};
pub use message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
pub use receipt::{
    ChildRequestReceipt, ChildRequestReceiptBody, Decision, FinancialReceiptMetadata,
    GuardEvidence, PactReceipt, PactReceiptBody, ToolCallAction,
};
pub use session::{
    CompleteOperation, CompletionArgument, CompletionReference, CompletionResult,
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, ElicitationAction, GetPromptOperation, OperationContext, OperationKind,
    OperationTerminalState, ProgressToken, PromptArgument, PromptDefinition, PromptMessage,
    PromptResult, ReadResourceOperation, RequestId, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition, RootDefinition, SamplingMessage, SamplingTool, SamplingToolChoice,
    SessionAuthContext, SessionAuthMethod, SessionId, SessionOperation, SessionTransport,
    ToolCallOperation,
};

pub use capability::{validate_attenuation, validate_delegation_chain};

/// Opaque agent identifier. In practice this is a hex-encoded Ed25519 public key
/// or a SPIFFE URI, but the core treats it as an opaque string.
pub type AgentId = String;

/// Opaque tool server identifier.
pub type ServerId = String;

/// UUIDv7 capability identifier (time-ordered).
pub type CapabilityId = String;
