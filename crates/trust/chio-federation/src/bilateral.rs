//! Bilateral cross-kernel runtime co-signing.
//!
//! When an agent from Organisation A invokes a tool hosted by Organisation B,
//! both kernels sign the same DSSE envelope so that either org can
//! independently verify the invocation. This module defines the
//! [`DsseCoSigningRequest`] / [`DsseCoSigningResponse`] exchange and the
//! [`BilateralCoSigningProtocol`] trait that the tool-host kernel (Org B)
//! calls to obtain the origin kernel's (Org A) signature over the DSSE PAE
//! bytes.
//!
//! The canonical bilateral verification API is
//! [`crate::bilateral_verifier::verify_bilateral_cosign_invocation`] over a
//! [`crate::bilateral_dsse::DsseEnvelope`].

use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use chio_core_types::receipt::body::ChioReceipt;

use crate::bilateral_dsse::{BilateralPredicateExtensions, DsseEnvelope};

pub const BILATERAL_DSSE_COSIGNING_SCHEMA: &str = "chio.bilateral.dsse-cosigning.v1";

/// Request sent from the tool-host kernel (Org B) to the origin kernel
/// (Org A) asking it to sign a DSSE PAE preimage. Org B's signature over
/// the same bytes is included so Org A can authenticate the exact payload
/// it is asked to co-sign.
#[derive(Debug, Clone)]
pub struct DsseCoSigningRequest {
    pub schema: String,
    pub org_a_kernel_id: String,
    pub org_b_kernel_id: String,
    pub pae_bytes: Vec<u8>,
    pub org_b_signature: Signature,
}

impl DsseCoSigningRequest {
    pub fn new(
        org_a_kernel_id: String,
        org_b_kernel_id: String,
        pae_bytes: Vec<u8>,
        org_b_signature: Signature,
    ) -> Self {
        Self {
            schema: BILATERAL_DSSE_COSIGNING_SCHEMA.to_string(),
            org_a_kernel_id,
            org_b_kernel_id,
            pae_bytes,
            org_b_signature,
        }
    }
}

/// Response from the origin kernel (Org A) carrying its DSSE signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsseCoSigningResponse {
    pub schema: String,
    pub org_a_signature: Signature,
}

/// Errors surfaced by the bilateral co-signing protocol. All variants are
/// fail-closed: on any error the kernel MUST refuse to persist a bilateral
/// artifact for the failing exchange.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BilateralCoSigningError {
    #[error("canonical JSON encoding failed: {0}")]
    CanonicalJson(String),

    #[error("origin (Org A) signature failed verification")]
    OrgASignatureInvalid,

    #[error("tool-host (Org B) signature failed verification")]
    OrgBSignatureInvalid,

    #[error("remote peer {0} is not a trusted federation peer")]
    UnknownPeer(String),

    #[error("remote peer {0} has exceeded its rotation window and must re-handshake")]
    PeerExpired(String),

    #[error("co-signing transport failed: {0}")]
    TransportFailure(String),

    #[error("co-signing request rejected by peer: {0}")]
    PeerRejected(String),

    #[error("unsupported bilateral co-signing schema: {0}")]
    UnsupportedSchema(String),

    #[error("receipt body mismatch between request and signed body")]
    ReceiptMismatch,
}

impl BilateralCoSigningError {
    /// Stable diagnostic code for wire-profile and signer failures.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::CanonicalJson(message) if message.starts_with("dsse.malformed:") => {
                "dsse.malformed"
            }
            Self::CanonicalJson(message) if message.starts_with("payload base64:") => {
                "dsse.malformed"
            }
            Self::CanonicalJson(message) if message.starts_with("statement.malformed:") => {
                "statement.malformed"
            }
            Self::CanonicalJson(message) if message.starts_with("payload json:") => {
                "statement.malformed"
            }
            Self::CanonicalJson(message) if message.starts_with("statement.schema_invalid:") => {
                "statement.schema_invalid"
            }
            Self::CanonicalJson(message) if message.starts_with("predicate.type_unrecognised:") => {
                "predicate.type_unrecognised"
            }
            Self::CanonicalJson(message)
                if message.contains("requires independent Org A and Org B signer keys") =>
            {
                "signer.independence_required"
            }
            Self::CanonicalJson(message) if message.starts_with("predicate.schema_invalid:") => {
                "predicate.schema_invalid"
            }
            Self::CanonicalJson(message) if message.starts_with("subject.digest_mismatch:") => {
                "subject.digest_mismatch"
            }
            Self::CanonicalJson(_) => "canonical_json.invalid",
            Self::OrgASignatureInvalid => "signature.server_a_invalid",
            Self::OrgBSignatureInvalid => "signature.server_b_invalid",
            Self::UnknownPeer(_) => "peer.unknown",
            Self::PeerExpired(_) => "peer.expired",
            Self::TransportFailure(_) => "transport.failed",
            Self::PeerRejected(_) => "peer.rejected",
            Self::UnsupportedSchema(_) => "schema.unsupported",
            Self::ReceiptMismatch => "subject.digest_mismatch",
        }
    }
}

/// Trait implemented by an object that can obtain a co-signature from a
/// remote kernel. Production deployments plug an mTLS-backed RPC client
/// in here; in-process tests use [`InProcessCoSigner`].
pub trait BilateralCoSigningProtocol: Send + Sync {
    /// Request the origin kernel's DSSE PAE co-signature for the bilateral
    /// invocation envelope. The caller is the tool-host kernel (Org B); the
    /// remote is the origin kernel (Org A) whose agent initiated the call.
    /// Implementations verify Org B's signature over `request.pae_bytes`
    /// before returning Org A's signature.
    fn request_dsse_cosignature(
        &self,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError>;
}

/// In-process reference implementation of [`BilateralCoSigningProtocol`].
///
/// Holds the origin kernel's signing keypair directly, so tests and
/// single-host integration environments can exercise the co-signing path
/// without an actual mTLS transport. Production deployments should wrap
/// the remote kernel behind an attested RPC client instead.
pub struct InProcessCoSigner {
    origin_kernel_id: String,
    origin_keypair: Keypair,
    /// Expected public key of the tool-host kernel (Org B). The origin
    /// kernel verifies Org B's signature against this key before it is
    /// willing to co-sign.
    tool_host_public_key: PublicKey,
}

impl core::fmt::Debug for InProcessCoSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InProcessCoSigner")
            .field("origin_kernel_id", &self.origin_kernel_id)
            .finish_non_exhaustive()
    }
}

impl InProcessCoSigner {
    pub fn new(
        origin_kernel_id: impl Into<String>,
        origin_keypair: Keypair,
        tool_host_public_key: PublicKey,
    ) -> Self {
        Self {
            origin_kernel_id: origin_kernel_id.into(),
            origin_keypair,
            tool_host_public_key,
        }
    }

    pub fn origin_kernel_id(&self) -> &str {
        &self.origin_kernel_id
    }

    pub fn origin_public_key(&self) -> PublicKey {
        self.origin_keypair.public_key()
    }
}

impl BilateralCoSigningProtocol for InProcessCoSigner {
    fn request_dsse_cosignature(
        &self,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        if request.schema != BILATERAL_DSSE_COSIGNING_SCHEMA {
            return Err(BilateralCoSigningError::UnsupportedSchema(
                request.schema.clone(),
            ));
        }
        if request.org_a_kernel_id != self.origin_kernel_id {
            return Err(BilateralCoSigningError::UnknownPeer(
                request.org_a_kernel_id.clone(),
            ));
        }
        if chio_core_types::crypto::verify_exempt(
            &self.tool_host_public_key,
            chio_core_types::crypto::ExemptFormat::DssePae,
            &request.pae_bytes,
            &request.org_b_signature,
        )
        .is_err()
        {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }

        let backend = Ed25519Backend::new(self.origin_keypair.clone());
        let signature = backend
            .sign_bytes(chio_core_types::crypto::SigningMessage::exempt(
                chio_core_types::crypto::ExemptFormat::DssePae,
                &request.pae_bytes,
            ))
            .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
        Ok(DsseCoSigningResponse {
            schema: BILATERAL_DSSE_COSIGNING_SCHEMA.to_string(),
            org_a_signature: signature,
        })
    }
}

/// Tool-host (Org B) side of the bilateral exchange for the DSSE
/// signature-slice profile: sign the PAE bytes locally, obtain the origin
/// kernel's (Org A) signature through `cosigner`, and return the envelope
/// after verifying both signatures.
///
/// `tool_name` and `timestamp_unix_ms` are surfaced to callers because
/// they are predicate fields the envelope binds. `tool_name` is typically
/// `receipt.tool_name`; `timestamp_unix_ms` is the wall-clock at
/// canonicalisation (Org B-side).
///
/// Verifier boundary: this helper emits the extensionless signature-slice
/// profile. That artifact verifies at the low-level DSSE signature-slice
/// layer, but it is not accepted by `verify_bilateral_cosign_invocation`
/// because the canonical verifier requires `policy_evaluation_summary` and
/// `capability_lease_ref`. Use [`execute_local_bilateral_invocation_fixture`]
/// or [`crate::bilateral_dsse::sign_dsse_envelope_with_cosigner`] with
/// predicate extensions when the artifact must be accepted by the canonical
/// verifier.
#[allow(clippy::too_many_arguments)]
pub fn co_sign_with_origin(
    origin_kernel_id: &str,
    origin_public_key: &PublicKey,
    tool_host_kernel_id: &str,
    tool_host_keypair: &Keypair,
    receipt: &ChioReceipt,
    cosigner: &dyn BilateralCoSigningProtocol,
    tool_name: &str,
    timestamp_unix_ms: u64,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    crate::bilateral_dsse::sign_dsse_envelope_with_cosigner(
        receipt,
        origin_public_key,
        tool_host_keypair,
        origin_kernel_id,
        tool_host_kernel_id,
        tool_name,
        timestamp_unix_ms,
        BilateralPredicateExtensions::default(),
        cosigner,
    )
}

pub struct LocalBilateralInvocationFixtureRequest<'a> {
    /// `did:chio` identifier of the origin kernel (Org A).
    pub origin_kernel_id: &'a str,
    /// Origin kernel's pinned public key. The returned Org A signature must
    /// verify under this key.
    pub origin_public_key: &'a PublicKey,
    /// `did:chio` identifier of the tool-host kernel (Org B).
    pub tool_host_kernel_id: &'a str,
    /// Tool-host kernel's signing keypair.
    pub tool_host_keypair: &'a Keypair,
    /// Receipt the agent produced for the invocation. The envelope subject
    /// binds the canonical-JSON of this body.
    pub receipt: ChioReceipt,
    /// Tool name as exposed by both kernels. Typically equals
    /// `receipt.tool_name`.
    pub tool_name: &'a str,
    /// Org B's wall-clock at predicate canonicalisation (Unix ms).
    pub timestamp_unix_ms: u64,
    /// §5 predicate extensions; the §7 verifier requires
    /// `capability_lease_ref` and `policy_evaluation_summary` to be
    /// present, otherwise verification fails-closed at step 13/14.
    pub predicate_extensions: BilateralPredicateExtensions,
    /// Cosigner that returns the origin kernel's DSSE signature. Production
    /// kernels supply a `BilateralCoSigningProtocol` over an mTLS-backed
    /// RPC client; demos use [`InProcessCoSigner`].
    pub cosigner: &'a dyn BilateralCoSigningProtocol,
}

#[derive(Debug, Clone)]
pub struct BilateralInvocationOutcome {
    /// DSSE signature-slice envelope produced by the co-signing exchange.
    pub dsse_envelope: DsseEnvelope,
    /// Verifier output. Constructed by running the partial local
    /// verifier (subset of §7) against the freshly-signed envelope.
    pub verified: crate::bilateral_verifier::VerifiedBilateralCoSignInvocation,
}

/// Errors surfaced by [`execute_local_bilateral_invocation_fixture`]. Distinct from
/// [`BilateralCoSigningError`] because the verifier's spec §7.1 codes
/// have their own taxonomy; the helper folds both surfaces into one
/// local fixture result.
#[derive(Debug, thiserror::Error)]
pub enum BilateralInvocationError {
    /// The signing path failed before the verifier ran.
    #[error("co-signing failed: {0}")]
    CoSigning(#[from] BilateralCoSigningError),
    /// The partial local verifier (subset of §7) rejected the
    /// freshly-signed envelope.
    #[error("§7 verifier rejected envelope: {0}")]
    Verifier(#[from] crate::bilateral_verifier::VerifierError),
}

/// 1. Drives the co-signing exchange through `request.cosigner` to produce
///    the DSSE signature-slice envelope, layered with the
///    [`crate::bilateral_dsse::BilateralPredicateExtensions`] (lease ref,
///    policy summary, etc.) the verifier needs.
/// 2. Runs the partial local verifier (subset of §7) from
///    [`crate::bilateral_verifier::verify_bilateral_cosign_invocation`]
///    against the just-emitted envelope. The verifier resolves the
///    receipt store, lease registry, governance store, and revocation
///    oracle the kernel passes in.
/// 3. Returns the envelope + the verifier output, or fails closed with a
///    `BilateralInvocationError` carrying either the co-signing error or
///    the verifier's spec §7.1 code.
///
/// This is a local fixture helper: it signs the signature-slice profile
/// rather than the treaty-bound strict invocation predicate the kernel
/// emits.
pub fn execute_local_bilateral_invocation_fixture(
    request: LocalBilateralInvocationFixtureRequest<'_>,
    verifier_config: &crate::bilateral_verifier::VerifierConfig<'_>,
) -> Result<BilateralInvocationOutcome, BilateralInvocationError> {
    let dsse_envelope = crate::bilateral_dsse::sign_dsse_envelope_with_cosigner(
        &request.receipt,
        request.origin_public_key,
        request.tool_host_keypair,
        request.origin_kernel_id,
        request.tool_host_kernel_id,
        request.tool_name,
        request.timestamp_unix_ms,
        request.predicate_extensions,
        request.cosigner,
    )?;

    let verified = crate::bilateral_verifier::verify_bilateral_cosign_invocation(
        &dsse_envelope,
        verifier_config,
    )?;

    Ok(BilateralInvocationOutcome {
        dsse_envelope,
        verified,
    })
}
