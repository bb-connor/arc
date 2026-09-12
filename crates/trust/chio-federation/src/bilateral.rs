//! Bilateral cross-kernel runtime co-signing.
//!
//! When an agent from Organisation A invokes a tool hosted by Organisation B,
//! both kernels need to sign the same receipt so that either org can
//! independently verify the chain. This module defines the wire-level
//! [`CoSigningRequest`] / [`CoSigningResponse`] envelope, the
//! [`DualSignedReceipt`] compatibility artifact (which carries both
//! signatures side-by-side without mutating the core `ChioReceipt` body), and a
//! [`BilateralCoSigningProtocol`] trait that the kernel calls after it
//! signs a receipt locally.
//!
//! The canonical verification API for new bilateral artifacts is
//! [`crate::bilateral_verifier::verify_bilateral_cosign_invocation`] over a
//! [`crate::bilateral_dsse::DsseEnvelope`]. `DualSignedReceipt::verify*`
//! remains a compatibility adapter for the older detached-signature
//! envelope only; it is not a DSSE verifier and must not be used as the
//! authorization or audit verifier for the signature-slice profile.
//!
//! ## Design notes
//!
//! * `chio-core-types::ChioReceipt` is intentionally untouched -- co-signatures
//!   ride in this federation-specific envelope. An Org A verifier that only
//!   understands the base receipt can still verify it in isolation; a Dual
//!   verifier checks the base receipt plus the remote org's detached
//!   signature over the same canonical body.
//! * Verification is strict: a `DualSignedReceipt` only verifies when BOTH
//!   signatures validate against their declared kernel IDs and both kernel
//!   IDs match the expected pinned peers. Either half alone is not
//!   sufficient.
//! * Signing happens over canonical JSON (RFC 8785) of the
//!   [`CoSigningBody`]: receipt body bytes + both kernel IDs. This keeps the
//!   detached remote signature deterministic across implementations.

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use chio_core_types::receipt::body::ChioReceipt;
use serde::{Deserialize, Serialize};

pub const BILATERAL_COSIGNING_SCHEMA: &str = "chio.federation-bilateral-cosigning.v1";
pub const BILATERAL_DUAL_RECEIPT_SCHEMA: &str = "chio.federation-dual-signed-receipt.v1";

/// Canonical body that the local and remote kernels both sign. The bytes of
/// this structure (in canonical JSON) are the signed message for
/// [`DualSignedReceipt::org_a_signature`] and
/// [`DualSignedReceipt::org_b_signature`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoSigningBody {
    pub schema: String,
    /// Canonical JSON encoding of the underlying `ChioReceipt`, as a UTF-8
    /// string. The string form (rather than a nested object) keeps signing
    /// stable even if the receipt schema grows new `skip_serializing_if`
    /// fields later: both kernels sign exactly the bytes they saw.
    pub receipt_canonical_json: String,
    pub org_a_kernel_id: String,
    pub org_b_kernel_id: String,
}

impl CoSigningBody {
    /// Construct the canonical body from a receipt and the two kernel IDs
    /// participating in the exchange. Returns the body plus the canonical
    /// bytes of the receipt, so callers can persist them.
    pub fn from_receipt(
        receipt: &ChioReceipt,
        org_a_kernel_id: &str,
        org_b_kernel_id: &str,
    ) -> Result<Self, BilateralCoSigningError> {
        let bytes = canonical_json_bytes(receipt)
            .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
        let receipt_canonical_json = String::from_utf8(bytes)
            .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
        Ok(Self {
            schema: BILATERAL_COSIGNING_SCHEMA.to_string(),
            receipt_canonical_json,
            org_a_kernel_id: org_a_kernel_id.to_string(),
            org_b_kernel_id: org_b_kernel_id.to_string(),
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BilateralCoSigningError> {
        canonical_json_bytes(self)
            .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))
    }
}

/// A receipt co-signed by two kernels across a federation boundary.
///
/// * `body` -- the underlying `ChioReceipt` that both kernels agreed on.
/// * `org_a_signature` -- detached signature by the origin (Org A) kernel
///   over the canonical [`CoSigningBody`].
/// * `org_b_signature` -- detached signature by the tool-host (Org B) kernel
///   over the same canonical body.
///
/// The existing receipt's built-in `signature` and `kernel_key` fields are
/// unchanged: a classic verifier can still check the receipt in isolation,
/// while a federation-aware verifier additionally checks both detached
/// signatures via [`DualSignedReceipt::verify`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DualSignedReceipt {
    pub schema: String,
    pub body: ChioReceipt,
    pub org_a_kernel_id: String,
    pub org_b_kernel_id: String,
    pub org_a_signature: Signature,
    pub org_b_signature: Signature,
}

/// Pinned peer identities expected by a verifier before it accepts a
/// [`DualSignedReceipt`].
#[derive(Debug, Clone, Copy)]
pub struct ExpectedBilateralPeers<'a> {
    pub org_a_kernel_id: &'a str,
    pub org_a_public_key: &'a PublicKey,
    pub org_b_kernel_id: &'a str,
    pub org_b_public_key: &'a PublicKey,
}

impl DualSignedReceipt {
    /// Verify both detached signatures against the provided public keys,
    /// using the kernel IDs carried in this receipt as the expected IDs.
    ///
    /// Prefer [`DualSignedReceipt::verify_pinned`] at trust boundaries so
    /// the verifier supplies the expected peer IDs independently of the
    /// artifact being checked.
    pub fn verify(
        &self,
        org_a_public_key: &PublicKey,
        org_b_public_key: &PublicKey,
    ) -> Result<(), BilateralCoSigningError> {
        self.verify_pinned(ExpectedBilateralPeers {
            org_a_kernel_id: &self.org_a_kernel_id,
            org_a_public_key,
            org_b_kernel_id: &self.org_b_kernel_id,
            org_b_public_key,
        })
    }

    /// Verify both detached signatures against independently supplied
    /// pinned peer IDs and keys. Returns `Ok(())` only when BOTH signatures
    /// validate and the receipt's declared peer IDs match the expected
    /// peers.
    ///
    /// Neither half of the dual signature is sufficient on its own; a
    /// caller that can only check one side must still refuse the receipt.
    ///
    /// **This method is NOT a DSSE signature-slice verifier.** The
    /// signatures it checks are computed over the canonical-JSON encoding
    /// of [`CoSigningBody`]; the DSSE signature-slice signatures are
    /// computed over DSSE PAE bytes wrapping an in-toto
    /// Statement. The DSSE artifact is a signature-slice profile, not the
    /// strict Chio invocation predicate.
    pub fn verify_pinned(
        &self,
        expected: ExpectedBilateralPeers<'_>,
    ) -> Result<(), BilateralCoSigningError> {
        if self.schema != BILATERAL_DUAL_RECEIPT_SCHEMA {
            return Err(BilateralCoSigningError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        if expected.org_a_kernel_id.is_empty()
            || expected.org_b_kernel_id.is_empty()
            || expected.org_a_kernel_id == expected.org_b_kernel_id
            || self.org_a_kernel_id != expected.org_a_kernel_id
            || self.org_b_kernel_id != expected.org_b_kernel_id
            || expected.org_a_public_key == expected.org_b_public_key
        {
            return Err(BilateralCoSigningError::PeerIdentityMismatch);
        }

        let body =
            CoSigningBody::from_receipt(&self.body, &self.org_a_kernel_id, &self.org_b_kernel_id)?;
        let bytes = body.canonical_bytes()?;

        if !expected
            .org_a_public_key
            .verify(&bytes, &self.org_a_signature)
        {
            return Err(BilateralCoSigningError::OrgASignatureInvalid);
        }
        if !expected
            .org_b_public_key
            .verify(&bytes, &self.org_b_signature)
        {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }
        let receipt_signature_valid = self
            .body
            .verify_signature()
            .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
        if !receipt_signature_valid {
            return Err(BilateralCoSigningError::ReceiptMismatch);
        }
        if self.body.kernel_key != *expected.org_b_public_key {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }
        Ok(())
    }
}

/// Request sent from the tool-host kernel (Org B) to the origin kernel
/// (Org A) asking it to co-sign a receipt that Org B already signed
/// locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoSigningRequest {
    pub schema: String,
    pub body: ChioReceipt,
    pub org_a_kernel_id: String,
    pub org_b_kernel_id: String,
    /// Org B's own signature over the canonical cosigning body. The origin
    /// kernel verifies this before agreeing to sign.
    pub org_b_signature: Signature,
}

impl CoSigningRequest {
    pub fn new(
        body: ChioReceipt,
        org_a_kernel_id: String,
        org_b_kernel_id: String,
        org_b_signature: Signature,
    ) -> Self {
        Self {
            schema: BILATERAL_COSIGNING_SCHEMA.to_string(),
            body,
            org_a_kernel_id,
            org_b_kernel_id,
            org_b_signature,
        }
    }
}

/// Response from the origin kernel (Org A) carrying its co-signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoSigningResponse {
    pub schema: String,
    pub org_a_signature: Signature,
}

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
/// fail-closed: on any error the kernel MUST refuse to persist a dual-signed
/// receipt for the failing exchange.
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

    #[error("bilateral receipt peer identity does not match pinned peers")]
    PeerIdentityMismatch,

    #[error("receipt body mismatch between request and signed body")]
    ReceiptMismatch,
}

/// Error returned when a string is not one of the [`RejectionCode`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown rejection code")]
pub struct UnknownRejectionCode;

macro_rules! rejection_codes {
    ($( $(#[$meta:meta])* $variant:ident => $code:literal ),+ $(,)?) => {
        /// The closed set of codes a bilateral verifier or the co-signing
        /// protocol can reject with (specification section 7.1).
        ///
        /// The code is the only part of a rejection that crosses the
        /// protocol surface: it names the check that failed and carries no
        /// presented or expected value. The diagnostic detail that
        /// [`BilateralCoSigningError`] and
        /// [`crate::bilateral_verifier::VerifierError`] render through
        /// `Display` is for local logs and must not be copied into a signed
        /// or exported artifact.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum RejectionCode {
            $( $(#[$meta])* $variant, )+
        }

        impl RejectionCode {
            /// Every code, in specification order.
            pub const ALL: &'static [RejectionCode] = &[ $( RejectionCode::$variant, )+ ];

            /// The dotted code string, exactly as the specification lists it.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( RejectionCode::$variant => $code, )+ }
            }
        }

        impl std::str::FromStr for RejectionCode {
            type Err = UnknownRejectionCode;

            fn from_str(code: &str) -> Result<Self, Self::Err> {
                match code {
                    $( $code => Ok(RejectionCode::$variant), )+
                    _ => Err(UnknownRejectionCode),
                }
            }
        }
    };
}

rejection_codes! {
    /// Wrong `payloadType`, a wrong signature count, an undecodable
    /// payload, a duplicate signature keyid, or two pinned keys that are
    /// not distinct.
    DsseMalformed => "dsse.malformed",
    /// The payload is not parseable JSON or is not canonical JSON.
    StatementMalformed => "statement.malformed",
    /// `_type` is not the in-toto Statement v1 type, or the subject count
    /// is not one.
    StatementSchemaInvalid => "statement.schema_invalid",
    /// `predicateType` is not `chio.bilateral-cosign-invocation.v1`.
    PredicateTypeUnrecognised => "predicate.type_unrecognised",
    /// The predicate fails the body schema or a strict rule.
    PredicateSchemaInvalid => "predicate.schema_invalid",
    /// The receipt is not resolvable, its signature is invalid, or the
    /// subject does not match the resolved receipt body.
    SubjectDigestMismatch => "subject.digest_mismatch",
    /// A kernel id is not pinned or its declared fingerprint disagrees
    /// with the pin.
    PeerUnpinnedOrKeyidMismatch => "peer.unpinned_or_keyid_mismatch",
    /// A pinned passport is not active at the pinned epoch height.
    PeerRevokedAtEpoch => "peer.revoked_at_epoch",
    /// `tool_server_a`'s signature is absent, undecodable, or invalid.
    SignatureServerAInvalid => "signature.server_a_invalid",
    /// `tool_server_b`'s signature is absent, undecodable, or invalid.
    SignatureServerBInvalid => "signature.server_b_invalid",
    /// The verdicts disagree, a verdict is unknown, or the joint
    /// disposition is inconsistent.
    PolicyVerdictDisagreement => "policy.verdict_disagreement",
    /// The capability lease is missing, unknown, mismatched, or expired.
    CapabilityLeaseExpiredOrUnknown => "capability.lease_expired_or_unknown",
    /// A receipt-backed action class lacks a resolvable governance
    /// receipt.
    GovernanceReceiptRequiredMissing => "governance.receipt_required_missing",
    /// A pinned peer has no ladder manifest reference.
    LadderManifestMissing => "ladder.manifest_missing",
    /// A pinned peer's ladder manifest reference is not fresh.
    LadderManifestStale => "ladder.manifest_stale",
    /// `tool_name` is not in the verifier's action-class table.
    GovernanceUnknownActionClass => "governance.unknown_action_class",
    /// The two signer keys or keyids are identical.
    SignerIndependenceRequired => "signer.independence_required",
    /// Canonical-JSON encoding failed for a reason no more specific code
    /// covers.
    CanonicalJsonInvalid => "canonical_json.invalid",
    /// The co-signing peer is not a trusted federation peer.
    PeerUnknown => "peer.unknown",
    /// The co-signing peer's rotation window has lapsed.
    PeerExpired => "peer.expired",
    /// The co-signing transport failed.
    TransportFailed => "transport.failed",
    /// The co-signing peer rejected the request.
    PeerRejected => "peer.rejected",
    /// The co-signing request schema is unsupported.
    SchemaUnsupported => "schema.unsupported",
    /// The bilateral receipt's peer identity does not match the pinned
    /// peers.
    PeerIdentityMismatch => "peer.identity_mismatch",
}

impl std::fmt::Display for RejectionCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for RejectionCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RejectionCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl BilateralCoSigningError {
    /// The rejection code, the only part of this error that may cross the
    /// protocol surface. `Display` keeps the diagnostic detail for local
    /// logs.
    #[must_use]
    pub fn redacted(&self) -> RejectionCode {
        match self {
            Self::CanonicalJson(message) => canonical_json_rejection_code(message),
            Self::OrgASignatureInvalid => RejectionCode::SignatureServerAInvalid,
            Self::OrgBSignatureInvalid => RejectionCode::SignatureServerBInvalid,
            Self::UnknownPeer(_) => RejectionCode::PeerUnknown,
            Self::PeerExpired(_) => RejectionCode::PeerExpired,
            Self::TransportFailure(_) => RejectionCode::TransportFailed,
            Self::PeerRejected(_) => RejectionCode::PeerRejected,
            Self::UnsupportedSchema(_) => RejectionCode::SchemaUnsupported,
            Self::PeerIdentityMismatch => RejectionCode::PeerIdentityMismatch,
            Self::ReceiptMismatch => RejectionCode::SubjectDigestMismatch,
        }
    }

    /// The dotted string of [`Self::redacted`]. Stable across releases.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.redacted().as_str()
    }
}

/// Envelope-layer failures share the `CanonicalJson` variant; the message
/// prefix written by the envelope verifier and signer names the check that
/// failed and selects the code. The signer-independence phrase is tested
/// first, so a message that carries both it and a prefix keeps the
/// independence code the negative corpus names. A message that matches
/// neither falls closed to `canonical_json.invalid`.
fn canonical_json_rejection_code(message: &str) -> RejectionCode {
    const PREFIXES: &[(&str, RejectionCode)] = &[
        ("dsse.malformed:", RejectionCode::DsseMalformed),
        ("payload base64:", RejectionCode::DsseMalformed),
        ("statement.malformed:", RejectionCode::StatementMalformed),
        ("payload json:", RejectionCode::StatementMalformed),
        (
            "statement.schema_invalid:",
            RejectionCode::StatementSchemaInvalid,
        ),
        (
            "predicate.type_unrecognised:",
            RejectionCode::PredicateTypeUnrecognised,
        ),
        (
            "predicate.schema_invalid:",
            RejectionCode::PredicateSchemaInvalid,
        ),
        (
            "subject.digest_mismatch:",
            RejectionCode::SubjectDigestMismatch,
        ),
    ];
    if message.contains("requires independent Org A and Org B signer keys") {
        return RejectionCode::SignerIndependenceRequired;
    }
    if let Some((_, code)) = PREFIXES
        .iter()
        .find(|(prefix, _)| message.starts_with(prefix))
    {
        return *code;
    }
    RejectionCode::CanonicalJsonInvalid
}

/// Trait implemented by an object that can obtain a co-signature from a
/// remote kernel. Production deployments plug an mTLS-backed RPC client
/// in here; in-process tests use [`InProcessCoSigner`].
pub trait BilateralCoSigningProtocol: Send + Sync {
    /// Request a co-signature for a receipt that this kernel already
    /// signed. The caller is the tool-host kernel (Org B); the remote is
    /// the origin kernel (Org A) whose agent initiated the call.
    fn request_cosignature(
        &self,
        request: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError>;

    /// Request a DSSE PAE co-signature for the bilateral invocation
    /// envelope. Implementations should verify Org B's signature over
    /// `request.pae_bytes` before returning Org A's signature.
    fn request_dsse_cosignature(
        &self,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        let _ = request;
        Err(BilateralCoSigningError::UnsupportedSchema(
            BILATERAL_DSSE_COSIGNING_SCHEMA.to_string(),
        ))
    }
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
    fn request_cosignature(
        &self,
        request: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        if request.org_a_kernel_id != self.origin_kernel_id {
            return Err(BilateralCoSigningError::UnknownPeer(
                request.org_a_kernel_id.clone(),
            ));
        }
        let body = CoSigningBody::from_receipt(
            &request.body,
            &request.org_a_kernel_id,
            &request.org_b_kernel_id,
        )?;
        let bytes = body.canonical_bytes()?;

        if !self
            .tool_host_public_key
            .verify(&bytes, &request.org_b_signature)
        {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }

        let backend = Ed25519Backend::new(self.origin_keypair.clone());
        let signature = backend
            .sign_bytes(&bytes)
            .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
        Ok(CoSigningResponse {
            schema: BILATERAL_COSIGNING_SCHEMA.to_string(),
            org_a_signature: signature,
        })
    }

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
        if !self
            .tool_host_public_key
            .verify(&request.pae_bytes, &request.org_b_signature)
        {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }

        let backend = Ed25519Backend::new(self.origin_keypair.clone());
        let signature = backend
            .sign_bytes(&request.pae_bytes)
            .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
        Ok(DsseCoSigningResponse {
            schema: BILATERAL_DSSE_COSIGNING_SCHEMA.to_string(),
            org_a_signature: signature,
        })
    }
}

/// Helper used by the tool-host (Org B) side to drive the full protocol:
/// locally sign the canonical body, ask the remote [`BilateralCoSigningProtocol`]
/// for a co-signature, and assemble the verified [`DualSignedReceipt`].
pub fn co_sign_with_origin(
    origin_kernel_id: &str,
    origin_public_key: &PublicKey,
    tool_host_kernel_id: &str,
    tool_host_keypair: &Keypair,
    receipt: ChioReceipt,
    cosigner: &dyn BilateralCoSigningProtocol,
) -> Result<DualSignedReceipt, BilateralCoSigningError> {
    let started = std::time::Instant::now();
    let outcome = co_sign_with_origin_inner(
        origin_kernel_id,
        origin_public_key,
        tool_host_kernel_id,
        tool_host_keypair,
        receipt,
        cosigner,
    );
    let result = if outcome.is_ok() {
        crate::metrics::HOP_RESULT_OK
    } else {
        crate::metrics::HOP_RESULT_ERROR
    };
    let elapsed_nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    crate::metrics::observe_federation_hop_latency_nanos(result, elapsed_nanos);
    outcome
}

fn co_sign_with_origin_inner(
    origin_kernel_id: &str,
    origin_public_key: &PublicKey,
    tool_host_kernel_id: &str,
    tool_host_keypair: &Keypair,
    receipt: ChioReceipt,
    cosigner: &dyn BilateralCoSigningProtocol,
) -> Result<DualSignedReceipt, BilateralCoSigningError> {
    let body = CoSigningBody::from_receipt(&receipt, origin_kernel_id, tool_host_kernel_id)?;
    let bytes = body.canonical_bytes()?;

    let backend = Ed25519Backend::new(tool_host_keypair.clone());
    let org_b_signature = backend
        .sign_bytes(&bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;

    let request = CoSigningRequest::new(
        receipt.clone(),
        origin_kernel_id.to_string(),
        tool_host_kernel_id.to_string(),
        org_b_signature.clone(),
    );
    let response = cosigner.request_cosignature(&request)?;

    if !origin_public_key.verify(&bytes, &response.org_a_signature) {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }

    let dual = DualSignedReceipt {
        schema: BILATERAL_DUAL_RECEIPT_SCHEMA.to_string(),
        body: receipt,
        org_a_kernel_id: origin_kernel_id.to_string(),
        org_b_kernel_id: tool_host_kernel_id.to_string(),
        org_a_signature: response.org_a_signature,
        org_b_signature,
    };
    // Double-check the assembled artifact verifies end-to-end. The kernel
    // relies on this invariant to persist only dual-signed artifacts that
    // would themselves pass third-party verification.
    dual.verify(origin_public_key, &tool_host_keypair.public_key())?;
    Ok(dual)
}

/// **Verifiers seeking DSSE signature-slice coverage MUST verify
/// [`Self::dsse_envelope`].** The compatibility `DualSignedReceipt` is a
/// compatibility-only adapter that shares zero signed bytes with the DSSE
/// PAE preimage and is therefore not a DSSE artifact; see
/// `crate::bilateral_dsse` module docs. Neither artifact is a strict
/// Chio bilateral invocation predicate.
#[derive(Debug, Clone)]
pub struct BilateralCoSignArtifacts {
    /// Compatibility artifact for callers that still consume the
    /// `CoSigningBody` preimage. New verifier paths must use `dsse_envelope`.
    pub dual_signed_receipt: DualSignedReceipt,
    /// Canonical bilateral verification artifact for this crate's
    /// signature-slice profile.
    pub dsse_envelope: crate::bilateral_dsse::DsseEnvelope,
}

/// `tool_name` and `timestamp_unix_ms` are surfaced to callers because
/// they are predicate fields the DSSE signature-slice envelope binds.
/// `tool_name` is typically `receipt.tool_name`; `timestamp_unix_ms` is the
/// wall-clock at canonicalisation (Org B-side).
///
/// Scope boundary: this helper is an in-process API/demo slice because it
/// takes the origin kernel private key to produce the DSSE Org A signature.
/// Production tool-host paths must route that DSSE signature through an
/// origin-kernel cosigner before making this the default hot path.
///
/// Verifier boundary: this helper emits the extensionless
/// `sign_dsse_envelope` profile. That artifact verifies at the low-level
/// DSSE signature-slice layer, but it is not accepted by
/// `verify_bilateral_cosign_invocation` because the canonical verifier
/// requires `policy_evaluation_summary` and `capability_lease_ref`. Use
/// [`execute_local_bilateral_invocation_fixture`] or
/// [`crate::bilateral_dsse::sign_dsse_envelope_full`] when the artifact
/// must be accepted by the canonical verifier.
#[allow(clippy::too_many_arguments)]
pub fn co_sign_with_origin_full(
    origin_kernel_id: &str,
    origin_keypair: &Keypair,
    tool_host_kernel_id: &str,
    tool_host_keypair: &Keypair,
    receipt: ChioReceipt,
    cosigner: &dyn BilateralCoSigningProtocol,
    tool_name: &str,
    timestamp_unix_ms: u64,
) -> Result<BilateralCoSignArtifacts, BilateralCoSigningError> {
    // dual-signed-receipt hop: produces the existing DualSignedReceipt (and emits the
    // hop counter / histogram via co_sign_with_origin's wrapper).
    let dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_keypair.public_key(),
        tool_host_kernel_id,
        tool_host_keypair,
        receipt.clone(),
        cosigner,
    )?;

    let dsse_envelope = crate::bilateral_dsse::sign_dsse_envelope(
        &receipt,
        origin_keypair,
        tool_host_keypair,
        origin_kernel_id,
        tool_host_kernel_id,
        tool_name,
        timestamp_unix_ms,
    )?;

    Ok(BilateralCoSignArtifacts {
        dual_signed_receipt: dual,
        dsse_envelope,
    })
}

pub struct LocalBilateralInvocationFixtureRequest<'a> {
    /// `did:chio` identifier of the origin kernel (Org A).
    pub origin_kernel_id: &'a str,
    /// Origin kernel's signing keypair. This makes the helper suitable only
    /// for local fixtures and deterministic demos.
    pub origin_keypair: &'a Keypair,
    /// `did:chio` identifier of the tool-host kernel (Org B).
    pub tool_host_kernel_id: &'a str,
    /// Tool-host kernel's signing keypair.
    pub tool_host_keypair: &'a Keypair,
    /// Receipt the agent produced for the invocation. Both kernels'
    /// signatures bind the canonical-JSON of this body.
    pub receipt: ChioReceipt,
    /// Tool name as exposed by both kernels. Typically equals
    /// `receipt.tool_name`.
    pub tool_name: &'a str,
    /// Org B's wall-clock at predicate canonicalisation (Unix ms).
    pub timestamp_unix_ms: u64,
    /// §5 predicate extensions; the §7 verifier requires
    /// `capability_lease_ref` and `policy_evaluation_summary` to be
    /// present, otherwise verification fails-closed at step 20/21.
    pub predicate_extensions: crate::bilateral_dsse::BilateralPredicateExtensions,
    /// Cosigner driving the dual-signed-receipt hop. Production
    /// kernels supply a `BilateralCoSigningProtocol` over an mTLS-backed
    /// RPC client; demos use [`InProcessCoSigner`].
    pub cosigner: &'a dyn BilateralCoSigningProtocol,
}

#[derive(Debug, Clone)]
pub struct BilateralInvocationOutcome {
    /// dual-signed-receipt + DSSE signature-slice artifacts produced by the hot path.
    pub artifacts: BilateralCoSignArtifacts,
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

/// 1. Drives the local fixture signing path to produce the
///    [`BilateralCoSignArtifacts`] (compatibility [`DualSignedReceipt`] +
///    DSSE signature-slice envelope) but layered with the
///    [`crate::bilateral_dsse::BilateralPredicateExtensions`] (lease ref,
///    policy summary, etc.) the verifier needs.
/// 2. Runs the partial local verifier (subset of §7) from
///    [`crate::bilateral_verifier::verify_bilateral_cosign_invocation`]
///    against the just-emitted envelope. The verifier resolves the
///    receipt store, lease registry, governance store, and revocation
///    oracle the kernel passes in.
/// 3. Returns the artifacts + the verifier output, or fails
///    closed with a `BilateralInvocationError` carrying either the
///    co-signing error or the verifier's spec §7.1 code.
///
/// This is intentionally a local fixture helper: it takes both private
/// keypairs in one process. Production callers must use a transport-backed
/// origin cosigner and must not hand Org A key material to Org B.
pub fn execute_local_bilateral_invocation_fixture(
    request: LocalBilateralInvocationFixtureRequest<'_>,
    verifier_config: &crate::bilateral_verifier::VerifierConfig<'_>,
) -> Result<BilateralInvocationOutcome, BilateralInvocationError> {
    // Step 1: dual-signed-receipt hop (drives the cosigner) +
    // DSSE signature-slice envelope with predicate extensions.
    let dual = co_sign_with_origin(
        request.origin_kernel_id,
        &request.origin_keypair.public_key(),
        request.tool_host_kernel_id,
        request.tool_host_keypair,
        request.receipt.clone(),
        request.cosigner,
    )?;

    let dsse_envelope = crate::bilateral_dsse::sign_dsse_envelope_full(
        &request.receipt,
        request.origin_keypair,
        request.tool_host_keypair,
        request.origin_kernel_id,
        request.tool_host_kernel_id,
        request.tool_name,
        request.timestamp_unix_ms,
        request.predicate_extensions,
    )?;

    let artifacts = BilateralCoSignArtifacts {
        dual_signed_receipt: dual,
        dsse_envelope,
    };

    // Step 2: partial local verifier (subset of §7).
    let verified = crate::bilateral_verifier::verify_bilateral_cosign_invocation(
        &artifacts.dsse_envelope,
        verifier_config,
    )?;

    Ok(BilateralInvocationOutcome {
        artifacts,
        verified,
    })
}
