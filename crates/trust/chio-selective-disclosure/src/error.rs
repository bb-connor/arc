/// Errors returned by selective disclosure projection and verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectiveDisclosureError {
    #[error("canonical JSON encoding failed: {0}")]
    CanonicalJson(String),
    #[error("malformed Hx field {field}: {reason}")]
    MalformedHexField { field: String, reason: String },
    #[error("disclosure set carries duplicate index {0}")]
    DisclosureDuplicateIndex(u16),
    #[error("disclosure set carries an out-of-range index {0}")]
    DisclosureIndexOutOfRange(u16),
    #[error("schema {0} is not accepted by the real BBS verifier")]
    SchemaMismatch(String),
    #[error("projection version {0} is not supported by this verifier")]
    ProjectionVersionMismatch(String),
    #[error("signed projection does not match the supplied projection")]
    SignedProjectionMismatch,
    #[error("BBS signature verification failed")]
    SignatureVerificationFailed,
    #[error("BBS proof verification failed")]
    ProofVerificationFailed,
    #[error("receipt signature verification failed")]
    ReceiptSignatureInvalid,
    #[error("receipt does not carry BBS signature material")]
    ReceiptBbsSignatureMissing,
    #[error("receipt BBS binding is invalid: {0}")]
    ReceiptBbsBindingInvalid(String),
    #[error("BBS projection manifest {0}")]
    ProjectionManifestInvalid(String),
    #[error("transparency inclusion proof {0}")]
    TransparencyInclusionInvalid(String),
    #[error("transparency inclusion proof {0}")]
    TransparencyInclusionHashMismatch(String),
    #[error("receipt content_hash does not match the bound canonical content (WYSIWYS): {0}")]
    ContentHashMismatch(String),
    #[error("issuer {0} is not registered")]
    UnknownIssuer(String),
    #[error("issuer public key does not match registry")]
    IssuerKeyMismatch,
    #[error("key material must be at least 32 bytes")]
    KeySeedTooShort,
    #[error("hex decoding failed: {0}")]
    Hex(String),
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
}
