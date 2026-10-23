//! The signing wrapper every Chio signature covers.
//!
//! ```text
//! wrapper = "chio.signing-wrapper.v1" || 0x00     (24 bytes)
//!        || SHA-256(utf8(schema_id))                (32 bytes)
//!        || SHA-256(canonical_body)                 (32 bytes)
//! ```

use alloc::string::ToString;

use sha2::{Digest, Sha256};

use crate::canonical::{CanonicalBytes, CanonicalJsonWitness};
use crate::error::{Error, Result};
use crate::signed_artifact::registered_wrapper_schema;

/// Domain tag that opens every wrapper; byte 23 is `0x00`.
pub const SIGNING_WRAPPER_PREFIX: &[u8; 24] = b"chio.signing-wrapper.v1\0";

/// Length of the wrapper in bytes.
pub const SIGNING_WRAPPER_LEN: usize = 88;

const PREFIX_LEN: usize = SIGNING_WRAPPER_PREFIX.len();
const SCHEMA_DIGEST_END: usize = PREFIX_LEN + 32;

/// The 88 bytes every Chio signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningWrapper([u8; SIGNING_WRAPPER_LEN]);

impl SigningWrapper {
    /// Refuses `schema_id` unless `registered_wrapper_schema(schema_id)` holds.
    pub fn new(
        schema_id: &str,
        canonical_body: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> Result<Self> {
        if !registered_wrapper_schema(schema_id) {
            return Err(Error::UnregisteredSchemaId(schema_id.to_string()));
        }
        #[cfg(feature = "wrapper-capture")]
        capture::record(schema_id, canonical_body.as_bytes());
        Ok(Self(assemble_wrapper(
            Sha256::digest(schema_id.as_bytes()).into(),
            Sha256::digest(canonical_body.as_bytes()).into(),
        )))
    }

    /// Accepts exactly 88 bytes that open with [`SIGNING_WRAPPER_PREFIX`]: the
    /// form a signer or verifier receives across a process or storage boundary.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let wrapper: [u8; SIGNING_WRAPPER_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidSignature("signing wrapper must be 88 bytes".to_string()))?;
        if !wrapper.starts_with(SIGNING_WRAPPER_PREFIX) {
            return Err(Error::InvalidSignature(
                "signing wrapper prefix mismatch".to_string(),
            ));
        }
        Ok(Self(wrapper))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNING_WRAPPER_LEN] {
        &self.0
    }
}

#[cfg(kani)]
impl SigningWrapper {
    /// Model constructor over precomputed digests; proofs cannot execute
    /// canonicalization or hashing.
    #[must_use]
    pub fn from_digests(schema_digest: [u8; 32], body_digest: [u8; 32]) -> Self {
        Self(assemble_wrapper(schema_digest, body_digest))
    }
}

/// Lays out the prefix, the schema digest and the body digest.
#[must_use]
pub fn assemble_wrapper(
    schema_digest: [u8; 32],
    body_digest: [u8; 32],
) -> [u8; SIGNING_WRAPPER_LEN] {
    let mut out = [0u8; SIGNING_WRAPPER_LEN];
    out[..PREFIX_LEN].copy_from_slice(SIGNING_WRAPPER_PREFIX);
    out[PREFIX_LEN..SCHEMA_DIGEST_END].copy_from_slice(&schema_digest);
    out[SCHEMA_DIGEST_END..].copy_from_slice(&body_digest);
    out
}

/// External formats whose signing bytes a standard fixes. Closed list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExemptFormat {
    /// RFC 7515 JWS signing input, including JWTs and SD-JWT.
    JwsSigningInput,
    /// DSSE pre-authentication encoding.
    DssePae,
}

/// The only input a signer accepts: a wrapper, or bytes of a named exempt format.
#[derive(Clone, Copy, Debug)]
pub struct SigningMessage<'a>(SigningMessageInner<'a>);

#[derive(Clone, Copy, Debug)]
enum SigningMessageInner<'a> {
    Wrapper(&'a SigningWrapper),
    Exempt(ExemptFormat, &'a [u8]),
}

impl<'a> SigningMessage<'a> {
    /// Bytes whose layout `format` fixes. Only the sites the exemption gate
    /// allowlists construct this.
    #[must_use]
    pub fn exempt(format: ExemptFormat, bytes: &'a [u8]) -> Self {
        Self(SigningMessageInner::Exempt(format, bytes))
    }

    #[must_use]
    pub(crate) fn wrapper(wrapper: &'a SigningWrapper) -> Self {
        Self(SigningMessageInner::Wrapper(wrapper))
    }

    /// Model message over a wrapper built from precomputed digests.
    #[cfg(kani)]
    #[must_use]
    pub fn of_wrapper(wrapper: &'a SigningWrapper) -> Self {
        Self(SigningMessageInner::Wrapper(wrapper))
    }

    /// The bytes the signature covers.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self.0 {
            SigningMessageInner::Wrapper(wrapper) => wrapper.as_bytes(),
            SigningMessageInner::Exempt(_, bytes) => bytes,
        }
    }

    /// The exempt format, or `None` for a wrapper.
    #[must_use]
    pub fn exempt_format(&self) -> Option<ExemptFormat> {
        match self.0 {
            SigningMessageInner::Wrapper(_) => None,
            SigningMessageInner::Exempt(format, _) => Some(format),
        }
    }
}

/// Test-run capture of wrapped bodies for schema example generation. Off by
/// default; no production build enables `wrapper-capture`.
#[cfg(feature = "wrapper-capture")]
mod capture {
    use std::io::Write;

    /// Appends one `{"schema_id", "body"}` line to
    /// `$CHIO_WRAPPER_CAPTURE_DIR/<schema_id>.ndjson` when the variable is set.
    pub(super) fn record(schema_id: &str, body: &[u8]) {
        let Some(dir) = std::env::var_os("CHIO_WRAPPER_CAPTURE_DIR") else {
            return;
        };
        let Ok(body) = core::str::from_utf8(body) else {
            return;
        };
        let line = serde_json::json!({ "schema_id": schema_id, "body": body });
        let path = std::path::Path::new(&dir).join(format!("{schema_id}.ndjson"));
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(file, "{line}");
        }
    }
}
