//! Authenticated caller-delivery messages. Signature verification establishes
//! the configured signer's statement, not durable execution ownership. An
//! executor must claim the original operation durably before any effect.
//!
//! These codecs do not reinterpret reservation nonces as dispatch permissions.
//! Kernel start publication and executor-ledger integration are separate ports.

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey, Signature};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::admission_operation::{
    AdmissionDigest, AdmissionDispatchCommitBindingV1, AdmissionIdentifier, AdmissionOperationId,
};

pub const CALLER_DISPATCH_AUTHORIZATION_SCHEMA: &str = "chio.caller-dispatch-authorization.v1";
pub const CALLER_DELIVERY_REPORT_SCHEMA: &str = "chio.caller-delivery-report.v1";
const MAX_AUTHORIZATION_BYTES: usize = 32 * 1024;
const MAX_REPORT_BYTES: usize = 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

mod retained;

/// Private retained delivery evidence. This belongs in the authority's raw
/// return record, never in public receipt metadata or agent-visible output.
/// Decoding this value does not establish either key's independent trust pin.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerDeliveryEvidenceV1 {
    pub authorization: SignedCallerDispatchAuthorizationV1,
    pub report: SignedCallerDeliveryReportV1,
}

/// A trusted-host selection. Values received in a message cannot select its
/// verifier, signing key, epoch, ledger namespace or routing destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerExecutorIdentityV1 {
    pub executor_id: AdmissionIdentifier,
    pub public_key: PublicKey,
    pub key_epoch: u64,
}

impl CallerExecutorIdentityV1 {
    pub(crate) fn validate(&self) -> Result<(), CallerDeliveryError> {
        require_time(self.key_epoch)?;
        if self.public_key.is_weak_ed25519() {
            return Err(CallerDeliveryError::Shape);
        }
        Ok(())
    }
}

/// Exact public invocation identity. Protected inputs and reusable credentials
/// are excluded; the complete admitted request is bound by its private digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerInvocationBindingV1 {
    pub operation_id: AdmissionOperationId,
    pub request_id: AdmissionIdentifier,
    pub request_binding_hash: AdmissionDigest,
    pub capability_id: AdmissionIdentifier,
    pub capability_digest: AdmissionDigest,
    pub server_id: AdmissionIdentifier,
    pub tool_name: AdmissionIdentifier,
    pub parameters_digest: AdmissionDigest,
}

/// The original commitment, not an independently reconstructed budget counter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerCommittedDispatchV1 {
    pub execution_nonce_id: AdmissionIdentifier,
    pub budget_hold_id: AdmissionIdentifier,
    pub dispatch_commit: AdmissionDispatchCommitBindingV1,
    pub frozen_context_digest: AdmissionDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerDispatchAuthorizationBodyV1 {
    pub schema: String,
    pub kernel_public_key: PublicKey,
    pub executor: CallerExecutorIdentityV1,
    pub invocation: CallerInvocationBindingV1,
    pub committed: CallerCommittedDispatchV1,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Untrusted wire envelope until verified against independent host selections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCallerDispatchAuthorizationV1 {
    pub authorization: CallerDispatchAuthorizationBodyV1,
    pub signature: Signature,
}

/// A checked statement, deliberately neither Clone nor Deserialize. It is not
/// an executor claim and must never be dispatched using a process-local map.
pub struct VerifiedCallerDispatchAuthorization<'a> {
    signed: &'a SignedCallerDispatchAuthorizationV1,
    digest: AdmissionDigest,
}

impl VerifiedCallerDispatchAuthorization<'_> {
    pub fn authorization(&self) -> &SignedCallerDispatchAuthorizationV1 {
        self.signed
    }

    pub fn digest(&self) -> &AdmissionDigest {
        &self.digest
    }

    /// Recheck immediately inside the executor's durable claim transaction.
    /// A prior verification cannot preserve validity while waiting for a lock.
    pub fn require_live_at(&self, now_unix_ms: u64) -> Result<(), CallerDeliveryError> {
        require_time(now_unix_ms)?;
        if now_unix_ms < self.signed.authorization.not_before_unix_ms
            || now_unix_ms >= self.signed.authorization.expires_at_unix_ms
        {
            return Err(CallerDeliveryError::Expired);
        }
        Ok(())
    }
}

impl SignedCallerDispatchAuthorizationV1 {
    /// Trusted authorizer primitive. The caller must already own the actual
    /// committed kernel context; signing arbitrary DTOs does not establish it.
    /// This method alone does not qualify a kernel start route.
    pub fn sign(
        body: CallerDispatchAuthorizationBodyV1,
        key: &Keypair,
    ) -> Result<Self, CallerDeliveryError> {
        if body.kernel_public_key != key.public_key() {
            return Err(CallerDeliveryError::Binding);
        }
        validate_authorization(&body)?;
        let bytes = bounded_canonical(&body, MAX_AUTHORIZATION_BYTES)?;
        let signed = Self {
            authorization: body,
            signature: key.sign(&bytes),
        };
        signed.canonical_bytes()?;
        Ok(signed)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CallerDeliveryError> {
        let signed: Self = decode(bytes, MAX_AUTHORIZATION_BYTES)?;
        validate_authorization(&signed.authorization)?;
        Ok(signed)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CallerDeliveryError> {
        validate_authorization(&self.authorization)?;
        bounded_canonical(self, MAX_AUTHORIZATION_BYTES)
    }

    /// Authentication for historical accounting. This deliberately performs no
    /// current-expiry check and grants no authority for a new execution.
    pub fn verify_historical(
        &self,
        trusted_kernel: &PublicKey,
        expected_executor: &CallerExecutorIdentityV1,
        expected_invocation: &CallerInvocationBindingV1,
    ) -> Result<AdmissionDigest, CallerDeliveryError> {
        let bytes = self.canonical_bytes()?;
        if &self.authorization.kernel_public_key != trusted_kernel
            || &self.authorization.executor != expected_executor
            || &self.authorization.invocation != expected_invocation
        {
            return Err(CallerDeliveryError::Binding);
        }
        if !trusted_kernel.verify_strict(
            &bounded_canonical(&self.authorization, MAX_AUTHORIZATION_BYTES)?,
            &self.signature,
        ) {
            return Err(CallerDeliveryError::Signature);
        }
        AdmissionDigest::try_new("caller_authorization_digest", sha256_hex(&bytes))
            .map_err(|_| CallerDeliveryError::Shape)
    }

    pub fn verify_for_claim(
        &self,
        trusted_kernel: &PublicKey,
        expected_executor: &CallerExecutorIdentityV1,
        expected_invocation: &CallerInvocationBindingV1,
        now_unix_ms: u64,
    ) -> Result<VerifiedCallerDispatchAuthorization<'_>, CallerDeliveryError> {
        let digest =
            self.verify_historical(trusted_kernel, expected_executor, expected_invocation)?;
        let verified = VerifiedCallerDispatchAuthorization {
            signed: self,
            digest,
        };
        verified.require_live_at(now_unix_ms)?;
        Ok(verified)
    }
}

/// Executor-authenticated observation. This is not provider attestation unless
/// that independent provider's own authenticated evidence is also verified.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerDeliveryReportBodyV1 {
    pub schema: String,
    pub authorization_digest: AdmissionDigest,
    pub executor: CallerExecutorIdentityV1,
    pub claim_id: AdmissionIdentifier,
    pub execution_started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub output: serde_json::Value,
    pub realized_cost: Option<chio_core::capability::scope::MonetaryAmount>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCallerDeliveryReportV1 {
    pub report: CallerDeliveryReportBodyV1,
    pub signature: Signature,
}

impl std::fmt::Debug for SignedCallerDeliveryReportV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedCallerDeliveryReportV1")
            .finish_non_exhaustive()
    }
}

impl SignedCallerDeliveryReportV1 {
    /// The trusted executor records the exact signed result in its ledger
    /// before publishing it. Signing alone is not evidence of a durable claim.
    pub fn sign(
        body: CallerDeliveryReportBodyV1,
        key: &Keypair,
    ) -> Result<Self, CallerDeliveryError> {
        if body.executor.public_key != key.public_key() {
            return Err(CallerDeliveryError::Binding);
        }
        validate_report(&body)?;
        let signature = key.sign(&bounded_canonical(&body, MAX_REPORT_BYTES)?);
        let signed = Self {
            report: body,
            signature,
        };
        signed.canonical_bytes()?;
        Ok(signed)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CallerDeliveryError> {
        let signed: Self = decode(bytes, MAX_REPORT_BYTES)?;
        validate_report(&signed.report)?;
        Ok(signed)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CallerDeliveryError> {
        validate_report(&self.report)?;
        bounded_canonical(self, MAX_REPORT_BYTES)
    }

    /// Verify late evidence against the independently authenticated original
    /// authorization. Permission expiry never becomes a new execution permit.
    pub fn verify(
        &self,
        authorization: &SignedCallerDispatchAuthorizationV1,
        trusted_kernel: &PublicKey,
        expected_executor: &CallerExecutorIdentityV1,
        expected_invocation: &CallerInvocationBindingV1,
    ) -> Result<(), CallerDeliveryError> {
        self.canonical_bytes()?;
        let digest = authorization.verify_historical(
            trusted_kernel,
            expected_executor,
            expected_invocation,
        )?;
        if self.report.authorization_digest != digest
            || &self.report.executor != expected_executor
            || self.report.execution_started_at_unix_ms
                < authorization.authorization.not_before_unix_ms
            || self.report.execution_started_at_unix_ms
                >= authorization.authorization.expires_at_unix_ms
        {
            return Err(CallerDeliveryError::Binding);
        }
        if !expected_executor.public_key.verify_strict(
            &bounded_canonical(&self.report, MAX_REPORT_BYTES)?,
            &self.signature,
        ) {
            return Err(CallerDeliveryError::Signature);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CallerDeliveryError {
    #[error("caller delivery message is malformed, noncanonical or exceeds its bound")]
    Shape,
    #[error("caller delivery message does not match the independently selected binding")]
    Binding,
    #[error("caller delivery signature is invalid")]
    Signature,
    #[error("caller dispatch authorization is outside its execution interval")]
    Expired,
}

fn validate_authorization(
    body: &CallerDispatchAuthorizationBodyV1,
) -> Result<(), CallerDeliveryError> {
    require_time(body.not_before_unix_ms)?;
    require_time(body.expires_at_unix_ms)?;
    require_time(body.executor.key_epoch)?;
    if body.schema != CALLER_DISPATCH_AUTHORIZATION_SCHEMA
        || body.not_before_unix_ms >= body.expires_at_unix_ms
        || body.kernel_public_key.is_weak_ed25519()
        || body.executor.public_key.is_weak_ed25519()
    {
        return Err(CallerDeliveryError::Shape);
    }
    let attempt = body
        .committed
        .dispatch_commit
        .provider_attempt
        .as_ref()
        .ok_or(CallerDeliveryError::Shape)?;
    if attempt.operation_id != body.invocation.operation_id.as_str()
        || attempt.transport_id
            != format!(
                "{}{}",
                if attempt.is_native_caller_report() {
                    chio_core_types::provider_attempt::ProviderAttemptBindingV1::NATIVE_CALLER_REPORT_TRANSPORT_PREFIX
                } else {
                    chio_core_types::provider_attempt::ProviderAttemptBindingV1::CALLER_REPORT_TRANSPORT_PREFIX
                },
                body.invocation.server_id.as_str()
            )
        || attempt.transport_key_epoch != body.executor.key_epoch
    {
        return Err(CallerDeliveryError::Binding);
    }
    // Validate public mutable DTO fields through the domain decoder as well.
    let _: AdmissionDispatchCommitBindingV1 = serde_json::from_slice(&bounded_canonical(
        &body.committed.dispatch_commit,
        MAX_AUTHORIZATION_BYTES,
    )?)
    .map_err(|_| CallerDeliveryError::Shape)?;
    Ok(())
}

fn validate_report(body: &CallerDeliveryReportBodyV1) -> Result<(), CallerDeliveryError> {
    require_time(body.execution_started_at_unix_ms)?;
    require_time(body.completed_at_unix_ms)?;
    require_time(body.executor.key_epoch)?;
    if body.schema != CALLER_DELIVERY_REPORT_SCHEMA
        || body.completed_at_unix_ms < body.execution_started_at_unix_ms
        || body.executor.public_key.is_weak_ed25519()
        || body.realized_cost.as_ref().is_some_and(|cost| {
            cost.units > MAX_SAFE_INTEGER || cost.currency.is_empty() || cost.currency.len() > 64
        })
    {
        return Err(CallerDeliveryError::Shape);
    }
    Ok(())
}

fn require_time(value: u64) -> Result<(), CallerDeliveryError> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(CallerDeliveryError::Shape);
    }
    Ok(())
}

fn bounded_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, CallerDeliveryError> {
    // Bound serialization before building a second value or canonical copy.
    // The same mechanism limits attacker-controlled nested report output.
    struct Writer {
        bytes: Vec<u8>,
        maximum: usize,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("caller message exceeds its bound"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| CallerDeliveryError::Shape)?;
    let value: serde_json::Value =
        serde_json::from_slice(&writer.bytes).map_err(|_| CallerDeliveryError::Shape)?;
    let bytes = canonical_json_bytes(&value).map_err(|_| CallerDeliveryError::Shape)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(CallerDeliveryError::Shape);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;

fn decode<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, CallerDeliveryError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(CallerDeliveryError::Shape);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| CallerDeliveryError::Shape)?;
    if bounded_canonical(&value, maximum)? != bytes {
        return Err(CallerDeliveryError::Shape);
    }
    Ok(value)
}
