//! Private native caller release material. This value describes custody, but
//! only the native capture transaction can establish its provenance. Neither
//! decoding it nor recovering a release owner authorizes another execution.
use super::*;
use crate::SecurityInvocationContext;

pub const NATIVE_CALLER_CONTEXT_SCHEMA: &str = "chio.kernel-caller-return-context.v5";
const MAX_LEDGER_BYTES: usize = 256 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCallerReleaseCustodyV1 {
    ledger_digest: AdmissionDigest,
    ledger_json: String,
    release_request_digest: AdmissionDigest,
    security_context: SecurityInvocationContext,
    valid_until_unix_ms: u64,
}

impl NativeCallerReleaseCustodyV1 {
    /// Build bounded release material from the live native capture inputs.
    /// The physical writer must independently compare the ledger and deadline.
    pub fn prepare(
        original: &RetainedToolAdmissionRequestV1,
        ledger: &NativeSecurityDispatchLedgerRecordV1,
        security_context: &SecurityInvocationContext,
        valid_until_unix_ms: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if ledger.canonical_record.is_empty() || ledger.canonical_record.len() > MAX_LEDGER_BYTES {
            return Err(invalid("native caller ledger exceeds its bound"));
        }
        let custody = Self {
            ledger_digest: ledger.record_digest.clone(),
            ledger_json: std::str::from_utf8(&ledger.canonical_record)
                .map_err(invalid)?
                .to_owned(),
            release_request_digest: release_request_digest(original)?,
            security_context: security_context.clone(),
            valid_until_unix_ms,
        };
        custody.validate(original)?;
        Ok(custody)
    }

    pub fn validate(
        &self,
        original: &RetainedToolAdmissionRequestV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        validate_positive_ijson("native_caller_valid_until", self.valid_until_unix_ms)?;
        if self.ledger_json.is_empty() || self.ledger_json.len() > MAX_LEDGER_BYTES {
            return Err(invalid("native caller ledger exceeds its bound"));
        }
        let value: serde_json::Value = serde_json::from_str(&self.ledger_json).map_err(invalid)?;
        if !value.is_object()
            || canonical_json_bytes(&value).map_err(invalid)? != self.ledger_json.as_bytes()
            || sha256_hex(self.ledger_json.as_bytes()) != self.ledger_digest.as_str()
            || self.release_request_digest != release_request_digest(original)?
            || original
                .authority_profile()
                .and_then(|profile| profile.caller_executor())
                .is_none()
            || original.native_security_authority_binding().is_none()
        {
            return Err(invalid(
                "native caller release material differs from original custody",
            ));
        }
        original.validate_native_security_context(&self.security_context)
    }

    pub fn ledger_digest(&self) -> &AdmissionDigest {
        &self.ledger_digest
    }
    pub fn ledger_bytes(&self) -> &[u8] {
        self.ledger_json.as_bytes()
    }
    pub fn security_context(&self) -> &SecurityInvocationContext {
        &self.security_context
    }
    pub fn valid_until_unix_ms(&self) -> u64 {
        self.valid_until_unix_ms
    }
}

impl AdmissionCallerDispatchContextV1 {
    /// Decode native release material, not authority. Callers must first read
    /// this frame through the original operation's fenced physical commit.
    pub fn native_release_custody(
        &self,
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
    ) -> Result<Option<NativeCallerReleaseCustodyV1>, AdmissionOperationStoreError> {
        let payload: serde_json::Value =
            serde_json::from_slice(self.kernel_context_json()).map_err(invalid)?;
        let native = operation
            .provider_attempt()
            .is_some_and(ProviderAttemptBindingV1::is_native_caller_report);
        let value = payload.get("native_custody");
        if !native {
            if value.is_some()
                || payload.get("schema").and_then(serde_json::Value::as_str)
                    == Some(NATIVE_CALLER_CONTEXT_SCHEMA)
            {
                return Err(invalid(
                    "ordinary caller frame cannot acquire native custody",
                ));
            }
            return Ok(None);
        }
        if payload.get("schema").and_then(serde_json::Value::as_str)
            != Some(NATIVE_CALLER_CONTEXT_SCHEMA)
        {
            return Err(invalid(
                "native caller requires its original versioned release custody",
            ));
        }
        let custody: NativeCallerReleaseCustodyV1 = serde_json::from_value(
            value
                .cloned()
                .ok_or_else(|| invalid("native caller release custody is absent"))?,
        )
        .map_err(invalid)?;
        custody.validate(original)?;
        if operation
            .native_dispatch_ledger_digest()
            .is_some_and(|digest| digest != custody.ledger_digest())
        {
            return Err(invalid("native caller frame changed its original ledger"));
        }
        Ok(Some(custody))
    }
}

fn release_request_digest(
    original: &RetainedToolAdmissionRequestV1,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    AdmissionDigest::try_new(
        "native_caller_release_request",
        sha256_hex(&canonical_json_bytes(original.request_for_revalidation()).map_err(invalid)?),
    )
    .map_err(Into::into)
}

fn invalid(error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(error.to_string())
}
