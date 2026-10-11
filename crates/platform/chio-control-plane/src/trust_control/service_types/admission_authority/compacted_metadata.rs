//! Bounded data-only retention status in an existing failure envelope.
use chio_kernel::admission_operation::AdmissionDigest;
use chio_kernel::tool_outcome::ToolOutcomeStoreError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CompactedRawWire")]
pub(crate) struct CompactedRawMetadata {
    raw_output_digest: AdmissionDigest,
    raw_output_size_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactedRawWire {
    raw_output_digest: AdmissionDigest,
    raw_output_size_bytes: u64,
}

impl TryFrom<CompactedRawWire> for CompactedRawMetadata {
    type Error = &'static str;
    fn try_from(value: CompactedRawWire) -> Result<Self, Self::Error> {
        Self::new(value.raw_output_digest, value.raw_output_size_bytes)
    }
}

impl CompactedRawMetadata {
    pub(crate) fn new(digest: AdmissionDigest, size: u64) -> Result<Self, &'static str> {
        if size == 0 || size > 269_484_032 {
            return Err("compacted raw payload size is outside its bound");
        }
        Ok(Self {
            raw_output_digest: digest,
            raw_output_size_bytes: size,
        })
    }
    pub(crate) fn into_store_error(self) -> ToolOutcomeStoreError {
        ToolOutcomeStoreError::Compacted {
            raw_output_digest: self.raw_output_digest,
            raw_output_size_bytes: self.raw_output_size_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compacted_raw_rpc_metadata_refuses_malformed_digest_and_sizes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (digest, size) in [
            ("invalid".to_string(), 1),
            ("a".repeat(64), 0),
            ("a".repeat(64), 269_484_033),
        ] {
            let error = serde_json::from_value::<CompactedRawMetadata>(
                serde_json::json!({"raw_output_digest":digest,"raw_output_size_bytes":size}),
            )
            .err()
            .ok_or("malformed retention metadata must reject")?;
            assert!(error.is_data());
            assert!(error.to_string().contains(if size == 1 {
                "persisted_admission_digest"
            } else {
                "outside its bound"
            }));
        }
        let valid =
            CompactedRawMetadata::new(AdmissionDigest::try_new("test", "a".repeat(64))?, 1)?;
        let roundtrip: CompactedRawMetadata = serde_json::from_slice(&serde_json::to_vec(&valid)?)?;
        assert_eq!(roundtrip, valid);
        Ok(())
    }
}
