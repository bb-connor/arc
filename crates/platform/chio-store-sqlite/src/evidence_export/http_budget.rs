//! Byte accounting before response allocation and before retaining each
//! decoded evidence record. The local operator export has no HTTP ceiling.
use std::io::{self, Write};

use chio_kernel::{ReceiptQuerySnapshotError, ReceiptStoreError};
use serde::Serialize;

pub const HTTP_EVIDENCE_EXPORT_MAX_BYTES: u64 = 32 * 1024 * 1024;
const BYTE_ALLOWANCE_EXHAUSTED: &str = "HTTP evidence export byte allowance; narrow the selected receipts or use local operator export";

pub(crate) fn refuse(reason: impl Into<String>) -> ReceiptStoreError {
    ReceiptQuerySnapshotError::WorkBudgetExhausted(reason.into()).into()
}

#[derive(Debug)]
pub(crate) struct ByteBudget {
    remaining: u64,
}

impl ByteBudget {
    pub(crate) fn new(bytes: u64) -> Self {
        Self { remaining: bytes }
    }
    pub(crate) fn remaining(&self) -> u64 {
        self.remaining
    }
    pub(crate) fn preflight(&self, bytes: u64) -> Result<(), ReceiptStoreError> {
        if bytes > self.remaining {
            return Err(refuse(BYTE_ALLOWANCE_EXHAUSTED));
        }
        Ok(())
    }
    pub(crate) fn charge(&mut self, value: &impl Serialize) -> Result<(), ReceiptStoreError> {
        let bytes = serialized_bytes(value, self.remaining)?;
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| refuse(BYTE_ALLOWANCE_EXHAUSTED))?;
        Ok(())
    }
}

/// Validate the complete HTTP response, including transparency, watermark and
/// federation policy, before eager JSON serialization allocates its body.
pub fn validate_http_evidence_export_size(value: &impl Serialize) -> Result<(), ReceiptStoreError> {
    serialized_bytes(value, HTTP_EVIDENCE_EXPORT_MAX_BYTES).map(|_| ())
}

fn serialized_bytes(value: &impl Serialize, limit: u64) -> Result<u64, ReceiptStoreError> {
    let mut writer = CountingWriter {
        limit,
        bytes: 0,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if writer.exceeded {
        return Err(refuse(BYTE_ALLOWANCE_EXHAUSTED));
    }
    result.map_err(ReceiptStoreError::from)?;
    Ok(writer.bytes)
}

struct CountingWriter {
    limit: u64,
    bytes: u64,
    exceeded: bool,
}
impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = crate::integer::count(bytes.len());
        let Some(next) = self
            .bytes
            .checked_add(length)
            .filter(|sum| *sum <= self.limit)
        else {
            self.exceeded = true;
            return Err(io::Error::other(
                "HTTP evidence export exceeds its byte allowance",
            ));
        };
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_serialized_byte_allowance_includes_json_escaping() {
        let value = serde_json::json!({"v": "\""});
        // {"v":"\""} contains ten wire bytes, including the escape.
        assert_eq!(serialized_bytes(&value, 10).ok(), Some(10));
        assert!(matches!(
            serialized_bytes(&value, 9),
            Err(ReceiptStoreError::QuerySnapshot(
                ReceiptQuerySnapshotError::WorkBudgetExhausted(_)
            ))
        ));
    }

    #[test]
    fn budget_charges_all_records_before_retaining_another() {
        let mut budget = ByteBudget::new(6);
        assert!(budget.charge(&123).is_ok());
        assert!(budget.charge(&456).is_ok());
        assert_eq!(budget.remaining(), 0);
        assert!(budget.charge(&0).is_err());
    }
}
