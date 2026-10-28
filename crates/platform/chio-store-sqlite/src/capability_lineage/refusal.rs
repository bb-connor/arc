use chio_core::canonical::UntrustedJsonError;
use chio_kernel::{ReceiptQuerySnapshotError, ReceiptStoreError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum LineageReaderRefusal {
    #[error(transparent)]
    Validation(Box<ReceiptStoreError>),
    #[error(transparent)]
    SignedInput(Box<UntrustedJsonError>),
    #[error("invalid capability lineage value at column {column}")]
    Conversion { column: usize },
    #[error("invalid capability lineage type at column {column}")]
    ColumnType { column: usize },
    #[error("capability lineage integer out of range at column {column}")]
    IntegerRange { column: usize },
    #[error("capability lineage contains invalid UTF-8 at column {column}")]
    Utf8 { column: usize },
}

impl LineageReaderRefusal {
    pub(crate) fn from_sql(error: rusqlite::Error) -> Result<Self, rusqlite::Error> {
        match error {
            rusqlite::Error::FromSqlConversionFailure(column, _, source) => {
                let source = match source.downcast::<ReceiptStoreError>() {
                    Ok(error) => return Ok(Self::Validation(error)),
                    Err(source) => source,
                };
                match source.downcast::<UntrustedJsonError>() {
                    Ok(error) => Ok(Self::SignedInput(error)),
                    Err(_) => Ok(Self::Conversion { column }),
                }
            }
            rusqlite::Error::InvalidColumnType(column, ..) => Ok(Self::ColumnType { column }),
            rusqlite::Error::IntegralValueOutOfRange(column, _) => {
                Ok(Self::IntegerRange { column })
            }
            rusqlite::Error::Utf8Error(column, _) => Ok(Self::Utf8 { column }),
            other => Err(other),
        }
    }

    pub(crate) fn message(&self, capability: &str) -> String {
        format!("capability lineage of {capability} is refused by the local reader: {self}")
    }
}

pub(crate) fn lineage_reader_error(error: rusqlite::Error, capability: &str) -> ReceiptStoreError {
    match LineageReaderRefusal::from_sql(error) {
        Ok(refusal) => ReceiptQuerySnapshotError::Invalid(refusal.message(capability)).into(),
        Err(other) => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_reader_negative_integer_keeps_field_and_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open_in_memory()?;
        let valid = connection.query_row("SELECT 0", [], |row| {
            crate::capability_lineage::non_negative_u64_from_column(row, 0, "issued_at")
        })?;
        assert_eq!(valid, 0);
        let source = connection
            .query_row("SELECT -1", [], |row| {
                crate::capability_lineage::non_negative_u64_from_column(row, 0, "issued_at")
            })
            .err()
            .ok_or("negative lineage timestamp was accepted")?;
        let refusal = LineageReaderRefusal::from_sql(source)?;
        assert_eq!(refusal.message("cap"), "capability lineage of cap is refused by the local reader: capability_lineage.issued_at must be non-negative, got -1 at column 0");
        Ok(())
    }

    #[test]
    fn lineage_reader_unknown_provenance_keeps_field_and_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open_in_memory()?;
        let valid = connection.query_row("SELECT 'signed_token'", [], |row| {
            crate::capability_lineage::provenance_from_row(row, 0)
        })?;
        assert_eq!(
            valid,
            crate::capability_lineage::CapabilitySnapshotProvenance::SignedToken
        );
        let source = connection
            .query_row("SELECT 'unknown'", [], |row| {
                crate::capability_lineage::provenance_from_row(row, 0)
            })
            .err()
            .ok_or("unknown lineage provenance was accepted")?;
        let refusal = LineageReaderRefusal::from_sql(source)?;
        assert_eq!(refusal.message("cap"), "capability lineage of cap is refused by the local reader: capability_lineage.provenance has unsupported value \"unknown\" at column 0");
        Ok(())
    }

    #[test]
    fn lineage_reader_backend_failures_keep_sqlite_codes() {
        for code in [
            rusqlite::ffi::SQLITE_BUSY,
            rusqlite::ffi::SQLITE_LOCKED,
            rusqlite::ffi::SQLITE_INTERRUPT,
            rusqlite::ffi::SQLITE_FULL,
            rusqlite::ffi::SQLITE_IOERR,
            rusqlite::ffi::SQLITE_NOMEM,
        ] {
            let source = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            let result = lineage_reader_error(source, "cap");
            assert!(matches!(result, ReceiptStoreError::Sqlite(
                rusqlite::Error::SqliteFailure(error, None)) if error.extended_code == code));
        }
    }

    #[test]
    fn lineage_reader_validation_retains_its_typed_cause() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = rusqlite::Error::FromSqlConversionFailure(
            10,
            rusqlite::types::Type::Text,
            Box::new(ReceiptStoreError::UntrustedInput(std::sync::Arc::new(
                UntrustedJsonError::NonCanonical,
            ))),
        );
        let refusal = LineageReaderRefusal::from_sql(source)?;
        assert!(matches!(&refusal, LineageReaderRefusal::Validation(error)
            if matches!(error.as_ref(), ReceiptStoreError::UntrustedInput(cause)
                if matches!(cause.as_ref(), UntrustedJsonError::NonCanonical))));
        assert_eq!(refusal.message("cap"), "capability lineage of cap is refused by the local reader: urn:chio:error:attest:signed-json-noncanonical");
        Ok(())
    }

    #[test]
    fn lineage_reader_signed_input_retains_its_typed_cause(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source = rusqlite::Error::FromSqlConversionFailure(
            10,
            rusqlite::types::Type::Text,
            Box::new(UntrustedJsonError::TooLarge { bytes: 9, bound: 8 }),
        );
        let refusal = LineageReaderRefusal::from_sql(source)?;
        assert!(matches!(&refusal, LineageReaderRefusal::SignedInput(error)
            if matches!(error.as_ref(), UntrustedJsonError::TooLarge { bytes: 9, bound: 8 })));
        assert_eq!(refusal.message("cap"), "capability lineage of cap is refused by the local reader: urn:chio:error:attest:signed-json-too-large");
        Ok(())
    }
}
