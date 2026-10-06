//! Independently compare raw-return data with the original captured ledger.
use super::*;
use chio_kernel::tool_outcome::RawInvocationOutcomeV1;

impl SqliteAdmissionOperationStore {
    /// One transaction-scoped check. It cannot renew custody, reconstruct an
    /// owner, capture invocation quota, execute a connector or release output.
    pub(crate) fn verify_original_native_return_tx(
        connection: &Connection,
        operation: &AdmissionOperationV1,
        raw: &RawInvocationOutcomeV1,
        require_original: bool,
    ) -> Result<(), AdmissionOperationStoreError> {
        let Some(attached) = operation.native_dispatch_ledger_digest() else {
            if raw
                .original_security_dispatch_binding()
                .is_some_and(|binding| binding.native_dispatch_ledger_digest().is_some())
            {
                return Err(invalid(
                    "ordinary return cannot adopt a native dispatch ledger",
                ));
            }
            return Ok(());
        };
        let Some(binding) = raw.original_security_dispatch_binding() else {
            return if require_original {
                Err(invalid(
                    "fresh native return lacks its original dispatch binding",
                ))
            } else {
                // Read exact old evidence without granting a fresh mutation.
                Ok(())
            };
        };
        if binding.native_dispatch_ledger_digest() != Some(attached)
            || raw.requires_security_release() != Ok(true)
        {
            return Err(invalid(
                "native return changed its original release requirement",
            ));
        }
        storage::verify_coverage(connection)?;
        let record = storage::load(connection, operation.binding().operation_id().as_str())?
            .ok_or_else(|| invalid("native return lost its original dispatch ledger"))?;
        capture::verify_capture_record(connection, operation, &record, None)?;
        let original = retained_request::load_retained_request_tx(connection, operation)?
            .ok_or_else(|| invalid("native return lost its original request material"))?;
        if !raw.matches_compacted_original_request(&original) {
            return Err(invalid(
                "native return changed its original request material",
            ));
        }
        raw.validate_original_native_dispatch_record(
            &record.evidence()?,
            &record.context,
            record.grant_index,
        )
        .map_err(invalid)
    }
}
