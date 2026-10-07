-- Successor-only lookup over immutable retained origin ownership.
CREATE INDEX IF NOT EXISTS admission_operation_recovery_origin_presence
    ON admission_operation_recovery_records(
        coalesce(json_type(payload,'$.origin'),'null'),record_key
    ) WHERE kind='workflow';
