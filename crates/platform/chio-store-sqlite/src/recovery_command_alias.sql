-- Successor-only scoped streaming verification of immutable command aliases.
CREATE INDEX IF NOT EXISTS admission_operation_recovery_command_alias
    ON admission_operation_recovery_records(scope_key,record_key)
    WHERE kind='command' AND record_key GLOB 'command-alias:*';
