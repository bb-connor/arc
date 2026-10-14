CREATE INDEX admission_operation_recovery_reference_capacity
ON admission_operation_recovery_records(record_key)
WHERE kind='command' AND record_key GLOB 'knowledge-reference-capacity:*';
