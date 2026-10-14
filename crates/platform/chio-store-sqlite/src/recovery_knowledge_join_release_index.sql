-- Candidate routing index for the immutable knowledge-join observation of an
-- original private release. NONUNIQUE by design: duplicate candidate
-- observations stay a lookup refusal, never an open-time duplicate rejection.
-- Installed from schema/recovery.rs so fresh current stores and supported
-- migrations share these exact SQL bytes.
CREATE INDEX idx_recovery_knowledge_join_release
ON admission_operation_recovery_records(json_extract(payload,'$.release.release'))
WHERE record_key GLOB 'knowledge-join:*';
