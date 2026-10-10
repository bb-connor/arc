CREATE INDEX idx_recovery_knowledge_journal_chunk_authority
ON admission_operation_recovery_records(json_extract(payload,'$.owner.authority'))
WHERE record_key GLOB 'knowledge-encoding-chunk:*'
  AND json_extract(payload,'$.owner.kind')='journal';
