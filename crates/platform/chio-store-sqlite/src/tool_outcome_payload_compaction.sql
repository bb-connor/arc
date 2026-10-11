-- Derived lookup metadata only. No committed outcome, evaluation, receipt,
-- digest, size, provenance or request identity is rewritten by this migration.
CREATE INDEX IF NOT EXISTS tool_outcomes_raw_digest_owners
ON tool_outcomes (raw_output_digest, operation_id);

CREATE INDEX IF NOT EXISTS tool_outcomes_resolved_digest_owners
ON tool_outcomes (json_extract(outcome_json, '$.disposition.resolved_output.digest'));

CREATE INDEX IF NOT EXISTS post_return_evaluations_resolved_digest_owners
ON post_return_evaluations (json_extract(evaluation_json, '$.state.resolution.resolved_output.digest'));

DROP TRIGGER IF EXISTS tool_outcome_blobs_compaction_requires_terminal;
CREATE TRIGGER tool_outcome_blobs_compaction_requires_terminal
BEFORE UPDATE OF canonical_bytes ON tool_outcome_blobs
WHEN NEW.canonical_bytes IS NULL
  AND (
      NOT EXISTS (
          SELECT 1 FROM tool_outcomes INDEXED BY tool_outcomes_raw_digest_owners
          WHERE raw_output_digest = OLD.digest
      )
      OR EXISTS (
          SELECT 1 FROM tool_outcomes AS o INDEXED BY tool_outcomes_raw_digest_owners
          JOIN admission_operations AS a ON a.operation_id = o.operation_id
          WHERE o.raw_output_digest = OLD.digest AND (a.terminal = 0 OR a.state <> 'completed')
      )
      -- Resolved-output custody is a separate replay contract. Hold every
      -- reference, including terminal owners, until that contract changes.
      OR EXISTS (
          SELECT 1 FROM tool_outcomes INDEXED BY tool_outcomes_resolved_digest_owners
          WHERE json_extract(outcome_json, '$.disposition.resolved_output.digest') = OLD.digest
      )
      OR EXISTS (
          SELECT 1 FROM post_return_evaluations INDEXED BY post_return_evaluations_resolved_digest_owners
          WHERE json_extract(evaluation_json, '$.state.resolution.resolved_output.digest') = OLD.digest
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'tool outcome blob is retained by live, unsupported terminal or resolved replay custody');
END;
