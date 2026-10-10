-- Private codec catalog contract; the owning migration installs this atomically.
CREATE TRIGGER admission_operation_recovery_codec_guard_insert
BEFORE INSERT ON admission_operation_recovery_records
WHEN json_type(CAST(NEW.payload AS TEXT), '$.checkpoint_restore_encoding') IS NOT NULL
 OR (json_type(CAST(NEW.payload AS TEXT), '$.knowledge_join_encoding') IS NOT NULL
  AND (json_type(CAST(NEW.payload AS TEXT), '$.knowledge_join_encoding') IS NOT 'text'
    OR json_extract(CAST(NEW.payload AS TEXT), '$.knowledge_join_encoding') IS NOT 'interned_labels_v1'
    OR NEW.record_key NOT GLOB 'knowledge-join:*'
    OR NEW.kind IS NOT 'command'
    OR NEW.native_namespace IS NOT NULL OR NEW.native_request IS NOT NULL
    OR NEW.version IS NOT 1))
BEGIN
  SELECT RAISE(ABORT, 'private recovery encoding refused');
END;
CREATE TRIGGER admission_operation_recovery_codec_guard_update
BEFORE UPDATE ON admission_operation_recovery_records
WHEN json_type(CAST(NEW.payload AS TEXT), '$.checkpoint_restore_encoding') IS NOT NULL
 OR (json_type(CAST(NEW.payload AS TEXT), '$.knowledge_join_encoding') IS NOT NULL
  AND (json_type(CAST(NEW.payload AS TEXT), '$.knowledge_join_encoding') IS NOT 'text'
    OR json_extract(CAST(NEW.payload AS TEXT), '$.knowledge_join_encoding') IS NOT 'interned_labels_v1'
    OR NEW.record_key NOT GLOB 'knowledge-join:*'
    OR NEW.kind IS NOT 'command'
    OR NEW.native_namespace IS NOT NULL OR NEW.native_request IS NOT NULL
    OR NEW.version IS NOT 1))
BEGIN
  SELECT RAISE(ABORT, 'private recovery encoding refused');
END;
