-- Versioned deployment verification roots cannot be rewritten or downgraded.
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_history_insert
BEFORE INSERT ON admission_operation_recovery_records
WHEN NEW.record_key GLOB 'deployment-history:*'
 AND (NEW.kind <> 'deployment' OR NEW.version <> 1
      OR NEW.native_namespace IS NOT NULL OR NEW.native_request IS NOT NULL)
BEGIN SELECT RAISE(ABORT,'historical deployment identity is invalid'); END;
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_history_immutable
BEFORE UPDATE ON admission_operation_recovery_records
WHEN OLD.record_key GLOB 'deployment-history:*'
BEGIN SELECT RAISE(ABORT,'historical deployment is immutable'); END;
