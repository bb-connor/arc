-- The auxiliary hold is monotone while ordinary quota counters may advance.
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_hold_immutable
BEFORE UPDATE ON admission_operation_recovery_records
WHEN OLD.record_key GLOB 'workflow-quota:*'
 AND json_type(OLD.payload,'$.native_hold') IS NOT NULL
 AND json_extract(NEW.payload,'$.native_hold') IS NOT json_extract(OLD.payload,'$.native_hold')
BEGIN SELECT RAISE(ABORT,'recovery historical hold is immutable'); END;
