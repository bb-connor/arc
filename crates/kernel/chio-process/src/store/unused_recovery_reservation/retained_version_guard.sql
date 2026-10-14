CREATE TRIGGER IF NOT EXISTS process_recovery_version_monotone BEFORE UPDATE OF version ON process_runtime
WHEN NEW.version < OLD.version OR NEW.version NOT BETWEEN 1 AND 6
BEGIN SELECT RAISE(ABORT,'recovery journal cannot downgrade'); END;
