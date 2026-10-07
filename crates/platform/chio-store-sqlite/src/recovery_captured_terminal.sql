-- Independent owed terminal and release custody retain the physical workflow.
CREATE TRIGGER admission_operation_recovery_terminal_shape_insert
BEFORE INSERT ON admission_operation_recovery_records
WHEN (NEW.record_key GLOB 'captured-terminal:*' OR NEW.record_key GLOB 'captured-release:*')
 AND (NEW.kind IS NOT 'command' OR NEW.version IS NOT 1
   OR NEW.native_namespace IS NOT NULL OR NEW.native_request IS NOT NULL
   OR length(NEW.payload) NOT BETWEEN 1 AND 4096
   OR (NEW.record_key GLOB 'captured-terminal:*'
     AND json_extract(CAST(NEW.payload AS TEXT),'$.schema') IS NOT 'chio.recovery.captured-terminal.v1')
   OR (NEW.record_key GLOB 'captured-release:*'
     AND json_extract(CAST(NEW.payload AS TEXT),'$.schema') IS NOT 'chio.recovery.captured-release.v1'))
BEGIN
 SELECT RAISE(ABORT,'captured terminal custody shape refused');
END;
CREATE TRIGGER admission_operation_recovery_terminal_immutable
BEFORE UPDATE ON admission_operation_recovery_records
WHEN OLD.record_key GLOB 'captured-terminal:*' OR OLD.record_key GLOB 'captured-release:*'
 OR NEW.record_key GLOB 'captured-terminal:*' OR NEW.record_key GLOB 'captured-release:*'
BEGIN
 SELECT RAISE(ABORT,'captured terminal custody is immutable');
END;
CREATE TRIGGER admission_operation_recovery_terminal_quota_immutable
BEFORE UPDATE ON admission_operation_recovery_records
WHEN (json_type(CAST(OLD.payload AS TEXT),'$.native_terminal') IS NOT NULL
 AND json_extract(CAST(NEW.payload AS TEXT),'$.native_terminal') IS NOT
     json_extract(CAST(OLD.payload AS TEXT),'$.native_terminal'))
 OR (json_type(CAST(OLD.payload AS TEXT),'$.native_release') IS NOT NULL
 AND json_extract(CAST(NEW.payload AS TEXT),'$.native_release') IS NOT
     json_extract(CAST(OLD.payload AS TEXT),'$.native_release'))
BEGIN
 SELECT RAISE(ABORT,'captured terminal allocation is immutable');
END;
CREATE TRIGGER admission_operation_recovery_terminal_workflow_immutable
BEFORE UPDATE ON admission_operation_recovery_records
WHEN OLD.kind='workflow' AND EXISTS(
 SELECT 1 FROM admission_operation_recovery_records quota
 WHERE quota.record_key='workflow-quota:'||substr(OLD.record_key,length('workflow:')+1)
 AND (json_type(CAST(quota.payload AS TEXT),'$.native_terminal') IS NOT NULL
   OR json_type(CAST(quota.payload AS TEXT),'$.native_release') IS NOT NULL))
BEGIN
 SELECT RAISE(ABORT,'captured terminal workflow is immutable');
END;
CREATE UNIQUE INDEX admission_operation_recovery_first_report
 ON admission_operation_recovery_records(scope_key,
   json_extract(CAST(payload AS TEXT),'$.reported_decision.workflow_id'))
 WHERE kind='command' AND record_key GLOB 'command:*'
   AND json_type(CAST(payload AS TEXT),'$.reported_decision') IS NOT NULL;
