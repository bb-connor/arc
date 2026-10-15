-- Delegation parent of every operation that has funded a caller share. A row
-- is derived from the immutable retained request in the transaction that first
-- funds the share and is never changed. Readers verify every matched operation.
CREATE TABLE IF NOT EXISTS admission_operation_caller_shares (
    operation_id TEXT NOT NULL PRIMARY KEY
        REFERENCES admission_operations(operation_id),
    parent_kind TEXT NOT NULL
        CHECK (parent_kind IN ('delegated', 'root', 'unresolved')),
    parent_capability_id TEXT CHECK (
        parent_capability_id IS NULL
        OR (length(parent_capability_id) BETWEEN 1 AND 512 AND octet_length(parent_capability_id) <= 2048 AND instr(parent_capability_id, char(0)) = 0)
    ),
    CHECK ((parent_kind = 'delegated') = (parent_capability_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS admission_operation_caller_shares_parent
    ON admission_operation_caller_shares(parent_kind, parent_capability_id, operation_id);
CREATE TRIGGER IF NOT EXISTS admission_operation_caller_shares_immutable
BEFORE UPDATE ON admission_operation_caller_shares
BEGIN
    SELECT RAISE(ABORT, 'caller share parents are immutable');
END;
CREATE TRIGGER IF NOT EXISTS admission_operation_caller_shares_no_delete
BEFORE DELETE ON admission_operation_caller_shares
BEGIN
    SELECT RAISE(ABORT, 'caller share parents cannot be deleted');
END;
