CREATE TABLE process_native_return_accounts (
    account_digest TEXT PRIMARY KEY CHECK(length(account_digest)=64 AND account_digest NOT GLOB '*[^0-9a-f]*'),
    process_id TEXT NOT NULL CHECK(length(CAST(process_id AS BLOB)) BETWEEN 1 AND 256),
    operation_key TEXT NOT NULL CHECK(length(CAST(operation_key AS BLOB)) BETWEEN 1 AND 256),
    attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
    native_operation_id TEXT NOT NULL UNIQUE CHECK(length(native_operation_id)=64 AND native_operation_id NOT GLOB '*[^0-9a-f]*'),
    account_json BLOB NOT NULL CHECK(typeof(account_json)='blob' AND length(account_json) BETWEEN 1 AND 32768),
    UNIQUE(process_id,operation_key,attempt),
    FOREIGN KEY(process_id,operation_key) REFERENCES process_calls(process_id,operation_key)
);
CREATE TABLE process_native_return_notices (
    account_digest TEXT PRIMARY KEY REFERENCES process_native_return_accounts(account_digest),
    notice_json BLOB NOT NULL CHECK(typeof(notice_json)='blob' AND length(notice_json) BETWEEN 1 AND 8192)
);
CREATE TABLE process_native_return_nonce_receipts (
    account_digest TEXT PRIMARY KEY REFERENCES process_native_return_accounts(account_digest),
    nonce_receipt_json BLOB NOT NULL CHECK(typeof(nonce_receipt_json)='blob' AND length(nonce_receipt_json) BETWEEN 1 AND 32768)
);
CREATE TABLE process_native_return_fates (
    account_digest TEXT PRIMARY KEY REFERENCES process_native_return_accounts(account_digest),
    fate_json BLOB NOT NULL CHECK(typeof(fate_json)='blob' AND length(fate_json) BETWEEN 1 AND 8192)
);
CREATE TABLE process_native_return_reconciliations (
    account_digest TEXT PRIMARY KEY REFERENCES process_native_return_fates(account_digest),
    reconciliation_json BLOB NOT NULL CHECK(typeof(reconciliation_json)='blob' AND length(reconciliation_json) BETWEEN 1 AND 8192)
);
CREATE TABLE process_native_return_events (
    sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 9007199254740991),
    account_digest TEXT NOT NULL REFERENCES process_native_return_accounts(account_digest),
    phase TEXT NOT NULL CHECK(phase IN('enrolled','nonce_retained','unavailable','native_custody','reconciled')),
    payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64 AND payload_digest NOT GLOB '*[^0-9a-f]*'),
    previous_digest TEXT NOT NULL CHECK(length(previous_digest)=64 AND previous_digest NOT GLOB '*[^0-9a-f]*'),
    event_digest TEXT NOT NULL CHECK(length(event_digest)=64 AND event_digest NOT GLOB '*[^0-9a-f]*'),
    event_json BLOB NOT NULL CHECK(typeof(event_json)='blob' AND length(event_json) BETWEEN 1 AND 512),
    UNIQUE(account_digest,phase)
);
CREATE TABLE process_native_return_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    sequence INTEGER NOT NULL CHECK(sequence BETWEEN 0 AND 9007199254740991),
    active_accounts INTEGER NOT NULL CHECK(active_accounts BETWEEN 0 AND 64),
    head_digest TEXT NOT NULL CHECK(length(head_digest)=64 AND head_digest NOT GLOB '*[^0-9a-f]*')
);
CREATE TRIGGER process_native_return_account_no_update BEFORE UPDATE ON process_native_return_accounts
BEGIN SELECT RAISE(ABORT,'native return account is immutable'); END;
CREATE TRIGGER process_native_return_account_no_delete BEFORE DELETE ON process_native_return_accounts
BEGIN SELECT RAISE(ABORT,'native return account is retained'); END;
CREATE TRIGGER process_native_return_notice_no_update BEFORE UPDATE ON process_native_return_notices
BEGIN SELECT RAISE(ABORT,'native return notice is immutable'); END;
CREATE TRIGGER process_native_return_notice_no_delete BEFORE DELETE ON process_native_return_notices
BEGIN SELECT RAISE(ABORT,'native return notice is retained'); END;
CREATE TRIGGER process_native_return_notice_before_fate BEFORE INSERT ON process_native_return_notices
WHEN EXISTS(SELECT 1 FROM process_native_return_fates WHERE account_digest=NEW.account_digest)
BEGIN SELECT RAISE(ABORT,'native return fate is already retained'); END;
CREATE TRIGGER process_native_return_nonce_receipt_no_update BEFORE UPDATE ON process_native_return_nonce_receipts
BEGIN SELECT RAISE(ABORT,'native original nonce receipt is immutable'); END;
CREATE TRIGGER process_native_return_nonce_receipt_no_delete BEFORE DELETE ON process_native_return_nonce_receipts
BEGIN SELECT RAISE(ABORT,'native original nonce receipt is retained'); END;
CREATE TRIGGER process_native_return_fate_no_update BEFORE UPDATE ON process_native_return_fates
BEGIN SELECT RAISE(ABORT,'native return fate is immutable'); END;
CREATE TRIGGER process_native_return_fate_no_delete BEFORE DELETE ON process_native_return_fates
BEGIN SELECT RAISE(ABORT,'native return fate is retained'); END;
CREATE TRIGGER process_native_return_reconciliation_no_update BEFORE UPDATE ON process_native_return_reconciliations
BEGIN SELECT RAISE(ABORT,'native return reconciliation is immutable'); END;
CREATE TRIGGER process_native_return_reconciliation_no_delete BEFORE DELETE ON process_native_return_reconciliations
BEGIN SELECT RAISE(ABORT,'native return reconciliation is retained'); END;
CREATE TRIGGER process_native_return_event_no_update BEFORE UPDATE ON process_native_return_events
BEGIN SELECT RAISE(ABORT,'native return event is immutable'); END;
CREATE TRIGGER process_native_return_event_no_delete BEFORE DELETE ON process_native_return_events
BEGIN SELECT RAISE(ABORT,'native return event is retained'); END;
CREATE TRIGGER process_native_return_meta_no_delete BEFORE DELETE ON process_native_return_meta
BEGIN SELECT RAISE(ABORT,'native return frontier is retained'); END;
CREATE TRIGGER process_native_return_meta_follows_event BEFORE UPDATE ON process_native_return_meta
WHEN NEW.singleton!=OLD.singleton OR NEW.sequence!=OLD.sequence+1
 OR NOT EXISTS(SELECT 1 FROM process_native_return_events e
    WHERE e.sequence=NEW.sequence AND e.previous_digest=OLD.head_digest AND e.event_digest=NEW.head_digest
      AND ((e.phase='enrolled' AND NEW.active_accounts=OLD.active_accounts+1)
        OR (e.phase IN('nonce_retained','unavailable','native_custody') AND NEW.active_accounts=OLD.active_accounts)
        OR (e.phase='reconciled' AND NEW.active_accounts=OLD.active_accounts-1)))
BEGIN SELECT RAISE(ABORT,'native return frontier has no exact next event'); END;
CREATE TRIGGER process_native_return_event_has_source BEFORE INSERT ON process_native_return_events
WHEN NOT EXISTS(SELECT 1 FROM process_native_return_meta m
    WHERE NEW.sequence=m.sequence+1 AND NEW.previous_digest=m.head_digest)
 OR (NEW.phase='unavailable' AND NOT EXISTS(SELECT 1 FROM process_native_return_notices n WHERE n.account_digest=NEW.account_digest))
 OR (NEW.phase='nonce_retained' AND NOT EXISTS(SELECT 1 FROM process_native_return_nonce_receipts n WHERE n.account_digest=NEW.account_digest))
 OR (NEW.phase='native_custody' AND NOT EXISTS(SELECT 1 FROM process_native_return_fates f WHERE f.account_digest=NEW.account_digest))
 OR (NEW.phase='reconciled' AND NOT EXISTS(SELECT 1 FROM process_native_return_reconciliations r WHERE r.account_digest=NEW.account_digest))
BEGIN SELECT RAISE(ABORT,'native return event has no original producer row'); END;
CREATE TRIGGER process_native_return_version_requires_account BEFORE UPDATE OF version ON process_runtime
WHEN NEW.version=8 AND NOT EXISTS(SELECT 1 FROM process_native_return_accounts)
BEGIN SELECT RAISE(ABORT,'native return version requires its original cohort'); END;
CREATE TRIGGER process_native_return_version_no_downgrade BEFORE UPDATE OF version ON process_runtime
WHEN OLD.version>=8 AND NEW.version<OLD.version
BEGIN SELECT RAISE(ABORT,'native return account version is permanent'); END;
