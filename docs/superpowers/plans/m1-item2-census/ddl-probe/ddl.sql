CREATE TABLE receipt_openings (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  salt_ref TEXT NOT NULL CHECK (typeof(salt_ref) = 'text' AND instr(salt_ref, char(0)) = 0 AND length(salt_ref) BETWEEN 1 AND 64 AND salt_ref GLOB '[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*' AND salt_ref NOT GLOB '*..*' AND salt_ref NOT GLOB '*.'),
  state TEXT NOT NULL CHECK (typeof(state) = 'text' AND instr(state, char(0)) = 0 AND state IN ('present', 'erased')),
  salt BLOB,
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer' AND state_at >= 0),
  CHECK ((state = 'present' AND typeof(salt) = 'blob' AND length(salt) = 32) OR (state = 'erased' AND salt IS NULL)),
  PRIMARY KEY (receipt_id, salt_ref)
) WITHOUT ROWID;
CREATE TABLE receipt_store_identity (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_id TEXT NOT NULL CHECK (typeof(store_id) = 'text' AND instr(store_id, char(0)) = 0 AND length(store_id) = 32 AND store_id NOT GLOB '*[^0-9a-f]*')
);
CREATE TRIGGER receipt_store_identity_no_replace BEFORE INSERT ON receipt_store_identity WHEN EXISTS (SELECT 1 FROM receipt_store_identity) BEGIN SELECT RAISE(ABORT, 'receipt store id is immutable'); END;
CREATE TRIGGER receipt_store_identity_no_update BEFORE UPDATE ON receipt_store_identity BEGIN SELECT RAISE(ABORT, 'receipt store id is immutable'); END;
CREATE TRIGGER receipt_store_identity_no_delete BEFORE DELETE ON receipt_store_identity BEGIN SELECT RAISE(ABORT, 'receipt store id is immutable'); END;
CREATE TABLE receipt_opening_erasures (
  openings_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(origin_store_id) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  origin_openings_seq INTEGER NOT NULL CHECK (typeof(origin_openings_seq) = 'integer' AND origin_openings_seq >= 1),
  erased_at INTEGER NOT NULL CHECK (typeof(erased_at) = 'integer' AND erased_at >= 0),
  UNIQUE (origin_store_id, origin_openings_seq)
);
CREATE INDEX receipt_opening_erasures_by_receipt ON receipt_opening_erasures (receipt_id);
CREATE TABLE receipt_erasure_facts (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(origin_store_id) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  origin_openings_seq INTEGER NOT NULL CHECK (typeof(origin_openings_seq) = 'integer' AND origin_openings_seq >= 1),
  erased_at INTEGER NOT NULL CHECK (typeof(erased_at) = 'integer' AND erased_at >= 0),
  recorded_at INTEGER NOT NULL CHECK (typeof(recorded_at) = 'integer' AND recorded_at >= 0),
  conflicted INTEGER NOT NULL CHECK (typeof(conflicted) = 'integer' AND conflicted IN (0, 1)),
  PRIMARY KEY (receipt_id)
) WITHOUT ROWID;
CREATE TRIGGER receipt_erasure_facts_no_replace BEFORE INSERT ON receipt_erasure_facts WHEN EXISTS (SELECT 1 FROM receipt_erasure_facts WHERE receipt_id = NEW.receipt_id) BEGIN SELECT RAISE(ABORT, 'receipt erasure fact is permanent'); END;
CREATE TRIGGER receipt_erasure_facts_only_marks_conflict BEFORE UPDATE ON receipt_erasure_facts WHEN NEW.receipt_id IS NOT OLD.receipt_id OR NEW.origin_store_id IS NOT OLD.origin_store_id OR NEW.origin_openings_seq IS NOT OLD.origin_openings_seq OR NEW.erased_at IS NOT OLD.erased_at OR NEW.recorded_at IS NOT OLD.recorded_at OR NEW.conflicted < OLD.conflicted BEGIN SELECT RAISE(ABORT, 'receipt erasure fact is permanent'); END;
CREATE TRIGGER receipt_erasure_facts_no_delete BEFORE DELETE ON receipt_erasure_facts BEGIN SELECT RAISE(ABORT, 'receipt erasure fact is permanent'); END;
CREATE TABLE replication_quarantine_erasures (
  quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(origin_store_id) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  origin_openings_seq INTEGER NOT NULL CHECK (typeof(origin_openings_seq) = 'integer' AND origin_openings_seq >= 1),
  reason TEXT NOT NULL CHECK (typeof(reason) = 'text' AND reason IN ('erasure_event_conflict', 'erasure_event_conflict_own_origin')),
  hold TEXT NOT NULL CHECK (typeof(hold) = 'text' AND hold IN ('below_watermark', 'origin_frozen', 'own_origin')),
  stored_receipt_id TEXT CHECK (stored_receipt_id IS NULL OR (typeof(stored_receipt_id) = 'text' AND instr(stored_receipt_id, char(0)) = 0 AND length(stored_receipt_id) = 64 AND stored_receipt_id NOT GLOB '*[^0-9a-f]*')),
  stored_erased_at INTEGER CHECK (stored_erased_at IS NULL OR (typeof(stored_erased_at) = 'integer' AND stored_erased_at >= 0)),
  incoming_receipt_id TEXT NOT NULL CHECK (typeof(incoming_receipt_id) = 'text' AND instr(incoming_receipt_id, char(0)) = 0 AND length(incoming_receipt_id) = 64 AND incoming_receipt_id NOT GLOB '*[^0-9a-f]*'),
  incoming_erased_at INTEGER NOT NULL CHECK (typeof(incoming_erased_at) = 'integer' AND incoming_erased_at >= 0),
  source_node_id TEXT NOT NULL CHECK (typeof(source_node_id) = 'text' AND instr(source_node_id, char(0)) = 0 AND length(source_node_id) BETWEEN 1 AND 2048 AND octet_length(source_node_id) <= 8192),
  recorded_at INTEGER NOT NULL CHECK (typeof(recorded_at) = 'integer' AND recorded_at >= 0),
  resolved_at INTEGER CHECK (resolved_at IS NULL OR (typeof(resolved_at) = 'integer' AND resolved_at >= recorded_at)),
  CHECK ((hold = 'own_origin') = (reason = 'erasure_event_conflict_own_origin')),
  CHECK ((stored_receipt_id IS NULL) = (stored_erased_at IS NULL)),
  UNIQUE (origin_store_id, origin_openings_seq, incoming_receipt_id, incoming_erased_at)
);
CREATE INDEX replication_quarantine_erasures_unresolved ON replication_quarantine_erasures (origin_store_id, hold) WHERE resolved_at IS NULL;
CREATE TRIGGER replication_quarantine_erasures_no_replace BEFORE INSERT ON replication_quarantine_erasures WHEN EXISTS (SELECT 1 FROM replication_quarantine_erasures WHERE quarantine_id = NEW.quarantine_id OR (origin_store_id = NEW.origin_store_id AND origin_openings_seq = NEW.origin_openings_seq AND incoming_receipt_id = NEW.incoming_receipt_id AND incoming_erased_at = NEW.incoming_erased_at)) BEGIN SELECT RAISE(ABORT, 'erasure conflict record is permanent'); END;
CREATE TRIGGER replication_quarantine_erasures_own_store_is_own_origin BEFORE INSERT ON replication_quarantine_erasures WHEN NEW.hold <> 'own_origin' AND EXISTS (SELECT 1 FROM receipt_store_identity WHERE store_id = NEW.origin_store_id) BEGIN SELECT RAISE(ABORT, 'a conflict naming this store has hold own_origin'); END;
CREATE TRIGGER replication_quarantine_erasures_monotone BEFORE UPDATE ON replication_quarantine_erasures WHEN OLD.resolved_at IS NOT NULL OR NEW.quarantine_id IS NOT OLD.quarantine_id OR NEW.origin_store_id IS NOT OLD.origin_store_id OR NEW.origin_openings_seq IS NOT OLD.origin_openings_seq OR NEW.reason IS NOT OLD.reason OR NEW.stored_receipt_id IS NOT OLD.stored_receipt_id OR NEW.stored_erased_at IS NOT OLD.stored_erased_at OR NEW.incoming_receipt_id IS NOT OLD.incoming_receipt_id OR NEW.incoming_erased_at IS NOT OLD.incoming_erased_at OR NEW.source_node_id IS NOT OLD.source_node_id OR NEW.recorded_at IS NOT OLD.recorded_at OR NOT ((OLD.hold = 'below_watermark' AND NEW.hold = 'origin_frozen' AND NEW.resolved_at IS NULL) OR (NEW.hold IS OLD.hold AND NEW.resolved_at IS NOT NULL)) BEGIN SELECT RAISE(ABORT, 'erasure conflict record is permanent'); END;
CREATE TRIGGER replication_quarantine_erasures_no_delete BEFORE DELETE ON replication_quarantine_erasures BEGIN SELECT RAISE(ABORT, 'erasure conflict record is permanent'); END;
CREATE TABLE receipt_openings_watermarks (
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(origin_store_id) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  applied_through INTEGER NOT NULL CHECK (typeof(applied_through) = 'integer' AND applied_through >= 0),
  gc_horizon INTEGER NOT NULL CHECK (typeof(gc_horizon) = 'integer' AND gc_horizon >= 0),
  CHECK (gc_horizon <= applied_through),
  PRIMARY KEY (origin_store_id)
) WITHOUT ROWID;
CREATE TABLE receipt_openings_member_watermarks (
  member_node_id TEXT NOT NULL CHECK (typeof(member_node_id) = 'text' AND instr(member_node_id, char(0)) = 0 AND length(member_node_id) BETWEEN 1 AND 2048 AND octet_length(member_node_id) <= 8192),
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(origin_store_id) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  applied_through INTEGER NOT NULL CHECK (typeof(applied_through) = 'integer' AND applied_through >= 0),
  PRIMARY KEY (member_node_id, origin_store_id)
) WITHOUT ROWID;
CREATE TABLE receipt_openings_peer_cursors (
  peer_node_id TEXT NOT NULL CHECK (typeof(peer_node_id) = 'text' AND instr(peer_node_id, char(0)) = 0 AND length(peer_node_id) BETWEEN 1 AND 2048 AND octet_length(peer_node_id) <= 8192),
  after_openings_seq INTEGER NOT NULL CHECK (typeof(after_openings_seq) = 'integer' AND after_openings_seq >= 0),
  PRIMARY KEY (peer_node_id)
) WITHOUT ROWID;
