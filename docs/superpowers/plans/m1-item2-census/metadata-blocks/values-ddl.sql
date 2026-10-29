CREATE TABLE receipt_metadata_values (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  salt_ref TEXT NOT NULL CHECK (typeof(salt_ref) = 'text' AND instr(salt_ref, char(0)) = 0 AND length(salt_ref) BETWEEN 10 AND 64 AND salt_ref GLOB 'metadata.[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*' AND salt_ref NOT GLOB '*..*' AND salt_ref NOT GLOB '*.'),
  state TEXT NOT NULL CHECK (typeof(state) = 'text' AND instr(state, char(0)) = 0 AND state IN ('present', 'erased')),
  value TEXT,
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer' AND state_at >= 0),
  CHECK ((state = 'present' AND typeof(value) = 'text' AND json_valid(value)) OR (state = 'erased' AND value IS NULL)),
  PRIMARY KEY (receipt_id, salt_ref)
) WITHOUT ROWID;
