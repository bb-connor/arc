CREATE TABLE receipt_openings (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(CAST(receipt_id AS BLOB)) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  salt_ref TEXT NOT NULL CHECK (typeof(salt_ref) = 'text' AND instr(salt_ref, char(0)) = 0 AND length(CAST(salt_ref AS BLOB)) BETWEEN 1 AND 64 AND salt_ref GLOB '[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*' AND salt_ref NOT GLOB '*..*' AND salt_ref NOT GLOB '*.'),
  state TEXT NOT NULL CHECK (typeof(state) = 'text' AND instr(state, char(0)) = 0 AND state IN ('present', 'erased')),
  salt BLOB,
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer' AND state_at >= 0),
  CHECK ((state = 'present' AND typeof(salt) = 'blob' AND length(salt) = 32) OR (state = 'erased' AND salt IS NULL)),
  PRIMARY KEY (receipt_id, salt_ref)
) WITHOUT ROWID;
