CREATE TABLE receipt_openings (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  salt_ref TEXT NOT NULL CHECK (typeof(salt_ref) = 'text' AND length(salt_ref) BETWEEN 1 AND 64 AND salt_ref GLOB '[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*' AND salt_ref NOT GLOB '*..*' AND salt_ref NOT GLOB '*.'),
  state TEXT NOT NULL CHECK (typeof(state) = 'text' AND state IN ('present', 'erased')),
  salt BLOB,
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer' AND state_at >= 0),
  CHECK ((state = 'present' AND typeof(salt) = 'blob' AND length(salt) = 32) OR (state = 'erased' AND salt IS NULL)),
  PRIMARY KEY (receipt_id, salt_ref)
) WITHOUT ROWID;
