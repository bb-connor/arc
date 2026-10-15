use super::*;

pub(crate) fn ensure_checkpoint_schema(connection: &Connection) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(CHECKPOINT_TABLE_SQL)?;
    connection.execute_batch(CHECKPOINT_PROJECTION_TABLES_SQL)?;
    connection.execute_batch(CHECKPOINT_BINDING_TABLE_SQL)?;
    connection.execute_batch(CHECKPOINT_PROJECTION_SQL)?;
    ensure_checkpoint_transparency_guards(connection)
}

const CHECKPOINT_TABLE_SQL: &str = r#"
            CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL,
                previous_checkpoint_sha256 TEXT CHECK (previous_checkpoint_sha256 IS NULL OR (typeof(previous_checkpoint_sha256) = 'text' AND length(previous_checkpoint_sha256) = 64 AND instr(previous_checkpoint_sha256, char(0)) = 0 AND previous_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'))
            );
            CREATE INDEX IF NOT EXISTS idx_kernel_checkpoints_batch_end
                ON kernel_checkpoints(batch_end_seq);

"#;
const CHECKPOINT_PROJECTION_TABLES_SQL: &str = r#"
            CREATE TABLE IF NOT EXISTS checkpoint_tree_heads (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                kernel_key TEXT NOT NULL,
                previous_checkpoint_sha256 TEXT CHECK (previous_checkpoint_sha256 IS NULL OR (typeof(previous_checkpoint_sha256) = 'text' AND length(previous_checkpoint_sha256) = 64 AND instr(previous_checkpoint_sha256, char(0)) = 0 AND previous_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*')),
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_tree_heads_tree_size
                ON checkpoint_tree_heads(tree_size);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_tree_heads_previous
                ON checkpoint_tree_heads(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_predecessor_witnesses (
                predecessor_checkpoint_seq INTEGER NOT NULL
                    REFERENCES checkpoint_tree_heads(checkpoint_seq) ON DELETE CASCADE,
                witness_checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES checkpoint_tree_heads(checkpoint_seq) ON DELETE CASCADE,
                previous_checkpoint_sha256 TEXT NOT NULL CHECK (previous_checkpoint_sha256 IS NULL OR (typeof(previous_checkpoint_sha256) = 'text' AND length(previous_checkpoint_sha256) = 64 AND instr(previous_checkpoint_sha256, char(0)) = 0 AND previous_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*')),
                witnessed_at INTEGER NOT NULL,
                witness_statement_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_predecessor_witnesses_predecessor
                ON checkpoint_predecessor_witnesses(predecessor_checkpoint_seq);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_predecessor_witnesses_previous
                ON checkpoint_predecessor_witnesses(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_publication_metadata (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                publication_schema TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                published_at INTEGER NOT NULL,
                kernel_key TEXT NOT NULL,
                log_tree_size INTEGER NOT NULL,
                entry_start_seq INTEGER NOT NULL,
                entry_end_seq INTEGER NOT NULL,
                previous_checkpoint_sha256 TEXT CHECK (previous_checkpoint_sha256 IS NULL OR (typeof(previous_checkpoint_sha256) = 'text' AND length(previous_checkpoint_sha256) = 64 AND instr(previous_checkpoint_sha256, char(0)) = 0 AND previous_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'))
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_published_at
                ON checkpoint_publication_metadata(published_at);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_log_tree_size
                ON checkpoint_publication_metadata(log_tree_size);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_previous
                ON checkpoint_publication_metadata(previous_checkpoint_sha256);

"#;
const CHECKPOINT_BINDING_TABLE_SQL: &str = r#"
            CREATE TABLE IF NOT EXISTS checkpoint_publication_trust_anchor_bindings (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                binding_json TEXT NOT NULL
            );

"#;
const CHECKPOINT_PROJECTION_SQL: &str = r#"
            DROP TRIGGER IF EXISTS kernel_checkpoints_project_tree_head;
            CREATE TRIGGER kernel_checkpoints_project_tree_head
            AFTER INSERT ON kernel_checkpoints
            BEGIN
                INSERT INTO checkpoint_tree_heads (
                    checkpoint_seq,
                    batch_start_seq,
                    batch_end_seq,
                    tree_size,
                    merkle_root,
                    issued_at,
                    kernel_key,
                    previous_checkpoint_sha256,
                    statement_json,
                    signature
                ) VALUES (
                    NEW.checkpoint_seq,
                    NEW.batch_start_seq,
                    NEW.batch_end_seq,
                    NEW.tree_size,
                    NEW.merkle_root,
                    NEW.issued_at,
                    NEW.kernel_key,
                    NEW.previous_checkpoint_sha256,
                    NEW.statement_json,
                    NEW.signature
                );

                INSERT INTO checkpoint_predecessor_witnesses (
                    predecessor_checkpoint_seq,
                    witness_checkpoint_seq,
                    previous_checkpoint_sha256,
                    witnessed_at,
                    witness_statement_json
                )
                SELECT
                    NEW.checkpoint_seq - 1,
                    NEW.checkpoint_seq,
                    NEW.previous_checkpoint_sha256,
                    NEW.issued_at,
                    NEW.statement_json
                WHERE NEW.previous_checkpoint_sha256 IS NOT NULL;

                INSERT INTO checkpoint_publication_metadata (
                    checkpoint_seq,
                    publication_schema,
                    merkle_root,
                    published_at,
                    kernel_key,
                    log_tree_size,
                    entry_start_seq,
                    entry_end_seq,
                    previous_checkpoint_sha256
                ) VALUES (
                    NEW.checkpoint_seq,
                    'chio.checkpoint_publication.v1',
                    NEW.merkle_root,
                    NEW.issued_at,
                    NEW.kernel_key,
                    NEW.batch_end_seq,
                    NEW.batch_start_seq,
                    NEW.batch_end_seq,
                    NEW.previous_checkpoint_sha256
                );
            END;

"#;
