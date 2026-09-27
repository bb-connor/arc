-- Version 6 projection trigger, retained only as an upgrade fixture.
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
        CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT),
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
        CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT),
        NEW.issued_at,
        NEW.statement_json
    WHERE json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') IS NOT NULL;

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
        CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT)
    );
END;
