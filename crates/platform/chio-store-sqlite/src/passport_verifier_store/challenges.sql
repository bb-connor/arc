CREATE TABLE passport_verifier_challenges (
    challenge_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(challenge_id) BETWEEN 1 AND 512
        AND instr(challenge_id, char(0)) = 0
        AND octet_length(challenge_id) <= 2048
    ),
    challenge_hash TEXT NOT NULL CHECK (
        length(challenge_hash) = 64
        AND instr(challenge_hash, char(0)) = 0
        AND octet_length(challenge_hash) <= 256
        AND challenge_hash NOT GLOB '*[^0-9a-f]*'
    ),
    challenge_json TEXT NOT NULL CHECK (
        octet_length(challenge_json) BETWEEN 1 AND 16777216
        AND instr(challenge_json, char(0)) = 0
    ),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at >= issued_at),
    status TEXT NOT NULL CHECK (status IN ('issued', 'verified', 'consumed', 'expired')),
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= 0),
    presentation_hash TEXT CHECK (
        presentation_hash IS NULL
        OR (
            length(presentation_hash) = 64
            AND instr(presentation_hash, char(0)) = 0
            AND octet_length(presentation_hash) <= 256
            AND presentation_hash NOT GLOB '*[^0-9a-f]*'
        )
    ),
    CHECK (
        (status = 'issued' AND presentation_hash IS NULL AND consumed_at IS NULL)
        OR (
            status IN ('verified', 'consumed')
            AND presentation_hash IS NOT NULL
            AND consumed_at IS NOT NULL
        )
        OR status = 'expired'
    )
) STRICT;
