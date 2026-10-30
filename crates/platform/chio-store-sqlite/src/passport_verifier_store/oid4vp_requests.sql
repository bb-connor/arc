CREATE TABLE passport_oid4vp_transactions (
    request_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(request_id) BETWEEN 1 AND 512
        AND instr(request_id, char(0)) = 0
        AND octet_length(request_id) <= 2048
    ),
    request_hash TEXT NOT NULL CHECK (
        length(request_hash) = 64
        AND instr(request_hash, char(0)) = 0
        AND octet_length(request_hash) <= 256
        AND request_hash NOT GLOB '*[^0-9a-f]*'
    ),
    request_json TEXT NOT NULL CHECK (
        octet_length(request_json) BETWEEN 1 AND 16777216
        AND instr(request_json, char(0)) = 0
    ),
    request_jwt TEXT NOT NULL CHECK (
        octet_length(request_jwt) BETWEEN 1 AND 16777216
        AND instr(request_jwt, char(0)) = 0
    ),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at >= issued_at),
    status TEXT NOT NULL CHECK (status IN ('issued', 'consumed', 'expired')),
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= 0),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
) STRICT;
