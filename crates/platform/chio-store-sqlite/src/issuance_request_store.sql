CREATE TABLE federation_issuance_requests (
    challenge_id TEXT NOT NULL PRIMARY KEY CHECK (octet_length(challenge_id) BETWEEN 1 AND 2048),
    subject TEXT NOT NULL,
    verifier TEXT NOT NULL,
    presentation_json TEXT NOT NULL,
    challenge_json TEXT NOT NULL,
    submitted_at INTEGER NOT NULL CHECK (submitted_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'deciding', 'approved', 'denied')),
    decided_at INTEGER CHECK (decided_at IS NULL OR decided_at >= 0),
    capability_id TEXT,
    decision_reason TEXT,
    claim_epoch INTEGER NOT NULL CHECK (claim_epoch >= 0),
    CHECK ((status = 'approved') = (capability_id IS NOT NULL))
) STRICT;
CREATE INDEX idx_federation_issuance_requests_status
    ON federation_issuance_requests(status, submitted_at, challenge_id);
CREATE INDEX idx_federation_issuance_requests_order
    ON federation_issuance_requests(submitted_at, challenge_id);
