pub(super) const SCHEMA: &str = include_str!("../issuance_request_store.sql");

pub(super) const EXPIRE_STALE: &str = "UPDATE federation_issuance_requests
    SET status = 'denied', decided_at = ?1, decision_reason = ?2
    WHERE status = 'pending' AND expires_at <= ?1";

pub(super) const EXISTS: &str =
    "SELECT 1 FROM federation_issuance_requests WHERE challenge_id = ?1";

pub(super) const COUNT_OPEN: &str = "SELECT count(*) FROM federation_issuance_requests
    WHERE status IN ('pending', 'deciding')";

pub(super) const INSERT_PENDING: &str = "INSERT INTO federation_issuance_requests (
        challenge_id, subject, verifier, presentation_json, challenge_json,
        submitted_at, expires_at, status, decided_at, capability_id, decision_reason,
        claim_epoch
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', NULL, NULL, NULL, 0)";

pub(super) const GET: &str = "SELECT challenge_id, subject, verifier, presentation_json,
        challenge_json, submitted_at, expires_at, status, decided_at, capability_id,
        decision_reason
    FROM federation_issuance_requests WHERE challenge_id = ?1";

pub(super) const SUBMITTED_AT: &str =
    "SELECT submitted_at FROM federation_issuance_requests WHERE challenge_id = ?1";

/// One listing statement per filter shape, so a status filter seeks
/// `idx_federation_issuance_requests_status` and a cursor seeks past the
/// previous page instead of scanning the terminal history.
pub(super) const LIST_ALL: &str = "SELECT challenge_id, subject, verifier, submitted_at,
        expires_at, status, decided_at, capability_id, decision_reason
    FROM federation_issuance_requests
    ORDER BY submitted_at, challenge_id LIMIT ?1";

pub(super) const LIST_ALL_AFTER: &str = "SELECT challenge_id, subject, verifier, submitted_at,
        expires_at, status, decided_at, capability_id, decision_reason
    FROM federation_issuance_requests
    WHERE (submitted_at, challenge_id) > (?1, ?2)
    ORDER BY submitted_at, challenge_id LIMIT ?3";

pub(super) const LIST_STATUS: &str = "SELECT challenge_id, subject, verifier, submitted_at,
        expires_at, status, decided_at, capability_id, decision_reason
    FROM federation_issuance_requests
    WHERE status = ?1
    ORDER BY submitted_at, challenge_id LIMIT ?2";

pub(super) const LIST_STATUS_AFTER: &str = "SELECT challenge_id, subject, verifier,
        submitted_at, expires_at, status, decided_at, capability_id, decision_reason
    FROM federation_issuance_requests
    WHERE status = ?1 AND (submitted_at, challenge_id) > (?2, ?3)
    ORDER BY submitted_at, challenge_id LIMIT ?4";

pub(super) const CLAIM: &str = "UPDATE federation_issuance_requests
    SET status = 'deciding', claim_epoch = claim_epoch + 1
    WHERE challenge_id = ?1 AND status = 'pending'
    RETURNING claim_epoch";

pub(super) const FINISH: &str = "UPDATE federation_issuance_requests
    SET status = ?2, decided_at = ?3, capability_id = ?4, decision_reason = ?5
    WHERE challenge_id = ?1 AND status = 'deciding' AND claim_epoch = ?6";

pub(super) const RELEASE: &str = "UPDATE federation_issuance_requests SET status = 'pending'
    WHERE challenge_id = ?1 AND status = 'deciding' AND claim_epoch = ?2";
