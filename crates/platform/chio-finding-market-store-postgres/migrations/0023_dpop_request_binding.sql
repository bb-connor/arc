-- Bind each admitted DPoP nonce to the exact request its proof authorized.
--
-- A request whose write is cancelled after admission has already spent its
-- nonce and a slot of its capability budget. Recording the proof's request
-- binding lets an identical retry be recognised as that request resuming,
-- while a proof replayed against any other request stays rejected. Rows
-- written before this column exists carry NULL and remain non-resumable.

ALTER TABLE chio_finding_market_dpop_nonces
    ADD COLUMN request_sha256 CHAR(64);

ALTER TABLE chio_finding_market_dpop_nonces
    ADD CONSTRAINT chio_finding_market_dpop_nonces_request_digest_v1
    CHECK (request_sha256 IS NULL OR request_sha256 !~ '[^0-9a-f]');
