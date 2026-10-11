CREATE TABLE IF NOT EXISTS payment_journal (
    operation_id TEXT PRIMARY KEY CHECK (operation_id <> '' AND length(operation_id) <= 512),
    journal_version INTEGER NOT NULL CHECK (
        journal_version BETWEEN 1 AND 9007199254740991
    ),
    request_namespace_digest TEXT NOT NULL CHECK (
        length(request_namespace_digest) = 64
        AND request_namespace_digest NOT GLOB '*[^0-9a-f]*'
    ),
    request_id TEXT NOT NULL CHECK (request_id <> '' AND length(request_id) <= 512),
    capability_id TEXT NOT NULL CHECK (capability_id <> '' AND length(capability_id) <= 512),
    grant_index INTEGER NOT NULL CHECK (grant_index BETWEEN 0 AND 4294967295),
    hold_id TEXT NOT NULL UNIQUE CHECK (hold_id <> '' AND length(hold_id) <= 512),
    rail TEXT NOT NULL CHECK (
        rail <> '' AND rail <> 'unspecified' AND length(rail) <= 512
    ),
    rail_mode TEXT NOT NULL CHECK (rail_mode IN ('reversible_hold', 'prepaid_final')),
    authorization_id TEXT CHECK (
        authorization_id IS NULL
        OR (authorization_id <> '' AND length(authorization_id) <= 512)
    ),
    transaction_id TEXT CHECK (
        transaction_id IS NULL
        OR (transaction_id <> '' AND length(transaction_id) <= 512)
    ),
    amount_units INTEGER NOT NULL CHECK (
        amount_units BETWEEN 1 AND 9007199254740991
    ),
    authorized_amount_units INTEGER CHECK (
        authorized_amount_units IS NULL OR authorized_amount_units BETWEEN 1 AND amount_units
    ),
    authorization_attempt TEXT CHECK (
        authorization_attempt IS NULL OR (authorized_amount_units IS NOT NULL
        AND authorization_attempt IN ('not_started', 'started'))
    ),
    settle_action TEXT CHECK (settle_action IN ('capture', 'release')),
    settle_amount_units INTEGER CHECK (
        settle_amount_units BETWEEN 1 AND COALESCE(authorized_amount_units, amount_units)
    ),
    release_authority_kind TEXT CHECK (
        release_authority_kind IN (
            'pre_dispatch_no_effect',
            'transport_not_accepted',
            'contractual_zero_charge'
        )
    ),
    release_authority_evidence_id TEXT CHECK (
        release_authority_evidence_id IS NULL
        OR (release_authority_evidence_id <> ''
            AND length(release_authority_evidence_id) <= 512)
    ),
    release_authority_evidence_digest TEXT CHECK (
        release_authority_evidence_digest IS NULL
        OR (length(release_authority_evidence_digest) = 64
            AND release_authority_evidence_digest NOT GLOB '*[^0-9a-f]*')
    ),
    release_authority_operation_version INTEGER CHECK (
        release_authority_operation_version BETWEEN 1 AND 9007199254740991
    ),
    currency TEXT NOT NULL CHECK (
        length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'
    ),
    state TEXT NOT NULL CHECK (state IN (
        'hold_placed', 'authorized', 'settling', 'settled', 'closed',
        'reconcile_failed'
    )),
    created_at_unix_ms INTEGER NOT NULL CHECK (
        created_at_unix_ms BETWEEN 1 AND 9007199254740991
    ),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms BETWEEN created_at_unix_ms AND 9007199254740991
    ),
    FOREIGN KEY (hold_id) REFERENCES budget_authorization_holds(hold_id),
    CHECK (authorization_attempt IS NOT 'not_started' OR
        (state IN ('hold_placed', 'closed') AND authorization_id IS NULL)),
    CHECK (authorization_attempt IS NOT 'started' OR journal_version >= 2),
    CHECK (
        (state = 'hold_placed'
         AND authorization_id IS NULL AND transaction_id IS NULL
         AND settle_action IS NULL AND settle_amount_units IS NULL
         AND release_authority_kind IS NULL
         AND release_authority_evidence_id IS NULL
         AND release_authority_evidence_digest IS NULL
         AND release_authority_operation_version IS NULL)
        OR
        (state = 'authorized' AND rail_mode = 'reversible_hold'
         AND authorization_id IS NOT NULL AND transaction_id IS NULL
         AND settle_action IS NULL AND settle_amount_units IS NULL
         AND release_authority_kind IS NULL
         AND release_authority_evidence_id IS NULL
         AND release_authority_evidence_digest IS NULL
         AND release_authority_operation_version IS NULL)
        OR
        (state IN ('settling', 'reconcile_failed') AND rail_mode = 'reversible_hold'
         AND authorization_id IS NOT NULL AND transaction_id IS NULL
         AND (
            (settle_action = 'capture' AND settle_amount_units IS NOT NULL
             AND release_authority_kind IS NULL
             AND release_authority_evidence_id IS NULL
             AND release_authority_evidence_digest IS NULL
             AND release_authority_operation_version IS NULL)
            OR
            (settle_action = 'release' AND settle_amount_units IS NULL
             AND release_authority_kind IS NOT NULL
             AND release_authority_evidence_id IS NOT NULL
             AND release_authority_evidence_digest IS NOT NULL
             AND release_authority_operation_version IS NOT NULL)
         ))
        OR
        (state IN ('settled', 'closed') AND authorization_id IS NOT NULL
         AND (
            (rail_mode = 'prepaid_final' AND transaction_id IS NULL
             AND settle_action IS NULL AND settle_amount_units IS NULL
             AND release_authority_kind IS NULL
             AND release_authority_evidence_id IS NULL
             AND release_authority_evidence_digest IS NULL
             AND release_authority_operation_version IS NULL)
            OR
            (rail_mode = 'reversible_hold' AND transaction_id IS NOT NULL
             AND (
                (settle_action = 'capture' AND settle_amount_units IS NOT NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
                OR
                (settle_action = 'release' AND settle_amount_units IS NULL
                 AND release_authority_kind IS NOT NULL
                 AND release_authority_evidence_id IS NOT NULL
                 AND release_authority_evidence_digest IS NOT NULL
                 AND release_authority_operation_version IS NOT NULL)
             ))
         ))
        OR
        (state = 'closed'
         AND authorization_id IS NULL AND transaction_id IS NULL
         AND settle_action IS NULL AND settle_amount_units IS NULL
         AND release_authority_kind IS NULL
         AND release_authority_evidence_id IS NULL
         AND release_authority_evidence_digest IS NULL
         AND release_authority_operation_version IS NULL)
        OR
        (rail_mode = 'prepaid_final'
         AND state IN ('settling', 'closed', 'reconcile_failed')
         AND authorization_id IS NOT NULL
         AND settle_action IS NULL AND settle_amount_units IS NULL
         AND release_authority_kind = 'pre_dispatch_no_effect'
         AND release_authority_evidence_id IS NOT NULL
         AND release_authority_evidence_digest IS NOT NULL
         AND release_authority_operation_version IS NOT NULL
         AND ((state = 'closed' AND transaction_id IS NOT NULL)
              OR (state IN ('settling', 'reconcile_failed') AND transaction_id IS NULL)))
        OR (state = 'reconcile_failed'
            AND settle_action IS NULL AND settle_amount_units IS NULL
            AND release_authority_kind IS NULL
            AND release_authority_evidence_id IS NULL
            AND release_authority_evidence_digest IS NULL
            AND release_authority_operation_version IS NULL
            AND (transaction_id IS NULL OR authorization_id IS NOT NULL))
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_journal_request
    ON payment_journal(request_namespace_digest, request_id);
CREATE INDEX IF NOT EXISTS idx_payment_journal_state
    ON payment_journal(state, updated_at_unix_ms);

CREATE TRIGGER IF NOT EXISTS payment_journal_identity_immutable
BEFORE UPDATE OF operation_id, request_namespace_digest, request_id,
                 capability_id, grant_index, hold_id, rail, rail_mode,
                 amount_units, authorized_amount_units, currency, created_at_unix_ms
ON payment_journal
BEGIN
    SELECT RAISE(ABORT, 'payment journal identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS payment_journal_no_delete
BEFORE DELETE ON payment_journal
BEGIN
    SELECT RAISE(ABORT, 'payment journal is append-preserving');
END;


CREATE TRIGGER IF NOT EXISTS payment_journal_authorization_attempt_monotone
BEFORE UPDATE OF authorization_attempt ON payment_journal
WHEN OLD.authorization_attempt IS NOT NEW.authorization_attempt
  AND (OLD.authorization_attempt IS NOT 'not_started'
       OR NEW.authorization_attempt IS NOT 'started')
BEGIN
    SELECT RAISE(ABORT, 'payment authorization attempt is monotone');
END;
