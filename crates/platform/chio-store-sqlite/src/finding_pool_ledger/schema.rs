// tenant-read-contract: finding_pool_debits; class=administrative; principal=kernel-admission
// Contracts: docs/security/trust-boundary-inventory.json
use crate::schema_version::SchemaTransaction;
use chio_kernel::finding_pool::{FindingPoolLedgerError, FindingPoolLedgerError::Storage};

const SCHEMA_KEY: &str = "finding_pool_ledger";

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS finding_pool_ledger_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    ledger_domain TEXT NOT NULL,
    receipt_sink_id TEXT,
    receipt_authority_json TEXT,
    ledger_store_binding_sha256 TEXT,
    store_generation TEXT NOT NULL DEFAULT '0',
    outbox_lease_epoch INTEGER NOT NULL DEFAULT 0,
    trusted_time_high_water_unix_ms TEXT NOT NULL DEFAULT '0'
) STRICT;

CREATE TABLE IF NOT EXISTS finding_pool_allocations (
    allocation_envelope_sha256 TEXT PRIMARY KEY,
    allocation_id TEXT NOT NULL UNIQUE,
    pool_id TEXT NOT NULL UNIQUE,
    pool_sha256 TEXT NOT NULL,
    purchaser_id TEXT NOT NULL,
    purchaser_key_json TEXT NOT NULL,
    currency TEXT NOT NULL,
    signed_amount_units TEXT NOT NULL,
    reserved_units TEXT NOT NULL,
    spent_units TEXT NOT NULL,
    expires_at_unix_ms TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS finding_pool_debits (
    purchase_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    allocation_envelope_sha256 TEXT NOT NULL,
    debit_request_binding_sha256 TEXT,
    finding_id TEXT NOT NULL,
    listing_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    authoritative_payment_operation_id TEXT NOT NULL,
    accepted_bid_envelope_sha256 TEXT NOT NULL,
    venue_admission_envelope_sha256 TEXT NOT NULL,
    amount_units TEXT NOT NULL,
    currency TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'finalized', 'released')),
    claim_deadline_unix_ms TEXT NOT NULL,
    claimed_at_unix_ms TEXT,
    durable_admission_operation_id TEXT,
    reserved_after_units TEXT NOT NULL,
    spent_after_units TEXT NOT NULL,
    CHECK (
        state <> 'reserved'
            OR claimed_at_unix_ms IS NULL
            OR durable_admission_operation_id IS NOT NULL
    ),
    FOREIGN KEY (allocation_envelope_sha256)
        REFERENCES finding_pool_allocations(allocation_envelope_sha256)
) STRICT;

CREATE TABLE IF NOT EXISTS finding_pool_receipt_outbox (
    receipt_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL,
    allocation_envelope_sha256 TEXT NOT NULL,
    mutation_kind TEXT NOT NULL,
    signed_receipt_json TEXT NOT NULL,
    occurred_at_unix_ms TEXT NOT NULL,
    acknowledged_at_unix_ms TEXT,
    delivery_claim_owner TEXT,
    delivery_claim_expires_at_unix_ms INTEGER,
    delivery_claim_epoch INTEGER,
    delivery_sequence INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS finding_pool_debits_admission_operation
    ON finding_pool_debits(durable_admission_operation_id)
    WHERE durable_admission_operation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS finding_pool_debits_expiration_reclamation
    ON finding_pool_debits(allocation_envelope_sha256, state, claimed_at_unix_ms, purchase_id);

CREATE INDEX IF NOT EXISTS finding_pool_debits_unclaimed_deadline
    ON finding_pool_debits(
        allocation_envelope_sha256, length(claim_deadline_unix_ms),
        claim_deadline_unix_ms, purchase_id
    ) WHERE state = 'reserved' AND claimed_at_unix_ms IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS finding_pool_receipt_outbox_delivery_sequence
    ON finding_pool_receipt_outbox(delivery_sequence);

CREATE INDEX IF NOT EXISTS finding_pool_receipt_outbox_pending
    ON finding_pool_receipt_outbox(delivery_sequence)
    WHERE acknowledged_at_unix_ms IS NULL;
"#;

pub(super) fn initialize_schema(
    connection: &mut rusqlite::Connection,
) -> Result<(), FindingPoolLedgerError> {
    let transaction = SchemaTransaction::begin(connection, &[SCHEMA_KEY])
        .map_err(|error| Storage(error.to_string()))?;
    if transaction.is_fresh() {
        transaction
            .connection()
            .execute_batch(SCHEMA)
            .map_err(|error| Storage(error.to_string()))?;
        transaction
            .stamp(SCHEMA_KEY)
            .map_err(|error| Storage(error.to_string()))?;
    }
    transaction
        .validate_catalog(SCHEMA)
        .map_err(|error| Storage(error.to_string()))?;
    transaction
        .commit()
        .map_err(|error| Storage(error.to_string()))
}
