#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::crypto::{Ed25519Backend, Keypair, SigningAlgorithm};
    use chio_core::receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::TrustLevel,
    };
    use chio_credit::{CreditEvaluatorHook, IouEnvelopeStore, LocalCreditAccount};
    use chio_kernel::settlement_retry::{SettleAttemptRecord, SettlementRetryStore};
    use chio_kernel::ReceiptStore;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        chio_test_support::private_fs::unique_sqlite_path(&format!("chio-{prefix}"))
    }

    fn attempt_record(
        receipt_id: &str,
        finalized_at: u64,
        attempts: u32,
        next_visible_at: u64,
    ) -> SettleAttemptRecord {
        SettleAttemptRecord {
            receipt_id: receipt_id.to_string(),
            finalized_at,
            attempts,
            next_visible_at,
            last_reason: Some(format!("retry {attempts}")),
        }
    }

    fn dead_letter_record(
        receipt_id: &str,
        finalized_at: u64,
        attempts: u32,
        reason: &str,
    ) -> chio_settle::DeadLetterRecord {
        chio_settle::DeadLetterRecord::new(receipt_id, finalized_at, attempts, reason)
    }

    fn priced_receipt(keypair: &Keypair, receipt_id: &str, timestamp: u64) -> ChioReceipt {
        ChioReceipt::sign(
            ChioReceiptBody {
                id: receipt_id.to_string(),
                timestamp,
                capability_id: format!("cap-{receipt_id}"),
                tool_server: "srv".to_string(),
                tool_name: "tool".to_string(),
                action: ToolCallAction::from_parameters(serde_json::json!({"id": receipt_id}))
                    .unwrap(),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: format!("content-{receipt_id}"),
                policy_hash: "policy".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "financial": {"cost_charged": 25, "currency": "USD"}
                })),
                trust_level: TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            keypair,
        )
        .unwrap()
    }

    fn append_attempt_receipt(
        receipts: &crate::SqliteReceiptStore,
        receipt_id: &str,
        timestamp: u64,
    ) -> ChioReceipt {
        let keypair = Keypair::from_seed(&[59; 32]);
        let receipt = priced_receipt(&keypair, receipt_id, timestamp);
        receipts.append_chio_receipt(&receipt).unwrap();
        receipt
    }

    fn wait_for_writer_queue_depth(store: &crate::SqliteReceiptStore, minimum: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let depth = store.receipt_store_health().unwrap().writer.queue_depth;
            if depth >= minimum {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "writer queue depth stayed at {depth}, below required {minimum}"
            );
            std::thread::yield_now();
        }
    }

    fn envelope(
        issuer: &Keypair,
        kernel: &Keypair,
        receipt: &ChioReceipt,
    ) -> chio_credit::IouEnvelope {
        LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(issuer.clone()),
            [kernel.public_key()],
        )
        .evaluate(receipt)
        .unwrap()
        .unwrap()
    }

    #[test]
    fn attempt_upsert_load_due_and_clear_roundtrip() {
        let path = unique_db_path("settle-attempts");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let receipt = append_attempt_receipt(&receipts, "r1", 100);
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();

        assert!(store.load_attempt(&receipt.id).unwrap().is_none());
        assert!(matches!(
            store.upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp + 1, 1, 250,)),
            Err(SettlementRetryError::Conflict(_))
        ));
        assert!(store.load_attempt(&receipt.id).unwrap().is_none());
        store
            .upsert_attempt(&SettleAttemptRecord {
                receipt_id: receipt.id.clone(),
                finalized_at: receipt.timestamp,
                attempts: 1,
                next_visible_at: 250,
                last_reason: Some("retryable".to_string()),
            })
            .unwrap();
        let loaded = store
            .load_attempt(&receipt.id)
            .unwrap()
            .expect("attempt present");
        assert_eq!(loaded.attempts, 1);
        assert_eq!(loaded.next_visible_at, 250);

        // Upsert again with a higher attempt count and a later visibility.
        store
            .upsert_attempt(&SettleAttemptRecord {
                receipt_id: receipt.id.clone(),
                finalized_at: receipt.timestamp,
                attempts: 2,
                next_visible_at: 500,
                last_reason: Some("retryable".to_string()),
            })
            .unwrap();
        assert_eq!(
            store.load_attempt(&receipt.id).unwrap().unwrap().attempts,
            2
        );

        // due_attempts respects next_visible_at.
        assert!(store.due_attempts(499, 10).unwrap().is_empty());
        assert_eq!(store.due_attempts(500, 10).unwrap().len(), 1);

        store.clear_attempt(&receipt.id).unwrap();
        assert!(store.load_attempt(&receipt.id).unwrap().is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dead_letter_insert_is_idempotent() {
        let path = unique_db_path("settle-dead-letter");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let record = chio_settle::DeadLetterRecord::new("r-dl", 100, 3, "permanent");
        assert!(
            store.insert_dead_letter(&record).unwrap(),
            "first insert is new"
        );
        assert!(
            !store.insert_dead_letter(&record).unwrap(),
            "byte-identical replay returns false, not a conflict"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_is_exactly_replayable_and_rejects_stale_or_divergent_rows() {
        let path = unique_db_path("settle-upsert-fence");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let receipt = append_attempt_receipt(&receipts, "r-upsert", 100);
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let first = attempt_record(&receipt.id, receipt.timestamp, 1, 10);

        store.upsert_attempt(&first).unwrap();
        store.upsert_attempt(&first).unwrap();

        let mut divergent = first.clone();
        divergent.next_visible_at = 11;
        assert!(matches!(
            store.upsert_attempt(&divergent),
            Err(SettlementRetryError::Conflict(_))
        ));

        let third = attempt_record(&receipt.id, receipt.timestamp, 3, 30);
        assert!(matches!(
            store.upsert_attempt(&third),
            Err(SettlementRetryError::Conflict(_))
        ));

        let second = attempt_record(&receipt.id, receipt.timestamp, 2, 20);
        store.upsert_attempt(&second).unwrap();
        assert!(matches!(
            store.upsert_attempt(&first),
            Err(SettlementRetryError::Conflict(_))
        ));
        assert_eq!(store.load_attempt(&receipt.id).unwrap(), Some(second));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn observer_insert_requires_exact_live_receipt_and_replays_without_mutation() {
        let path = unique_db_path("settle-observer-insert");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let receipt = append_attempt_receipt(&receipts, "r-observer-insert", 100);
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let record = attempt_record(&receipt.id, receipt.timestamp, 1, 10);

        assert!(store.insert_observer_attempt_if_absent(&record).unwrap());
        assert!(!store.insert_observer_attempt_if_absent(&record).unwrap());
        let mismatched = attempt_record(&receipt.id, receipt.timestamp + 1, 1, 10);
        assert!(matches!(
            store.insert_observer_attempt_if_absent(&mismatched),
            Err(SettlementRetryError::Conflict(_))
        ));
        assert_eq!(store.load_attempt(&receipt.id).unwrap(), Some(record));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn retry_open_installs_iou_live_owner_and_immutability_guards() {
        let path = unique_db_path("settle-installs-iou-guards");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let _store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let raw = rusqlite::Connection::open(&path).unwrap();
        let installed_guards: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' \
                 AND tbl_name = 'iou_envelope' \
                 AND name IN ('iou_envelope_require_live_receipt_insert', \
                              'iou_envelope_reject_update', \
                              'iou_envelope_reject_delete')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(installed_guards, 3);
        assert!(raw
            .execute(
                "INSERT INTO iou_envelope \
                 (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units, currency, issuer_key, canonical_json) \
                 VALUES ('orphan', 'iou-orphan', 1, NULL, 1, 'USD', 'issuer', '{}')",
                [],
            )
            .is_err());
        drop(raw);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn independent_handles_preserve_global_head_of_line_and_fencing() {
        let path = unique_db_path("settle-two-handles");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let later = append_attempt_receipt(&receipts, "r-later", 200);
        let earlier = append_attempt_receipt(&receipts, "r-earlier", 100);
        let first_store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let second_store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();

        first_store
            .upsert_attempt(&attempt_record(&later.id, later.timestamp, 1, 1))
            .unwrap();
        first_store
            .upsert_attempt(&attempt_record(&earlier.id, earlier.timestamp, 1, 10))
            .unwrap();

        let first_lease = first_store
            .claim_due_attempts(10, 20, "worker-a", 64)
            .unwrap()
            .pop()
            .expect("earliest eligible row claimed");
        assert_eq!(first_lease.record.receipt_id, earlier.id);
        assert!(second_store
            .claim_due_attempts(10, 21, "worker-b", 64)
            .unwrap()
            .is_empty());

        let reclaimed = second_store
            .claim_due_attempts(20, 30, "worker-b", 64)
            .unwrap()
            .pop()
            .expect("expired earliest lease reclaimed");
        assert_eq!(reclaimed.record.receipt_id, earlier.id);
        assert!(reclaimed.version > first_lease.version);
        assert!(!first_store.complete_claimed_attempt(&first_lease).unwrap());
        assert!(second_store.complete_claimed_attempt(&reclaimed).unwrap());

        let next = first_store
            .claim_due_attempts(20, 31, "worker-a", 64)
            .unwrap()
            .pop()
            .expect("next eligible row unblocked");
        assert_eq!(next.record.receipt_id, later.id);
        assert!(first_store.complete_claimed_attempt(&next).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reschedule_advances_attempt_and_invalidates_the_old_lease() {
        let path = unique_db_path("settle-reschedule");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let receipt = append_attempt_receipt(&receipts, "r-reschedule", 100);
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        store
            .upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp, 1, 10))
            .unwrap();
        let lease = store
            .claim_due_attempts(10, 20, "worker-a", 1)
            .unwrap()
            .pop()
            .expect("attempt claimed");
        let next = attempt_record(&receipt.id, receipt.timestamp, 2, 30);
        assert!(store.reschedule_claimed_attempt(&lease, &next).unwrap());
        assert!(!store.complete_claimed_attempt(&lease).unwrap());
        assert!(store
            .claim_due_attempts(29, 40, "worker-b", 1)
            .unwrap()
            .is_empty());
        let next_lease = store
            .claim_due_attempts(30, 40, "worker-b", 1)
            .unwrap()
            .pop()
            .expect("rescheduled attempt became visible");
        assert_eq!(next_lease.record, next);
        assert!(store.complete_claimed_attempt(&next_lease).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn claimed_dead_letter_requires_exact_next_count_and_commits_atomically() {
        let path = unique_db_path("settle-claimed-dead-letter");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let dead_receipt = append_attempt_receipt(&receipts, "r-dead", 100);
        let divergent_receipt = append_attempt_receipt(&receipts, "r-divergent", 200);
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        store
            .upsert_attempt(&attempt_record(
                &dead_receipt.id,
                dead_receipt.timestamp,
                1,
                10,
            ))
            .unwrap();
        let lease = store
            .claim_due_attempts(10, 20, "worker-a", 1)
            .unwrap()
            .pop()
            .expect("attempt claimed");

        let mut forged_lease = lease.clone();
        forged_lease.record.attempts = 31;
        let forged = dead_letter_record(
            &dead_receipt.id,
            dead_receipt.timestamp,
            32,
            "forged history",
        );
        assert!(!store
            .dead_letter_claimed_attempt(&forged_lease, &forged)
            .unwrap());
        assert!(store.load_attempt(&dead_receipt.id).unwrap().is_some());
        assert!(store.dead_letters.get(&dead_receipt.id).unwrap().is_none());

        for attempts in [0, 1, 4] {
            let invalid = dead_letter_record(
                &dead_receipt.id,
                dead_receipt.timestamp,
                attempts,
                "invalid count",
            );
            assert!(matches!(
                store.dead_letter_claimed_attempt(&lease, &invalid),
                Err(SettlementRetryError::Conflict(_))
            ));
        }
        let mut invalid_schema = dead_letter_record(
            &dead_receipt.id,
            dead_receipt.timestamp,
            2,
            "invalid schema",
        );
        invalid_schema.schema = "chio.settle.dead-letter.v0".to_string();
        assert!(matches!(
            store.dead_letter_claimed_attempt(&lease, &invalid_schema),
            Err(SettlementRetryError::Conflict(_))
        ));
        assert!(store.load_attempt(&dead_receipt.id).unwrap().is_some());
        assert!(store.dead_letters.get(&dead_receipt.id).unwrap().is_none());

        let valid = dead_letter_record(&dead_receipt.id, dead_receipt.timestamp, 2, "terminal");
        assert!(store.dead_letter_claimed_attempt(&lease, &valid).unwrap());
        assert!(store.load_attempt(&dead_receipt.id).unwrap().is_none());
        assert_eq!(
            store.dead_letters.get(&dead_receipt.id).unwrap(),
            Some(valid)
        );

        store
            .upsert_attempt(&attempt_record(
                &divergent_receipt.id,
                divergent_receipt.timestamp,
                1,
                10,
            ))
            .unwrap();
        let existing = dead_letter_record(
            &divergent_receipt.id,
            divergent_receipt.timestamp,
            2,
            "existing",
        );
        store.insert_dead_letter(&existing).unwrap();
        let divergent_lease = store
            .claim_due_attempts(10, 20, "worker-a", 1)
            .unwrap()
            .pop()
            .expect("divergent attempt claimed");
        let divergent = dead_letter_record(
            &divergent_receipt.id,
            divergent_receipt.timestamp,
            2,
            "different",
        );
        assert!(matches!(
            store.dead_letter_claimed_attempt(&divergent_lease, &divergent),
            Err(SettlementRetryError::Conflict(_))
        ));
        assert!(store.load_attempt(&divergent_receipt.id).unwrap().is_some());
        assert!(store.complete_claimed_attempt(&divergent_lease).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn retry_inputs_and_sqlite_integer_boundaries_fail_closed() {
        let path = unique_db_path("settle-input-bounds");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let maximum_receipt = append_attempt_receipt(&receipts, "r-maximum-attempts", 100);
        let token_receipt = append_attempt_receipt(&receipts, "r-token", 100);
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();

        for receipt_id in [" ".to_string(), "x".repeat(513), "é".repeat(257)] {
            let mut record = attempt_record("valid", 100, 1, 10);
            record.receipt_id = receipt_id;
            assert!(matches!(
                store.upsert_attempt(&record),
                Err(SettlementRetryError::Conflict(_))
            ));
        }
        let mut blank_reason = attempt_record("r-blank", 100, 1, 10);
        blank_reason.last_reason = Some(" \t".to_string());
        assert!(matches!(
            store.upsert_attempt(&blank_reason),
            Err(SettlementRetryError::Conflict(_))
        ));
        let mut long_reason = attempt_record("r-long", 100, 1, 10);
        long_reason.last_reason = Some("x".repeat(2_049));
        assert!(matches!(
            store.upsert_attempt(&long_reason),
            Err(SettlementRetryError::Conflict(_))
        ));
        let maximum = attempt_record(
            &maximum_receipt.id,
            maximum_receipt.timestamp,
            MAX_SETTLEMENT_RETRY_ATTEMPTS,
            10,
        );
        store.upsert_attempt(&maximum).unwrap();
        assert_eq!(
            store.load_attempt(&maximum.receipt_id).unwrap(),
            Some(maximum)
        );
        let excessive = attempt_record(
            "r-excessive-attempts",
            100,
            chio_settle::DEAD_LETTER_MAX_ATTEMPTS,
            10,
        );
        assert!(matches!(
            store.upsert_attempt(&excessive),
            Err(SettlementRetryError::Conflict(_))
        ));

        store
            .upsert_attempt(&attempt_record(
                &token_receipt.id,
                token_receipt.timestamp,
                1,
                10,
            ))
            .unwrap();
        for token in [" ".to_string(), "x".repeat(513)] {
            assert!(matches!(
                store.claim_due_attempts(10, 20, &token, 1),
                Err(SettlementRetryError::Conflict(_))
            ));
        }
        assert!(matches!(
            store.due_attempts(u64::MAX, 1),
            Err(SettlementRetryError::Backend(_))
        ));
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            store.due_attempts(10, usize::MAX),
            Err(SettlementRetryError::Backend(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn opening_rejects_a_same_name_tampered_trigger() {
        let path = unique_db_path("settle-schema-tamper");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let _store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let checkout = receipt_connection_checkout(&receipts);
        let connection = checkout().unwrap();
        connection
            .connection()
            .execute_batch(
                "DROP TRIGGER settle_attempts_validate_insert; \
                 CREATE TRIGGER settle_attempts_validate_insert \
                 BEFORE INSERT ON settle_attempts BEGIN SELECT 1; END;",
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteSettlementRetryStore::open_alongside(&receipts),
            Err(SettlementRetryError::Conflict(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn opening_rejects_a_corrupted_persisted_retry_value() {
        let path = unique_db_path("settle-value-tamper");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let corrupt_receipt = append_attempt_receipt(&receipts, "r-corrupt", 100);
        let _store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let checkout = receipt_connection_checkout(&receipts);
        let connection = checkout().unwrap();
        connection
            .connection()
            .execute_batch(
                "DROP TRIGGER settle_attempts_validate_insert; \
                 PRAGMA ignore_check_constraints = ON;",
            )
            .unwrap();
        connection
            .connection()
            .execute(
                "INSERT INTO settle_attempts \
                     (receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at) \
                 VALUES (?1, ?2, -1, 10, 'retry', 10)",
                rusqlite::params![
                    corrupt_receipt.id.as_str(),
                    sqlite_i64(corrupt_receipt.timestamp, "finalized_at").unwrap()
                ],
            )
            .unwrap();
        connection
            .connection()
            .execute_batch("PRAGMA ignore_check_constraints = OFF;")
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteSettlementRetryStore::open_alongside(&receipts),
            Err(SettlementRetryError::Conflict(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn opening_rejects_a_retry_count_that_cannot_dead_letter() {
        let path = unique_db_path("settle-attempt-count-tamper");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let excessive_receipt = append_attempt_receipt(&receipts, "r-excessive", 100);
        let _store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let checkout = receipt_connection_checkout(&receipts);
        let connection = checkout().unwrap();
        connection
            .connection()
            .execute_batch(
                "DROP TRIGGER settle_attempts_validate_insert; \
                 PRAGMA ignore_check_constraints = ON;",
            )
            .unwrap();
        connection
            .connection()
            .execute(
                "INSERT INTO settle_attempts \
                     (receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at) \
                 VALUES (?1, ?2, 33, 10, 'retry', 10)",
                rusqlite::params![
                    excessive_receipt.id.as_str(),
                    sqlite_i64(excessive_receipt.timestamp, "finalized_at").unwrap()
                ],
            )
            .unwrap();
        connection
            .connection()
            .execute_batch("PRAGMA ignore_check_constraints = OFF;")
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteSettlementRetryStore::open_alongside(&receipts),
            Err(SettlementRetryError::Conflict(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn exact_legacy_table_is_rebuilt_with_the_fenced_schema() {
        let path = unique_db_path("settle-legacy-rebuild");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let legacy_receipt = append_attempt_receipt(&receipts, "r-legacy", 100);
        let checkout = receipt_connection_checkout(&receipts);
        let connection = checkout().unwrap();
        connection
            .connection()
            .execute_batch(
                "CREATE TABLE settle_attempts ( \
                     receipt_id TEXT PRIMARY KEY, finalized_at INTEGER NOT NULL, \
                     attempts INTEGER NOT NULL, next_visible_at INTEGER NOT NULL, \
                     last_reason TEXT, updated_at INTEGER NOT NULL \
                 );",
            )
            .unwrap();
        connection
            .connection()
            .execute(
                "INSERT INTO settle_attempts VALUES (?1, ?2, 1, 10, 'retry 1', 10)",
                rusqlite::params![
                    legacy_receipt.id.as_str(),
                    sqlite_i64(legacy_receipt.timestamp, "finalized_at").unwrap()
                ],
            )
            .unwrap();
        drop(connection);

        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        assert_eq!(
            store.load_attempt(&legacy_receipt.id).unwrap(),
            Some(attempt_record(
                &legacy_receipt.id,
                legacy_receipt.timestamp,
                1,
                10,
            ))
        );
        let lease = store
            .claim_due_attempts(10, 20, "worker", 1)
            .unwrap()
            .pop()
            .expect("legacy row is claimable after rebuild");
        assert!(store.complete_claimed_attempt(&lease).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn invalid_legacy_retry_count_rejects_without_partial_rebuild() {
        let path = unique_db_path("settle-invalid-legacy-rebuild");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let invalid_receipt = append_attempt_receipt(&receipts, "r-invalid-legacy", 100);
        let checkout = receipt_connection_checkout(&receipts);
        let connection = checkout().unwrap();
        connection
            .connection()
            .execute_batch(
                "CREATE TABLE settle_attempts ( \
                     receipt_id TEXT PRIMARY KEY, finalized_at INTEGER NOT NULL, \
                     attempts INTEGER NOT NULL, next_visible_at INTEGER NOT NULL, \
                     last_reason TEXT, updated_at INTEGER NOT NULL \
                 );",
            )
            .unwrap();
        connection
            .connection()
            .execute(
                "INSERT INTO settle_attempts VALUES (?1, ?2, 33, 10, 'retry', 10)",
                rusqlite::params![
                    invalid_receipt.id.as_str(),
                    sqlite_i64(invalid_receipt.timestamp, "finalized_at").unwrap()
                ],
            )
            .unwrap();
        let table_sql_before: String = connection
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);

        assert!(SqliteSettlementRetryStore::open_alongside(&receipts).is_err());
        let connection = checkout().unwrap();
        let table_sql_after: String = connection
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_sql_after, table_sql_before);
        let row: (String, i64) = connection
            .connection()
            .query_row(
                "SELECT receipt_id, attempts FROM settle_attempts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, (invalid_receipt.id, 33));
        let staging_exists: i64 = connection
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts_legacy')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(staging_exists, 0);
        drop(connection);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn orphaned_legacy_retry_rejects_without_partial_rebuild() {
        let path = unique_db_path("settle-orphaned-legacy-rebuild");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let checkout = receipt_connection_checkout(&receipts);
        let connection = checkout().unwrap();
        connection
            .connection()
            .execute_batch(
                "CREATE TABLE settle_attempts ( \
                     receipt_id TEXT PRIMARY KEY, finalized_at INTEGER NOT NULL, \
                     attempts INTEGER NOT NULL, next_visible_at INTEGER NOT NULL, \
                     last_reason TEXT, updated_at INTEGER NOT NULL \
                 ); \
                 INSERT INTO settle_attempts VALUES \
                     ('r-orphaned-legacy', 100, 1, 10, 'retry', 10);",
            )
            .unwrap();
        let table_sql_before: String = connection
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteSettlementRetryStore::open_alongside(&receipts),
            Err(SettlementRetryError::Conflict(_))
        ));
        let connection = checkout().unwrap();
        let table_sql_after: String = connection
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_sql_after, table_sql_before);
        let row: (String, i64) = connection
            .connection()
            .query_row(
                "SELECT receipt_id, finalized_at FROM settle_attempts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, ("r-orphaned-legacy".to_string(), 100));
        let staging_exists: i64 = connection
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts_legacy')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(staging_exists, 0);
        drop(connection);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn retry_writes_queued_or_blocked_after_rotation_cannot_strand_state() {
        let path = unique_db_path("settle-post-rotation-ownership");
        let archive = unique_db_path("settle-post-rotation-ownership-archive");
        let archive_path = archive.to_string_lossy().into_owned();
        let checkpoint_keypair = Keypair::from_seed(&[59; 32]);
        let receipts = std::sync::Arc::new(crate::SqliteReceiptStore::open(&path).unwrap());
        let receipt = append_attempt_receipt(receipts.as_ref(), "r-post-rotation", 100);
        assert!(
            receipts
                .create_next_receipt_checkpoint(1, &checkpoint_keypair)
                .unwrap()
                .created
        );
        let store = std::sync::Arc::new(
            SqliteSettlementRetryStore::open_alongside(receipts.as_ref()).unwrap(),
        );

        // Open a genuinely independent receipt writer before rotation. Its
        // cached head and connections predate archival, matching a second
        // process that stays alive across the rotation.
        let independent_receipts =
            std::sync::Arc::new(crate::SqliteReceiptStore::open_existing(&path).unwrap());
        let independent_store =
            SqliteSettlementRetryStore::open_alongside(independent_receipts.as_ref()).unwrap();

        // Park the local actor, enqueue rotation, then enqueue the retry. FIFO
        // order is observed through queue_depth before the blocker is released.
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker_handle = receipts.writer_handle();
        let blocker = std::thread::spawn(move || {
            blocker_handle.run_write(move |_connection| {
                started_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .unwrap();
                Ok(())
            })
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();

        let rotation_receipts = std::sync::Arc::clone(&receipts);
        let rotation_archive_path = archive_path.clone();
        let cutoff = receipt.timestamp + 1;
        let rotation = std::thread::spawn(move || {
            rotation_receipts.archive_receipts_before(cutoff, &rotation_archive_path)
        });
        wait_for_writer_queue_depth(receipts.as_ref(), 1);

        let queued_store = std::sync::Arc::clone(&store);
        let queued_record = attempt_record(&receipt.id, receipt.timestamp, 1, 10);
        let queued = std::thread::spawn(move || queued_store.upsert_attempt(&queued_record));
        wait_for_writer_queue_depth(receipts.as_ref(), 2);

        release_tx.send(()).unwrap();
        blocker.join().unwrap().unwrap();
        assert_eq!(rotation.join().unwrap().unwrap(), 1);
        assert!(matches!(
            queued.join().unwrap(),
            Err(SettlementRetryError::Conflict(_))
        ));
        assert!(store.load_attempt(&receipt.id).unwrap().is_none());

        let live_count: i64 = receipts
            .reader_connection_for_test()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
                rusqlite::params![receipt.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(live_count, 0, "rotation must remove the live owner row");
        assert!(
            receipts.load_chio_receipt(&receipt.id).unwrap().is_some(),
            "the receipt remains readable only through the trusted archive"
        );

        // Hold a database-level writer lock after rotation, start the
        // independent writer, and wait until its actor has dequeued the job.
        // When the lock is released, it must re-read live storage and deny;
        // archive-only lookup is deliberately insufficient ownership.
        let database_blocker = rusqlite::Connection::open(&path).unwrap();
        database_blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let observer_record = attempt_record(&receipt.id, receipt.timestamp, 1, 10);
        let independent = std::thread::spawn(move || {
            independent_store.insert_observer_attempt_if_absent(&observer_record)
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let health = independent_receipts.receipt_store_health().unwrap();
            if health.writer.inflight == 1 && health.writer.queue_depth == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "independent retry writer did not block on the database lock"
            );
            std::thread::yield_now();
        }
        database_blocker.execute_batch("ROLLBACK").unwrap();
        assert!(matches!(
            independent.join().unwrap(),
            Err(SettlementRetryError::Conflict(_))
        ));
        assert!(store.load_attempt(&receipt.id).unwrap().is_none());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&archive);
    }

    #[test]
    fn stale_claim_cannot_commit_after_reclaimed_claim_dead_letters() {
        let path = unique_db_path("settle-stale-success");
        let kernel = Keypair::from_seed(&[61; 32]);
        let issuer = Keypair::from_seed(&[62; 32]);
        let receipt = priced_receipt(&kernel, "r-stale-success", 100);
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        receipts.append_chio_receipt(&receipt).unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        store
            .upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp, 1, 10))
            .unwrap();
        let stale = store
            .claim_due_attempts(10, 20, "worker-a", 1)
            .unwrap()
            .pop()
            .unwrap();
        let current = store
            .claim_due_attempts(20, 30, "worker-b", 1)
            .unwrap()
            .pop()
            .unwrap();
        let dead_letter = dead_letter_record(&receipt.id, receipt.timestamp, 2, "terminal");
        assert!(store
            .dead_letter_claimed_attempt(&current, &dead_letter)
            .unwrap());

        let expected = envelope(&issuer, &kernel, &receipt);
        assert!(!store
            .commit_claimed_settlement_exact(
                &stale,
                &expected,
                &[issuer.public_key()],
                &[kernel.public_key()],
                Some("transcript=stale"),
            )
            .unwrap());
        let reader = receipts.reader_connection_for_test().unwrap();
        let iou_count: i64 = reader
            .query_row(
                "SELECT COUNT(*) FROM iou_envelope WHERE receipt_id = ?1",
                rusqlite::params![receipt.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let reconciliation_count: i64 = reader
            .query_row(
                "SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1",
                rusqlite::params![receipt.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((iou_count, reconciliation_count), (0, 0));
        assert_eq!(
            store.dead_letters.get(&receipt.id).unwrap(),
            Some(dead_letter)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn divergent_receipt_economics_cannot_commit_any_terminal_evidence() {
        let path = unique_db_path("settle-divergent-economics");
        let kernel = Keypair::from_seed(&[71; 32]);
        let issuer = Keypair::from_seed(&[72; 32]);
        let receipt = priced_receipt(&kernel, "r-divergent-economics", 100);
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        receipts.append_chio_receipt(&receipt).unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        store
            .upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp, 1, 0))
            .unwrap();
        let lease = store
            .claim_due_attempts(0, 20, "worker", 1)
            .unwrap()
            .pop()
            .unwrap();

        let mut divergent = envelope(&issuer, &kernel, &receipt);
        divergent.body.amount_units += 1;
        let issuer_backend = Ed25519Backend::new(issuer.clone());
        divergent.signature =
            chio_core::crypto::sign_canonical_with_backend(&issuer_backend, &divergent.body)
                .unwrap()
                .0;
        assert!(matches!(
            store.commit_claimed_settlement_exact(
                &lease,
                &divergent,
                &[issuer.public_key()],
                &[kernel.public_key()],
                Some("transcript=divergent"),
            ),
            Err(SettlementRetryError::Conflict(_))
        ));

        let reader = receipts.reader_connection_for_test().unwrap();
        let counts: (i64, i64, i64) = reader
            .query_row(
                "SELECT \
                   (SELECT COUNT(*) FROM iou_envelope WHERE receipt_id = ?1), \
                   (SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1), \
                   (SELECT COUNT(*) FROM settle_attempts WHERE receipt_id = ?1 AND state = 'claimed')",
                rusqlite::params![receipt.id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (0, 0, 1));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn algorithm_mismatched_iou_cannot_commit_any_terminal_evidence() {
        let path = unique_db_path("settle-algorithm-mismatch");
        let kernel = Keypair::from_seed(&[73; 32]);
        let issuer = Keypair::from_seed(&[74; 32]);
        let receipt = priced_receipt(&kernel, "r-algorithm-mismatch", 100);
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        receipts.append_chio_receipt(&receipt).unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        store
            .upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp, 1, 0))
            .unwrap();
        let lease = store
            .claim_due_attempts(0, 20, "worker", 1)
            .unwrap()
            .pop()
            .unwrap();

        let mut mismatched = envelope(&issuer, &kernel, &receipt);
        mismatched.algorithm = Some(SigningAlgorithm::Hybrid);
        assert!(matches!(
            store.commit_claimed_settlement_exact(
                &lease,
                &mismatched,
                &[issuer.public_key()],
                &[kernel.public_key()],
                Some("transcript=algorithm-mismatch"),
            ),
            Err(SettlementRetryError::Conflict(_))
        ));

        let reader = receipts.reader_connection_for_test().unwrap();
        let counts: (i64, i64, i64) = reader
            .query_row(
                "SELECT \
                   (SELECT COUNT(*) FROM iou_envelope WHERE receipt_id = ?1), \
                   (SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1), \
                   (SELECT COUNT(*) FROM settle_attempts WHERE receipt_id = ?1 AND state = 'claimed')",
                rusqlite::params![receipt.id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (0, 0, 1));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persisted_iou_with_unknown_field_cannot_complete_settlement() {
        let path = unique_db_path("settle-unknown-iou-field");
        let kernel = Keypair::from_seed(&[75; 32]);
        let issuer = Keypair::from_seed(&[76; 32]);
        let receipt = priced_receipt(&kernel, "r-unknown-iou-field", 100);
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        receipts.append_chio_receipt(&receipt).unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let ious = crate::SqliteIouEnvelopeStore::open_alongside(&receipts).unwrap();
        let expected = envelope(&issuer, &kernel, &receipt);
        assert!(ious.insert(&expected).unwrap());
        store
            .upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp, 1, 0))
            .unwrap();
        let lease = store
            .claim_due_attempts(0, 20, "worker", 1)
            .unwrap()
            .pop()
            .unwrap();

        let mut persisted = serde_json::to_value(&expected).unwrap();
        persisted
            .as_object_mut()
            .unwrap()
            .insert("unsigned_extension".to_string(), serde_json::json!(true));
        let persisted =
            String::from_utf8(chio_core::canonical::canonical_json_bytes(&persisted).unwrap())
                .unwrap();
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch("DROP TRIGGER iou_envelope_reject_update;")
            .unwrap();
        raw.execute(
            "UPDATE iou_envelope SET canonical_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![persisted, receipt.id.as_str()],
        )
        .unwrap();
        drop(raw);

        assert!(matches!(
            store.commit_claimed_settlement_exact(
                &lease,
                &expected,
                &[issuer.public_key()],
                &[kernel.public_key()],
                Some("transcript=unknown-iou-field"),
            ),
            Err(SettlementRetryError::Conflict(_))
        ));
        let reader = receipts.reader_connection_for_test().unwrap();
        let counts: (i64, i64, i64) = reader
            .query_row(
                "SELECT \
                   (SELECT COUNT(*) FROM iou_envelope WHERE receipt_id = ?1), \
                   (SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1), \
                   (SELECT COUNT(*) FROM settle_attempts WHERE receipt_id = ?1 AND state = 'claimed')",
                rusqlite::params![receipt.id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (1, 0, 1));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn settlement_evidence_rolls_back_when_exact_reconciliation_conflicts() {
        let path = unique_db_path("settle-atomic-rollback");
        let kernel = Keypair::from_seed(&[63; 32]);
        let issuer = Keypair::from_seed(&[64; 32]);
        let receipt = priced_receipt(&kernel, "r-rollback", 100);
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        receipts.append_chio_receipt(&receipt).unwrap();
        receipts
            .upsert_settlement_reconciliation(
                &receipt.id,
                chio_kernel::operator_report::SettlementReconciliationState::Ignored,
                Some("operator decision"),
            )
            .unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        store
            .upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp, 1, 0))
            .unwrap();
        let lease = store
            .claim_due_attempts(0, 20, "worker", 1)
            .unwrap()
            .pop()
            .unwrap();
        let expected = envelope(&issuer, &kernel, &receipt);
        assert!(matches!(
            store.commit_claimed_settlement_exact(
                &lease,
                &expected,
                &[issuer.public_key()],
                &[kernel.public_key()],
                Some("transcript=conflict"),
            ),
            Err(SettlementRetryError::Conflict(_))
        ));
        let reader = receipts.reader_connection_for_test().unwrap();
        let iou_count: i64 = reader
            .query_row(
                "SELECT COUNT(*) FROM iou_envelope WHERE receipt_id = ?1",
                rusqlite::params![receipt.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(iou_count, 0);
        assert!(store.load_attempt(&receipt.id).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn issuer_rotation_accepts_verified_existing_bytes_without_rewrite() {
        let path = unique_db_path("settle-issuer-rotation");
        let kernel = Keypair::from_seed(&[65; 32]);
        let old_issuer = Keypair::from_seed(&[66; 32]);
        let current_issuer = Keypair::from_seed(&[67; 32]);
        let receipt = priced_receipt(&kernel, "r-issuer-rotation", 100);
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        receipts.append_chio_receipt(&receipt).unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let ious = crate::SqliteIouEnvelopeStore::open_alongside(&receipts).unwrap();
        let old_envelope = envelope(&old_issuer, &kernel, &receipt);
        assert!(ious.insert(&old_envelope).unwrap());
        let canonical_before = chio_core::canonical::canonical_json_bytes(&old_envelope).unwrap();
        store
            .upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp, 1, 0))
            .unwrap();
        let lease = store
            .claim_due_attempts(0, 20, "worker", 1)
            .unwrap()
            .pop()
            .unwrap();
        let expected = envelope(&current_issuer, &kernel, &receipt);
        assert!(store
            .commit_claimed_settlement_exact(
                &lease,
                &expected,
                &[old_issuer.public_key(), current_issuer.public_key()],
                &[kernel.public_key()],
                Some("transcript=rotation"),
            )
            .unwrap());
        let persisted = ious.get_by_receipt_id(&receipt.id).unwrap().unwrap();
        assert_eq!(
            chio_core::canonical::canonical_json_bytes(&persisted).unwrap(),
            canonical_before
        );
        assert!(store.load_attempt(&receipt.id).unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn query_only_reader_pool_does_not_block_retry_writes() {
        let path = unique_db_path("settle-query-only-readers");
        let kernel = Keypair::from_seed(&[68; 32]);
        let issuer = Keypair::from_seed(&[69; 32]);
        let receipt = priced_receipt(&kernel, "r-query-only", 100);
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        receipts.append_chio_receipt(&receipt).unwrap();
        {
            let mut held = Vec::new();
            for _ in 0..crate::DEFAULT_READER_POOL_MAX_SIZE {
                held.push(receipts.reader_connection_for_test().unwrap());
            }
            for connection in &held {
                connection.execute_batch("PRAGMA query_only = ON;").unwrap();
            }
        }

        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        store
            .upsert_attempt(&attempt_record(&receipt.id, receipt.timestamp, 1, 0))
            .unwrap();
        let lease = store
            .claim_due_attempts(0, 20, "worker", 1)
            .unwrap()
            .pop()
            .unwrap();
        let expected = envelope(&issuer, &kernel, &receipt);
        assert!(store
            .commit_claimed_settlement_exact(
                &lease,
                &expected,
                &[issuer.public_key()],
                &[kernel.public_key()],
                Some("transcript=query-only"),
            )
            .unwrap());
        assert!(store.load_attempt(&receipt.id).unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }
}
