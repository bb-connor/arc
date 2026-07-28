    use super::*;
    use chio_core::credit::IouEnvelopeStore;
    use chio_core::receipt::economics::{
        EconomicAmountBoundsReceiptMetadata, EconomicAuthorizationMode,
        EconomicAuthorizationReceiptMetadata, EconomicAuthorizationReceiptMetadataVersion,
        EconomicBudgetReceiptMetadata, EconomicMerchantReceiptMetadata,
        EconomicPayeeReceiptMetadata, EconomicPayerReceiptMetadata, EconomicRailReceiptMetadata,
        EconomicSettlementReceiptMetadata, FinancialReceiptMetadata, SettlementStatus,
    };
    use chio_core::receipt::governance::{
        GovernedApprovalReceiptMetadata, GovernedTransactionReceiptMetadata,
    };
    use chio_kernel::settlement_retry::{SettleAttemptRecord, SettlementRetryStore};
    use chio_kernel::ReceiptStore;
    use chio_test_support::private_fs::private_tempdir;
    use rusqlite::params;
    use std::sync::Arc;

    fn signed_money_receipt(
        keypair: &chio_core::Keypair,
        marker: &str,
        timestamp: u64,
    ) -> chio_core::receipt::body::ChioReceipt {
        let action = chio_core::receipt::decision::ToolCallAction::from_parameters(
            serde_json::json!({"marker": marker}),
        )
        .expect("hash parameters");
        signed_money_receipt_with_action(keypair, marker, timestamp, action)
    }

    fn signed_money_receipt_with_action(
        keypair: &chio_core::Keypair,
        marker: &str,
        timestamp: u64,
        action: chio_core::receipt::decision::ToolCallAction,
    ) -> chio_core::receipt::body::ChioReceipt {
        let intent_digest = chio_core::hashing::sha256_hex(format!("intent:{marker}").as_bytes());
        let authority_digest =
            chio_core::hashing::sha256_hex(format!("authority:{marker}").as_bytes());
        let credit_authority_digest =
            chio_core::hashing::sha256_hex(b"settlement-drive-credit-authority");
        let payee_digest = chio_core::hashing::sha256_hex(b"settlement-drive-payee");
        let financial = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 250,
            currency: "USD".to_string(),
            budget_remaining: 750,
            budget_total: 1_000,
            delegation_depth: 0,
            root_budget_holder: "settlement-drive-debtor".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        let governed = GovernedTransactionReceiptMetadata {
            intent_id: format!("intent-{marker}"),
            intent_hash: intent_digest.clone(),
            purpose: "settlement retry credit facility".to_string(),
            server_id: "srv".to_string(),
            tool_name: "tool".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: format!("approval-{marker}"),
                approver_key: "settlement-drive-approver".to_string(),
                approval_artifact_digest: Some(authority_digest.clone()),
                approved: true,
            }),
            runtime_assurance: None,
            call_chain: None,
            autonomy: None,
            economic_authorization: Some(EconomicAuthorizationReceiptMetadata {
                version: EconomicAuthorizationReceiptMetadataVersion::V1,
                economic_intent_digest: Some(intent_digest),
                payee_binding_digest: Some(payee_digest),
                pre_action_authority_digest: Some(authority_digest),
                credit_authority_digest: Some(credit_authority_digest),
                economic_mode: EconomicAuthorizationMode::BudgetOnly,
                payer: EconomicPayerReceiptMetadata {
                    party_id: "settlement-drive-debtor".to_string(),
                    funding_source_ref: "facility:settlement-drive".to_string(),
                    custody_provider: None,
                    obligor_ref: None,
                },
                merchant: EconomicMerchantReceiptMetadata {
                    merchant_id: "settlement-drive-merchant".to_string(),
                    merchant_of_record: None,
                    order_ref: None,
                },
                payee: EconomicPayeeReceiptMetadata {
                    beneficiary_id: "settlement-drive-payee".to_string(),
                    settlement_destination_ref: "account:settlement-drive-payee".to_string(),
                },
                rail: EconomicRailReceiptMetadata {
                    kind: "credit_facility".to_string(),
                    asset: "USD".to_string(),
                    network: None,
                    facilitator: None,
                    contract_or_account_ref: Some("facility:settlement-drive".to_string()),
                },
                amount_bounds: EconomicAmountBoundsReceiptMetadata {
                    approved_max: chio_core::capability::scope::MonetaryAmount {
                        currency: "USD".to_string(),
                        units: 250,
                    },
                    hold_amount: None,
                    settlement_cap: chio_core::capability::scope::MonetaryAmount {
                        currency: "USD".to_string(),
                        units: 250,
                    },
                },
                pricing_basis: None,
                metering: None,
                liability_refs: None,
                budget: EconomicBudgetReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 250,
                    currency: "USD".to_string(),
                    budget_remaining: 750,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: "settlement-drive-debtor".to_string(),
                    attempted_cost: None,
                },
                settlement: EconomicSettlementReceiptMetadata {
                    settlement_status: SettlementStatus::Pending,
                },
            }),
        };
        chio_core::receipt::body::ChioReceipt::sign(
            chio_core::receipt::body::ChioReceiptBody {
                id: marker.to_string(),
                timestamp,
                capability_id: format!("cap-{marker}"),
                tool_server: "srv".to_string(),
                tool_name: "tool".to_string(),
                action,
                decision: Some(chio_core::receipt::decision::Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: format!("content-{marker}"),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "financial": financial,
                    "governed_transaction": governed,
                })),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            keypair,
        )
        .expect("sign receipt")
    }

    fn signed_captured_receipt(
        keypair: &chio_core::Keypair,
        marker: &str,
        timestamp: u64,
    ) -> chio_core::receipt::body::ChioReceipt {
        let receipt = signed_money_receipt(keypair, marker, timestamp);
        let mut body = receipt.body();
        let metadata = body.metadata.as_mut().expect("receipt metadata");
        metadata["financial"]["payment_reference"] = serde_json::json!("capture-1");
        metadata["financial"]["settlement_status"] = serde_json::json!("settled");
        metadata["governed_transaction"]["economic_authorization"]["economic_mode"] =
            serde_json::json!("hold_capture");
        metadata["governed_transaction"]["economic_authorization"]["settlement"]
            ["settlement_status"] = serde_json::json!("settled");
        metadata["governed_transaction"]["economic_authorization"]["rail"]["kind"] =
            serde_json::json!("card_capture");
        chio_core::receipt::body::ChioReceipt::sign(body, keypair)
            .expect("sign captured receipt")
    }

    fn seed_attempt(
        receipts: &chio_store_sqlite::SqliteReceiptStore,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) {
        let retry_store =
            chio_store_sqlite::SqliteSettlementRetryStore::open_alongside(receipts)
                .expect("open retry store");
        retry_store
            .upsert_attempt(&SettleAttemptRecord {
                receipt_id: receipt.id.clone(),
                finalized_at: receipt.timestamp,
                attempts: 1,
                next_visible_at: 0,
                last_reason: Some("rail temporarily unavailable".to_string()),
            })
            .expect("seed attempt");
    }

    fn reconciliation_row(path: &Path, receipt_id: &str) -> (String, Option<String>, i64) {
        Connection::open(path)
            .expect("open reconciliation reader")
            .query_row(
                "SELECT reconciliation_state, note, updated_at \
                 FROM settlement_reconciliations WHERE receipt_id = ?1",
                params![receipt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("load reconciliation")
    }

    fn table_row_count(path: &Path, table: &str, receipt_id: &str) -> i64 {
        let connection = Connection::open(path).expect("open diagnostic reader");
        if !table_exists(&connection, table).expect("inspect table") {
            return 0;
        }
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE receipt_id = ?1");
        connection
            .query_row(&sql, params![receipt_id], |row| row.get(0))
            .expect("count receipt rows")
    }

    fn assert_attempt_preserved_without_terminal_evidence(path: &Path, receipt_id: &str) {
        assert_eq!(table_row_count(path, "settle_attempts", receipt_id), 1);
        assert_eq!(table_row_count(path, "iou_envelope", receipt_id), 0);
        assert_eq!(
            table_row_count(path, "settlement_reconciliations", receipt_id),
            0
        );
        assert_eq!(table_row_count(path, "settle_dead_letters", receipt_id), 0);
    }

    fn insert_raw_receipt(
        path: &Path,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) {
        let raw_json = serde_json::to_string(receipt).expect("encode receipt");
        Connection::open(path)
            .expect("open raw receipt writer")
            .execute(
                "INSERT INTO chio_tool_receipts \
                 (receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index, \
                  tool_server, tool_name, decision_kind, policy_hash, content_hash, tenant_id, raw_json) \
                 VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?5, 'allow', ?6, ?7, ?8, ?9)",
                params![
                    receipt.id,
                    i64::try_from(receipt.timestamp).expect("timestamp fits sqlite"),
                    receipt.capability_id,
                    receipt.tool_server,
                    receipt.tool_name,
                    receipt.policy_hash,
                    receipt.content_hash,
                    receipt.tenant_id,
                    raw_json,
                ],
            )
            .expect("insert raw receipt");
    }

    fn tamper_live_receipt(
        path: &Path,
        receipt_id: &str,
        mutate: impl FnOnce(&mut chio_core::receipt::body::ChioReceipt),
    ) {
        let connection = Connection::open(path).expect("open tamper connection");
        let immutable_trigger_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master \
                 WHERE type = 'trigger' AND name = 'chio_tool_receipts_reject_update'",
                [],
                |row| row.get(0),
            )
            .expect("load immutable-row test guard");
        connection
            .execute_batch("DROP TRIGGER IF EXISTS chio_tool_receipts_reject_update;")
            .expect("disable immutable-row test guard");
        let raw_json: String = connection
            .query_row(
                "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get(0),
            )
            .expect("load receipt bytes");
        let mut receipt: chio_core::receipt::body::ChioReceipt =
            serde_json::from_str(&raw_json).expect("decode receipt");
        mutate(&mut receipt);
        let tampered = serde_json::to_string(&receipt).expect("encode tampered receipt");
        connection
            .execute(
                "UPDATE chio_tool_receipts SET raw_json = ?1 WHERE receipt_id = ?2",
                params![tampered, receipt_id],
            )
            .expect("tamper receipt bytes");
        connection
            .execute_batch(&immutable_trigger_sql)
            .expect("restore immutable-row test guard");
    }

    #[test]
    fn drive_mints_truthful_iou_with_historical_kernel_trust_and_exact_replay() {
        let dir = private_tempdir("chio-settle-drive-").expect("private tempdir");
        let path = dir.path().join("drive.sqlite3");
        let current_kernel = chio_core::Keypair::from_seed(&[11_u8; 32]);
        let historical_kernel = chio_core::Keypair::from_seed(&[12_u8; 32]);
        let iou_issuer = chio_core::Keypair::from_seed(&[13_u8; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open receipts");
        let current_receipt = signed_money_receipt(&current_kernel, "drive-current", 99);
        let receipt = signed_money_receipt(&historical_kernel, "drive-1", 100);
        receipts
            .append_chio_receipt(&current_receipt)
            .expect("append current-key receipt");
        receipts
            .append_chio_receipt(&receipt)
            .expect("append historical-key receipt");
        seed_attempt(&receipts, &current_receipt);
        seed_attempt(&receipts, &receipt);
        drop(receipts);

        let trust_roots = vec![current_kernel.public_key(), historical_kernel.public_key()];
        let report = run_settlement_drive(&path, 16, &iou_issuer, &trust_roots).expect("drive");
        assert_eq!(report.settled, 2, "both trusted-key attempts settle: {report:?}");

        let receipts =
            chio_store_sqlite::SqliteReceiptStore::open_existing(&path).expect("reopen receipts");
        let retry_store =
            chio_store_sqlite::SqliteSettlementRetryStore::open_alongside(&receipts)
                .expect("reopen retry store");
        assert!(
            retry_store
                .load_attempt(&receipt.id)
                .expect("load attempt")
                .is_none(),
            "the bounded envelope drains"
        );
        assert!(retry_store
            .load_attempt(&current_receipt.id)
            .expect("load current-key attempt")
            .is_none());

        let iou_store = chio_store_sqlite::SqliteIouEnvelopeStore::open_alongside(&receipts)
            .expect("open IOU store");
        let envelope = iou_store
            .get_by_receipt_id(&receipt.id)
            .expect("load IOU")
            .expect("accepted settlement persists IOU");
        assert_eq!(envelope.body.receipt_id, receipt.id);
        assert_eq!(envelope.body.amount_units, 250);
        assert_eq!(envelope.body.currency, "USD");
        assert_eq!(envelope.body.issuer_key, iou_issuer.public_key());
        assert_ne!(envelope.body.issuer_key, receipt.kernel_key);
        assert!(envelope.verify_signature().expect("verify IOU signature"));
        let current_envelope = iou_store
            .get_by_receipt_id(&current_receipt.id)
            .expect("load current-key IOU")
            .expect("current-key settlement persists IOU");
        assert_eq!(current_envelope.body.issuer_key, iou_issuer.public_key());
        assert!(current_envelope
            .verify_signature()
            .expect("verify current-key IOU signature"));

        let expected_note = format!("transcript=ops:{}", receipt.id);
        let (state, note, first_updated_at) = reconciliation_row(&path, &receipt.id);
        assert_eq!(state, "reconciled");
        assert_eq!(note.as_deref(), Some(expected_note.as_str()));
        assert!(!receipts
            .complete_settlement_reconciliation_exact(&receipt.id, Some(&expected_note))
            .expect("exact replay"));
        let (_, _, replay_updated_at) = reconciliation_row(&path, &receipt.id);
        assert_eq!(replay_updated_at, first_updated_at);
        assert!(matches!(
            receipts.complete_settlement_reconciliation_exact(
                &receipt.id,
                Some("transcript=divergent")
            ),
            Err(chio_kernel::ReceiptStoreError::Conflict(_))
        ));

        let status = SettleStatusReport::load(&path).expect("status");
        let settled = status
            .settled
            .iter()
            .find(|row| row.receipt_id == receipt.id)
            .expect("status reports reconciliation");
        assert_eq!(settled.reconciliation_state, "reconciled");
        assert!(status
            .settled
            .iter()
            .any(|row| row.receipt_id == current_receipt.id));

        drop(iou_store);
        drop(retry_store);
        drop(receipts);
        let again = run_settlement_drive(&path, 16, &iou_issuer, &trust_roots)
            .expect("second drive");
        assert_eq!(again, SettleDriveReport::default());
    }

    #[test]
    fn drive_dead_letters_captured_receipt_without_minting_a_second_obligation() {
        let dir = private_tempdir("chio-settle-drive-").expect("private tempdir");
        let path = dir.path().join("captured.sqlite3");
        let kernel = chio_core::Keypair::from_seed(&[14_u8; 32]);
        let iou_issuer = chio_core::Keypair::from_seed(&[15_u8; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open receipts");
        let receipt = signed_captured_receipt(&kernel, "captured", 100);
        receipts
            .append_chio_receipt(&receipt)
            .expect("append captured receipt");
        seed_attempt(&receipts, &receipt);
        drop(receipts);

        let report =
            run_settlement_drive(&path, 16, &iou_issuer, &[kernel.public_key()]).expect("drive");
        assert_eq!(report.dead_lettered, 1);
        assert_eq!(report.settled, 0);
        assert_eq!(table_row_count(&path, "iou_envelope", &receipt.id), 0);
        assert_eq!(table_row_count(&path, "settle_dead_letters", &receipt.id), 1);
        assert_eq!(table_row_count(&path, "settle_attempts", &receipt.id), 0);
    }

    #[test]
    fn exact_reconciliation_rejects_empty_or_unbounded_evidence() {
        let dir = private_tempdir("chio-settle-drive-").expect("private tempdir");
        let path = dir.path().join("reconciliation-validation.sqlite3");
        let kernel = chio_core::Keypair::from_seed(&[14_u8; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open receipts");
        let receipt = signed_money_receipt(&kernel, "reconciliation-validation", 100);
        receipts
            .append_chio_receipt(&receipt)
            .expect("append receipt");

        assert!(matches!(
            receipts.complete_settlement_reconciliation_exact("", Some("transcript=test")),
            Err(chio_kernel::ReceiptStoreError::Conflict(_))
        ));
        let oversized_receipt_id = "r".repeat(513);
        assert!(matches!(
            receipts.complete_settlement_reconciliation_exact(
                &oversized_receipt_id,
                Some("transcript=test")
            ),
            Err(chio_kernel::ReceiptStoreError::Conflict(_))
        ));
        assert!(matches!(
            receipts.complete_settlement_reconciliation_exact(&receipt.id, Some("")),
            Err(chio_kernel::ReceiptStoreError::Conflict(_))
        ));
        let oversized_note = "n".repeat(4_097);
        assert!(matches!(
            receipts.complete_settlement_reconciliation_exact(
                &receipt.id,
                Some(&oversized_note)
            ),
            Err(chio_kernel::ReceiptStoreError::Conflict(_))
        ));
        assert_eq!(
            table_row_count(&path, "settlement_reconciliations", &receipt.id),
            0
        );
    }

    #[test]
    fn untrusted_receipt_signer_dead_letters_without_minting_an_iou() {
        let dir = private_tempdir("chio-settle-drive-").expect("private tempdir");
        let path = dir.path().join("untrusted.sqlite3");
        let trusted_kernel = chio_core::Keypair::from_seed(&[21_u8; 32]);
        let untrusted_kernel = chio_core::Keypair::from_seed(&[22_u8; 32]);
        let iou_issuer = chio_core::Keypair::from_seed(&[23_u8; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open receipts");
        let receipt = signed_money_receipt(&untrusted_kernel, "untrusted", 100);
        receipts
            .append_chio_receipt(&receipt)
            .expect("append receipt");
        seed_attempt(&receipts, &receipt);
        drop(receipts);

        let report = run_settlement_drive(
            &path,
            16,
            &iou_issuer,
            &[trusted_kernel.public_key()],
        )
        .expect("drive terminal trust failure");
        assert_eq!(report.dead_lettered, 1);
        assert_eq!(report.settled, 0);
        assert_eq!(table_row_count(&path, "settle_attempts", &receipt.id), 0);
        assert_eq!(table_row_count(&path, "iou_envelope", &receipt.id), 0);
        assert_eq!(
            table_row_count(&path, "settlement_reconciliations", &receipt.id),
            0
        );
        assert_eq!(table_row_count(&path, "settle_dead_letters", &receipt.id), 1);
        let status = SettleStatusReport::load(&path).expect("status");
        let dead_letter = status
            .dead_lettered
            .iter()
            .find(|row| row.receipt_id == receipt.id)
            .expect("trust failure is operator-visible");
        assert!(dead_letter
            .reason
            .starts_with("settlement_failure:sha256:"));
        assert!(!dead_letter.reason.contains("kernel trust set"));

        let again = run_settlement_drive(
            &path,
            16,
            &iou_issuer,
            &[trusted_kernel.public_key()],
        )
        .expect("second drive");
        assert_eq!(again, SettleDriveReport::default());
    }

    #[test]
    fn tampered_signature_preserves_attempt_without_economic_or_terminal_evidence() {
        let dir = private_tempdir("chio-settle-drive-").expect("private tempdir");
        let path = dir.path().join("signature-tamper.sqlite3");
        let kernel = chio_core::Keypair::from_seed(&[31_u8; 32]);
        let iou_issuer = chio_core::Keypair::from_seed(&[32_u8; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open receipts");
        let receipt = signed_money_receipt(&kernel, "signature-tamper", 100);
        receipts
            .append_chio_receipt(&receipt)
            .expect("append receipt");
        seed_attempt(&receipts, &receipt);
        drop(receipts);
        tamper_live_receipt(&path, &receipt.id, |tampered| {
            tampered.signature = chio_core::Signature::from_bytes(&[0_u8; 64]);
        });

        let error = run_settlement_drive(&path, 16, &iou_issuer, &[kernel.public_key()])
            .expect_err("tampered signature must fail closed");
        assert!(matches!(error, SettleStatusError::Integrity(_)));
        assert_attempt_preserved_without_terminal_evidence(&path, &receipt.id);
    }

    #[test]
    fn invalid_action_hash_preserves_attempt_without_economic_or_terminal_evidence() {
        let dir = private_tempdir("chio-settle-drive-").expect("private tempdir");
        let path = dir.path().join("action-tamper.sqlite3");
        let kernel = chio_core::Keypair::from_seed(&[41_u8; 32]);
        let iou_issuer = chio_core::Keypair::from_seed(&[42_u8; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open receipts");
        let retry_store =
            chio_store_sqlite::SqliteSettlementRetryStore::open_alongside(&receipts)
                .expect("open retry store");
        drop(receipts);
        let invalid_action = chio_core::receipt::decision::ToolCallAction {
            parameters: serde_json::json!({"marker": "invalid-action"}),
            parameter_hash: "invalid-parameter-hash".to_string(),
        };
        let receipt = signed_money_receipt_with_action(
            &kernel,
            "invalid-action",
            100,
            invalid_action,
        );
        insert_raw_receipt(&path, &receipt);
        retry_store
            .upsert_attempt(&SettleAttemptRecord {
                receipt_id: receipt.id.clone(),
                finalized_at: receipt.timestamp,
                attempts: 1,
                next_visible_at: 0,
                last_reason: Some("rail temporarily unavailable".to_string()),
            })
            .expect("seed attempt");
        drop(retry_store);

        let error = run_settlement_drive(&path, 16, &iou_issuer, &[kernel.public_key()])
            .expect_err("invalid action hash must fail closed");
        assert!(matches!(
            error,
            SettleStatusError::Integrity(message)
                if message.contains("mismatched action parameter hash")
        ));
        assert_attempt_preserved_without_terminal_evidence(&path, &receipt.id);
    }

    #[test]
    fn archive_only_legacy_attempt_stops_without_iou_reconciliation_or_dead_letter() {
        let dir = private_tempdir("chio-settle-drive-").expect("private tempdir");
        let path = dir.path().join("archive-only.sqlite3");
        let archive = dir.path().join("archive.sqlite3");
        let archive_path = archive.to_str().expect("utf-8 archive path");
        let kernel = chio_core::Keypair::from_seed(&[51_u8; 32]);
        let iou_issuer = chio_core::Keypair::from_seed(&[52_u8; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open receipts");
        assert!(
            <chio_store_sqlite::SqliteReceiptStore as ReceiptStore>::enable_background_checkpoints(
                &receipts,
                Arc::new(chio_core::crypto::Ed25519Backend::new(kernel.clone())),
                1,
            )
            .expect("enable checkpoints")
        );
        let receipt = signed_money_receipt(&kernel, "archive-only", 100);
        receipts
            .append_chio_receipt_returning_seq(&receipt)
            .expect("append receipt");
        receipts.flush_receipt_writes().expect("flush checkpoint");
        assert!(receipts
            .load_checkpoint_by_seq(1)
            .expect("load checkpoint")
            .is_some());
        assert_eq!(
            receipts
                .archive_receipts_before(150, archive_path)
                .expect("archive receipt"),
            1
        );
        assert!(!receipts
            .contains_live_chio_receipt(&receipt.id)
            .expect("inspect live receipt"));
        assert!(receipts
            .load_chio_receipt(&receipt.id)
            .expect("load authoritative receipt")
            .is_some());

        // Seed a pre-ownership-schema legacy table after archival. The normal
        // retry API now rejects this state at insertion time, so only a raw
        // legacy fixture can exercise fail-closed migration of archive-only
        // ownership.
        let legacy = Connection::open(&path).expect("open raw legacy retry writer");
        legacy
            .execute_batch(
                "CREATE TABLE settle_attempts ( \
                     receipt_id TEXT PRIMARY KEY, finalized_at INTEGER NOT NULL, \
                     attempts INTEGER NOT NULL, next_visible_at INTEGER NOT NULL, \
                     last_reason TEXT, updated_at INTEGER NOT NULL \
                 );",
            )
            .expect("create legacy retry table");
        legacy
            .execute(
                "INSERT INTO settle_attempts VALUES (?1, ?2, 1, 0, \
                     'rail temporarily unavailable', 0)",
                params![
                    receipt.id.as_str(),
                    i64::try_from(receipt.timestamp).expect("timestamp fits SQLite")
                ],
            )
            .expect("seed archive-only legacy retry");
        drop(legacy);
        drop(receipts);

        let error = run_settlement_drive(&path, 16, &iou_issuer, &[kernel.public_key()])
            .expect_err("archive-only attempt must stop the pass");
        assert!(matches!(
            error,
            SettleStatusError::Integrity(message)
                if message.contains("exact authoritative live receipt")
        ));
        assert_attempt_preserved_without_terminal_evidence(&path, &receipt.id);
    }
