//! The native payment participant finishes on its own prepaid journal family.
//!
//! These regressions drive the real public Process/Kernel entry with a local
//! reversible-hold rail: the pre-authorization gate admits the external hold
//! only against the Confirmed account's four outstanding payment purposes,
//! every later journal write spends its own purpose inside its transaction,
//! a declined hold compensates before dispatch, and a real serving restart
//! replays the settled operation without a second authorization, charge or
//! effect. No adapter here performs network IO or moves funds, so nothing in
//! this file qualifies an external rail; it exercises the durable contract.
use super::*;
use chio_security_types::semantic::SemanticOutputDispositionV1;

/// Counted rail calls of the local reversible-hold adapter.
#[derive(Clone, Default)]
struct PaymentRailCalls {
    authorizations: Arc<AtomicUsize>,
    captures: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
}

/// A local reversible-hold rail: authorize holds, capture settles later, and
/// every method is idempotent by its reference so a replayed drive cannot
/// double-charge. It moves no funds and performs no network IO.
struct HoldingPaymentAdapter {
    calls: PaymentRailCalls,
}

impl chio_kernel::PaymentAdapter for HoldingPaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "native-payment-finishing-hold"
    }

    fn rail_mode(&self) -> Option<chio_kernel::PaymentRailMode> {
        Some(chio_kernel::PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &chio_kernel::PaymentAuthorizeRequest,
    ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
        if request.amount_units != 10 || request.currency != "USD" || request.reference.is_empty() {
            return Err(chio_kernel::PaymentError::RailError(
                "payment finishing control received an invalid original payment".into(),
            ));
        }
        self.calls.authorizations.fetch_add(1, Ordering::SeqCst);
        Ok(chio_kernel::PaymentAuthorization {
            authorization_id: format!("hold-{}", request.reference),
            state: chio_kernel::PaymentAuthorizationState::Held,
            metadata: serde_json::json!({"adapter": "native-payment-finishing"}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        if amount_units == 0 || amount_units > 10 || currency != "USD" {
            return Err(chio_kernel::PaymentError::RailError(
                "payment finishing control refused an out-of-bound capture".into(),
            ));
        }
        self.calls.captures.fetch_add(1, Ordering::SeqCst);
        Ok(chio_kernel::PaymentResult {
            transaction_id: format!("txn-{authorization_id}"),
            settlement_status: chio_kernel::RailSettlementStatus::Captured,
            metadata: serde_json::json!({"adapter": "native-payment-finishing"}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.calls.releases.fetch_add(1, Ordering::SeqCst);
        Ok(chio_kernel::PaymentResult {
            transaction_id: format!("release-{authorization_id}"),
            settlement_status: chio_kernel::RailSettlementStatus::Released,
            metadata: serde_json::json!({"adapter": "native-payment-finishing"}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Ok(chio_kernel::PaymentResult {
            transaction_id: transaction_id.to_owned(),
            settlement_status: chio_kernel::RailSettlementStatus::Refunded,
            metadata: serde_json::json!({"adapter": "native-payment-finishing"}),
        })
    }

    fn settlement_state(
        &self,
        authorization_id: &str,
        _transaction_id: Option<&str>,
    ) -> Result<chio_kernel::RailSettlementState, chio_kernel::PaymentError> {
        let _ = authorization_id;
        Ok(chio_kernel::RailSettlementState::NoAuthorization)
    }
}

/// A local rail that declines the held authorization without moving funds.
struct DecliningPaymentAdapter {
    authorizations: Arc<AtomicUsize>,
}

impl chio_kernel::PaymentAdapter for DecliningPaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "native-payment-finishing-decline"
    }

    fn rail_mode(&self) -> Option<chio_kernel::PaymentRailMode> {
        Some(chio_kernel::PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &chio_kernel::PaymentAuthorizeRequest,
    ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
        if request.amount_units != 10 || request.currency != "USD" {
            return Err(chio_kernel::PaymentError::RailError(
                "declining payment control received an invalid original payment".into(),
            ));
        }
        self.authorizations.fetch_add(1, Ordering::SeqCst);
        Err(chio_kernel::PaymentError::Declined(
            "local payment finishing control declined without moving funds".into(),
        ))
    }

    fn capture(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Err(chio_kernel::PaymentError::RailError(
            "a declined authorization cannot capture".into(),
        ))
    }

    fn release(
        &self,
        _: &str,
        _: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Err(chio_kernel::PaymentError::RailError(
            "a declined authorization cannot release".into(),
        ))
    }

    fn refund(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Err(chio_kernel::PaymentError::RailError(
            "a declined authorization cannot refund".into(),
        ))
    }
}

/// The retained payment journal row of one operation, from the real store.
struct RetainedJournalRow {
    state: String,
    settle_action: Option<String>,
    settle_amount_units: Option<i64>,
    authorization_id: Option<String>,
    transaction_id: Option<String>,
    journal_version: i64,
}

fn retained_payment_journal(
    path: &std::path::Path,
    operation: &str,
) -> TestResult<RetainedJournalRow> {
    let database = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let row = database.query_row(
        "SELECT state, settle_action, settle_amount_units, authorization_id,
                transaction_id, journal_version
         FROM payment_journal WHERE operation_id=?1",
        [operation],
        |row| {
            Ok(RetainedJournalRow {
                state: row.get(0)?,
                settle_action: row.get(1)?,
                settle_amount_units: row.get(2)?,
                authorization_id: row.get(3)?,
                transaction_id: row.get(4)?,
                journal_version: row.get(5)?,
            })
        },
    )?;
    Ok(row)
}

/// The disposition of one purpose kind in the retained account envelope.
fn purpose_disposition(account: &serde_json::Value, kind: &str) -> TestResult<String> {
    let liabilities = account["liabilities"]
        .as_array()
        .ok_or("native payment account liabilities absent")?;
    for liability in liabilities {
        if liability["purpose"]["kind"].as_str() == Some(kind) {
            return liability["disposition"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "native payment account purpose lost its disposition".into());
        }
    }
    Err(format!("native payment account purpose {kind} absent").into())
}

fn terminal_payment_record(path: &std::path::Path, operation: &str) -> TestResult<String> {
    let database = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let record: String = database.query_row(
        "SELECT record_id FROM admission_operation_terminal_records
         WHERE operation_id=?1 AND record_kind='payment_terminal'",
        [operation],
        |row| row.get(0),
    )?;
    Ok(record)
}

/// Open a payment-native fixture: the real semantic connector, the default
/// retained output profile, a genuine imported flow source and the local rail.
async fn payment_fixture(
    directory: tempfile::TempDir,
    adapter: Box<dyn chio_kernel::PaymentAdapter>,
) -> TestResult<RecoveryFixture> {
    std::fs::write(directory.path().join("semantic-kind"), "write")?;
    RecoveryFixture::open_with_payment_adapter(
        directory.path().to_path_buf(),
        Some(directory),
        false,
        adapter,
    )
}

#[tokio::test]
async fn native_payment_hold_captures_and_settles_each_prepaid_purpose_once() -> TestResult {
    let calls = PaymentRailCalls::default();
    let directory = tempfile::tempdir()?;
    let adapter = Box::new(HoldingPaymentAdapter {
        calls: calls.clone(),
    });
    let f = Box::pin(payment_fixture(directory, adapter)).await?;
    let key = "native-payment-hold-capture";
    let (runtime, request, _) =
        semantic::prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    let result = Box::pin(runtime.execute_step(&f.process, "root", key, &request)).await?;
    assert_eq!(result.verdict, Verdict::Allow);
    assert!(result.receipt.verify_signature()?);
    assert!(
        result.output.is_some(),
        "settled payment withheld its output"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    let (operation, original) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("native payment original admission absent")?;
    original.validate_binding(operation.binding())?;
    original.validate_request_material(&request)?;
    assert_eq!(
        operation.binding().effect_class(),
        chio_kernel::admission_operation::SideEffectClass::Monetary
    );
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(operation.dispatch_commit().is_some());
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    let journal = retained_payment_journal(&f.path, &operation_id)?;
    assert_eq!(journal.state, "settled");
    assert_eq!(journal.settle_action.as_deref(), Some("capture"));
    assert_eq!(journal.settle_amount_units, Some(10));
    assert_eq!(
        journal.authorization_id.as_deref(),
        Some(format!("hold-{operation_id}").as_str())
    );
    assert!(journal.transaction_id.is_some());
    // The terminal payment record binds this exact operation.
    assert_eq!(
        terminal_payment_record(&f.path, &operation_id)?,
        operation_id
    );
    // The settled receipt carries its priced financial evidence.
    let metadata = result
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .ok_or("settled payment receipt lost its financial block")?;
    assert_eq!(metadata["cost_charged"].as_u64(), Some(10));
    assert!(metadata["payment_reference"].as_str().is_some());
    // Every journal write spent its own prepaid purpose exactly once; the
    // compensation purpose was priced and released unused.
    let account = super::native_lifecycle::native_account(&f.path, &operation_id)?;
    assert_eq!(account["state"], "settled");
    assert_eq!(
        purpose_disposition(&account, "payment_authorization")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_settlement")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_completion")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_compensation")?,
        "released"
    );
    assert_eq!(
        purpose_disposition(&account, "terminal_projection")?,
        "consumed"
    );
    assert_eq!(purpose_disposition(&account, "receipt_sink")?, "consumed");
    // Replaying the completed step returns the retained receipt and charges
    // nothing again: no authorization, capture, journal write or effect.
    let replay = Box::pin(runtime.execute_step(&f.process, "root", key, &request)).await?;
    assert_eq!(replay.request_id, result.request_id);
    assert_eq!(
        chio_core::canonical_json_bytes(&replay.receipt)?,
        chio_core::canonical_json_bytes(&result.receipt)?
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(
        retained_payment_journal(&f.path, &operation_id)?.journal_version,
        journal.journal_version,
        "once-only settlement wrote the journal again"
    );
    Ok(())
}

#[tokio::test]
async fn native_payment_decline_compensates_before_dispatch_without_charge() -> TestResult {
    let authorizations = Arc::new(AtomicUsize::new(0));
    let directory = tempfile::tempdir()?;
    let adapter = Box::new(DecliningPaymentAdapter {
        authorizations: authorizations.clone(),
    });
    let f = Box::pin(payment_fixture(directory, adapter)).await?;
    let key = "native-payment-decline-compensation";
    let (runtime, request, _) =
        semantic::prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    let result = Box::pin(runtime.execute_step(&f.process, "root", key, &request)).await?;
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(result.receipt.verify_signature()?);
    assert!(result.output.is_none());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    // The gate admitted exactly one real external authorization attempt; the
    // rail declined it and no retried action re-authorizes.
    assert_eq!(authorizations.load(Ordering::SeqCst), 1);
    let (operation, original) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("declined native payment original admission absent")?;
    original.validate_binding(operation.binding())?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    let journal = retained_payment_journal(&f.path, &operation_id)?;
    assert_eq!(journal.state, "closed");
    assert!(
        journal.authorization_id.is_none(),
        "declined hold left a charge"
    );
    assert!(journal.transaction_id.is_none());
    assert!(journal.settle_action.is_none());
    // The compensation write spent its own prepaid purpose; the never-used
    // authorization, settlement and completion purposes were released intact.
    let account = super::native_lifecycle::native_account(&f.path, &operation_id)?;
    assert_eq!(account["state"], "settled");
    assert_eq!(
        purpose_disposition(&account, "payment_compensation")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_authorization")?,
        "released"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_settlement")?,
        "released"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_completion")?,
        "released"
    );
    Ok(())
}

#[tokio::test]
async fn native_payment_settled_operation_replays_after_restart_without_second_charge() -> TestResult
{
    let calls = PaymentRailCalls::default();
    let directory = tempfile::tempdir()?;
    let adapter = Box::new(HoldingPaymentAdapter {
        calls: calls.clone(),
    });
    let mut f = Box::pin(payment_fixture(directory, adapter)).await?;
    let key = "native-payment-restart-replay";
    let (runtime, request, _) =
        semantic::prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    let result = Box::pin(runtime.execute_step(&f.process, "root", key, &request)).await?;
    assert_eq!(result.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let (operation, _) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("native payment restart original admission absent")?;
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    let settled = retained_payment_journal(&f.path, &operation_id)?;
    assert_eq!(settled.state, "settled");
    let account_before = super::native_lifecycle::native_account(&f.path, &operation_id)?;
    let receipt = chio_core::canonical_json_bytes(&result.receipt)?;
    // A real cold restart: drop every owner, reopen the same authority file
    // and let startup reconciliation reauthenticate the retained state.
    let path = f.path.clone();
    let directory = f._directory.take();
    drop(runtime);
    drop(f);
    let adapter = Box::new(HoldingPaymentAdapter {
        calls: calls.clone(),
    });
    let f = RecoveryFixture::open_with_payment_adapter(path.clone(), directory, false, adapter)?;
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let restarted = retained_payment_journal(&path, &operation_id)?;
    assert_eq!(restarted.journal_version, settled.journal_version);
    assert_eq!(restarted.state, "settled");
    assert_eq!(restarted.authorization_id, settled.authorization_id);
    assert_eq!(restarted.transaction_id, settled.transaction_id);
    let account_after = super::native_lifecycle::native_account(&path, &operation_id)?;
    assert_eq!(account_after, account_before);
    assert_eq!(terminal_payment_record(&path, &operation_id)?, operation_id);
    // The restarted Process replay returns the retained receipt without a
    // second authorization, capture, journal write or external effect.
    let replay = Box::pin(f.process.invoke_known_only("root", key, &request)).await?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(chio_core::canonical_json_bytes(&replay.receipt)?, receipt);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(
        retained_payment_journal(&path, &operation_id)?.journal_version,
        settled.journal_version,
        "restart replayed a settled payment write"
    );
    Ok(())
}

/// The local reversible-hold rail for the payment-capable crash child.
pub(in crate::recovery::tests) fn reversible_hold_payment_adapter(
) -> Box<dyn chio_kernel::PaymentAdapter> {
    Box::new(HoldingPaymentAdapter {
        calls: PaymentRailCalls::default(),
    })
}

/// A local rail whose first capture answers with the wrong settlement
/// status, so the genuine reconciliation retry drives it to completion.
struct ReconcileRetryPaymentAdapter {
    captures: Arc<AtomicUsize>,
}

impl chio_kernel::PaymentAdapter for ReconcileRetryPaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "native-payment-finishing-retry"
    }

    fn rail_mode(&self) -> Option<chio_kernel::PaymentRailMode> {
        Some(chio_kernel::PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &chio_kernel::PaymentAuthorizeRequest,
    ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
        if request.amount_units != 10 || request.currency != "USD" {
            return Err(chio_kernel::PaymentError::RailError(
                "reconciliation retry control received an invalid original payment".into(),
            ));
        }
        Ok(chio_kernel::PaymentAuthorization {
            authorization_id: format!("hold-{}", request.reference),
            state: chio_kernel::PaymentAuthorizationState::Held,
            metadata: serde_json::json!({"adapter": "native-payment-finishing"}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        let attempt = self.captures.fetch_add(1, Ordering::SeqCst);
        // The first drive returns an incompatible status for a capture
        // intent; the retained journal seals reconcile_failed and the retry
        // re-drives the same intent, which this rail then completes.
        let status = if attempt == 0 {
            chio_kernel::RailSettlementStatus::Released
        } else {
            chio_kernel::RailSettlementStatus::Captured
        };
        Ok(chio_kernel::PaymentResult {
            transaction_id: format!("txn-{authorization_id}"),
            settlement_status: status,
            metadata: serde_json::json!({"adapter": "native-payment-finishing"}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Ok(chio_kernel::PaymentResult {
            transaction_id: format!("release-{authorization_id}"),
            settlement_status: chio_kernel::RailSettlementStatus::Released,
            metadata: serde_json::json!({"adapter": "native-payment-finishing"}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Ok(chio_kernel::PaymentResult {
            transaction_id: transaction_id.to_owned(),
            settlement_status: chio_kernel::RailSettlementStatus::Refunded,
            metadata: serde_json::json!({"adapter": "native-payment-finishing"}),
        })
    }

    fn settlement_state(
        &self,
        _authorization_id: &str,
        _transaction_id: Option<&str>,
    ) -> Result<chio_kernel::RailSettlementState, chio_kernel::PaymentError> {
        Ok(chio_kernel::RailSettlementState::NoAuthorization)
    }
}

#[tokio::test]
async fn native_payment_wrong_settlement_status_reconciles_and_retries_to_completion() -> TestResult
{
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("payment-effect"), b"1")?;
    let captures = Arc::new(AtomicUsize::new(0));
    let adapter = Box::new(ReconcileRetryPaymentAdapter {
        captures: captures.clone(),
    });
    let f = RecoveryFixture::open_with_payment_adapter(
        directory.path().to_path_buf(),
        Some(directory),
        false,
        adapter,
    )?;
    let id = f.ready().await?;
    let record = f.record(&id)?;
    let resume = f.command(
        "resume-first-settlement",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: record.revision,
        },
    )?;
    // The rail answers the first capture drive with the wrong status: the
    // settlement begin and the reconcile failure are both real journal
    // writes, and the command surfaces the refusal.
    let failed = f.runtime.execute_command(&f.control, &resume).await;
    assert!(
        failed.is_err(),
        "incompatible rail status completed a payment"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let intent = f
        .record(&id)?
        .admission
        .ok_or("reconcile retry native intent absent")?;
    let operation_id = intent.native_operation_id.as_str().to_owned();
    let sealed = retained_payment_journal(&f.path, &operation_id)?;
    assert_eq!(
        sealed.state, "reconcile_failed",
        "the rail refusal was not retained"
    );
    assert_eq!(sealed.settle_action.as_deref(), Some("capture"));
    assert!(sealed.authorization_id.is_some());
    // The interrupted settlement keeps its genuine outstanding liabilities:
    // the begin and the refused reconcile failed write each spent their own
    // purpose, and the once-only completion is still reserved.
    let account = super::native_lifecycle::native_account(&f.path, &operation_id)?;
    assert_eq!(account["state"], "confirmed");
    assert_eq!(
        purpose_disposition(&account, "payment_authorization")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_settlement")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_compensation")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_completion")?,
        "outstanding"
    );
    // The reconciliation retry re-drives the same retained intent.
    let record = f.record(&id)?;
    let retry = f.command(
        "resume-reconcile-retry",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: record.revision,
        },
    )?;
    let retried = f
        .runtime
        .execute_command(&f.control, &retry)
        .await
        .map_err(|error| format!("reconciliation retry failed: {error}"))?;
    assert!(matches!(
        retried.status.effect,
        EffectObservationV1::Complete { .. }
    ));
    let settled = retained_payment_journal(&f.path, &operation_id)?;
    assert_eq!(settled.state, "settled");
    assert_eq!(settled.settle_action.as_deref(), Some("capture"));
    assert_eq!(settled.journal_version, sealed.journal_version + 1);
    let account = super::native_lifecycle::native_account(&f.path, &operation_id)?;
    assert_eq!(account["state"], "settled");
    assert_eq!(
        purpose_disposition(&account, "payment_completion")?,
        "consumed"
    );
    // The rail was driven twice with the same intent; the once-only charge
    // is proven by the retained journal, not by the adapter counter.
    assert_eq!(captures.load(Ordering::SeqCst), 2);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn native_payment_delivery_denial_releases_the_held_authorization_at_zero_charge(
) -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("payment-effect"), b"1")?;
    std::fs::write(directory.path().join("mismatched-output-digest"), b"1")?;
    let calls = PaymentRailCalls::default();
    let adapter = Box::new(HoldingPaymentAdapter {
        calls: calls.clone(),
    });
    let f = RecoveryFixture::open_with_payment_adapter(
        directory.path().to_path_buf(),
        Some(directory),
        false,
        adapter,
    )?;
    let id = f.ready().await?;
    let record = f.record(&id)?;
    let resume = f.command(
        "resume-denied-delivery",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: record.revision,
        },
    )?;
    let result = f.runtime.execute_command(&f.control, &resume).await?;
    assert!(
        matches!(result.status.effect, EffectObservationV1::Complete { .. }),
        "a denied delivery must still complete its terminal observation: {:?}",
        result.status.effect
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 1);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    let intent = f
        .record(&id)?
        .admission
        .ok_or("denied delivery native intent absent")?;
    let operation_id = intent.native_operation_id.as_str().to_owned();
    let journal = retained_payment_journal(&f.path, &operation_id)?;
    assert_eq!(journal.state, "settled");
    assert_eq!(journal.settle_action.as_deref(), Some("release"));
    assert!(journal.transaction_id.is_some());
    // The contractual zero-charge release evidence is retained beside the journal.
    let database = rusqlite::Connection::open_with_flags(
        f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let evidence_kind: String = database.query_row(
        "SELECT evidence_kind FROM payment_release_evidence WHERE operation_id=?1",
        [&operation_id],
        |row| row.get(0),
    )?;
    assert_eq!(evidence_kind, "contractual_zero_charge");
    // The release drove the real funded writers: the settlement begin wrote
    // the release intent with its evidence, and the completion settled once.
    let account = super::native_lifecycle::native_account(&f.path, &operation_id)?;
    assert_eq!(account["state"], "settled");
    assert_eq!(
        purpose_disposition(&account, "payment_authorization")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_settlement")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_completion")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_compensation")?,
        "released"
    );
    let settled = f.runtime.settle(&f.control, &id)?;
    assert!(settled.effect.is_settled());
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn native_payment_crash_after_effect_drains_settlement_once_across_restart() -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("payment-effect"), b"1")?;
    // The original denial and its persisted payment-effect capability are
    // created in the parent so the child reopens the same real fixture.
    let original = RecoveryFixture::open_with_payment_adapter(
        directory.path().to_path_buf(),
        None,
        false,
        reversible_hold_payment_adapter(),
    )?;
    Box::pin(original.denied_seed_named("ticket-1")).await?;
    drop(original);
    let log = std::fs::File::create(directory.path().join("payment-crash-child.log"))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "recovery::tests::recovery_crash_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CHIO_RECOVERY_CRASH_CHILD", "1")
        .env("CHIO_RECOVERY_CRASH_ROOT", directory.path())
        .env("CHIO_RECOVERY_CRASH_POINT", "return-recorded")
        .env("CHIO_RECOVERY_CRASH_PAYMENT", "1")
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(90) {
            child.kill()?;
            child.wait()?;
            return Err("payment crash child timed out".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let log = std::fs::read_to_string(directory.path().join("payment-crash-child.log"))?;
    assert_eq!(status.signal(), Some(6), "return-recorded: {log}");
    assert!(
        log.contains("recovery crash cutpoint: return-recorded"),
        "payment child missed its cutpoint: {log}"
    );
    let retained_path = directory.path().to_path_buf();
    let path = retained_path.as_path();
    // One external effect happened before the abort; the payment settlement
    // was interrupted before its terminal completion.
    assert_eq!(external_count(path)?, 1);
    let interrupted = authority_history::retained_workflow(path)?;
    assert!(interrupted.captured);
    let intent = interrupted
        .admission
        .as_ref()
        .ok_or("interrupted payment native intent absent")?;
    let operation_id = intent.native_operation_id.as_str().to_owned();
    let held = retained_payment_journal(path, &operation_id)?;
    assert_eq!(held.state, "authorized", "the rail hold must be retained");
    assert!(held.authorization_id.is_some());
    assert_eq!(held.journal_version, 2);
    // Genuine remaining liabilities are retained across the interruption:
    // the consumed authorization is proven by the journal; the settlement,
    // completion and compensation purposes are still outstanding.
    let account = super::native_lifecycle::native_account(path, &operation_id)?;
    assert_eq!(account["state"], "confirmed");
    assert_eq!(
        purpose_disposition(&account, "payment_authorization")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_settlement")?,
        "outstanding"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_completion")?,
        "outstanding"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_compensation")?,
        "outstanding"
    );
    // A real cold restart reopens the same authority and drains the funded
    // settlement to completion. The restarted rail counts every call: the
    // child's single authorization is never repeated.
    let calls = PaymentRailCalls::default();
    let f = RecoveryFixture::open_with_payment_adapter(
        path.to_path_buf(),
        Some(directory),
        false,
        Box::new(HoldingPaymentAdapter {
            calls: calls.clone(),
        }),
    )?;
    let settled = f
        .runtime
        .settle(&f.control, &interrupted.workflow_id)
        .map_err(|error| format!("payment settlement drain failed: {error}"))?;
    assert!(
        matches!(settled.effect, EffectObservationV1::Complete { .. }),
        "the interrupted payment must settle its actual completed effect: {:?}",
        settled.effect
    );
    assert_eq!(external_count(path)?, 1);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    let drained = retained_payment_journal(path, &operation_id)?;
    assert_eq!(drained.state, "settled");
    assert_eq!(drained.settle_action.as_deref(), Some("capture"));
    assert!(drained.transaction_id.is_some());
    assert_eq!(drained.journal_version, held.journal_version + 2);
    let account = super::native_lifecycle::native_account(path, &operation_id)?;
    assert_eq!(account["state"], "settled");
    assert_eq!(
        purpose_disposition(&account, "payment_settlement")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_completion")?,
        "consumed"
    );
    assert_eq!(
        purpose_disposition(&account, "payment_compensation")?,
        "released"
    );
    // The settled continuation replays the same receipt exactly once: no
    // second effect, charge or journal write.
    let resume: RecoveryCommandV1 =
        serde_json::from_slice(&std::fs::read(path.join("resume.json"))?)?;
    let first = f.runtime.execute_command(&f.control, &resume).await?;
    let receipt = first
        .original_response
        .as_ref()
        .map(|response| chio_core::canonical_json_bytes(&response.receipt))
        .transpose()?
        .ok_or("settled payment response absent")?;
    let replay = f.runtime.execute_command(&f.control, &resume).await?;
    assert_eq!(
        replay
            .original_response
            .as_ref()
            .map(|response| chio_core::canonical_json_bytes(&response.receipt))
            .transpose()?,
        Some(receipt),
        "settled payment replay returned a different receipt"
    );
    assert_eq!(external_count(path)?, 1);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(
        retained_payment_journal(path, &operation_id)?.journal_version,
        drained.journal_version,
        "replay wrote the settled payment journal again"
    );
    Ok(())
}

/// Disposition of one retained budget hold, read from the real store.
fn budget_hold_state(path: &std::path::Path, hold_id: &str) -> TestResult<(String, String)> {
    let database = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(database.query_row(
        "SELECT disposition, invocation_state FROM budget_authorization_holds WHERE hold_id=?1",
        [hold_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

fn payment_hold_id(path: &std::path::Path, operation: &str) -> TestResult<String> {
    let database = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(database.query_row(
        "SELECT hold_id FROM payment_journal WHERE operation_id=?1",
        [operation],
        |row| row.get(0),
    )?)
}

/// The external authorization is held and the process aborts inside the
/// native capture transaction, before any dispatch commit or effect. The
/// cold restart compensates before dispatch: the rail hold is released once,
/// every live budget hold is reversed in the transaction funded by the
/// account's own PaymentSettlement purpose, and the terminal spends
/// TerminalProjection instead of ordinary intake. A second restart replays
/// nothing: no rail call, journal write or account transition repeats.
#[cfg(unix)]
#[tokio::test]
async fn native_payment_crash_after_authorization_reverses_holds_on_prepaid_purposes() -> TestResult
{
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("payment-effect"), b"1")?;
    let original = RecoveryFixture::open_with_payment_adapter(
        directory.path().to_path_buf(),
        None,
        false,
        reversible_hold_payment_adapter(),
    )?;
    Box::pin(original.denied_seed_named("ticket-1")).await?;
    drop(original);
    let log = std::fs::File::create(directory.path().join("payment-cancel-child.log"))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "recovery::tests::recovery_crash_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CHIO_RECOVERY_CRASH_CHILD", "1")
        .env("CHIO_RECOVERY_CRASH_ROOT", directory.path())
        .env("CHIO_RECOVERY_CRASH_POINT", "capture-before-commit")
        .env("CHIO_RECOVERY_CRASH_PAYMENT", "1")
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(90) {
            child.kill()?;
            child.wait()?;
            return Err("payment cancellation child timed out".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let log = std::fs::read_to_string(directory.path().join("payment-cancel-child.log"))?;
    assert_eq!(status.signal(), Some(6), "capture-before-commit: {log}");
    assert!(
        log.contains("native capture transaction cutpoint: BeforeCommit"),
        "payment child missed its capture cutpoint: {log}"
    );
    let retained_path = directory.path().to_path_buf();
    let path = retained_path.as_path();
    assert_eq!(
        external_count(path)?,
        0,
        "no effect precedes the dispatch commit"
    );
    let interrupted = authority_history::retained_workflow(path)?;
    assert!(!interrupted.captured);
    let intent = interrupted
        .admission
        .as_ref()
        .ok_or("interrupted payment native intent absent")?;
    let operation_id = intent.native_operation_id.as_str().to_owned();
    let held = retained_payment_journal(path, &operation_id)?;
    assert_eq!(held.state, "authorized", "the rail hold must be retained");
    assert!(held.authorization_id.is_some());
    let hold_id = payment_hold_id(path, &operation_id)?;
    assert_eq!(budget_hold_state(path, &hold_id)?.1, "authorized");
    let account = super::native_lifecycle::native_account(path, &operation_id)?;
    assert_eq!(account["state"], "confirmed");
    assert_eq!(
        purpose_disposition(&account, "payment_authorization")?,
        "consumed"
    );
    for purpose in [
        "payment_compensation",
        "payment_settlement",
        "payment_completion",
        "terminal_projection",
    ] {
        assert_eq!(purpose_disposition(&account, purpose)?, "outstanding");
    }
    // The cold restart compensates the authorized operation before dispatch.
    let calls = PaymentRailCalls::default();
    let mut f = RecoveryFixture::open_with_payment_adapter(
        path.to_path_buf(),
        Some(directory),
        false,
        Box::new(HoldingPaymentAdapter {
            calls: calls.clone(),
        }),
    )?;
    let settled = f
        .runtime
        .settle(&f.control, &interrupted.workflow_id)
        .map_err(|error| format!("payment cancellation drain failed: {error}"))?;
    assert!(
        !matches!(settled.effect, EffectObservationV1::Complete { .. }),
        "a compensated operation reported an effect: {:?}",
        settled.effect
    );
    assert_eq!(external_count(path)?, 0);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 1);
    let released = retained_payment_journal(path, &operation_id)?;
    assert_eq!(released.state, "settled");
    assert_eq!(released.settle_action.as_deref(), Some("release"));
    assert!(released.transaction_id.is_some());
    assert_eq!(released.journal_version, held.journal_version + 2);
    assert_eq!(
        budget_hold_state(path, &hold_id)?,
        ("reversed".to_owned(), "reversed".to_owned())
    );
    // Each post-authorization write spent its own prepaid purpose: the
    // release intent, its completion, the funded hold reversal and the
    // terminal. Nothing after the external authorization was ordinary intake.
    let account = super::native_lifecycle::native_account(path, &operation_id)?;
    assert_eq!(account["state"], "settled");
    for purpose in [
        "payment_authorization",
        "payment_compensation",
        "payment_completion",
        "payment_settlement",
        "terminal_projection",
    ] {
        assert_eq!(
            purpose_disposition(&account, purpose)?,
            "consumed",
            "{purpose}"
        );
    }
    // A second cold restart replays the compensated operation without any
    // rail call, journal write, hold mutation or account transition.
    let directory = f._directory.take();
    drop(f);
    let replay_calls = PaymentRailCalls::default();
    let f = RecoveryFixture::open_with_payment_adapter(
        path.to_path_buf(),
        directory,
        false,
        Box::new(HoldingPaymentAdapter {
            calls: replay_calls.clone(),
        }),
    )?;
    f.runtime
        .settle(&f.control, &interrupted.workflow_id)
        .map_err(|error| format!("compensated payment replay failed: {error}"))?;
    assert_eq!(replay_calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(replay_calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(replay_calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(
        retained_payment_journal(path, &operation_id)?.journal_version,
        released.journal_version
    );
    assert_eq!(
        super::native_lifecycle::native_account(path, &operation_id)?,
        account
    );
    assert_eq!(external_count(path)?, 0);
    Ok(())
}

/// Abort a payment original inside its native capture transaction, after the
/// external authorization and before any dispatch commit or effect.
#[cfg(unix)]
async fn crash_after_payment_authorization() -> TestResult<tempfile::TempDir> {
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("payment-effect"), b"1")?;
    let original = RecoveryFixture::open_with_payment_adapter(
        directory.path().to_path_buf(),
        None,
        false,
        reversible_hold_payment_adapter(),
    )?;
    Box::pin(original.denied_seed_named("ticket-1")).await?;
    drop(original);
    let log = std::fs::File::create(directory.path().join("payment-pressure-child.log"))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "recovery::tests::recovery_crash_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CHIO_RECOVERY_CRASH_CHILD", "1")
        .env("CHIO_RECOVERY_CRASH_ROOT", directory.path())
        .env("CHIO_RECOVERY_CRASH_POINT", "capture-before-commit")
        .env("CHIO_RECOVERY_CRASH_PAYMENT", "1")
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(90) {
            child.kill()?;
            child.wait()?;
            return Err("payment pressure child timed out".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let log = std::fs::read_to_string(directory.path().join("payment-pressure-child.log"))?;
    assert_eq!(status.signal(), Some(6), "capture-before-commit: {log}");
    assert!(
        log.contains("native capture transaction cutpoint: BeforeCommit"),
        "payment child missed its capture cutpoint: {log}"
    );
    Ok(directory)
}

/// Retain one ordinary protected record batch through the real fenced writer.
fn retain_ordinary_records(
    f: &RecoveryFixture,
    first: usize,
    count: usize,
) -> TestResult<Result<(), String>> {
    use chio_store_sqlite::admission_operation_store::{
        retain_recovery_quota_fixture_records, RecoveryQuotaFixtureRecord,
    };
    let records = (first..first + count)
        .map(|index| {
            Ok(RecoveryQuotaFixtureRecord {
                scope: f.runtime.scope().clone(),
                key: format!("protected-setup:payment-restart-pressure:{index}"),
                payload: chio_core::canonical_json_bytes(
                    &serde_json::json!({"fixture": "ordinary shared-history pressure"}),
                )?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(retain_recovery_quota_fixture_records(
        &f.authority.admission_operation_store(),
        &f.authority.mutation_fence(),
        &records,
    )
    .map_err(|error| error.to_string()))
}

/// The restart after an authorized hold runs with no ordinary shared-history
/// row left: real ordinary protected writes exhaust it, and the established
/// standalone recovery claim refuses there. Startup still compensates before
/// dispatch, because each restart claim commits inside the funded payment or
/// terminal transaction that spends its own prepaid purpose.
#[cfg(unix)]
#[tokio::test]
async fn native_payment_restart_claims_commit_inside_funded_purposes_under_row_pressure(
) -> TestResult {
    use chio_kernel::admission_operation::{
        AdmissionOperationId, QualifiedAdmissionOperationStoreExt,
    };

    const OWED_ROW: &str = "owed native table row";
    let directory = Box::pin(crash_after_payment_authorization()).await?;
    let retained_path = directory.path().to_path_buf();
    let path = retained_path.as_path();
    assert_eq!(external_count(path)?, 0);
    let interrupted = authority_history::retained_workflow(path)?;
    let operation_id = interrupted
        .admission
        .as_ref()
        .ok_or("interrupted payment native intent absent")?
        .native_operation_id
        .clone();
    let held = retained_payment_journal(path, operation_id.as_str())?;
    assert_eq!(held.state, "authorized");
    let hold_id = payment_hold_id(path, operation_id.as_str())?;
    std::fs::write(path.join("defer-startup-reconcile"), b"1")?;
    let calls = PaymentRailCalls::default();
    let f = RecoveryFixture::open_with_payment_adapter(
        path.to_path_buf(),
        Some(directory),
        false,
        Box::new(HoldingPaymentAdapter {
            calls: calls.clone(),
        }),
    )?;
    assert_eq!(
        retained_payment_journal(path, operation_id.as_str())?.journal_version,
        held.journal_version,
        "startup ran before the pressure was applied"
    );
    // Exhaust every ordinary row of the shared histories with real writes.
    let mut next = 0;
    for batch in [16, 1] {
        loop {
            match retain_ordinary_records(&f, next, batch)? {
                Ok(()) => next += batch,
                Err(refusal) => {
                    assert!(refusal.contains(OWED_ROW), "{refusal}");
                    break;
                }
            }
            if next > 16_384 {
                return Err("ordinary shared-history intake never reached its owed rows".into());
            }
        }
    }
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    let operation_id = AdmissionOperationId::from_persisted(operation_id.as_str())?;
    let original = store
        .load_by_operation_id(&operation_id)?
        .ok_or("authorized payment original absent")?;
    let now = now_ms()?;
    let probe = store
        .claim_recovery(
            &operation_id,
            original.version(),
            &AdmissionIdentifier::try_new("claimant_id", "payment-restart-pressure-probe")?,
            now,
            now + 60_000,
            &fence,
        )
        .err()
        .ok_or("a standalone restart claim consumed an owed row")?
        .to_string();
    assert!(probe.contains(OWED_ROW), "{probe}");
    assert_eq!(store.load_by_operation_id(&operation_id)?, Some(original));
    f.kernel
        .reconcile_durable_admission_startup()
        .map_err(|error| format!("funded restart under row pressure failed: {error}"))?;
    assert_eq!(external_count(path)?, 0);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 1);
    let released = retained_payment_journal(path, operation_id.as_str())?;
    assert_eq!(released.state, "settled");
    assert_eq!(released.settle_action.as_deref(), Some("release"));
    assert_eq!(released.journal_version, held.journal_version + 2);
    assert_eq!(
        budget_hold_state(path, &hold_id)?,
        ("reversed".to_owned(), "reversed".to_owned())
    );
    let account = super::native_lifecycle::native_account(path, operation_id.as_str())?;
    assert_eq!(account["state"], "settled");
    for purpose in [
        "payment_authorization",
        "payment_compensation",
        "payment_completion",
        "payment_settlement",
        "terminal_projection",
    ] {
        assert_eq!(
            purpose_disposition(&account, purpose)?,
            "consumed",
            "{purpose}"
        );
    }
    assert_eq!(
        store
            .load_by_operation_id(&operation_id)?
            .ok_or("compensated payment original absent")?
            .state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    Ok(())
}
