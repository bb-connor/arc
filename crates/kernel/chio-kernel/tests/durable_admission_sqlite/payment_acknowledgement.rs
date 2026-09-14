use super::*;
use chio_kernel::admission_operation::{AdmissionIdentifier, DurableAdmissionMode};
use chio_kernel::RailSettlementState;
use std::sync::Mutex;

#[derive(Clone, Copy)]
enum Lookup {
    Held,
    Absent,
    Unavailable,
    Panic,
    InvalidIdentifier,
    ChangedMode,
}

struct RailState {
    lookup: Mutex<Lookup>,
    release_available: AtomicBool,
    releases: AtomicU64,
    original_mode: AtomicBool,
}

struct LostAcknowledgementRail(Arc<RailState>);

impl PaymentAdapter for LostAcknowledgementRail {
    fn rail_id(&self) -> &'static str {
        "test-lost-authorization-ack"
    }
    fn rail_mode(&self) -> Option<PaymentRailMode> {
        self.0
            .original_mode
            .load(Ordering::SeqCst)
            .then_some(PaymentRailMode::ReversibleHold)
    }
    fn authorize(&self, _: &PaymentAuthorizeRequest) -> Result<PaymentAuthorization, PaymentError> {
        Err(PaymentError::Unavailable(
            "authorization reply lost".to_owned(),
        ))
    }
    fn settlement_state(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        let lookup = *self
            .0
            .lookup
            .lock()
            .map_err(|_| PaymentError::Unavailable("test lock".to_owned()))?;
        match lookup {
            Lookup::Held => Ok(RailSettlementState::Held {
                authorization_id: "original-authorization".to_owned(),
            }),
            Lookup::Absent | Lookup::ChangedMode => Ok(RailSettlementState::NoAuthorization),
            Lookup::Unavailable => Err(PaymentError::Unavailable("lookup unavailable".to_owned())),
            Lookup::Panic => panic!("injected adapter panic"),
            Lookup::InvalidIdentifier => Ok(RailSettlementState::Held {
                authorization_id: String::new(),
            }),
        }
    }
    fn release(&self, id: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        assert_eq!(id, "original-authorization");
        self.0.releases.fetch_add(1, Ordering::SeqCst);
        if !self.0.release_available.load(Ordering::SeqCst) {
            return Err(PaymentError::Unavailable(
                "release acknowledgement unavailable".to_owned(),
            ));
        }
        Ok(PaymentResult {
            transaction_id: "original-release".to_owned(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }
    fn capture(&self, _: &str, _: u64, _: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable("unexpected capture".to_owned()))
    }
    fn refund(&self, _: &str, _: u64, _: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable("unexpected refund".to_owned()))
    }
}

fn configured_kernel(
    authority: &SqliteAuthorityStore,
    rail: Arc<RailState>,
    invocations: Arc<AtomicU64>,
) -> Result<ChioKernel, Box<dyn Error>> {
    let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
    kernel.require_durable_request_retention();
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
    kernel.set_payment_adapter(Box::new(LostAcknowledgementRail(rail)));
    kernel.register_tool_server(Box::new(PaidMutationServer { invocations }));
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    Ok(kernel)
}

#[test]
fn sqlite_unacknowledged_authorization_requires_authoritative_recovery(
) -> Result<(), Box<dyn Error>> {
    for lookup in [
        Lookup::Held,
        Lookup::Absent,
        Lookup::Unavailable,
        Lookup::Panic,
        Lookup::InvalidIdentifier,
        Lookup::ChangedMode,
    ] {
        let directory = tempfile::tempdir()?;
        secure_directory(directory.path())?;
        let locks = directory.path().join("locks");
        create_private_directory(&locks)?;
        let database = directory.path().join("authority.sqlite");
        SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let rail = Arc::new(RailState {
            lookup: Mutex::new(lookup),
            release_available: AtomicBool::new(false),
            releases: AtomicU64::new(0),
            original_mode: AtomicBool::new(true),
        });
        let invocations = Arc::new(AtomicU64::new(0));
        let kernel = configured_kernel(&authority, rail.clone(), invocations.clone())?;
        let capability =
            kernel.issue_capability(&Keypair::generate().public_key(), paid_scope(), 300)?;
        let request = paid_request(&capability);
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        let operations = authority.admission_operation_store();
        let (original, _) = operations
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
                &authority.mutation_fence(),
                now_unix_ms()?,
            )?
            .ok_or("original operation missing")?;
        let id = original.binding().operation_id().clone();
        let before = operations
            .load_payment_journal(id.as_str(), &authority.mutation_fence())?
            .ok_or("payment missing")?;
        assert_eq!(before.state, PaymentJournalState::HoldPlaced);
        if matches!(lookup, Lookup::ChangedMode) {
            rail.original_mode.store(false, Ordering::SeqCst);
        }
        drop(kernel);
        drop(operations);
        drop(authority);

        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let kernel = configured_kernel(&authority, rail.clone(), invocations.clone())?;
        let recovered = kernel.reconcile_durable_admission_startup();
        let operations = authority.admission_operation_store();
        let after = operations
            .load_payment_journal(id.as_str(), &authority.mutation_fence())?
            .ok_or("payment missing after restart")?;
        assert_eq!(after.hold_id, before.hold_id);
        match lookup {
            Lookup::Absent => {
                recovered?;
                assert_eq!(after.state, PaymentJournalState::Closed);
                assert!(after.authorization_id.is_none());
            }
            Lookup::Held => {
                assert!(recovered.is_err());
                assert_eq!(after.state, PaymentJournalState::Settling);
                assert_eq!(
                    after.authorization_id.as_deref(),
                    Some("original-authorization")
                );
                assert_eq!(after.settle_action, Some(PaymentSettleAction::Release));
                let retained_authority = after.release_authority.clone();
                rail.release_available.store(true, Ordering::SeqCst);
                drop(operations);
                drop(kernel);
                drop(authority);
                let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
                let kernel = configured_kernel(&authority, rail.clone(), invocations.clone())?;
                kernel.reconcile_durable_admission_startup()?;
                let operations = authority.admission_operation_store();
                let settled = operations
                    .load_payment_journal(id.as_str(), &authority.mutation_fence())?
                    .ok_or("settled payment missing")?;
                assert_eq!(settled.state, PaymentJournalState::Settled);
                assert_eq!(settled.release_authority, retained_authority);
                assert_eq!(settled.hold_id, before.hold_id);
                assert_eq!(settled.transaction_id.as_deref(), Some("original-release"));
                assert_eq!(rail.releases.load(Ordering::SeqCst), 2);
            }
            _ => {
                assert!(recovered.is_err());
                assert_eq!(after, before);
                *rail.lookup.lock().map_err(|_| "test lock")? = Lookup::Absent;
                rail.original_mode.store(true, Ordering::SeqCst);
                // A fresh owner can retry immediately; a live owner's recovery
                // lease intentionally excludes it from an immediate sweep.
                drop(operations);
                drop(kernel);
                drop(authority);
                let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
                let kernel = configured_kernel(&authority, rail.clone(), invocations.clone())?;
                kernel.reconcile_durable_admission_startup()?;
            }
        }
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        let reader = rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let holds: i64 = reader.query_row(
            "SELECT count(*) FROM budget_authorization_holds",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(holds, 1);
    }
    Ok(())
}
