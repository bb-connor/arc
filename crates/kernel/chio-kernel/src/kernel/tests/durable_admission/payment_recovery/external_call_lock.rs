//! External payment-rail and price-oracle calls must leave the serving fence's
//! admission mutation lock free. Each test parks operation A inside one
//! external call, proves the call was entered, and then requires an
//! independent acquisition of the same fence's lock within `PROBE_BOUND`.

use super::*;
use crate::admission_operation::AdmissionMutationSequencer;
use crate::payment::PaymentSettleAction;
use std::sync::{mpsc, Condvar, PoisonError};
use std::time::{Duration, Instant};

const ENTRY_BOUND: Duration = Duration::from_secs(10);
const PROBE_BOUND: Duration = Duration::from_secs(1);
const SETTLE_BOUND: Duration = Duration::from_secs(10);
const PARK_BOUND: Duration = Duration::from_secs(30);

fn poisoned<T>(_: PoisonError<T>) -> String {
    "external call gate poisoned".to_owned()
}

#[derive(Default)]
struct GateState {
    entered: Vec<String>,
    parked: usize,
    open: bool,
}

/// Parks a thread inside an external call until the test opens the gate. A
/// call still parked after `PARK_BOUND` fails instead of blocking forever.
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl Gate {
    fn park(&self, reference: &str) -> Result<(), String> {
        let mut state = self.state.lock().map_err(poisoned)?;
        state.entered.push(reference.to_owned());
        state.parked += 1;
        self.changed.notify_all();
        let deadline = Instant::now() + PARK_BOUND;
        while !state.open {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.parked -= 1;
                return Err(format!(
                    "gated external call {reference} was never released"
                ));
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(poisoned)?
                .0;
        }
        state.parked -= 1;
        Ok(())
    }

    fn wait_entered(&self) -> Result<Vec<String>, String> {
        let mut state = self.state.lock().map_err(poisoned)?;
        let deadline = Instant::now() + ENTRY_BOUND;
        while state.entered.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "operation A did not enter the gated external call within {ENTRY_BOUND:?}"
                ));
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(poisoned)?
                .0;
        }
        Ok(state.entered.clone())
    }

    fn parked(&self) -> Result<usize, String> {
        Ok(self.state.lock().map_err(poisoned)?.parked)
    }

    fn open(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .open = true;
        self.changed.notify_all();
    }
}

/// Opens the gate when the test ends, including when an assertion unwinds.
struct OpenOnDrop(Arc<Gate>);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GatedCall {
    Capture,
    Release,
}

struct GatedRail {
    inner: RecoveryRail,
    gate: Arc<Gate>,
    gated: GatedCall,
}

impl GatedRail {
    fn park_if(&self, call: GatedCall, reference: &str) -> Result<(), PaymentError> {
        if self.gated == call {
            self.gate
                .park(reference)
                .map_err(PaymentError::Unavailable)?;
        }
        Ok(())
    }
}

impl PaymentAdapter for GatedRail {
    fn egress_allowance_digest(&self) -> &str {
        self.inner.egress_allowance_digest()
    }

    fn rail_id(&self) -> &'static str {
        self.inner.rail_id()
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        self.inner.rail_mode()
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.inner.authorize(request)
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.park_if(GatedCall::Capture, reference)?;
        self.inner
            .capture(authorization_id, amount_units, currency, reference)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.park_if(GatedCall::Release, reference)?;
        self.inner.release(authorization_id, reference)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner
            .refund(transaction_id, amount_units, currency, reference)
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<crate::payment::RailSettlementState, PaymentError> {
        self.inner.settlement_state(reference, authorization_id)
    }

    fn replayed_authorization_metadata(
        &self,
        authorization_id: &str,
    ) -> Result<serde_json::Value, PaymentError> {
        self.inner.replayed_authorization_metadata(authorization_id)
    }
}

struct GatedOracle {
    inner: MovingOracle,
    gate: Arc<Gate>,
}

/// Dates each gated quote this far before it is read, so a quote taken after
/// a park never postdates the trusted time sampled before the call.
const QUOTE_AGE_SECS: u64 = 60;

impl PriceOracle for GatedOracle {
    fn get_rate<'a>(&'a self, base: &'a str, quote: &'a str) -> chio_link::OracleFuture<'a> {
        let parked = self.gate.park(&format!("{base}/{quote}"));
        let rate = self.inner.get_rate(base, quote);
        Box::pin(async move {
            parked.map_err(chio_link::PriceOracleError::InvalidConfiguration)?;
            let mut rate = rate.await?;
            rate.updated_at = rate.updated_at.saturating_sub(QUOTE_AGE_SECS);
            rate.fetched_at = rate.fetched_at.saturating_sub(QUOTE_AGE_SECS);
            Ok(rate)
        })
    }

    fn supported_pairs(&self) -> Vec<String> {
        self.inner.supported_pairs()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum MutationLockProbe {
    /// An independent acquisition on the same fence finished while operation
    /// A was still parked inside the external call.
    AcquiredWhileParked,
    /// The acquisition stayed blocked for `PROBE_BOUND` while A was parked and
    /// finished only after the gate let A return from the external call.
    HeldUntilGateOpened,
}

fn probe_mutation_lock(
    gate: &Gate,
    fence: &StoreMutationFence,
) -> Result<MutationLockProbe, Box<dyn std::error::Error>> {
    let sequencer = AdmissionMutationSequencer::for_fence(fence)?;
    let (sender, acquired) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(
            sequencer
                .lock()
                .map(drop)
                .map_err(|error| error.to_string()),
        );
    });
    match acquired.recv_timeout(PROBE_BOUND) {
        Ok(result) => {
            result?;
            assert_eq!(
                gate.parked()?,
                1,
                "operation A left the external call before the probe acquired the lock"
            );
            Ok(MutationLockProbe::AcquiredWhileParked)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            assert_eq!(
                gate.parked()?,
                1,
                "operation A left the external call during the probe bound"
            );
            gate.open();
            acquired.recv_timeout(SETTLE_BOUND).map_err(|_| {
                "the fence mutation lock stayed held after the external call returned"
            })??;
            Ok(MutationLockProbe::HeldUntilGateOpened)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("the mutation lock probe exited without a result".into())
        }
    }
}

fn run_operation_a<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> mpsc::Receiver<T> {
    let (sender, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    finished
}

fn wait_for_entry<T: std::fmt::Debug>(
    gate: &Gate,
    finished: &mpsc::Receiver<T>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    gate.wait_entered().map_err(|missing| {
        let outcome = finished.recv_timeout(Duration::from_millis(100));
        format!("{missing}; operation A outcome: {outcome:?}").into()
    })
}

/// Moves the fixture onto a fence no other test shares, so the probe measures
/// only operation A's hold on the sequencer.
fn isolated_fence(
    kernel: &mut ChioKernel,
    store: &Arc<TestAdmissionOperationStore>,
    name: &str,
) -> Result<StoreMutationFence, Box<dyn std::error::Error>> {
    let fence = StoreMutationFence {
        store_uuid: format!("external-call-lock-{name}"),
        lease_id: "external-call-lock-lease".into(),
        owner_epoch: 1,
    };
    store.rotate_fence(fence.clone());
    kernel.set_durable_admission_store(store.clone(), store.clone(), fence.clone())?;
    Ok(fence)
}

#[test]
fn rail_capture_leaves_the_fence_mutation_lock_free() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("external-call-lock-capture", false);
    let fence = isolated_fence(&mut kernel, &store, "capture")?;
    let gate = Arc::new(Gate::default());
    let _open = OpenOnDrop(gate.clone());
    kernel.set_payment_adapter(Box::new(GatedRail {
        inner: RecoveryRail {
            prepaid: false,
            calls: calls.clone(),
        },
        gate: gate.clone(),
        gated: GatedCall::Capture,
    }));
    let finished = run_operation_a(move || {
        kernel
            .evaluate_tool_call_blocking(&request)
            .map(|response| response.verdict)
            .map_err(|error| error.to_string())
    });

    let entered = wait_for_entry(&gate, &finished)?;
    let operation = store.operation();
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    assert_eq!(entered, [operation_id.as_str()]);
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    let journal = store.payment_journal().ok_or("settling journal")?;
    assert_eq!(
        (
            journal.state,
            journal.settle_action,
            journal.settle_amount_units
        ),
        (
            PaymentJournalState::Settling,
            Some(PaymentSettleAction::Capture),
            Some(10)
        )
    );
    assert_eq!(calls.captures.lock().map_err(|_| "capture lock")?.len(), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let probe = probe_mutation_lock(&gate, &fence)?;
    gate.open();
    let outcome = finished.recv_timeout(SETTLE_BOUND);
    assert_eq!(
        probe,
        MutationLockProbe::AcquiredWhileParked,
        "the fence admission mutation lock was not acquirable within {PROBE_BOUND:?} while operation A was parked inside the payment rail capture"
    );
    assert_eq!(outcome?, Ok(Verdict::Allow));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(
        calls
            .captures
            .lock()
            .map_err(|_| "capture lock")?
            .as_slice(),
        [(operation_id, 10)]
    );
    Ok(())
}

#[test]
fn price_oracle_rate_leaves_the_fence_mutation_lock_free() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("external-call-lock-oracle", false);
    let fence = isolated_fence(&mut kernel, &store, "oracle")?;
    let gate = Arc::new(Gate::default());
    let _open = OpenOnDrop(gate.clone());
    let oracle_calls = Arc::new(AtomicU64::new(0));
    kernel.set_price_oracle(Box::new(GatedOracle {
        inner: MovingOracle {
            rate: Arc::new(AtomicU64::new(10)),
            calls: oracle_calls.clone(),
        },
        gate: gate.clone(),
    }));
    kernel.register_tool_server(Box::new(ReportedCostServer {
        units: 1_000_000_000_000_000,
        currency: "ETH",
        invocations: invocations.clone(),
    }));
    let finished = run_operation_a(move || {
        kernel
            .evaluate_tool_call_blocking(&request)
            .map(|response| response.verdict)
            .map_err(|error| error.to_string())
    });

    let entered = wait_for_entry(&gate, &finished)?;
    let operation = store.operation();
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    assert_eq!(entered, ["ETH/USD"]);
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    let journal = store.payment_journal().ok_or("authorized journal")?;
    assert_eq!(
        (journal.state, journal.settle_action),
        (PaymentJournalState::Authorized, None)
    );
    assert_eq!(oracle_calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.captures.lock().map_err(|_| "capture lock")?.len(), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let probe = probe_mutation_lock(&gate, &fence)?;
    gate.open();
    let outcome = finished.recv_timeout(SETTLE_BOUND);
    assert_eq!(
        probe,
        MutationLockProbe::AcquiredWhileParked,
        "the fence admission mutation lock was not acquirable within {PROBE_BOUND:?} while operation A was parked inside the price oracle get_rate"
    );
    assert_eq!(outcome?, Ok(Verdict::Allow));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(oracle_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        calls
            .captures
            .lock()
            .map_err(|_| "capture lock")?
            .as_slice(),
        [(operation_id, 1)]
    );
    Ok(())
}

#[test]
fn pre_dispatch_rail_release_leaves_the_fence_mutation_lock_free() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("external-call-lock-release", false);
    let fence = isolated_fence(&mut kernel, &store, "release")?;
    let gate = Arc::new(Gate::default());
    let _open = OpenOnDrop(gate.clone());
    kernel.set_payment_adapter(Box::new(GatedRail {
        inner: RecoveryRail {
            prepaid: false,
            calls: calls.clone(),
        },
        gate: gate.clone(),
        gated: GatedCall::Release,
    }));
    authorize_without_dispatch(&kernel, &request)?;
    let operation = store.operation();
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    assert_eq!(operation.state(), AdmissionOperationState::BudgetAuthorized);
    let finished = run_operation_a(move || {
        kernel
            .compensate_durable_admission_before_dispatch(
                &operation,
                serde_json::json!({"authority": "external-call-lock"}),
                current_unix_timestamp_ms(),
                None,
                compensation_response(),
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    });

    let entered = wait_for_entry(&gate, &finished)?;
    assert_eq!(entered, [operation_id.as_str()]);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::BudgetAuthorized
    );
    let journal = store.payment_journal().ok_or("releasing journal")?;
    assert_eq!(
        (journal.state, journal.settle_action),
        (
            PaymentJournalState::Settling,
            Some(PaymentSettleAction::Release)
        )
    );
    assert_eq!(calls.releases.lock().map_err(|_| "release lock")?.len(), 0);

    let probe = probe_mutation_lock(&gate, &fence)?;
    gate.open();
    let outcome = finished.recv_timeout(SETTLE_BOUND);
    assert_eq!(
        probe,
        MutationLockProbe::AcquiredWhileParked,
        "the fence admission mutation lock was not acquirable within {PROBE_BOUND:?} while operation A was parked inside the pre-dispatch rail release"
    );
    assert_eq!(outcome?, Ok(()));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        calls
            .releases
            .lock()
            .map_err(|_| "release lock")?
            .as_slice(),
        [operation_id]
    );
    assert_released_budget(&store)?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[path = "external_call_lock/regression_guards.rs"]
mod regression_guards;
