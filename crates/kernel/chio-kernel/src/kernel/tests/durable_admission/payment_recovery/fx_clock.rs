//! Oracle freshness is judged against trusted time observed with the quote.
//!
//! Trusted time starts at one sampled epoch and then moves only when the test
//! or the oracle moves it. Each quote read takes `ORACLE_IO_SECS` of trusted
//! time, so every freshness comparison is between exact instants.
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use serde_json::{json, Value};
use std::error::Error;

/// 0.001 ETH reported in wei. At 40 USD per ETH it converts to 4 cents.
const REPORTED_WEI: u64 = 1_000_000_000_000_000;
const USD_PER_ETH: u64 = 40;
const CONVERTED_CENTS: u64 = 4;
/// The durable grant's original hold. A failed conversion captures all of it.
const AUTHORIZED_CENTS: u64 = 10;
/// The ordinary grant's provisional charge. A failed conversion keeps all of it.
const PROVISIONAL_CENTS: u64 = 400;
const ORACLE_IO_SECS: u64 = 2;
/// Trusted time after which recovery may take over the original claim.
const CLAIM_EXPIRY_SECS: u64 = 61;
const FUTURE_QUOTE: &str = "ETH/USD returned a future updated_at timestamp";

type Fallible<T> = Result<T, Box<dyn Error>>;
type DurablePricing = (Vec<(String, u64)>, Value, Value, Value);

/// Trusted wall time in milliseconds, or the fault a read reports. It
/// advances only when it is set.
struct SteppedClock(Mutex<Result<u64, ClockError>>);

impl SteppedClock {
    fn set_secs(&self, secs: u64) -> Result<(), ClockError> {
        let millis = UnixMillis::from_secs(secs)?.get();
        *self.0.lock().map_err(|_| ClockError::Unavailable)? = Ok(millis);
        Ok(())
    }

    fn secs(&self) -> Result<u64, ClockError> {
        Ok(self.read()?.unix_millis().as_secs())
    }
}

impl Clock for SteppedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let millis = (*self.0.lock().map_err(|_| ClockError::Unavailable)?)?;
        let nanos = millis.checked_mul(1_000_000).ok_or(ClockError::Overflow)?;
        Ok(ClockReading::new(
            UnixMillis::new(millis),
            MonotonicInstant::from_nanos(nanos),
        ))
    }
}

/// Where a quote's `updated_at` falls relative to the oracle read.
#[derive(Clone, Copy)]
enum QuoteStamp {
    ReadStart,
    ReadEnd,
    AfterReadEnd(u64),
    ReadEndWithClockFault(ClockError),
    ReadEndWithClockRegression,
}

struct OracleRead {
    started_at: u64,
    completed_at: u64,
    quote: ExchangeRate,
}

/// Reads one quote while `ORACLE_IO_SECS` of trusted time pass.
struct ClockAdvancingOracle {
    clock: Arc<SteppedClock>,
    usd_per_eth: Arc<AtomicU64>,
    stamp: QuoteStamp,
    reads: Arc<Mutex<Vec<OracleRead>>>,
}

impl PriceOracle for ClockAdvancingOracle {
    fn get_rate<'a>(&'a self, base: &'a str, quote: &'a str) -> chio_link::OracleFuture<'a> {
        Box::pin(async move {
            let clock_fault =
                |_: ClockError| PriceOracleError::Unavailable("test oracle clock".into());
            let started_at = self.clock.secs().map_err(clock_fault)?;
            let completed_at = started_at + ORACLE_IO_SECS;
            self.clock.set_secs(completed_at).map_err(clock_fault)?;
            let updated_at = match self.stamp {
                QuoteStamp::ReadStart => started_at,
                QuoteStamp::ReadEnd
                | QuoteStamp::ReadEndWithClockFault(_)
                | QuoteStamp::ReadEndWithClockRegression => completed_at,
                QuoteStamp::AfterReadEnd(secs) => completed_at + secs,
            };
            let rate = ExchangeRate {
                base: base.into(),
                quote: quote.into(),
                rate_numerator: u128::from(self.usd_per_eth.load(Ordering::SeqCst)),
                rate_denominator: 1,
                updated_at,
                fetched_at: completed_at,
                source: "fx-clock-oracle".into(),
                feed_reference: "advancing-feed".into(),
                max_age_seconds: 600,
                conversion_margin_bps: 0,
                confidence_numerator: None,
                confidence_denominator: None,
            };
            self.reads
                .lock()
                .map_err(|_| PriceOracleError::Unavailable("test oracle log".into()))?
                .push(OracleRead {
                    started_at,
                    completed_at,
                    quote: rate.clone(),
                });
            match self.stamp {
                QuoteStamp::ReadEndWithClockFault(error) => {
                    *self.clock.0.lock().map_err(|_| {
                        PriceOracleError::Unavailable("test oracle clock lock".into())
                    })? = Err(error);
                }
                QuoteStamp::ReadEndWithClockRegression => {
                    let regressed = started_at.checked_sub(1).ok_or_else(|| {
                        PriceOracleError::Unavailable("test oracle clock regression".into())
                    })?;
                    self.clock.set_secs(regressed).map_err(clock_fault)?;
                }
                _ => {}
            }
            Ok(rate)
        })
    }

    fn supported_pairs(&self) -> Vec<String> {
        vec!["ETH/USD".into()]
    }
}

/// One sampled epoch, the trusted clock that starts there, and its reads.
struct Timeline {
    start: u64,
    clock: Arc<SteppedClock>,
    reads: Arc<Mutex<Vec<OracleRead>>>,
}

impl Timeline {
    fn new() -> Fallible<Self> {
        let start = chio_test_support::clock::unix_seconds();
        Ok(Self {
            start,
            clock: Arc::new(SteppedClock(Mutex::new(Ok(
                UnixMillis::from_secs(start)?.get()
            )))),
            reads: Arc::default(),
        })
    }

    fn oracle(&self, stamp: QuoteStamp, usd_per_eth: &Arc<AtomicU64>) -> Box<dyn PriceOracle> {
        Box::new(ClockAdvancingOracle {
            clock: self.clock.clone(),
            usd_per_eth: usd_per_eth.clone(),
            stamp,
            reads: self.reads.clone(),
        })
    }

    /// Each read as (started_at, completed_at, pair, updated_at).
    fn reads(&self) -> Fallible<Vec<(u64, u64, String, u64)>> {
        Ok(self
            .reads
            .lock()
            .map_err(|_| "oracle read log")?
            .iter()
            .map(|read| {
                (
                    read.started_at,
                    read.completed_at,
                    read.quote.pair(),
                    read.quote.updated_at,
                )
            })
            .collect())
    }

    fn last_quote(&self) -> Fallible<ExchangeRate> {
        Ok(self
            .reads
            .lock()
            .map_err(|_| "oracle read log")?
            .last()
            .ok_or("oracle quote")?
            .quote
            .clone())
    }
}

/// Precondition: pricing consulted the oracle exactly once, trusted time moved
/// only during that read, and the returned quote is refused as future at the
/// instant the read began.
fn assert_single_read(
    timeline: &Timeline,
    kernel: &ChioKernel,
    started_at: u64,
    updated_at: u64,
) -> Fallible<ExchangeRate> {
    let completed_at = started_at + ORACLE_IO_SECS;
    assert_eq!(
        timeline.reads()?,
        [(started_at, completed_at, "ETH/USD".to_owned(), updated_at)]
    );
    assert_eq!(
        kernel.read_authority_time().map(UnixMillis::get),
        Ok(completed_at * 1_000)
    );
    let quote = timeline.last_quote()?;
    assert!(matches!(
        quote.ensure_fresh(started_at),
        Err(PriceOracleError::InvalidFeed(detail)) if detail == FUTURE_QUOTE
    ));
    Ok(quote)
}

struct DurableFx {
    timeline: Timeline,
    kernel: ChioKernel,
    request: ToolCallRequest,
    store: Arc<TestAdmissionOperationStore>,
    invocations: Arc<AtomicU64>,
    calls: Arc<RailCalls>,
    usd_per_eth: Arc<AtomicU64>,
}

fn durable_fx(name: &str, stamp: QuoteStamp) -> Fallible<DurableFx> {
    let timeline = Timeline::new()?;
    let usd_per_eth = Arc::new(AtomicU64::new(USD_PER_ETH));
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: AUTHORIZED_CENTS,
        currency: "USD".into(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".into(),
    });
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut kernel = ChioKernel::new_with_clock(config, timeline.clock.clone());
    kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    let fence = admission_test_fence();
    let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel.set_durable_admission_store(store.clone(), store.clone(), fence)?;
    kernel.set_budget_store_handle(store.budget_store());
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(ReportedCostServer {
        units: REPORTED_WEI,
        currency: "ETH",
        invocations: invocations.clone(),
    }));
    let calls = Arc::new(RailCalls::default());
    kernel.set_payment_adapter(Box::new(RecoveryRail {
        prepaid: false,
        calls: calls.clone(),
    }));
    kernel.set_price_oracle(timeline.oracle(stamp, &usd_per_eth));
    let capability =
        kernel.issue_capability(&make_keypair().public_key(), make_scope(vec![grant]), 300)?;
    let request = make_request_with_arguments(
        name,
        &capability,
        "mutate",
        "durable-server",
        json!({"record": "ledger-7", "value": "settled"}),
    );
    Ok(DurableFx {
        timeline,
        kernel,
        request,
        store,
        invocations,
        calls,
        usd_per_eth,
    })
}

impl DurableFx {
    fn operation_id(&self) -> String {
        self.store
            .operation()
            .binding()
            .operation_id()
            .as_str()
            .to_owned()
    }

    fn captures(&self) -> Fallible<Vec<(String, u64)>> {
        Ok(self
            .calls
            .captures
            .lock()
            .map_err(|_| "capture trace")?
            .clone())
    }

    /// The capture trace and the terminal receipt's pricing outcome.
    fn pricing(&self, response: &ToolCallResponse) -> Fallible<DurablePricing> {
        let financial = &response
            .receipt
            .metadata
            .as_ref()
            .ok_or("financial metadata")?["financial"];
        Ok((
            self.captures()?,
            financial["settlement_status"].clone(),
            financial["cost_breakdown"]["payment"]["pricing_failure"].clone(),
            financial["oracle_evidence"]["updated_at"].clone(),
        ))
    }

    fn converted(&self, updated_at: u64, captures: usize) -> DurablePricing {
        (
            vec![(self.operation_id(), CONVERTED_CENTS); captures],
            json!("settled"),
            Value::Null,
            json!(updated_at),
        )
    }
}

/// A read that began at `started_at` returned a quote stamped when it ended.
/// That quote is current at the decision and must price the capture.
fn assert_durable_read_priced(
    fx: &DurableFx,
    response: &ToolCallResponse,
    started_at: u64,
) -> TestResult {
    let completed_at = started_at + ORACLE_IO_SECS;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(fx.invocations.load(Ordering::SeqCst), 1);
    let quote = assert_single_read(&fx.timeline, &fx.kernel, started_at, completed_at)?;
    assert!(matches!(quote.ensure_fresh(completed_at), Ok(())));
    assert_eq!(
        fx.store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(fx.pricing(response)?, fx.converted(completed_at, 1));
    assert_eq!(
        fx.store
            .payment_journal()
            .ok_or("settled journal")?
            .settle_amount_units,
        Some(CONVERTED_CENTS)
    );
    Ok(())
}

struct OrdinaryFx {
    timeline: Timeline,
    kernel: ChioKernel,
    request: ToolCallRequest,
}

fn ordinary_fx(name: &str, stamp: QuoteStamp) -> Fallible<OrdinaryFx> {
    let timeline = Timeline::new()?;
    let mut kernel = ChioKernel::new_with_clock(make_monetary_config(), timeline.clock.clone());
    kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    kernel.set_price_oracle(timeline.oracle(stamp, &Arc::new(AtomicU64::new(USD_PER_ETH))));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(
        "cost-srv",
        REPORTED_WEI,
        "ETH",
    )));
    let grant = make_monetary_grant("cost-srv", "compute", PROVISIONAL_CENTS, 1_000, "USD");
    let capability = kernel.issue_capability(
        &Keypair::generate().public_key(),
        make_scope(vec![grant]),
        3_600,
    )?;
    let request = make_request_with_arguments(name, &capability, "compute", "cost-srv", json!({}));
    Ok(OrdinaryFx {
        timeline,
        kernel,
        request,
    })
}

/// The ordinary receipt's charge, conversion outcome, and priced quote.
fn ordinary_pricing(response: &ToolCallResponse) -> Fallible<(Value, Value, Value, Value, Value)> {
    let financial = &response
        .receipt
        .metadata
        .as_ref()
        .ok_or("financial metadata")?["financial"];
    let conversion = &financial["cost_breakdown"]["oracle_conversion"];
    Ok((
        financial["cost_charged"].clone(),
        financial["settlement_status"].clone(),
        conversion["status"].clone(),
        conversion["reason"].clone(),
        financial["oracle_evidence"]["updated_at"].clone(),
    ))
}

/// The ordinary path began pricing at the evaluation's first trusted reading.
fn assert_ordinary_read_priced(fx: &OrdinaryFx, response: &ToolCallResponse) -> TestResult {
    let started_at = fx.timeline.start;
    let completed_at = started_at + ORACLE_IO_SECS;
    assert_eq!(response.verdict, Verdict::Allow);
    let quote = assert_single_read(&fx.timeline, &fx.kernel, started_at, completed_at)?;
    assert!(matches!(quote.ensure_fresh(completed_at), Ok(())));
    assert_eq!(
        ordinary_pricing(response)?,
        (
            json!(CONVERTED_CENTS),
            json!("settled"),
            json!("applied"),
            Value::Null,
            json!(completed_at)
        )
    );
    Ok(())
}

fn evaluate_nested(kernel: &ChioKernel, request: &ToolCallRequest) -> Fallible<ToolCallResponse> {
    let session =
        kernel.open_session(request.agent_id.clone(), vec![request.capability.clone()])?;
    kernel.activate_session(&session)?;
    let parent = make_operation_context(
        &session,
        &format!("{}-parent", request.request_id),
        &request.agent_id,
    );
    kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
    Ok(kernel.evaluate_tool_call_with_nested_flow_client(
        &parent,
        request,
        &mut NoopNestedFlowClient,
        None,
    )?)
}

#[test]
fn durable_live_return_prices_a_quote_stamped_during_oracle_io() -> TestResult {
    let fx = durable_fx("fx-clock-durable-live", QuoteStamp::ReadEnd)?;
    let response = fx.kernel.evaluate_tool_call_blocking(&fx.request)?;
    assert_durable_read_priced(&fx, &response, fx.timeline.start)
}

#[test]
fn durable_nested_return_prices_a_quote_stamped_during_oracle_io() -> TestResult {
    let fx = durable_fx("fx-clock-durable-nested", QuoteStamp::ReadEnd)?;
    let response = evaluate_nested(&fx.kernel, &fx.request)?;
    assert_durable_read_priced(&fx, &response, fx.timeline.start)
}

#[test]
fn durable_recovery_prices_a_quote_stamped_during_oracle_io() -> TestResult {
    let fx = durable_fx("fx-clock-durable-recovery", QuoteStamp::ReadEnd)?;
    fx.store.fail_next_evaluation_begin();
    let error = fx
        .kernel
        .evaluate_tool_call_blocking(&fx.request)
        .err()
        .ok_or("injected evaluation begin failure was accepted")?;
    assert!(matches!(error, KernelError::AdmissionRecovery(failure)
        if matches!(failure.as_ref(), crate::admission_operation::AdmissionRecoveryError::Outcome(
            crate::tool_outcome::ToolOutcomeStoreError::Unavailable(detail)
        ) if detail == "injected evaluation begin failure")));
    assert_eq!(
        fx.store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(fx.timeline.reads()?.len(), 0);
    assert_eq!(fx.captures()?.len(), 0);
    let recovery_start = fx.timeline.start + CLAIM_EXPIRY_SECS;
    fx.timeline.clock.set_secs(recovery_start)?;
    assert_eq!(fx.kernel.reconcile_recoverable_admissions()?, 1);
    let replay = fx.kernel.evaluate_tool_call_blocking(&fx.request)?;
    assert_durable_read_priced(&fx, &replay, recovery_start)
}

#[test]
fn ordinary_return_prices_a_quote_stamped_during_oracle_io() -> TestResult {
    let fx = ordinary_fx("fx-clock-ordinary", QuoteStamp::ReadEnd)?;
    let response = fx.kernel.evaluate_tool_call_blocking(&fx.request)?;
    assert_ordinary_read_priced(&fx, &response)
}

#[test]
fn ordinary_nested_return_prices_a_quote_stamped_during_oracle_io() -> TestResult {
    let fx = ordinary_fx("fx-clock-ordinary-nested", QuoteStamp::ReadEnd)?;
    let response = evaluate_nested(&fx.kernel, &fx.request)?;
    assert_ordinary_read_priced(&fx, &response)
}

#[test]
fn durable_return_refuses_a_quote_stamped_after_oracle_io() -> TestResult {
    let fx = durable_fx("fx-clock-durable-future", QuoteStamp::AfterReadEnd(1))?;
    let response = fx.kernel.evaluate_tool_call_blocking(&fx.request)?;
    let started_at = fx.timeline.start;
    let completed_at = started_at + ORACLE_IO_SECS;
    assert_eq!(response.verdict, Verdict::Allow);
    let quote = assert_single_read(&fx.timeline, &fx.kernel, started_at, completed_at + 1)?;
    assert!(matches!(
        quote.ensure_fresh(completed_at),
        Err(PriceOracleError::InvalidFeed(detail)) if detail == FUTURE_QUOTE
    ));
    assert_eq!(
        fx.pricing(&response)?,
        (
            vec![(fx.operation_id(), AUTHORIZED_CENTS)],
            json!("failed"),
            json!("conversion_unavailable"),
            Value::Null
        )
    );
    Ok(())
}

#[test]
fn ordinary_return_refuses_a_quote_stamped_after_oracle_io() -> TestResult {
    let fx = ordinary_fx("fx-clock-ordinary-future", QuoteStamp::AfterReadEnd(1))?;
    let response = fx.kernel.evaluate_tool_call_blocking(&fx.request)?;
    let started_at = fx.timeline.start;
    let completed_at = started_at + ORACLE_IO_SECS;
    assert_eq!(response.verdict, Verdict::Allow);
    let quote = assert_single_read(&fx.timeline, &fx.kernel, started_at, completed_at + 1)?;
    assert!(matches!(
        quote.ensure_fresh(completed_at),
        Err(PriceOracleError::InvalidFeed(detail)) if detail == FUTURE_QUOTE
    ));
    assert_eq!(
        ordinary_pricing(&response)?,
        (
            json!(PROVISIONAL_CENTS),
            json!("failed"),
            json!("failed"),
            json!(format!(
                "cross-currency budget enforcement failed: invalid feed response: {FUTURE_QUOTE}"
            )),
            Value::Null
        )
    );
    Ok(())
}

#[test]
fn resolved_durable_pricing_replays_without_a_live_quote() -> TestResult {
    let fx = durable_fx("fx-clock-durable-replay", QuoteStamp::ReadStart)?;
    fx.calls.capture_pending.store(true, Ordering::SeqCst);
    let error = fx
        .kernel
        .evaluate_tool_call_blocking(&fx.request)
        .err()
        .ok_or("pending payment capture was accepted")?;
    assert!(matches!(error, KernelError::AdmissionRecovery(failure)
        if matches!(failure.as_ref(), crate::admission_operation::AdmissionRecoveryError::Item {
            kind: crate::admission_operation::AdmissionRecoveryFailureKind::PaymentPending,
            detail,
        } if detail == "payment settlement remains pending")));
    let started_at = fx.timeline.start;
    let reads = [(
        started_at,
        started_at + ORACLE_IO_SECS,
        "ETH/USD".to_owned(),
        started_at,
    )];
    assert_eq!(fx.timeline.reads()?, reads);
    assert_eq!(
        fx.store
            .payment_journal()
            .ok_or("pending journal")?
            .settle_amount_units,
        Some(CONVERTED_CENTS)
    );
    fx.usd_per_eth.store(USD_PER_ETH * 2, Ordering::SeqCst);
    let replay = fx.kernel.evaluate_tool_call_blocking(&fx.request)?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(
        fx.store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(fx.timeline.reads()?, reads);
    assert_eq!(fx.pricing(&replay)?, fx.converted(started_at, 2));
    assert_eq!(fx.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

/// The quote is valid at completion; only the fenced authority clock fails.
fn assert_quote_completed_before_clock_fault(
    timeline: &Timeline,
    kernel: &ChioKernel,
    expected: ClockError,
) -> TestResult {
    let completed_at = timeline.start + ORACLE_IO_SECS;
    assert_eq!(
        timeline.reads()?,
        [(
            timeline.start,
            completed_at,
            "ETH/USD".to_owned(),
            completed_at
        )]
    );
    timeline.last_quote()?.ensure_fresh(completed_at)?;
    assert_eq!(kernel.read_authority_time(), Err(expected));
    Ok(())
}

fn assert_durable_quote_clock_fault(stamp: QuoteStamp, expected: ClockError) -> TestResult {
    let fx = durable_fx("fx-clock-durable-global-fault", stamp)?;
    let result = fx.kernel.evaluate_tool_call_blocking(&fx.request);
    assert!(
        matches!(&result, Err(KernelError::Clock(error)) if *error == expected),
        "{result:?}"
    );
    assert_quote_completed_before_clock_fault(&fx.timeline, &fx.kernel, expected)?;
    assert!(fx.captures()?.is_empty());
    assert_eq!(fx.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        fx.store
            .payment_journal()
            .ok_or("unresolved payment journal")?
            .settle_amount_units,
        None
    );
    let operation = fx.store.operation();
    let outcome = fx
        .store
        .lookup_by_operation(operation.binding().operation_id())?
        .ok_or("unresolved raw outcome")?;
    assert!(matches!(
        outcome.disposition(),
        ResolvedToolOutcomeV1::Returned
    ));
    Ok(())
}

fn assert_ordinary_quote_clock_fault(stamp: QuoteStamp, expected: ClockError) -> TestResult {
    let fx = ordinary_fx("fx-clock-ordinary-global-fault", stamp)?;
    let result = fx.kernel.evaluate_tool_call_blocking(&fx.request);
    assert!(
        matches!(&result, Err(KernelError::Clock(error)) if *error == expected),
        "{result:?}"
    );
    assert_quote_completed_before_clock_fault(&fx.timeline, &fx.kernel, expected)?;
    let usage = fx
        .kernel
        .budget_store
        .get_usage(&fx.request.capability.id, 0)?
        .ok_or("retained provisional budget exposure")?;
    assert_eq!(usage.total_cost_exposed, PROVISIONAL_CENTS);
    assert_eq!(usage.total_cost_realized_spend, 0);
    assert!(fx.kernel.receipt_log().is_empty());
    Ok(())
}

#[test]
fn durable_quote_clock_unavailability_stays_global_before_settlement() -> TestResult {
    assert_durable_quote_clock_fault(
        QuoteStamp::ReadEndWithClockFault(ClockError::Unavailable),
        ClockError::Unavailable,
    )
}

#[test]
fn durable_quote_clock_regression_stays_global_before_settlement() -> TestResult {
    assert_durable_quote_clock_fault(
        QuoteStamp::ReadEndWithClockRegression,
        ClockError::WallClockRegression,
    )
}

#[test]
fn ordinary_quote_clock_unavailability_stays_global_before_budget_reconciliation() -> TestResult {
    assert_ordinary_quote_clock_fault(
        QuoteStamp::ReadEndWithClockFault(ClockError::Unavailable),
        ClockError::Unavailable,
    )
}

#[test]
fn ordinary_quote_clock_regression_stays_global_before_budget_reconciliation() -> TestResult {
    assert_ordinary_quote_clock_fault(
        QuoteStamp::ReadEndWithClockRegression,
        ClockError::WallClockRegression,
    )
}
