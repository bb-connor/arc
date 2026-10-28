use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use chio_kernel::{
    ExecutionNonceStore, PaymentAdapter, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, X402Eip3009Authorization, X402ExactEvmPayload, X402Network, X402PaymentAdapter,
    X402PaymentContext, X402PaymentPayload, X402PaymentRequirements, X402RailConfig, X402Refusal,
    DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
};
use chio_security_types::clock::{
    Clock, ClockError, ClockReading, FixedClock, MonotonicInstant, UnixMillis,
};
use chio_store_sqlite::SqliteExecutionNonceStore;

type TestResult = Result<(), Box<dyn Error>>;

const NETWORK: &str = "eip155:84532";
const ASSET: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const PAY_TO: &str = "0x2000000000000000000000000000000000000002";
const PAYER: &str = "0x1000000000000000000000000000000000000001";
const NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_NONCE: &str = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const TRANSACTION: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VALID_AFTER: u64 = 1_744_000_000;
const VALID_BEFORE: u64 = 1_744_000_600;
const NOW: u64 = VALID_AFTER + 60;
const UNREACHABLE: &str = "http://127.0.0.1:1";

fn clock() -> Arc<dyn Clock> {
    Arc::new(FixedClock::from_millis(NOW * 1_000))
}

fn adapter(
    facilitator: &str,
    replay: Arc<dyn ExecutionNonceStore>,
) -> Result<X402PaymentAdapter, Box<dyn Error>> {
    adapter_at(facilitator, replay, clock())
}

fn adapter_at(
    facilitator: &str,
    replay: Arc<dyn ExecutionNonceStore>,
    clock: Arc<dyn Clock>,
) -> Result<X402PaymentAdapter, Box<dyn Error>> {
    let rail = X402RailConfig::new(X402Network::allowlisted(NETWORK)?, ASSET, "USDC", 6, PAY_TO)?;
    Ok(X402PaymentAdapter::new(
        facilitator,
        rail,
        &chio_kernel::payment::EgressAllowanceSet::default(),
        clock,
        replay,
    )?
    .with_timeout(Duration::from_secs(2)))
}

fn open_store(path: &std::path::Path) -> Result<Arc<dyn ExecutionNonceStore>, Box<dyn Error>> {
    open_store_at(path, clock())
}

fn open_store_at(
    path: &std::path::Path,
    clock: Arc<dyn Clock>,
) -> Result<Arc<dyn ExecutionNonceStore>, Box<dyn Error>> {
    Ok(Arc::new(SqliteExecutionNonceStore::open_with_clock(
        path,
        DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
        clock,
    )?))
}

fn request(nonce: &str) -> PaymentAuthorizeRequest {
    expiring_request(nonce, VALID_BEFORE)
}

fn expiring_request(nonce: &str, valid_before: u64) -> PaymentAuthorizeRequest {
    let requirements = X402PaymentRequirements {
        scheme: "exact".to_owned(),
        network: NETWORK.to_owned(),
        amount: "125".to_owned(),
        asset: ASSET.to_owned(),
        pay_to: PAY_TO.to_owned(),
        max_timeout_seconds: 60,
        extra: None,
    };
    PaymentAuthorizeRequest {
        amount_units: 125,
        currency: "USDC".to_owned(),
        payer: "agent-1".to_owned(),
        payee: "tool-server".to_owned(),
        reference: "operation-1".to_owned(),
        governed: None,
        commerce: None,
        x402: Some(X402PaymentContext {
            payment_payload: X402PaymentPayload {
                x402_version: 2,
                resource: None,
                accepted: requirements.clone(),
                payload: X402ExactEvmPayload {
                    signature: format!("0x{}", "c".repeat(130)),
                    authorization: X402Eip3009Authorization {
                        from: PAYER.to_owned(),
                        to: PAY_TO.to_owned(),
                        value: "125".to_owned(),
                        valid_after: VALID_AFTER.to_string(),
                        valid_before: valid_before.to_string(),
                        nonce: nonce.to_owned(),
                    },
                },
                extensions: None,
            },
            payment_requirements: requirements,
        }),
        authority_expires_at: Some(VALID_BEFORE),
        reference_is_durable: true,
    }
}

/// Facilitator stub that answers every `/verify` as valid and every
/// `/settle` as settled, counting settlements, until it is stopped.
struct Facilitator {
    url: String,
    settlements: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<Result<(), String>>,
}

impl Facilitator {
    fn spawn() -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let settlements = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let settlements = settlements.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => answer(stream, &settlements)?,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => return Err(error.to_string()),
                    }
                }
                Ok(())
            })
        };
        Ok(Self {
            url,
            settlements,
            stop,
            handle,
        })
    }

    fn finish(self) -> Result<usize, Box<dyn Error>> {
        self.stop.store(true, Ordering::SeqCst);
        self.handle
            .join()
            .map_err(|_| "facilitator stub panicked")??;
        Ok(self.settlements.load(Ordering::SeqCst))
    }
}

fn answer(mut stream: TcpStream, settlements: &AtomicUsize) -> Result<(), String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let mut received = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !request_is_complete(&received) {
        let read = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..read]);
    }
    let body = if received.starts_with(b"POST /settle ") {
        settlements.fetch_add(1, Ordering::SeqCst);
        serde_json::json!({
            "success": true,
            "payer": PAYER,
            "transaction": TRANSACTION,
            "network": NETWORK,
        })
    } else {
        serde_json::json!({ "isValid": true })
    }
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| error.to_string())
}

fn request_is_complete(received: &[u8]) -> bool {
    let text = String::from_utf8_lossy(received);
    let Some(header_end) = text.find("\r\n\r\n") else {
        return false;
    };
    let content_length = text[..header_end]
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    received.len() >= header_end + 4 + content_length
}

fn settle_once(replay: Arc<dyn ExecutionNonceStore>, nonce: &str) -> TestResult {
    let facilitator = Facilitator::spawn()?;
    let authorization = adapter(&facilitator.url, replay)?.authorize(&request(nonce))?;
    assert_eq!(facilitator.finish()?, 1);
    assert_eq!(authorization.state, PaymentAuthorizationState::PrepaidFinal);
    Ok(())
}

fn is_nonce_reused(error: &PaymentError) -> bool {
    matches!(error, PaymentError::Declined(message) if *message == X402Refusal::NonceReused.to_string())
}

#[test]
fn x402_nonce_spent_before_a_restart_stays_spent() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("x402-replay.sqlite3");

    settle_once(open_store(&path)?, NONCE)?;

    let restarted = open_store(&path)?;
    let error = adapter(UNREACHABLE, restarted.clone())?
        .authorize(&request(NONCE))
        .err()
        .ok_or("a reused nonce must be refused after a restart")?;
    assert!(is_nonce_reused(&error), "unexpected refusal: {error:?}");

    settle_once(restarted, OTHER_NONCE)
}

#[test]
fn x402_concurrent_duplicates_on_one_store_settle_once() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("x402-replay.sqlite3");
    let facilitator = Facilitator::spawn()?;
    let start = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let adapter = adapter(&facilitator.url, open_store(&path)?)?;
        let start = start.clone();
        workers.push(thread::spawn(move || {
            start.wait();
            adapter.authorize(&request(NONCE))
        }));
    }
    let mut settled = 0;
    let mut reused = 0;
    for worker in workers {
        match worker.join().map_err(|_| "worker panicked")? {
            Ok(_) => settled += 1,
            Err(error) if is_nonce_reused(&error) => reused += 1,
            Err(error) => return Err(format!("unexpected refusal: {error:?}").into()),
        }
    }
    assert_eq!((settled, reused), (1, 1));
    assert_eq!(facilitator.finish()?, 1);
    Ok(())
}

/// Trusted clock whose wall and monotonic time advance together on demand.
struct AdvancingClock(AtomicU64);

impl Clock for AdvancingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let unix_secs = self.0.load(Ordering::SeqCst);
        let nanos = unix_secs
            .checked_mul(1_000_000_000)
            .ok_or(ClockError::Overflow)?;
        Ok(ClockReading::new(
            UnixMillis::from_secs(unix_secs)?,
            MonotonicInstant::from_nanos(nanos),
        ))
    }
}

#[test]
fn x402_nonce_outlives_its_first_expiry_across_a_reopen() -> TestResult {
    let short_valid_before = NOW + 100;
    let after_short_retention = short_valid_before + 61;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("x402-replay.sqlite3");
    let clock = Arc::new(AdvancingClock(AtomicU64::new(NOW)));

    let facilitator = Facilitator::spawn()?;
    adapter_at(
        &facilitator.url,
        open_store_at(&path, clock.clone())?,
        clock.clone(),
    )?
    .authorize(&expiring_request(NONCE, short_valid_before))?;
    assert_eq!(facilitator.finish()?, 1);

    clock.0.store(after_short_retention, Ordering::SeqCst);
    let reopened = open_store_at(&path, clock.clone())?;
    let error = adapter_at(UNREACHABLE, reopened.clone(), clock.clone())?
        .authorize(&expiring_request(NONCE, VALID_BEFORE))
        .err()
        .ok_or("the nonce must stay spent under a later expiry")?;
    assert!(is_nonce_reused(&error), "unexpected refusal: {error:?}");

    let facilitator = Facilitator::spawn()?;
    adapter_at(&facilitator.url, reopened, clock)?
        .authorize(&expiring_request(OTHER_NONCE, VALID_BEFORE))?;
    assert_eq!(facilitator.finish()?, 1);
    Ok(())
}
