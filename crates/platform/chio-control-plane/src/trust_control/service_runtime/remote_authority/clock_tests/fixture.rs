use super::*;
use chio_security_types::clock::{Clock, ClockReading, MonotonicInstant, UnixMillis};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;

const WAIT: Duration = Duration::from_secs(10);

pub(super) struct MutableClock {
    reading: Mutex<Result<ClockReading, ClockError>>,
    observed: Mutex<Option<Sender<()>>>,
}

impl MutableClock {
    pub(super) fn new() -> Self {
        Self {
            reading: Mutex::new(Ok(Self::reading_at(109_000))),
            observed: Mutex::new(None),
        }
    }

    fn reading_at(milliseconds: u64) -> ClockReading {
        ClockReading::new(
            UnixMillis::new(milliseconds),
            MonotonicInstant::from_nanos(milliseconds * 1_000_000),
        )
    }

    pub(super) fn set(&self, value: Result<u64, ClockError>) -> TestResult {
        *self.reading.lock().map_err(|_| "fixture clock poisoned")? = value.map(Self::reading_at);
        Ok(())
    }

    pub(super) fn observe_next_read(&self) -> TestResult<Receiver<()>> {
        let (sender, receiver) = mpsc::channel();
        *self
            .observed
            .lock()
            .map_err(|_| "clock observer poisoned")? = Some(sender);
        Ok(receiver)
    }
}

impl Clock for MutableClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let reading = *self.reading.lock().map_err(|_| ClockError::Unavailable)?;
        if let Some(observed) = self
            .observed
            .lock()
            .map_err(|_| ClockError::Unavailable)?
            .take()
        {
            let _ = observed.send(());
        }
        reading
    }
}

pub(super) struct StatusServer {
    address: SocketAddr,
    paused: Receiver<usize>,
    release: Option<Sender<()>>,
    stopped: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    thread: Option<JoinHandle<std::io::Result<()>>>,
}

impl StatusServer {
    pub(super) fn new(status: &TrustAuthorityStatus, pause_request: usize) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let body = serde_json::to_vec(status)?;
        let (paused_tx, paused) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let stopped = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let server_stopped = stopped.clone();
        let server_requests = requests.clone();
        let thread = std::thread::spawn(move || -> std::io::Result<()> {
            loop {
                let (mut stream, _) = listener.accept()?;
                if server_stopped.load(Ordering::SeqCst) {
                    return Ok(());
                }
                stream.set_read_timeout(Some(WAIT))?;
                stream.set_write_timeout(Some(WAIT))?;
                read_status_request(&mut stream)?;
                let request = server_requests.fetch_add(1, Ordering::SeqCst) + 1;
                if request == pause_request {
                    paused_tx.send(request).map_err(std::io::Error::other)?;
                    release_rx
                        .recv_timeout(WAIT)
                        .map_err(std::io::Error::other)?;
                }
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
                stream.write_all(&body)?;
            }
        });
        Ok(Self {
            address,
            paused,
            release: Some(release),
            stopped,
            requests,
            thread: Some(thread),
        })
    }

    pub(super) fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    pub(super) fn pause_and_change(
        &mut self,
        clock: &MutableClock,
        value: Result<u64, ClockError>,
    ) -> TestResult<usize> {
        let paused = self.paused.recv_timeout(WAIT);
        let changed = if paused.is_ok() {
            clock.set(value)
        } else {
            Ok(())
        };
        self.resume();
        changed?;
        Ok(paused?)
    }

    fn resume(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }

    fn stop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.resume();
        let _ = TcpStream::connect(self.address);
    }

    pub(super) fn finish(mut self) -> TestResult<usize> {
        self.stop();
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "status server panicked")??;
        }
        Ok(self.requests.load(Ordering::SeqCst))
    }
}

impl Drop for StatusServer {
    fn drop(&mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_status_request(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut request = Vec::new();
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut buffer = [0; 1024];
        let count = stream.read(&mut buffer)?;
        if count == 0 || request.len() + count > 8192 {
            return Err(std::io::Error::other(
                "incomplete or oversized status request",
            ));
        }
        request.extend_from_slice(&buffer[..count]);
    }
    let request = String::from_utf8(request).map_err(std::io::Error::other)?;
    if !request.starts_with(&format!("GET {AUTHORITY_PATH} HTTP/1.1\r\n"))
        || !request
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer test-only-control\r\n")
    {
        return Err(std::io::Error::other("unexpected authority status request"));
    }
    Ok(())
}

pub(super) fn remote(
    status: &TrustAuthorityStatus,
    endpoint: &str,
    clock: Arc<dyn Clock>,
    stale: bool,
) -> TestResult<RemoteCapabilityAuthority> {
    let mut cache = AuthorityKeyCache::from_status(status)?;
    if stale {
        cache.refreshed_at = Instant::now() - AUTHORITY_CACHE_TTL;
    }
    Ok(RemoteCapabilityAuthority {
        clock,
        client: build_client(endpoint, "test-only-control")?,
        cache: Mutex::new(cache),
        refresh_lock: Mutex::new(()),
        pinned_current: None,
        pinned_trusted: Vec::new(),
    })
}

pub(super) fn rotated_status() -> TestResult<(TrustAuthorityStatus, PublicKey, PublicKey)> {
    let root = chio_test_support::private_tempdir()?;
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("issuer.db"),
        Arc::new(chio_security_types::clock::FixedClock::new(100)),
    )?;
    let old = source.authority_public_key();
    let current = source.rotate_with_verification_deadline(110)?.public_key;
    let status = crate::trust_control::report_validation::authority_status_response(
        "sqlite".into(),
        source.status()?,
    );
    Ok((status, old, current))
}

pub(super) fn wait_for_read(receiver: Receiver<()>) -> TestResult {
    receiver.recv_timeout(WAIT)?;
    Ok(())
}
