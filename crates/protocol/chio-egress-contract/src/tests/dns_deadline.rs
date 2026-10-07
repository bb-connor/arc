//! DNS fixtures affect only their installed host and thread. Raw fixture
//! answers still pass through the real connect-time address checks.
use super::{client_builder_with_contract, send_with_contract, ContractDnsResolver};
use crate::{HttpEgressContract, HttpEgressError};
use reqwest::dns::Resolve;
use std::{
    cell::RefCell,
    error::Error,
    io::{Read, Write},
    marker::PhantomData,
    net::{IpAddr, SocketAddr, TcpListener},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

type TestError = Box<dyn Error + Send + Sync>;
const PROGRESS_WINDOW: Duration = Duration::from_secs(2);
const CLEANUP_LIMIT: Duration = Duration::from_secs(20);

thread_local! {
    static ACTIVE: RefCell<Option<Arc<DnsFixture>>> = const { RefCell::new(None) };
}

struct LookupGate {
    released: Mutex<bool>,
    wake: Condvar,
    expired: AtomicBool,
}

impl LookupGate {
    fn new() -> Self {
        Self {
            released: Mutex::new(false),
            wake: Condvar::new(),
            expired: AtomicBool::new(false),
        }
    }

    fn wait(&self) {
        let released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (released, timeout) = self
            .wake
            .wait_timeout_while(released, CLEANUP_LIMIT, |released| !*released)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !*released && timeout.timed_out() {
            self.expired.store(true, Ordering::SeqCst);
        }
    }

    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
}

struct DnsFixture {
    host: String,
    addresses: Vec<SocketAddr>,
    gate: Option<LookupGate>,
    synchronous_lookups: AtomicUsize,
    connect_lookups: AtomicUsize,
}

impl DnsFixture {
    fn new(host: &str, addresses: Vec<SocketAddr>, block_preflight: bool) -> Arc<Self> {
        Arc::new(Self {
            host: host.to_owned(),
            addresses,
            gate: block_preflight.then(LookupGate::new),
            synchronous_lookups: AtomicUsize::new(0),
            connect_lookups: AtomicUsize::new(0),
        })
    }

    fn release(&self) {
        if let Some(gate) = &self.gate {
            gate.release();
        }
    }
}

struct FixtureScope {
    installed: Arc<DnsFixture>,
    previous: Option<Arc<DnsFixture>>,
    _thread: PhantomData<Rc<()>>,
}

impl FixtureScope {
    fn install(fixture: Arc<DnsFixture>) -> Self {
        let previous = ACTIVE.with(|active| active.borrow_mut().replace(fixture.clone()));
        Self {
            installed: fixture,
            previous,
            _thread: PhantomData,
        }
    }
}

impl Drop for FixtureScope {
    fn drop(&mut self) {
        self.installed.release();
        ACTIVE.with(|active| *active.borrow_mut() = self.previous.take());
    }
}

fn fixture_for(host: &str) -> Option<Arc<DnsFixture>> {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .filter(|fixture| fixture.host == host)
            .cloned()
    })
}

pub(crate) fn before_synchronous_lookup(host: &str) {
    if let Some(fixture) = fixture_for(host) {
        fixture.synchronous_lookups.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &fixture.gate {
            gate.wait();
        }
    }
}

pub(crate) fn lookup_addresses(host: &str) -> Option<Vec<SocketAddr>> {
    fixture_for(host).map(|fixture| {
        fixture.connect_lookups.fetch_add(1, Ordering::SeqCst);
        fixture.addresses.clone()
    })
}

struct ResponseServer {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<std::io::Result<()>>>,
}

impl ResponseServer {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let requests = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let observed = requests.clone();
        let worker = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
                        stream.set_write_timeout(Some(Duration::from_millis(500)))?;
                        let mut request = Vec::new();
                        let mut buffer = [0; 1024];
                        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                            let count = stream.read(&mut buffer)?;
                            if count == 0 || request.len() + count > 4096 {
                                return Err(std::io::Error::other("incomplete bounded request"));
                            }
                            request.extend_from_slice(&buffer[..count]);
                        }
                        observed.fetch_add(1, Ordering::SeqCst);
                        stream.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::park_timeout(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            requests,
            stopped,
            worker: Some(worker),
        })
    }

    fn finish(&mut self) -> std::io::Result<usize> {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            worker
                .join()
                .map_err(|_| std::io::Error::other("response fixture panicked"))??;
        }
        Ok(self.requests.load(Ordering::SeqCst))
    }
}

impl Drop for ResponseServer {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[test]
fn contract_dispatch_keeps_runtime_progress_during_dns_resolution() -> Result<(), TestError> {
    let mut server = ResponseServer::start()?;
    let fixture = DnsFixture::new("localhost", vec![server.address], true);
    let worker_fixture = fixture.clone();
    let authority = format!("localhost:{}", server.address.port());
    let (started_tx, started_rx) = mpsc::channel();
    let (heartbeat_tx, heartbeat_rx) = mpsc::channel();
    let worker = thread::spawn(move || -> Result<_, TestError> {
        let _scope = FixtureScope::install(worker_fixture);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let contract = HttpEgressContract::permissive_for_tests(&authority);
            let client = client_builder_with_contract(&contract)
                .no_retries()
                .timeout(Duration::from_secs(5))
                .build()?;
            let request = client.get(format!("http://{authority}/progress")).build()?;
            started_tx.send(())?;
            let heartbeat = async {
                tokio::task::yield_now().await;
                heartbeat_tx.send(())
            };
            // The exchange is polled first. Synchronous DNS here prevents the
            // sibling from running until the independent controller releases it.
            let (exchange, heartbeat) = tokio::join!(
                biased;
                send_with_contract(&contract, &client, request),
                heartbeat,
            );
            heartbeat?;
            Ok(exchange)
        })
    });
    let started = started_rx.recv_timeout(CLEANUP_LIMIT).is_ok();
    let progressed = started && heartbeat_rx.recv_timeout(PROGRESS_WINDOW).is_ok();
    let sync_before_release = fixture.synchronous_lookups.load(Ordering::SeqCst);
    let requests_before_release = server.requests.load(Ordering::SeqCst);
    fixture.release();
    let worker_result = worker.join();
    let requests = server.finish()?;
    let exchange =
        worker_result.map_err(|_| std::io::Error::other("dispatch fixture panicked"))??;
    eprintln!(
        "HTTP_EGRESS_DNS_PROGRESS started={started} heartbeat_before_release={progressed} \
         sync_lookups_before_release={sync_before_release} \
         requests_before_release={requests_before_release} requests={requests} connect_lookups={}",
        fixture.connect_lookups.load(Ordering::SeqCst),
    );
    assert!(started, "the prepared dispatch must actually start");
    assert!(
        progressed,
        "DNS preflight blocked the runtime until the controller released its lookup"
    );
    assert_eq!(
        sync_before_release, 0,
        "async dispatch must not resolve synchronously"
    );
    assert!(
        fixture
            .gate
            .as_ref()
            .is_none_or(|gate| !gate.expired.load(Ordering::SeqCst)),
        "cleanup deadline cannot stand in for controller release"
    );
    assert!(exchange?.status().is_success());
    assert_eq!(requests, 1);
    assert_eq!(fixture.connect_lookups.load(Ordering::SeqCst), 1);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Denial {
    Loopback,
    LinkLocal,
    UniqueLocal,
    Private,
}

impl Denial {
    fn matches(self, error: &HttpEgressError) -> bool {
        matches!(
            (self, error),
            (Self::Loopback, HttpEgressError::LoopbackDenied { .. })
                | (Self::LinkLocal, HttpEgressError::LinkLocalDenied { .. })
                | (Self::UniqueLocal, HttpEgressError::Ipv6UlaDenied { .. })
                | (Self::Private, HttpEgressError::PrivateNetworkDenied { .. })
        )
    }
}

fn forbidden_addresses() -> Result<Vec<(IpAddr, Denial)>, std::net::AddrParseError> {
    [
        ("127.0.0.1", Denial::Loopback),
        ("169.254.1.1", Denial::LinkLocal),
        ("10.20.30.40", Denial::Private),
        ("::1", Denial::Loopback),
        ("fe80::1", Denial::LinkLocal),
        ("fc00::1", Denial::UniqueLocal),
        ("::ffff:127.0.0.1", Denial::Loopback),
        ("::ffff:169.254.1.1", Denial::LinkLocal),
        ("::ffff:10.20.30.40", Denial::Private),
    ]
    .into_iter()
    .map(|(address, denial)| address.parse().map(|address| (address, denial)))
    .collect()
}

fn strict_contract(authority: &str) -> HttpEgressContract {
    let mut contract = HttpEgressContract::permissive_for_tests(authority);
    contract.deny_loopback = true;
    contract.deny_link_local = true;
    contract.deny_ipv6_ula = true;
    contract.max_redirect_chain = 0;
    contract
}

#[tokio::test]
async fn contract_resolver_refuses_every_forbidden_actual_address() -> Result<(), TestError> {
    let host = "resolved-egress.test";
    let contract = strict_contract(host);
    for (address, denial) in forbidden_addresses()? {
        // A public first answer cannot hide a forbidden later answer. These
        // are raw backend answers, not replacement validated resolver results.
        let fixture = DnsFixture::new(
            host,
            vec!["8.8.8.8:0".parse()?, SocketAddr::new(address, 0)],
            false,
        );
        let _scope = FixtureScope::install(fixture.clone());
        let result = ContractDnsResolver::new(contract.clone())
            .resolve(host.parse()?)
            .await;
        let error = match result {
            Ok(_) => return Err(format!("resolver accepted forbidden address {address}").into()),
            Err(error) => error,
        };
        let typed = error
            .downcast_ref::<HttpEgressError>()
            .ok_or("resolver lost its native denial")?;
        assert!(denial.matches(typed), "{address}: {typed:?}");
        assert_eq!(fixture.connect_lookups.load(Ordering::SeqCst), 1);
        eprintln!("HTTP_EGRESS_ACTUAL_DNS_REFUSAL address={address} reason={denial:?}");
    }
    Ok(())
}

#[tokio::test]
async fn contract_resolver_preserves_exact_public_answers_and_refuses_foreign_names(
) -> Result<(), TestError> {
    let host = "resolved-egress.test";
    let addresses = vec![
        "8.8.8.8:9000".parse()?,
        "[2606:4700:4700::1111]:9000".parse()?,
    ];
    let fixture = DnsFixture::new(host, addresses.clone(), false);
    let _scope = FixtureScope::install(fixture.clone());
    let resolver = ContractDnsResolver::new(strict_contract(host));
    let resolved = resolver.resolve(host.parse()?).await?.collect::<Vec<_>>();
    let expected = addresses
        .into_iter()
        .map(|mut address| {
            address.set_port(0);
            address
        })
        .collect::<Vec<_>>();
    assert_eq!(
        resolved, expected,
        "the checked addresses must be the connect answers"
    );
    let refused = resolver.resolve("foreign-egress.test".parse()?).await;
    let error = match refused {
        Ok(_) => return Err("resolver accepted an undeclared name".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error.downcast_ref::<HttpEgressError>(),
        Some(HttpEgressError::AuthorityDenied { .. })
    ));
    assert_eq!(fixture.connect_lookups.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn contract_dispatch_refuses_forbidden_literals_before_connect() -> Result<(), TestError> {
    for (address, denial) in forbidden_addresses()? {
        let authority = SocketAddr::new(address, 80).to_string();
        let contract = strict_contract(&authority);
        let client = client_builder_with_contract(&contract).build()?;
        let request = client.get(format!("http://{authority}/refuse")).build()?;
        let error = match send_with_contract(&contract, &client, request).await {
            Ok(_) => return Err(format!("dispatch accepted forbidden literal {address}").into()),
            Err(error) => error,
        };
        assert!(denial.matches(&error), "{address}: {error:?}");
    }
    Ok(())
}
