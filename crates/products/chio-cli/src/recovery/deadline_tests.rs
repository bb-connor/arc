//! A cancelled OS lookup may keep a Tokio blocking task alive. The owned
//! transport runtime must release its caller without waiting for that task.
use super::dispatch;
use chio_egress_contract::HttpEgressContract;
use std::{
    cell::RefCell,
    error::Error,
    marker::PhantomData,
    net::{SocketAddr, TcpListener, TcpStream},
    rc::Rc,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Sender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

type TestError = Box<dyn Error + Send + Sync>;
const PROGRESS_WINDOW: Duration = Duration::from_secs(2);
const CLEANUP_LIMIT: Duration = Duration::from_secs(20);

thread_local! {
    static ACTIVE: RefCell<Option<Arc<BlockingLookup>>> = const { RefCell::new(None) };
}

pub(super) struct BlockingLookup {
    url: String,
    released: Mutex<bool>,
    wake: Condvar,
    expired: AtomicBool,
    started: Sender<()>,
    dispatch_started: Sender<()>,
    completed: Sender<()>,
}

impl BlockingLookup {
    pub(super) fn start_blocking_lookup(self: &Arc<Self>, runtime: &tokio::runtime::Runtime) {
        let fixture = self.clone();
        // Dropping the handle mirrors a cancelled Tokio lookup: the underlying
        // OS work is already running and cannot be aborted by its awaiter.
        drop(runtime.spawn_blocking(move || {
            let _ = fixture.started.send(());
            let released = fixture
                .released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (released, timeout) = fixture
                .wake
                .wait_timeout_while(released, CLEANUP_LIMIT, |released| !*released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !*released && timeout.timed_out() {
                fixture.expired.store(true, Ordering::SeqCst);
            }
            let _ = fixture.completed.send(());
        }));
    }

    pub(super) fn mark_dispatch_started(&self) {
        let _ = self.dispatch_started.send(());
    }

    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
}

struct FixtureScope {
    installed: Arc<BlockingLookup>,
    previous: Option<Arc<BlockingLookup>>,
    _thread: PhantomData<Rc<()>>,
}

impl FixtureScope {
    fn install(fixture: Arc<BlockingLookup>) -> Self {
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

pub(super) fn fixture_for(url: &reqwest::Url) -> Option<Arc<BlockingLookup>> {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .filter(|fixture| fixture.url == url.as_str())
            .cloned()
    })
}

struct PendingHost {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<std::io::Result<()>>>,
}

impl PendingHost {
    fn start(accepted_tx: Sender<()>) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let observed = accepted.clone();
        let stop = stopped.clone();
        let worker = thread::spawn(move || {
            let mut pending = Vec::<TcpStream>::new();
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        pending.push(stream);
                        observed.fetch_add(1, Ordering::SeqCst);
                        let _ = accepted_tx.send(());
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
            accepted,
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
                .map_err(|_| std::io::Error::other("pending host fixture panicked"))??;
        }
        Ok(self.accepted.load(Ordering::SeqCst))
    }
}

impl Drop for PendingHost {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[test]
fn transport_deadline_returns_before_cancelled_blocking_lookup_finishes() -> Result<(), TestError> {
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let mut host = PendingHost::start(accepted_tx)?;
    let authority = host.address.to_string();
    let url = reqwest::Url::parse(&format!("http://{authority}/deadline"))?;
    let contract = HttpEgressContract::permissive_for_tests(&authority);
    let (started_tx, started_rx) = mpsc::channel();
    let (dispatch_tx, dispatch_rx) = mpsc::channel();
    let (completed_tx, completed_rx) = mpsc::channel();
    let fixture = Arc::new(BlockingLookup {
        url: url.to_string(),
        released: Mutex::new(false),
        wake: Condvar::new(),
        expired: AtomicBool::new(false),
        started: started_tx,
        dispatch_started: dispatch_tx,
        completed: completed_tx,
    });
    let worker_fixture = fixture.clone();
    let (returned_tx, returned_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let _scope = FixtureScope::install(worker_fixture);
        let refused = dispatch(&contract, url, b"{}".to_vec(), Duration::from_millis(100)).is_err();
        let _ = returned_tx.send(refused);
        refused
    });
    let blocking_started = started_rx.recv_timeout(CLEANUP_LIMIT).is_ok();
    let dispatch_started = dispatch_rx.recv_timeout(CLEANUP_LIMIT).is_ok();
    let host_accepted = accepted_rx.recv_timeout(CLEANUP_LIMIT).is_ok();
    let returned_before_release = returned_rx.recv_timeout(PROGRESS_WINDOW).is_ok();
    fixture.release();
    let worker_result = worker.join();
    let blocking_task_completed = completed_rx.recv_timeout(CLEANUP_LIMIT).is_ok();
    let accepted = host.finish()?;
    let refused = worker_result.map_err(|_| std::io::Error::other("transport fixture panicked"))?;
    eprintln!(
        "HTTP_EGRESS_RUNTIME_DEADLINE blocking_lookup_started={blocking_started} \
         dispatch_started={dispatch_started} host_accepted={host_accepted} \
         returned_before_lookup_release={returned_before_release} \
         blocking_task_completed={blocking_task_completed} accepted_connections={accepted}",
    );
    assert!(blocking_started && dispatch_started && host_accepted);
    assert!(refused, "the pending host must hit the request timeout");
    assert!(
        returned_before_release,
        "owned runtime shutdown waited for a cancelled blocking lookup after the transport deadline"
    );
    assert!(!fixture.expired.load(Ordering::SeqCst));
    assert!(
        blocking_task_completed,
        "the held fixture task must finish after release"
    );
    assert_eq!(accepted, 1);
    Ok(())
}
