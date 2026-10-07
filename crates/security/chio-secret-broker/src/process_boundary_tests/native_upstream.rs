//! Start the native TLS observer at dispatch, with invocation-owned cancellation.
use super::*;
use rustix::event::{poll, PollFd, PollFlags};

enum ObserverOutcome {
    Cancelled,
    Started(ManagedChild),
}

pub(super) struct UpstreamObserver {
    owner: Option<UnixStream>,
    pending: Option<JoinHandle<io::Result<ObserverOutcome>>>,
    child: Option<ManagedChild>,
}

impl UpstreamObserver {
    pub(super) fn immediate(child: ManagedChild) -> Self {
        Self {
            owner: None,
            pending: None,
            child: Some(child),
        }
    }

    pub(super) fn when_connected(command: Command, listener: TcpListener) -> io::Result<Self> {
        Self::when_connected_with_ready(command, listener, None)
    }

    pub(super) fn when_connected_with_ready(
        command: Command,
        listener: TcpListener,
        ready: Option<std::sync::mpsc::Sender<()>>,
    ) -> io::Result<Self> {
        let (owner, cancel) = UnixStream::pair()?;
        for stream in [&owner, &cancel] {
            if !fcntl_getfd(stream)?.contains(FdFlags::CLOEXEC) {
                return Err(io::Error::other(
                    "provider cancellation must remain private",
                ));
            }
        }
        let pending = thread::spawn(move || {
            if !wait_for_dispatch_or_cancel(&listener, &cancel)? {
                return Ok(ObserverOutcome::Cancelled);
            }
            if let Some(ready) = ready {
                ready
                    .send(())
                    .map_err(|_| io::Error::other("provider readiness owner was cancelled"))?;
            }
            Ok(ObserverOutcome::Started(spawn_with_stdin(
                command,
                OwnedFd::from(listener),
                "native TLS observer at dispatch",
            )))
        });
        Ok(Self {
            owner: Some(owner),
            pending: Some(pending),
            child: None,
        })
    }

    fn join_pending(&mut self) -> io::Result<()> {
        if let Some(pending) = self.pending.take() {
            let outcome = pending
                .join()
                .map_err(|_| io::Error::other("native provider observer worker panicked"))??;
            if let ObserverOutcome::Started(child) = outcome {
                self.child = Some(child);
            }
        }
        Ok(())
    }

    pub(super) fn is_waiting_for_dispatch(&mut self) -> bool {
        if self.pending.as_ref().is_some_and(JoinHandle::is_finished) {
            self.join_pending()
                .test_expect("native provider observer readiness");
        }
        self.pending.is_some() && self.child.is_none()
    }

    pub(super) fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        if self.pending.as_ref().is_some_and(JoinHandle::is_finished) {
            self.join_pending()
                .test_expect("native provider observer readiness");
        }
        self.child.as_mut().and_then(ManagedChild::try_wait)
    }

    pub(super) fn wait_output(&mut self) -> Output {
        // Invocation is finished. A successful call has already used the
        // real helper; cancellation cannot manufacture a completed report.
        drop(self.owner.take());
        self.join_pending()
            .test_expect("native provider observer completion");
        self.child
            .as_mut()
            .test_expect("native provider never received a dispatched connection")
            .wait_output()
    }
}

impl Drop for UpstreamObserver {
    fn drop(&mut self) {
        // EOF wakes a pending readiness wait even if the invocation fails.
        // Joining transfers any raced child into ManagedChild's kill/reap Drop.
        drop(self.owner.take());
        if let Some(pending) = self.pending.take() {
            let _ = pending.join();
        }
    }
}

fn wait_for_dispatch_or_cancel(listener: &TcpListener, cancel: &UnixStream) -> io::Result<bool> {
    let mut descriptors = [
        PollFd::new(listener, PollFlags::IN),
        PollFd::new(cancel, PollFlags::IN),
    ];
    loop {
        match poll(&mut descriptors, None) {
            Err(rustix::io::Errno::INTR) => continue,
            result => {
                result?;
            }
        }
        // Owner closure wins simultaneous observed readiness. Drop joins
        // and reaps a launch that races cancellation after this poll.
        if descriptors[1]
            .revents()
            .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
        {
            return Ok(false);
        }
        if descriptors[0].revents().contains(PollFlags::IN) {
            return Ok(true);
        }
        if descriptors[0]
            .revents()
            .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
        {
            return Err(io::Error::other("native provider listener is unavailable"));
        }
    }
}

#[test]
fn native_upstream_owner_cancellation_joins_without_child_or_effect() -> io::Result<()> {
    use std::net::TcpStream;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let directory = crate::private_tempdir()?;
    let command = helper_command(UPSTREAM_HELPER, "upstream", directory.path());
    let mut observer = UpstreamObserver::when_connected(command, listener)?;
    assert!(observer.is_waiting_for_dispatch());
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _invocation_owner = observer;
        panic!("fixed owned invocation failure before provider dispatch");
    }));
    let Err(payload) = failure else {
        panic!("owned invocation fixture must unwind");
    };
    assert_eq!(
        payload.downcast_ref::<&'static str>(),
        Some(&"fixed owned invocation failure before provider dispatch")
    );
    let Err(error) = TcpStream::connect_timeout(&address, Duration::from_secs(1)) else {
        panic!("cancelled observer listener remained reachable");
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);

    // Cancellation also wins when a real connection is already queued.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let (owner, cancel) = UnixStream::pair()?;
    let _queued = TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(1))?;
    drop(owner);
    assert!(!wait_for_dispatch_or_cancel(&listener, &cancel)?);
    Ok(())
}

#[test]
fn native_upstream_owner_drop_reaps_a_started_real_helper(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use rustix::process::{waitpid, Pid, WaitOptions};
    use std::net::TcpStream;

    let directory = crate::private_tempdir()?;
    let root = fs::canonicalize(directory.path())?;
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![UPSTREAM_HOST.into()])?;
    let certificate = root.join("peer.der");
    let key = root.join("peer-key.der");
    write_private(&certificate, cert.der().as_ref());
    write_private(&key, &key_pair.serialize_der());
    let canary = random_canary();
    let probe = CanaryProbe::from_bytes(&canary);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let mut command = helper_command(UPSTREAM_HELPER, "upstream", &root);
    command
        .env(CERT_ENV, certificate)
        .env(KEY_ENV, key)
        .env(FALLBACK_MARKER_ENV, root.join("complete"))
        .env(CANARY_LENGTH_ENV, probe.length.to_string())
        .env(CANARY_DIGEST_ENV, hex::encode(probe.sha256));
    let mut observer = UpstreamObserver::when_connected(command, listener)?;
    let _connection = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
    observer.join_pending()?;
    let child = observer
        .child
        .as_mut()
        .test_expect("real TLS helper started");
    assert!(child.try_wait().is_none());
    let pid = Pid::from_raw(i32::try_from(child.id())?).test_expect("owned helper PID");
    drop(observer);
    // ECHILD verifies the exact owned child was reaped. No PID-directed
    // signal or inference from a potentially reused /proc entry is needed.
    assert!(matches!(
        waitpid(Some(pid), WaitOptions::NOHANG),
        Err(rustix::io::Errno::CHILD)
    ));
    Ok(())
}
