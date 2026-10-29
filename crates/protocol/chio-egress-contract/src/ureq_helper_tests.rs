use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Condvar;
use std::thread;
use std::time::Instant;

fn serve_once(response: &'static str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let authority = listener.local_addr().expect("address").to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).expect("read") == 0 {
                break;
            }
            request.push(byte[0]);
        }
        stream.write_all(response.as_bytes()).expect("write");
    });
    (authority, handle)
}

fn agent_for(authority: &str, max_response_bytes: u64) -> BlockingContractAgent {
    let mut contract = HttpEgressContract::permissive_for_tests(authority);
    contract.max_response_bytes = max_response_bytes;
    BlockingContractAgent::new(&contract, Duration::from_secs(2), Duration::from_secs(10))
        .expect("agent")
}

#[test]
fn request_outside_the_authority_set_is_refused_before_dispatch() {
    let agent = agent_for("127.0.0.1:9", 1024);
    let refusal = agent
        .get("http://127.0.0.2:9/")
        .expect_err("authority outside the contract");
    assert_eq!(
        refusal,
        HttpEgressError::AuthorityDenied {
            authority: "127.0.0.2:9".to_string()
        }
    );
}

#[test]
fn pinned_resolver_refuses_any_other_host() {
    let resolver = PinnedResolver {
        host: "rail.example".to_string(),
        addresses: vec![SocketAddr::from(([93, 184, 216, 34], 443))],
    };
    let refusal = ureq::Resolver::resolve(&resolver, "other.example:443").expect_err("other host");
    assert_eq!(
        contract_refusal(&refusal),
        Some(HttpEgressError::AuthorityDenied {
            authority: "other.example:443".to_string()
        })
    );
    assert_eq!(
        ureq::Resolver::resolve(&resolver, "rail.example:443").expect("pinned host"),
        vec![SocketAddr::from(([93, 184, 216, 34], 443))]
    );
}

#[test]
fn error_and_redirect_statuses_are_returned_unfollowed() {
    let (authority, handle) = serve_once(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:9/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let response = agent_for(&authority, 1024)
        .get(&format!("http://{authority}/"))
        .expect("allowed")
        .call()
        .expect("response");
    assert_eq!(response.status(), 302);
    handle.join().expect("server");

    let (authority, handle) = serve_once(
        "HTTP/1.1 402 Payment Required\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    );
    let response = agent_for(&authority, 1024)
        .post(&format!("http://{authority}/"))
        .expect("allowed")
        .send_bytes(b"{}")
        .expect("response");
    assert_eq!(response.status(), 402);
    assert_eq!(response.body(), b"{}");
    handle.join().expect("server");
}

#[test]
fn response_over_the_byte_ceiling_is_refused() {
    let (authority, handle) = serve_once(
        "HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\n0123456789abcdef0123456789abcdef",
    );
    let refusal = agent_for(&authority, 16)
        .get(&format!("http://{authority}/"))
        .expect("allowed")
        .call()
        .expect_err("body over the ceiling");
    assert_eq!(
        refusal,
        HttpEgressError::ResponseTooLarge {
            observed: 17,
            max: 16
        }
    );
    handle.join().expect("server");
}

#[test]
fn one_private_record_in_the_answer_refuses_the_host() {
    let prepared = HttpEgressContract::permissive_for_tests("rail.example:443")
        .prepare()
        .expect("prepared");
    let public: SocketAddr = "93.184.216.34:443".parse().expect("public");
    let private: SocketAddr = "10.0.0.1:443".parse().expect("private");
    for answer in [vec![public, private], vec![private, public]] {
        assert_eq!(
            enforce_resolved_addresses(&prepared, "rail.example", answer),
            Err(HttpEgressError::PrivateNetworkDenied {
                host: "rail.example resolved to 10.0.0.1".to_string()
            })
        );
    }
    assert_eq!(
        enforce_resolved_addresses(&prepared, "rail.example", vec![public]),
        Ok(vec![public])
    );
}

#[test]
fn deadline_bounds_a_response_that_drips_inside_the_phase_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let authority = listener.local_addr().expect("address").to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).expect("read") == 0 {
                return;
            }
            request.push(byte[0]);
        }
        if stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\nConnection: close\r\n\r\n")
            .is_err()
        {
            return;
        }
        for _ in 0..40 {
            thread::sleep(Duration::from_millis(100));
            if stream
                .write_all(b"x")
                .and_then(|()| stream.flush())
                .is_err()
            {
                return;
            }
        }
    });
    let contract = HttpEgressContract::permissive_for_tests(&authority);
    let agent =
        BlockingContractAgent::new(&contract, Duration::from_secs(2), Duration::from_secs(1))
            .expect("agent");
    let outcome = agent
        .get(&format!("http://{authority}/"))
        .expect("allowed")
        .call();
    assert!(
        matches!(outcome, Err(HttpEgressError::Transport(_))),
        "a 4 second drip must exceed the 1 second deadline: {outcome:?}"
    );
    handle.join().expect("server");
}

fn lookup_after(delay: Duration, answer: SocketAddr) -> ContractLookup {
    ContractLookup::new(move |_host: &str, _port: u16| {
        thread::sleep(delay);
        Ok(vec![answer])
    })
}

#[derive(Default)]
struct Hold {
    released: Mutex<bool>,
    release: Condvar,
    started: AtomicUsize,
    finished: AtomicUsize,
}

impl Hold {
    fn open(&self) {
        *self.released.lock().expect("hold") = true;
        self.release.notify_all();
    }

    fn wait_finished(&self, count: usize) {
        for _ in 0..500 {
            if self.finished.load(Ordering::SeqCst) == count {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("held lookups did not return");
    }
}

/// Every lookup blocks until the hold opens, then answers `answer`.
fn held_lookup(answer: SocketAddr) -> (ContractLookup, Arc<Hold>) {
    let hold = Arc::new(Hold::default());
    let gate = Arc::clone(&hold);
    let lookup = ContractLookup::new(move |_host: &str, _port: u16| {
        gate.started.fetch_add(1, Ordering::SeqCst);
        let mut released = gate.released.lock().expect("hold");
        while !*released {
            released = gate.release.wait(released).expect("hold");
        }
        drop(released);
        gate.finished.fetch_add(1, Ordering::SeqCst);
        Ok(vec![answer])
    });
    (lookup, hold)
}

#[test]
fn slow_resolution_spends_the_request_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let server = listener.local_addr().expect("address");
    let (lookup, hold) = held_lookup(server);
    let target = format!("slow.example:{}", server.port());
    let agent = BlockingContractAgent::with_lookup(
        &HttpEgressContract::permissive_for_tests(&target),
        Duration::from_secs(5),
        Duration::from_secs(1),
        lookup,
    )
    .expect("agent");
    let started = Instant::now();
    let outcome = agent
        .get(&format!("http://{target}/"))
        .expect("allowed")
        .call();
    let elapsed = started.elapsed();
    assert_eq!(
        outcome,
        Err(HttpEgressError::DnsResolutionFailed {
            host: "slow.example".to_string(),
            details: "resolution did not finish within the request deadline".to_string(),
        })
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "a held lookup must end at the 1 second deadline, took {elapsed:?}"
    );
    assert_eq!(
        listener.accept().map(drop).map_err(|error| error.kind()),
        Err(io::ErrorKind::WouldBlock),
        "a lookup past the deadline must not dial"
    );
    hold.open();
    hold.wait_finished(1);
}

#[test]
fn held_lookups_are_shared_bounded_and_freed_only_when_they_return() {
    let (authority, handle) =
        serve_once("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let server: SocketAddr = authority.parse().expect("server");
    let (lookup, hold) = held_lookup(server);
    let call = |name: &str, deadline: Duration| {
        let target = format!("{name}:{}", server.port());
        BlockingContractAgent::with_lookup(
            &HttpEgressContract::permissive_for_tests(&target),
            Duration::from_secs(2),
            deadline,
            lookup.clone(),
        )
        .expect("agent")
        .get(&format!("http://{target}/"))
        .expect("allowed")
        .call()
    };
    for index in 0..LOOKUPS_IN_FLIGHT {
        let host = format!("held{index}.example");
        assert_eq!(
            call(&host, Duration::from_millis(50)),
            Err(deadline_refusal(&host))
        );
    }
    for _ in 0..3 {
        assert_eq!(
            call("held0.example", Duration::from_millis(50)),
            Err(deadline_refusal("held0.example"))
        );
    }
    assert_eq!(hold.started.load(Ordering::SeqCst), LOOKUPS_IN_FLIGHT);
    let full = HttpEgressError::DnsResolutionFailed {
        host: "spare.example".to_string(),
        details: "too many name lookups are in flight".to_string(),
    };
    let started = Instant::now();
    assert_eq!(
        call("spare.example", Duration::from_secs(5)),
        Err(full.clone())
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(hold.started.load(Ordering::SeqCst), LOOKUPS_IN_FLIGHT);

    hold.open();
    hold.wait_finished(LOOKUPS_IN_FLIGHT);
    let response = (0..100)
        .find_map(|_| match call("spare.example", Duration::from_secs(5)) {
            Err(refusal) if refusal == full => {
                thread::sleep(Duration::from_millis(10));
                None
            }
            outcome => Some(outcome),
        })
        .expect("a returned lookup frees its slot")
        .expect("response");
    assert_eq!(response.status(), 204);
    assert_eq!(hold.started.load(Ordering::SeqCst), LOOKUPS_IN_FLIGHT + 1);
    handle.join().expect("server");
}

#[test]
fn http_phase_gets_only_the_budget_left_after_resolution() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let server = listener.local_addr().expect("address");
    let handle = thread::spawn(move || {
        let accepted = listener.accept();
        thread::sleep(Duration::from_secs(3));
        drop(accepted);
    });
    let target = format!("silent.example:{}", server.port());
    let agent = BlockingContractAgent::with_lookup(
        &HttpEgressContract::permissive_for_tests(&target),
        Duration::from_secs(5),
        Duration::from_secs(1),
        lookup_after(Duration::from_millis(600), server),
    )
    .expect("agent");
    let started = Instant::now();
    let outcome = agent
        .get(&format!("http://{target}/"))
        .expect("allowed")
        .call();
    let elapsed = started.elapsed();
    assert!(
        matches!(outcome, Err(HttpEgressError::Transport(_))),
        "a silent server must fail the request: {outcome:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_500),
        "resolution and the HTTP phase share the 1 second deadline, took {elapsed:?}"
    );
    handle.join().expect("server");
}

#[test]
fn the_first_checked_answer_is_the_only_address_dialed() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let server = listener.local_addr().expect("address");
    let handle = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).expect("read") == 0 {
                    break;
                }
                request.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write");
        }
    });
    let target = format!("rebind.example:{}", server.port());
    let lookups = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&lookups);
    let rebinding = ContractLookup::new(move |_host: &str, port: u16| {
        if observed.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(vec![server])
        } else {
            Ok(vec![SocketAddr::from(([10, 0, 0, 1], port))])
        }
    });
    let agent = BlockingContractAgent::with_lookup(
        &HttpEgressContract::permissive_for_tests(&target),
        Duration::from_secs(2),
        Duration::from_secs(10),
        rebinding,
    )
    .expect("agent");
    for _ in 0..2 {
        let response = agent
            .clone()
            .get(&format!("http://{target}/"))
            .expect("allowed")
            .call()
            .expect("response");
        assert_eq!(response.status(), 204);
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
    handle.join().expect("server");
}
