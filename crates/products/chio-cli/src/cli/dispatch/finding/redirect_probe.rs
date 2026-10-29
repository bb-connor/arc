//! A venue whose every answer redirects to a second loopback authority.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::Duration;

const PROBE_PATH: &str = "/probe";
/// Longest either authority waits for a request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct RedirectProbe {
    pub(super) venue_url: String,
    venue_address: SocketAddr,
    venue: JoinHandle<bool>,
    second_address: SocketAddr,
    second: JoinHandle<bool>,
}

/// Which authorities received a complete client request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProbeOutcome {
    pub(super) venue_reached: bool,
    pub(super) followed: bool,
}

/// Accept one connection, answer it with `reply`, and report whether it
/// carried a complete request head other than the probe's own.
fn answer_one(listener: &TcpListener, reply: &[u8]) -> bool {
    let Ok((mut stream, _)) = listener.accept() else {
        return false;
    };
    if stream.set_read_timeout(Some(HEAD_TIMEOUT)).is_err() {
        return false;
    }
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte), Ok(1)) {
        head.push(byte[0]);
    }
    let _ = stream.write_all(reply);
    head.ends_with(b"\r\n\r\n")
        && !String::from_utf8_lossy(&head).contains(&format!(" {PROBE_PATH} "))
}

impl RedirectProbe {
    /// `status` is the redirect the venue answers with, such as `302 Found`
    /// or `303 See Other`.
    pub(super) fn start(status: &str) -> Self {
        let second_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let second_address = second_listener.local_addr().unwrap();
        let second = std::thread::spawn(move || {
            answer_one(
                &second_listener,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
        });
        let venue_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let venue_address = venue_listener.local_addr().unwrap();
        let venue_url = format!("http://{venue_address}");
        let reply = format!(
            "HTTP/1.1 {status}\r\nLocation: http://{second_address}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let venue = std::thread::spawn(move || answer_one(&venue_listener, reply.as_bytes()));
        Self {
            venue_url,
            venue_address,
            venue,
            second_address,
            second,
        }
    }

    /// Release both authorities and report what they received. A listener
    /// still waiting gets a probe request, and a stalled client is cut off
    /// after [`HEAD_TIMEOUT`], so the call always returns.
    pub(super) fn finish(self) -> ProbeOutcome {
        for address in [self.venue_address, self.second_address] {
            if let Ok(mut probe) = TcpStream::connect(address) {
                let _ = probe.write_all(format!("GET {PROBE_PATH} HTTP/1.1\r\n\r\n").as_bytes());
            }
        }
        ProbeOutcome {
            venue_reached: self.venue.join().unwrap(),
            followed: self.second.join().unwrap(),
        }
    }

    /// Assert that `client` reached the venue and did not follow its
    /// redirect to the second authority.
    pub(super) fn assert_redirect_not_followed(self, client: &str) {
        let outcome = self.finish();
        assert!(outcome.venue_reached, "{client} never reached the venue");
        assert!(!outcome.followed, "{client} followed a venue redirect");
    }
}

const NOTHING_RECEIVED: ProbeOutcome = ProbeOutcome {
    venue_reached: false,
    followed: false,
};

fn finish_within(probe: RedirectProbe, bound: Duration) -> Option<ProbeOutcome> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(probe.finish());
    });
    receiver.recv_timeout(bound).ok()
}

#[test]
fn finish_returns_when_the_client_never_reaches_the_venue() {
    let probe = RedirectProbe::start("302 Found");
    assert_eq!(
        finish_within(probe, Duration::from_secs(10)),
        Some(NOTHING_RECEIVED)
    );
}

#[test]
fn finish_returns_when_a_client_stalls_inside_its_request() {
    let probe = RedirectProbe::start("302 Found");
    let venue = probe.venue_url.trim_start_matches("http://").to_string();
    let mut stalled = TcpStream::connect(venue).unwrap();
    stalled.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    assert_eq!(
        finish_within(probe, HEAD_TIMEOUT * 4),
        Some(NOTHING_RECEIVED)
    );
    drop(stalled);
}

#[test]
fn finish_returns_when_a_client_trickles_its_request() {
    let probe = RedirectProbe::start("302 Found");
    let venue = probe.venue_url.trim_start_matches("http://").to_string();
    let mut client = TcpStream::connect(venue).unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nX-Trickle: ").unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trickling = std::sync::Arc::clone(&stop);
    let trickler = std::thread::spawn(move || {
        while !trickling.load(std::sync::atomic::Ordering::SeqCst) && client.write_all(b"a").is_ok()
        {
            std::thread::sleep(HEAD_TIMEOUT / 5);
        }
    });
    let outcome = finish_within(probe, HEAD_TIMEOUT * 4);
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(outcome, Some(NOTHING_RECEIVED));
    trickler.join().unwrap();
}
