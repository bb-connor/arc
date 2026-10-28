//! A venue whose every answer redirects to a second loopback authority.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::JoinHandle;

const PROBE_PATH: &str = "/probe";

pub(super) struct RedirectProbe {
    pub(super) venue_url: String,
    venue: JoinHandle<()>,
    second_address: SocketAddr,
    second: JoinHandle<bool>,
}

fn read_request_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

impl RedirectProbe {
    /// `status` is the redirect the venue answers with, such as `302 Found`
    /// or `303 See Other`.
    pub(super) fn start(status: &str) -> Self {
        let second_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let second_address = second_listener.local_addr().unwrap();
        let second = std::thread::spawn(move || {
            let (mut stream, _) = second_listener.accept().unwrap();
            let head = read_request_head(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            );
            !head.contains(&format!(" {PROBE_PATH} "))
        });
        let venue_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let venue_url = format!("http://{}", venue_listener.local_addr().unwrap());
        let reply = format!(
            "HTTP/1.1 {status}\r\nLocation: http://{second_address}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let venue = std::thread::spawn(move || {
            let (mut stream, _) = venue_listener.accept().unwrap();
            read_request_head(&mut stream);
            let _ = stream.write_all(reply.as_bytes());
        });
        Self {
            venue_url,
            venue,
            second_address,
            second,
        }
    }

    /// Whether the client followed the redirect to the second authority.
    pub(super) fn followed(self) -> bool {
        self.venue.join().unwrap();
        if let Ok(mut probe) = TcpStream::connect(self.second_address) {
            let _ = probe.write_all(format!("GET {PROBE_PATH} HTTP/1.1\r\n\r\n").as_bytes());
        }
        self.second.join().unwrap()
    }
}
