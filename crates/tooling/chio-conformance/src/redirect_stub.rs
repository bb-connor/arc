//! Loopback servers that answer one canned response and record what they receive.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

pub(crate) struct Stub {
    pub(crate) port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    pub(crate) fn requests(&self) -> Vec<String> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

pub(crate) fn serve(response: String) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buffer = [0u8; 8192];
            let read = stream.read(&mut buffer).unwrap_or(0);
            if let Ok(mut log) = log.lock() {
                log.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            }
            let _ = stream.write_all(response.as_bytes());
        }
    });
    Stub { port, requests }
}

pub(crate) fn redirect_to(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

pub(crate) fn ok_empty() -> String {
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}
