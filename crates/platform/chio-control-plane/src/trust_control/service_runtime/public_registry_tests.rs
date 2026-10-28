use super::*;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use chio_egress_contract::HttpEgressError;
use chio_test_support::prelude::*;

fn watch_for_dials() -> (u16, thread::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
    listener.set_nonblocking(true).test_unwrap();
    let port = listener.local_addr().test_unwrap().port();
    let dials = thread::spawn(move || {
        for _ in 0..200 {
            if listener.accept().is_ok() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    });
    (port, dials)
}

fn redirect_once(location: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
    let address = listener.local_addr().test_unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().test_unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request);
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes());
    });
    format!("http://{address}")
}

fn registry_failures(registry_url: &str) -> Vec<String> {
    let message = |error: CliError| error.to_string();
    vec![
        resolve_public_certification(registry_url, "tool-server")
            .err()
            .map(message),
        resolve_public_certification_metadata(registry_url)
            .err()
            .map(message),
        resolve_public_generic_namespace(registry_url)
            .err()
            .map(message),
        search_public_generic_listings(registry_url, &GenericListingQuery::default())
            .err()
            .map(message),
        search_public_certifications(registry_url, &CertificationPublicSearchQuery::default())
            .err()
            .map(message),
        resolve_public_certification_transparency(
            registry_url,
            &CertificationTransparencyQuery::default(),
        )
        .err()
        .map(message),
    ]
    .into_iter()
    .map(|failure| failure.unwrap_or_default())
    .collect()
}

fn expected(label: &str, detail: String) -> String {
    CliError::cli_other_error(format!("{label} {detail}")).to_string()
}

#[test]
fn public_registry_refuses_a_private_target_before_dialing() {
    let (port, dials) = watch_for_dials();
    let registry_url = format!("https://0.0.0.0:{port}");
    let failures = registry_failures(&registry_url);
    assert!(
        !dials.join().test_unwrap(),
        "a registry fetcher dialed 0.0.0.0"
    );
    let refusal = HttpEgressError::PrivateNetworkDenied {
        host: "0.0.0.0".to_owned(),
    };
    let certification = "public certification registry";
    let generic = "public registry";
    let detail = format!("egress to {registry_url} failed: {refusal}");
    assert_eq!(
        failures,
        vec![
            expected(certification, detail.clone()),
            expected(certification, detail.clone()),
            expected(generic, detail.clone()),
            expected(generic, detail.clone()),
            expected(certification, detail.clone()),
            expected(certification, detail),
        ]
    );
}

#[test]
fn public_registry_does_not_follow_redirects() {
    for (label, fetch) in [
        (
            "public registry",
            (|url: &str| {
                resolve_public_generic_namespace(url)
                    .err()
                    .map(|e| e.to_string())
            }) as fn(&str) -> Option<String>,
        ),
        ("public certification registry", |url: &str| {
            resolve_public_certification_metadata(url)
                .err()
                .map(|e| e.to_string())
        }),
    ] {
        let (port, dials) = watch_for_dials();
        let registry_url = redirect_once(format!("http://127.0.0.1:{port}/elsewhere"));
        let failure = fetch(&registry_url);
        assert!(!dials.join().test_unwrap(), "{label} followed a redirect");
        assert_eq!(
            failure,
            Some(expected(
                label,
                format!("{registry_url} returned HTTP status 302")
            ))
        );
    }
}
