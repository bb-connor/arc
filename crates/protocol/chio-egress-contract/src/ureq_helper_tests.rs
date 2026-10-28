use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

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
fn resolver_refusal_surfaces_as_the_contract_error() {
    let agent = agent_for("127.0.0.1:9", 1024);
    let outcome = agent.agent.get("http://unlisted.invalid:9/").call();
    let Err(ureq::Error::Transport(transport)) = outcome else {
        panic!("resolver must refuse the unlisted host");
    };
    assert_eq!(
        transport_failure(transport),
        HttpEgressError::AuthorityDenied {
            authority: "unlisted.invalid".to_string()
        }
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

fn vpc_agent(allowances: &[(&str, u16, &str)]) -> BlockingContractAgent {
    let contract = HttpEgressContract {
        tenant_egress_namespace: "payment-rail".to_string(),
        allowed_schemes: std::collections::BTreeSet::from(["https".to_string()]),
        allowed_authority_set: std::collections::BTreeSet::from([
            "10.255.255.254:9".to_string(),
            "facilitator.vpc.internal:8443".to_string(),
        ]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 1024,
        private_network_allowances: allowances
            .iter()
            .map(|(host, port, cidr)| crate::PrivateNetworkAllowance {
                host: (*host).to_string(),
                port: *port,
                cidr: cidr.parse().expect("cidr"),
            })
            .collect(),
    };
    BlockingContractAgent::new(&contract, Duration::from_millis(300), Duration::from_secs(2))
        .expect("agent")
}

#[test]
fn allowed_private_literal_is_dialed() {
    let refusal = vpc_agent(&[])
        .get("https://10.255.255.254:9/verify")
        .expect_err("unlisted private literal");
    assert_eq!(
        refusal,
        HttpEgressError::PrivateNetworkDenied {
            host: "10.255.255.254".to_string()
        }
    );

    let outcome = vpc_agent(&[("10.255.255.254", 9, "10.255.255.254/32")])
        .get("https://10.255.255.254:9/verify")
        .expect("allowed private literal passes the contract")
        .call();
    assert!(
        matches!(outcome, Err(HttpEgressError::Transport(_))),
        "an allowed private literal reaches the socket: {outcome:?}"
    );
}

#[test]
fn mixed_answer_for_a_pinned_host_is_refused() {
    let agent = vpc_agent(&[("facilitator.vpc.internal", 8443, "10.20.0.0/24")]);
    let inside: SocketAddr = "10.20.0.5:8443".parse().expect("address");
    assert_eq!(
        enforce_resolved_addresses(&agent.prepared, "facilitator.vpc.internal", vec![inside]),
        Ok(vec![inside])
    );
    for answer in [
        vec![inside, "34.1.2.3:8443".parse().expect("address")],
        vec!["34.1.2.3:8443".parse().expect("address"), inside],
        vec![inside, "10.21.0.5:8443".parse().expect("address")],
    ] {
        let stray = answer
            .iter()
            .find(|address| **address != inside)
            .expect("stray")
            .ip();
        assert_eq!(
            enforce_resolved_addresses(&agent.prepared, "facilitator.vpc.internal", answer),
            Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
                host: "facilitator.vpc.internal".to_string(),
                port: 8443,
                address: stray,
            })
        );
    }
}

#[test]
fn unlisted_private_answer_is_refused() {
    let agent = vpc_agent(&[]);
    assert_eq!(
        enforce_resolved_addresses(
            &agent.prepared,
            "facilitator.vpc.internal",
            vec!["10.20.0.5:8443".parse().expect("address")]
        ),
        Err(HttpEgressError::PrivateNetworkDenied {
            host: "facilitator.vpc.internal resolved to 10.20.0.5".to_string()
        })
    );
}
