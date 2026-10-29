use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use ureq::rustls::pki_types::{CertificateDer, PrivateKeyDer};

struct Materials {
    root_pem: String,
    server_chain_pem: String,
    server_key_pem: String,
    client_chain_pem: String,
    client_key_pem: String,
}

fn issue_materials() -> Materials {
    issue_materials_naming("127.0.0.1")
}

fn issue_materials_naming(server_name: &str) -> Materials {
    let mut root = CertificateParams::new(Vec::<String>::new()).expect("root params");
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root.distinguished_name = DistinguishedName::new();
    root.distinguished_name
        .push(DnType::CommonName, "egress test root");
    let root_key = KeyPair::generate().expect("root key");
    let root = root.self_signed(&root_key).expect("root");

    let mut server = CertificateParams::new(vec![server_name.to_string()]).expect("server");
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("server key");
    let server = server
        .signed_by(&server_key, &root, &root_key)
        .expect("server cert");

    let mut client = CertificateParams::new(Vec::<String>::new()).expect("client");
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().expect("client key");
    let client = client
        .signed_by(&client_key, &root, &root_key)
        .expect("client cert");

    Materials {
        root_pem: root.pem(),
        server_chain_pem: format!("{}{}", server.pem(), root.pem()),
        server_key_pem: server_key.serialize_pem(),
        client_chain_pem: format!("{}{}", client.pem(), root.pem()),
        client_key_pem: client_key.serialize_pem(),
    }
}

fn certificates(pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("certificates")
}

fn server_config(materials: &Materials, require_client: bool) -> Arc<ureq::rustls::ServerConfig> {
    let provider = Arc::new(ureq::rustls::crypto::ring::default_provider());
    let builder = ureq::rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions");
    let builder = if require_client {
        let mut roots = ureq::rustls::RootCertStore::empty();
        for certificate in certificates(&materials.root_pem) {
            roots.add(certificate).expect("client root");
        }
        let verifier = ureq::rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider,
        )
        .build()
        .expect("client verifier");
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let key = PrivateKeyDer::from_pem_slice(materials.server_key_pem.as_bytes()).expect("key");
    Arc::new(
        builder
            .with_single_cert(certificates(&materials.server_chain_pem), key)
            .expect("server config"),
    )
}

/// Serves one TLS connection. The thread reports whether a request arrived.
fn serve_tls_once(config: Arc<ureq::rustls::ServerConfig>) -> (String, thread::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let authority = listener.local_addr().expect("address").to_string();
    let handle = thread::spawn(move || {
        let Ok((tcp, _)) = listener.accept() else {
            return false;
        };
        let Ok(connection) = ureq::rustls::ServerConnection::new(config) else {
            return false;
        };
        let mut stream = ureq::rustls::StreamOwned::new(connection, tcp);
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => request.push(byte[0]),
                _ => return false,
            }
        }
        stream
            .write_all(
                b"HTTP/1.1 204 No Content\r\nX-Egress: pinned\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .is_ok()
    });
    (authority, handle)
}

/// Every layer of an error, outermost first: the opaque transport class hides
/// the ureq, rustls or I/O error that caused it.
fn source_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = format!("{error:?}");
    let mut source = error.source();
    while let Some(inner) = source {
        chain.push_str(&format!(" <- {inner:?}"));
        source = inner.source();
    }
    chain
}

fn tls_agent(authority: &str) -> BlockingContractAgent {
    let contract = HttpEgressContract::permissive_for_tests(authority);
    BlockingContractAgent::new(&contract, Duration::from_secs(2), Duration::from_secs(10))
        .expect("agent")
}

#[test]
fn an_agent_trusts_a_server_signed_by_its_configured_root() {
    let materials = issue_materials();
    let (authority, server) = serve_tls_once(server_config(&materials, false));
    let tls = BlockingContractTls::from_pem(std::slice::from_ref(&materials.root_pem), None)
        .expect("tls");
    let response = tls_agent(&authority)
        .with_tls(tls)
        .delete(&format!("https://{authority}/task"))
        .expect("allowed")
        .call()
        .unwrap_or_else(|error| panic!("response: {}", source_chain(&error)));
    assert_eq!(response.status(), 204);
    assert_eq!(response.header("x-egress"), Some("pinned"));
    assert!(server.join().expect("server"));
}

#[test]
fn an_agent_refuses_a_server_its_roots_do_not_sign() {
    let materials = issue_materials();
    let (authority, server) = serve_tls_once(server_config(&materials, false));
    let refusal = tls_agent(&authority)
        .get(&format!("https://{authority}/"))
        .expect("allowed")
        .call()
        .expect_err("an unknown issuer is refused");
    assert!(
        matches!(refusal, HttpEgressError::Transport(_)),
        "{}",
        source_chain(&refusal)
    );
    assert!(!server.join().expect("server"));

    let other = issue_materials();
    let (authority, server) = serve_tls_once(server_config(&materials, false));
    let tls = BlockingContractTls::from_pem(&[other.root_pem], None).expect("tls");
    let refusal = tls_agent(&authority)
        .with_tls(tls)
        .get(&format!("https://{authority}/"))
        .expect("allowed")
        .call()
        .expect_err("a root that did not sign the server is refused");
    assert!(
        matches!(refusal, HttpEgressError::Transport(_)),
        "{}",
        source_chain(&refusal)
    );
    assert!(!server.join().expect("server"));
}

#[test]
fn a_mutual_tls_server_admits_only_the_configured_identity() {
    let materials = issue_materials();
    let (authority, server) = serve_tls_once(server_config(&materials, true));
    let identity = ClientIdentityPem {
        cert_chain_pem: &materials.client_chain_pem,
        private_key_pem: &materials.client_key_pem,
    };
    let tls =
        BlockingContractTls::from_pem(std::slice::from_ref(&materials.root_pem), Some(identity))
            .expect("tls");
    let response = tls_agent(&authority)
        .with_tls(tls)
        .post(&format!("https://{authority}/"))
        .expect("allowed")
        .send_bytes(b"{}")
        .unwrap_or_else(|error| panic!("response: {}", source_chain(&error)));
    assert_eq!(response.status(), 204);
    assert!(server.join().expect("server"));

    let (authority, server) = serve_tls_once(server_config(&materials, true));
    let tls = BlockingContractTls::from_pem(std::slice::from_ref(&materials.root_pem), None)
        .expect("tls");
    let refusal = tls_agent(&authority)
        .with_tls(tls)
        .post(&format!("https://{authority}/"))
        .expect("allowed")
        .send_bytes(b"{}")
        .expect_err("no client identity is refused");
    assert!(
        matches!(refusal, HttpEgressError::Transport(_)),
        "{}",
        source_chain(&refusal)
    );
    assert!(!server.join().expect("server"));
}

#[test]
fn malformed_tls_material_is_refused_at_construction() {
    let materials = issue_materials();
    assert_eq!(
        BlockingContractTls::from_pem(&["not a certificate".to_string()], None)
            .expect_err("no PEM certificate")
            .to_string(),
        "custom TLS root CA did not contain any PEM certificates"
    );
    let identity = ClientIdentityPem {
        cert_chain_pem: &materials.client_chain_pem,
        private_key_pem: "not a key",
    };
    assert_eq!(
        BlockingContractTls::from_pem(std::slice::from_ref(&materials.root_pem), Some(identity))
            .expect_err("no PEM key")
            .to_string(),
        "failed to parse mutual TLS client private key"
    );
}

#[test]
fn an_agent_refuses_a_trusted_certificate_issued_for_another_name() {
    let materials = issue_materials_naming("wrong.example");
    let (authority, server) = serve_tls_once(server_config(&materials, false));
    let tls = BlockingContractTls::from_pem(std::slice::from_ref(&materials.root_pem), None)
        .expect("tls");
    let refusal = tls_agent(&authority)
        .with_tls(tls)
        .get(&format!("https://{authority}/"))
        .expect("allowed")
        .call()
        .expect_err("a certificate for another name is refused");
    assert!(
        matches!(refusal, HttpEgressError::Transport(_)),
        "{}",
        source_chain(&refusal)
    );
    assert!(!server.join().expect("server"));
}
