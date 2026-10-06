use super::*;

fn transport(base_url: &str, auth: AuthScheme) -> Result<HttpTransport, HttpTransportError> {
    HttpTransport::new(HttpTransportConfig::new(base_url).with_auth(auth))
}

fn credentials() -> [AuthScheme; 3] {
    [
        AuthScheme::Bearer("secret-token".to_string()),
        AuthScheme::Header {
            name: "x-api-key".to_string(),
            value: "secret-token".to_string(),
        },
        AuthScheme::QueryParam {
            name: "key".to_string(),
            value: "secret-token".to_string(),
        },
    ]
}

#[test]
fn a_credential_is_refused_over_plaintext_to_a_remote_host() {
    for auth in credentials() {
        for base_url in [
            "http://api.groq.com",
            "http://10.0.0.5:11434",
            "http://localhost.example.com",
        ] {
            assert!(
                matches!(
                    transport(base_url, auth.clone()),
                    Err(HttpTransportError::InvalidUrl { .. })
                ),
                "{base_url} accepted a credential over plaintext"
            );
        }
    }
}

#[test]
fn a_credential_over_plaintext_loopback_is_allowed() {
    for auth in credentials() {
        for base_url in [
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://[::1]:11434",
        ] {
            assert!(transport(base_url, auth.clone()).is_ok(), "{base_url}");
        }
    }
}

#[test]
fn plaintext_without_a_credential_and_https_with_one_are_allowed() {
    assert!(transport("http://api.groq.com", AuthScheme::None).is_ok());
    for auth in credentials() {
        assert!(transport("https://api.groq.com", auth).is_ok());
    }
}
