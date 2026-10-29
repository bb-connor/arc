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
fn plaintext_to_a_remote_host_is_refused_and_https_is_allowed() {
    assert!(matches!(
        transport("http://api.groq.com", AuthScheme::None),
        Err(HttpTransportError::InvalidUrl { .. })
    ));
    for auth in credentials() {
        assert!(transport("https://api.groq.com", auth).is_ok());
    }
}

#[test]
fn custom_headers_cannot_bypass_plaintext_credential_protection() {
    for name in [
        "Authorization",
        "aUtHoRiZaTiOn",
        "Proxy-Authorization",
        "Cookie",
        "x-api-key",
        "x-custom-token",
    ] {
        let config =
            HttpTransportConfig::new("http://api.example.com").with_header(name, "private-value");
        assert!(matches!(
            HttpTransport::new(config),
            Err(HttpTransportError::InvalidUrl { .. })
        ));
    }
    let mut config = HttpTransportConfig::new("http://api.example.com");
    config
        .extra_headers
        .push(("x-private-session".into(), "private-value".into()));
    assert!(matches!(
        HttpTransport::new(config),
        Err(HttpTransportError::InvalidUrl { .. })
    ));
}

#[test]
fn custom_headers_over_https_or_loopback_are_allowed() {
    for base_url in [
        "https://api.example.com",
        "http://localhost:11434",
        "http://127.0.0.1:11434",
        "http://[::1]:11434",
    ] {
        assert!(
            HttpTransport::new(
                HttpTransportConfig::new(base_url)
                    .with_header("x-private-session", "private-value")
            )
            .is_ok(),
            "{base_url}"
        );
    }
}
