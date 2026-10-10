use super::super::*;

#[derive(Debug, thiserror::Error)]
#[error("control URL must be a valid URL")]
struct ControlEndpointParseError(#[source] url::ParseError);

pub(super) fn validate_control_token(control_token: &str) -> Result<(), CliError> {
    validate_control_secret(control_token, "control token")
}

pub(super) fn normalize_control_endpoint(endpoint: &str) -> Result<String, CliError> {
    let parsed = Url::parse(endpoint)
        .map_err(|error| std::io::Error::other(ControlEndpointParseError(error)))?;
    let literal_loopback = match parsed.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && literal_loopback) {
        return Err(CliError::cli_other_error(
            "control URL requires HTTPS or literal loopback HTTP",
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(CliError::cli_other_error(
            "control URL must not contain credentials, query or fragment",
        ));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

pub(crate) fn encode_path_segment(segment: &str) -> String {
    utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string()
}

pub(crate) fn path_with_encoded_param(template: &str, param_name: &str, value: &str) -> String {
    template.replace(&format!("{{{param_name}}}"), &encode_path_segment(value))
}

pub(crate) fn certification_marketplace_search_path(
    query: &CertificationMarketplaceSearchQuery,
) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(criteria_profile) = query.filters.criteria_profile.as_deref() {
        serializer.append_pair("criteriaProfile", criteria_profile);
    }
    if let Some(evidence_profile) = query.filters.evidence_profile.as_deref() {
        serializer.append_pair("evidenceProfile", evidence_profile);
    }
    if let Some(status) = query.filters.status {
        serializer.append_pair("status", status.label());
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_SEARCH_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_SEARCH_PATH}?{encoded}")
    }
}

pub(crate) fn certification_marketplace_transparency_path(
    query: &CertificationMarketplaceTransparencyQuery,
) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH}?{encoded}")
    }
}

pub(crate) fn should_retry_status(status: u16) -> bool {
    matches!(status, 500 | 502 | 503 | 504)
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn control_transport_refuses_public_plaintext_and_redacts_urls() -> TestResult {
        for endpoint in [
            "http://example.com",
            "http://10.0.0.1",
            "http://localhost",
            "https://user:private@localhost",
            "https://localhost/?token=private",
        ] {
            let error = normalize_control_endpoint(endpoint)
                .err()
                .ok_or("unsafe endpoint accepted")?;
            assert!(!error.to_string().contains("private"));
        }
        assert_eq!(
            normalize_control_endpoint("http://127.1:8080/")?,
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            normalize_control_endpoint("http://[::1]:8080/")?,
            "http://[::1]:8080"
        );
        assert!(normalize_control_endpoint("https://control.example").is_ok());
        Ok(())
    }

    #[test]
    fn control_transport_never_follows_redirects() -> TestResult {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            time::{Duration, Instant},
        };
        let target = TcpListener::bind("127.0.0.1:0")?;
        target.set_nonblocking(true)?;
        let target_addr = target.local_addr()?;
        let source = TcpListener::bind("127.0.0.1:0")?;
        let source_addr = source.local_addr()?;
        let first = std::thread::spawn(move || -> std::io::Result<()> {
            let (mut socket, _) = source.accept()?;
            let mut request = [0; 8192];
            assert!(socket.read(&mut request)? > 0, "client sent no request");
            write!(socket, "HTTP/1.1 302 Found\r\nLocation: http://{target_addr}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
            Ok(())
        });
        let second = std::thread::spawn(move || -> std::io::Result<bool> {
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                match target.accept() {
                    Ok((mut socket, _)) => {
                        socket.write_all(b"HTTP/1.1 500 Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                        return Ok(true);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(false)
        });
        let client = super::super::factory::build_client(
            &format!("http://{source_addr}"),
            "transport-regression-token",
        )?;
        let error = client
            .list_revocations(&RevocationQuery {
                capability_id: Some("test".into()),
                limit: Some(1),
            })
            .err()
            .ok_or("redirect accepted as a revocation response")?;
        assert!(
            matches!(error, CliError::SignedJson(_)),
            "unexpected redirect response error: {error}"
        );
        first.join().map_err(|_| "source thread failed")??;
        assert!(
            !second.join().map_err(|_| "target thread failed")??,
            "redirect reached another authority"
        );
        Ok(())
    }
}
