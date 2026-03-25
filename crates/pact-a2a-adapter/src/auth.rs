fn bearer_request_header(access_token: String) -> A2aRequestHeader {
    A2aRequestHeader {
        name: "Authorization".to_string(),
        value: format!("Bearer {access_token}"),
    }
}

fn basic_request_header_value(username: String, password: String) -> String {
    format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{username}:{password}"))
    )
}

fn merged_oauth_scopes(required_scopes: &[String], configured_scopes: &[String]) -> Vec<String> {
    let mut scopes = Vec::new();
    for scope in required_scopes.iter().chain(configured_scopes.iter()) {
        if !scope.trim().is_empty() && !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.clone());
        }
    }
    scopes
}

fn oauth_cache_key(scheme_name: &str, token_endpoint: &Url, scopes: &[String]) -> String {
    let mut normalized_scopes = scopes.to_vec();
    normalized_scopes.sort();
    normalized_scopes.dedup();
    format!(
        "{scheme_name}|{}|{}",
        token_endpoint,
        normalized_scopes.join(" ")
    )
}

fn request_client_credentials_token(
    token_endpoint: &Url,
    credentials: &A2aOAuthClientCredentials,
    scopes: &[String],
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<A2aOAuthTokenResponse, AdapterError> {
    let basic_header = A2aRequestHeader {
        name: "Authorization".to_string(),
        value: format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!(
                "{}:{}",
                credentials.client_id, credentials.client_secret
            ))
        ),
    };
    let basic_body = build_client_credentials_form(scopes, None);
    match post_form_json::<A2aOAuthTokenResponse>(
        token_endpoint,
        basic_body.as_str(),
        &[basic_header],
        timeout,
        transport_config,
        A2aTlsMode::Default,
    ) {
        Ok(response) => Ok(response),
        Err(AdapterError::Remote(message))
            if message.starts_with("HTTP 400:") || message.starts_with("HTTP 401:") =>
        {
            let fallback_body = build_client_credentials_form(
                scopes,
                Some((&credentials.client_id, &credentials.client_secret)),
            );
            post_form_json::<A2aOAuthTokenResponse>(
                token_endpoint,
                fallback_body.as_str(),
                &[],
                timeout,
                transport_config,
                A2aTlsMode::Default,
            )
        }
        Err(error) => Err(error),
    }
}

fn build_client_credentials_form(scopes: &[String], credentials: Option<(&str, &str)>) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    serializer.append_pair("grant_type", "client_credentials");
    if !scopes.is_empty() {
        serializer.append_pair("scope", &scopes.join(" "));
    }
    if let Some((client_id, client_secret)) = credentials {
        serializer.append_pair("client_id", client_id);
        serializer.append_pair("client_secret", client_secret);
    }
    serializer.finish()
}

fn fetch_json<T: for<'de> Deserialize<'de>>(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    let request = agent
        .get(request_url.as_str())
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    let response = request.call().map_err(map_ureq_error)?;
    response.into_json().map_err(|error| {
        AdapterError::Protocol(format!(
            "failed to decode A2A JSON from {}: {error}",
            request_url
        ))
    })
}

fn delete_empty(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<(), AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    let request = agent
        .delete(request_url.as_str())
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    request.call().map_err(map_ureq_error)?;
    Ok(())
}

fn get_sse<F>(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    let request = agent
        .get(request_url.as_str())
        .set("Accept", SSE_CONTENT_TYPE)
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    let response = request.call().map_err(map_ureq_error)?;
    let content_type = response.header("Content-Type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains(SSE_CONTENT_TYPE) {
        return Err(AdapterError::Protocol(format!(
            "expected {SSE_CONTENT_TYPE} response, got {content_type}"
        )));
    }
    parse_sse_stream(response.into_reader(), decode_event)
}

fn post_json<T: for<'de> Deserialize<'de>, B: Serialize>(
    url: &str,
    body: &B,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(
        Url::parse(url).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?,
        request_auth,
    );
    let request = agent
        .post(request_url.as_str())
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    let response = request.send_json(serde_json::to_value(body).map_err(|error| {
        AdapterError::Protocol(format!("failed to serialize A2A request: {error}"))
    })?);
    response
        .map_err(map_ureq_error)?
        .into_json()
        .map_err(|error| AdapterError::Protocol(format!("failed to decode A2A response: {error}")))
}

fn post_form_json<T: for<'de> Deserialize<'de>>(
    url: &Url,
    body: &str,
    request_headers: &[A2aRequestHeader],
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    tls_mode: A2aTlsMode,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, tls_mode)?;
    let request = agent
        .post(url.as_str())
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("Accept", "application/json");
    let request = apply_request_headers(request, request_headers);
    request
        .send_string(body)
        .map_err(map_ureq_error)?
        .into_json()
        .map_err(|error| {
            AdapterError::Protocol(format!(
                "failed to decode OAuth token response from {}: {error}",
                url
            ))
        })
}

fn post_sse_json<T: Serialize, F>(
    url: &str,
    body: &T,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(
        Url::parse(url).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?,
        request_auth,
    );
    let request = agent
        .post(request_url.as_str())
        .set("Content-Type", "application/json")
        .set("Accept", SSE_CONTENT_TYPE)
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    let response = request.send_json(serde_json::to_value(body).map_err(|error| {
        AdapterError::Protocol(format!("failed to serialize A2A request: {error}"))
    })?);
    let response = response.map_err(map_ureq_error)?;
    let content_type = response.header("Content-Type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains(SSE_CONTENT_TYPE) {
        return Err(AdapterError::Protocol(format!(
            "expected {SSE_CONTENT_TYPE} response, got {content_type}"
        )));
    }
    parse_sse_stream(response.into_reader(), decode_event)
}

fn build_optional_default_tls_config(
    root_ca_pems: &[String],
) -> Result<Option<Arc<ureq::rustls::ClientConfig>>, AdapterError> {
    if root_ca_pems.is_empty() {
        return Ok(None);
    }
    Ok(Some(Arc::new(build_client_tls_config(root_ca_pems, None)?)))
}

fn build_optional_mutual_tls_config(
    root_ca_pems: &[String],
    mutual_tls_identity: Option<&A2aMutualTlsIdentity>,
) -> Result<Option<Arc<ureq::rustls::ClientConfig>>, AdapterError> {
    let Some(mutual_tls_identity) = mutual_tls_identity else {
        return Ok(None);
    };
    Ok(Some(Arc::new(build_client_tls_config(
        root_ca_pems,
        Some(mutual_tls_identity),
    )?)))
}

fn build_client_tls_config(
    root_ca_pems: &[String],
    mutual_tls_identity: Option<&A2aMutualTlsIdentity>,
) -> Result<ureq::rustls::ClientConfig, AdapterError> {
    let root_store = build_root_cert_store(root_ca_pems)?;
    let builder = ureq::rustls::ClientConfig::builder().with_root_certificates(root_store);
    if let Some(mutual_tls_identity) = mutual_tls_identity {
        let cert_chain = parse_pem_certificates(
            mutual_tls_identity.cert_chain_pem.as_str(),
            "mutual TLS client certificate chain",
        )?;
        let private_key = parse_pem_private_key(
            mutual_tls_identity.private_key_pem.as_str(),
            "mutual TLS client private key",
        )?;
        builder
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|error| {
                AdapterError::AuthNegotiation(format!(
                    "failed to build mutual TLS client identity: {error}"
                ))
            })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

fn build_root_cert_store(
    root_ca_pems: &[String],
) -> Result<ureq::rustls::RootCertStore, AdapterError> {
    let mut root_store = ureq::rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for root_ca_pem in root_ca_pems {
        for certificate in parse_pem_certificates(root_ca_pem, "custom TLS root CA")? {
            root_store.add(certificate).map_err(|error| {
                AdapterError::AuthNegotiation(format!(
                    "failed to add custom TLS root CA certificate: {error}"
                ))
            })?;
        }
    }
    Ok(root_store)
}

fn parse_pem_certificates(
    pem: &str,
    field_name: &str,
) -> Result<Vec<ureq::rustls::pki_types::CertificateDer<'static>>, AdapterError> {
    let mut reader = pem.as_bytes();
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AdapterError::AuthNegotiation(format!("failed to parse {field_name}: {error}"))
        })?;
    if certificates.is_empty() {
        return Err(AdapterError::AuthNegotiation(format!(
            "{field_name} did not contain any PEM certificates"
        )));
    }
    Ok(certificates)
}

fn parse_pem_private_key(
    pem: &str,
    field_name: &str,
) -> Result<ureq::rustls::pki_types::PrivateKeyDer<'static>, AdapterError> {
    let mut reader = pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut reader)
        .map_err(|error| {
            AdapterError::AuthNegotiation(format!("failed to parse {field_name}: {error}"))
        })?
        .ok_or_else(|| {
            AdapterError::AuthNegotiation(format!(
                "{field_name} did not contain a supported PEM private key"
            ))
        })?;
    Ok(private_key)
}

fn build_agent(
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    tls_mode: A2aTlsMode,
) -> Result<ureq::Agent, AdapterError> {
    let builder = ureq::AgentBuilder::new().timeout(timeout);
    let builder = match tls_mode {
        A2aTlsMode::Default => match transport_config.default_tls_config.as_ref() {
            Some(tls_config) => builder.tls_config(Arc::clone(tls_config)),
            None => builder,
        },
        A2aTlsMode::MutualTls => {
            let tls_config = transport_config.mutual_tls_config.as_ref().ok_or_else(|| {
                AdapterError::AuthNegotiation(
                    "mutual TLS transport was selected without a client identity".to_string(),
                )
            })?;
            builder.tls_config(Arc::clone(tls_config))
        }
    };
    Ok(builder.build())
}
