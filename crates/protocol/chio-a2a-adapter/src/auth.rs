fn bearer_request_header(access_token: String) -> A2aRequestHeader {
    A2aRequestHeader {
        name: "Authorization".to_string(),
        value: format!("Bearer {access_token}"),
        sensitive: true,
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
        sensitive: true,
    };
    let basic_body = build_client_credentials_form(scopes, None);
    let response = match post_form_json::<A2aOAuthTokenResponse>(
        token_endpoint,
        basic_body.as_str(),
        &[basic_header],
        timeout,
        transport_config,
        A2aTlsMode::Default,
    ) {
        Ok(response) => response,
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
            )?
        }
        Err(error) => return Err(error),
    };
    validate_oauth_token_response(response)
}

fn validate_oauth_token_response(
    response: A2aOAuthTokenResponse,
) -> Result<A2aOAuthTokenResponse, AdapterError> {
    if response.access_token.trim().is_empty() {
        return Err(AdapterError::AuthNegotiation(
            "OAuth token endpoint returned empty access_token".to_string(),
        ));
    }
    if response.access_token.trim() != response.access_token {
        return Err(AdapterError::AuthNegotiation(
            "OAuth token endpoint returned access_token with surrounding whitespace".to_string(),
        ));
    }
    if bearer_token_contains_forbidden_character(&response.access_token) {
        return Err(AdapterError::AuthNegotiation(
            "OAuth token endpoint returned access_token with whitespace or control characters"
                .to_string(),
        ));
    }
    let token_type = response.token_type.as_deref().ok_or_else(|| {
        AdapterError::AuthNegotiation("OAuth token endpoint omitted token_type".to_string())
    })?;
    if !token_type.trim().eq_ignore_ascii_case("bearer") {
        return Err(AdapterError::AuthNegotiation(format!(
            "OAuth token endpoint returned unsupported token_type `{token_type}`"
        )));
    }
    Ok(response)
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

/// Send through the contract agent and follow each redirect only after its
/// target passes the contract at its position in the chain. The agent never
/// follows a redirect itself, and it resolves and checks every hop's host
/// before dialing. Error statuses become [`AdapterError::Remote`].
fn dispatch_with_redirect_validation<F>(
    initial_url: &str,
    transport_config: &A2aTransportConfig,
    allow_cross_origin_redirects: bool,
    mut send: F,
) -> Result<BlockingContractResponse, AdapterError>
where
    F: FnMut(&str, bool) -> Result<BlockingContractResponse, HttpEgressError>,
{
    let contract = required_contract(transport_config)?;
    let max_chain = contract.max_redirect_chain;
    let mut current_url = initial_url.to_string();
    let mut chain_len: u8 = 0;
    let mut strip_sensitive_headers = false;
    loop {
        let response = send(&current_url, strip_sensitive_headers).map_err(map_egress_error)?;
        let status = response.status();
        if status >= 400 {
            return Err(error_status(&response, contract));
        }
        if !(300..400).contains(&status) {
            return Ok(response);
        }
        let Some(location) = response.header("Location") else {
            return Ok(response);
        };
        if chain_len >= max_chain {
            return Err(AdapterError::InvalidUrl(format!(
                "HttpEgressContract redirect limit exceeded ({max_chain}) following A2A redirect from {current_url}"
            )));
        }
        chain_len = chain_len.saturating_add(1);
        let next_url = match Url::parse(location) {
            Ok(absolute) => absolute,
            Err(_) => Url::parse(&current_url)
                .and_then(|base| base.join(location))
                .map_err(|error| {
                    AdapterError::InvalidUrl(format!(
                        "invalid A2A redirect target `{location}`: {error}"
                    ))
                })?,
        };
        contract
            .enforce_url(next_url.as_str(), chain_len)
            .map_err(|err| {
                AdapterError::InvalidUrl(format!(
                    "HttpEgressContract rejects A2A redirect target: {err}"
                ))
            })?;
        let previous_url = Url::parse(&current_url).map_err(|error| {
            AdapterError::InvalidUrl(format!(
                "invalid A2A redirect source `{current_url}`: {error}"
            ))
        })?;
        let cross_origin = !same_origin(&previous_url, &next_url);
        if cross_origin && !allow_cross_origin_redirects {
            return Err(AdapterError::InvalidUrl(format!(
                "A2A body-bearing request rejected cross-origin redirect from {previous_url} to {next_url}"
            )));
        }
        strip_sensitive_headers = strip_sensitive_headers || cross_origin;
        current_url = next_url.into();
    }
}

fn read_json_response_with_contract<T: for<'de> Deserialize<'de>>(
    response: BlockingContractResponse,
    context: &str,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let contract = required_contract(transport_config)?;
    let body = response_body_with_contract(&response, contract, context)?;
    chio_core::canonical::UntrustedJsonText::from_wire(body, MAX_A2A_JSON_BYTES)?
        .decode_document()
        .map_err(Into::into)
}

fn read_sse_response_with_contract<F>(
    response: BlockingContractResponse,
    context: &str,
    transport_config: &A2aTransportConfig,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let contract = required_contract(transport_config)?;
    enforce_declared_content_length(contract, &response, context)?;
    parse_sse_stream_with_limit(response.body(), contract.max_response_bytes, decode_event)
}

fn fetch_json<T: for<'de> Deserialize<'de>>(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    let response = dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        true,
        |target, strip_sensitive_headers| {
            let request = agent
                .get(target)?
                .header(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.call()
        },
    )?;
    read_json_response_with_contract(response, request_url.as_str(), transport_config)
}

fn delete_empty(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<(), AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        true,
        |target, strip_sensitive_headers| {
            let request = agent
                .delete(target)?
                .header(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.call()
        },
    )?;
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
    let response = dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        true,
        |target, strip_sensitive_headers| {
            let request = agent
                .get(target)?
                .header("Accept", SSE_CONTENT_TYPE)
                .header(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.call()
        },
    )?;
    let content_type = response.header("Content-Type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains(SSE_CONTENT_TYPE) {
        return Err(AdapterError::Protocol(format!(
            "expected {SSE_CONTENT_TYPE} response, got {content_type}"
        )));
    }
    read_sse_response_with_contract(
        response,
        request_url.as_str(),
        transport_config,
        decode_event,
    )
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
    let body_bytes = serde_json::to_vec(body).map_err(|error| {
        AdapterError::Protocol(format!("failed to serialize A2A request: {error}"))
    })?;
    let response = dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        false,
        |target, strip_sensitive_headers| {
            let request = agent
                .post(target)?
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.send_bytes(&body_bytes)
        },
    )?;
    read_json_response_with_contract(response, request_url.as_str(), transport_config)
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
    let response = dispatch_with_redirect_validation(
        url.as_str(),
        transport_config,
        false,
        |target, strip_sensitive_headers| {
            let request = agent
                .post(target)?
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json");
            let request = apply_request_headers(request, request_headers, strip_sensitive_headers);
            request.send_bytes(body.as_bytes())
        },
    )?;
    read_json_response_with_contract(response, url.as_str(), transport_config)
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
    let body_bytes = serde_json::to_vec(body).map_err(|error| {
        AdapterError::Protocol(format!("failed to serialize A2A request: {error}"))
    })?;
    let response = dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        false,
        |target, strip_sensitive_headers| {
            let request = agent
                .post(target)?
                .header("Content-Type", "application/json")
                .header("Accept", SSE_CONTENT_TYPE)
                .header(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.send_bytes(&body_bytes)
        },
    )?;
    let content_type = response.header("Content-Type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains(SSE_CONTENT_TYPE) {
        return Err(AdapterError::Protocol(format!(
            "expected {SSE_CONTENT_TYPE} response, got {content_type}"
        )));
    }
    read_sse_response_with_contract(
        response,
        request_url.as_str(),
        transport_config,
        decode_event,
    )
}

fn build_optional_default_tls_config(
    root_ca_pems: &[String],
) -> Result<Option<BlockingContractTls>, AdapterError> {
    if root_ca_pems.is_empty() {
        return Ok(None);
    }
    BlockingContractTls::from_pem(root_ca_pems, None)
        .map(Some)
        .map_err(|error| AdapterError::AuthNegotiation(error.to_string()))
}

fn build_optional_mutual_tls_config(
    root_ca_pems: &[String],
    mutual_tls_identity: Option<&A2aMutualTlsIdentity>,
) -> Result<Option<BlockingContractTls>, AdapterError> {
    let Some(mutual_tls_identity) = mutual_tls_identity else {
        return Ok(None);
    };
    let identity = ClientIdentityPem {
        cert_chain_pem: mutual_tls_identity.cert_chain_pem.as_str(),
        private_key_pem: mutual_tls_identity.private_key_pem.as_str(),
    };
    BlockingContractTls::from_pem(root_ca_pems, Some(identity))
        .map(Some)
        .map_err(|error| AdapterError::AuthNegotiation(error.to_string()))
}

fn required_contract(
    transport_config: &A2aTransportConfig,
) -> Result<&HttpEgressContract, AdapterError> {
    transport_config.egress_contract.as_ref().ok_or_else(|| {
        AdapterError::InvalidUrl("A2A outbound HTTP requires an HttpEgressContract".to_string())
    })
}

fn build_agent(
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    tls_mode: A2aTlsMode,
) -> Result<BlockingContractAgent, AdapterError> {
    let tls = match tls_mode {
        A2aTlsMode::Default => transport_config.default_tls_config.clone(),
        A2aTlsMode::MutualTls => Some(transport_config.mutual_tls_config.clone().ok_or_else(
            || {
                AdapterError::AuthNegotiation(
                    "mutual TLS transport was selected without a client identity".to_string(),
                )
            },
        )?),
    };
    let agent = BlockingContractAgent::new(required_contract(transport_config)?, timeout, timeout)
        .map_err(map_egress_error)?;
    Ok(match tls {
        Some(tls) => agent.with_tls(tls),
        None => agent,
    })
}
