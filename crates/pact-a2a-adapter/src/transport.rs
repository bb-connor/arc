fn parse_sse_stream<R: Read, F>(
    reader: R,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut data_lines = Vec::new();
    let mut chunks = Vec::new();
    let mut saw_terminal_or_interrupted = false;

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).map_err(|error| {
            AdapterError::Remote(format!("failed to read A2A SSE stream: {error}"))
        })?;
        if bytes_read == 0 {
            if !data_lines.is_empty() {
                process_sse_event(
                    &mut chunks,
                    &mut saw_terminal_or_interrupted,
                    &mut data_lines,
                    &decode_event,
                )?;
            }
            break;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            process_sse_event(
                &mut chunks,
                &mut saw_terminal_or_interrupted,
                &mut data_lines,
                &decode_event,
            )?;
            continue;
        }
        if trimmed.starts_with(':') {
            continue;
        }
        if let Some(data) = trimmed.strip_prefix("data:") {
            data_lines.push(data.trim_start().to_string());
        }
    }

    let stream = ToolCallStream { chunks };
    if stream.chunks.is_empty() {
        return Ok(ToolServerStreamResult::Incomplete {
            stream,
            reason: "A2A streaming response ended without any stream events".to_string(),
        });
    }

    if saw_terminal_or_interrupted {
        Ok(ToolServerStreamResult::Complete(stream))
    } else {
        Ok(ToolServerStreamResult::Incomplete {
            stream,
            reason: "A2A streaming response ended before a terminal or interrupted task state"
                .to_string(),
        })
    }
}

fn process_sse_event<F>(
    chunks: &mut Vec<ToolCallChunk>,
    saw_terminal_or_interrupted: &mut bool,
    data_lines: &mut Vec<String>,
    decode_event: &F,
) -> Result<(), AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    if data_lines.is_empty() {
        return Ok(());
    }

    let payload = data_lines.join("\n");
    data_lines.clear();
    let event = serde_json::from_str::<Value>(&payload).map_err(|error| {
        AdapterError::Protocol(format!("failed to decode A2A SSE event JSON: {error}"))
    })?;
    let stream_response = decode_event(event)?;
    let (stream_response, terminal_or_interrupted) = validate_stream_response(stream_response)?;
    *saw_terminal_or_interrupted |= terminal_or_interrupted;
    chunks.push(ToolCallChunk {
        data: stream_response,
    });
    Ok(())
}

fn apply_request_headers(
    mut request: ureq::Request,
    request_headers: &[A2aRequestHeader],
) -> ureq::Request {
    for header in request_headers {
        request = request.set(header.name.as_str(), header.value.as_str());
    }
    request
}

fn apply_request_auth(
    mut request: ureq::Request,
    request_auth: &A2aResolvedRequestAuth,
) -> ureq::Request {
    request = apply_request_headers(request, &request_auth.headers);
    if !request_auth.cookies.is_empty() {
        let cookie_value = build_cookie_header(request_auth);
        request = request.set("Cookie", cookie_value.as_str());
    }
    request
}

fn build_cookie_header(request_auth: &A2aResolvedRequestAuth) -> String {
    let mut cookie_fragments = request_auth
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Cookie"))
        .map(|header| header.value.clone())
        .collect::<Vec<_>>();
    cookie_fragments.extend(
        request_auth
            .cookies
            .iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value)),
    );
    cookie_fragments.join("; ")
}

fn apply_request_auth_url(mut url: Url, request_auth: &A2aResolvedRequestAuth) -> Url {
    if request_auth.query_params.is_empty() {
        return url;
    }
    let auth_names = request_auth
        .query_params
        .iter()
        .map(|query_param| query_param.name.as_str())
        .collect::<Vec<_>>();
    let existing_pairs = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .filter(|(name, _)| !auth_names.iter().any(|auth_name| auth_name == name))
        .collect::<Vec<_>>();
    url.set_query(None);
    {
        let mut query_pairs = url.query_pairs_mut();
        for (name, value) in existing_pairs {
            query_pairs.append_pair(name.as_str(), value.as_str());
        }
        for query_param in &request_auth.query_params {
            query_pairs.append_pair(query_param.name.as_str(), query_param.value.as_str());
        }
    }
    url
}

fn map_ureq_error(error: ureq::Error) -> AdapterError {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_else(|_| String::new());
            AdapterError::Remote(format!("HTTP {status}: {}", body.trim()))
        }
        ureq::Error::Transport(error) => AdapterError::Remote(error.to_string()),
    }
}
