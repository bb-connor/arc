use chio_egress_contract::HttpEgressContract;
use chio_openapi::{ChioExtensions, OpenApiSpec, Parameter, ParameterLocation};
use serde_json::{json, Value};

use crate::{BridgeError, BridgedResponse, RouteBinding};

#[derive(Debug, Clone)]
pub(crate) struct RouteDispatch {
    binding: RouteBinding,
    query_parameters: Vec<String>,
}

impl RouteDispatch {
    fn new(binding: RouteBinding, query_parameters: Vec<String>) -> Self {
        Self {
            binding,
            query_parameters,
        }
    }

    pub(crate) fn binding(&self) -> &RouteBinding {
        &self.binding
    }
}

pub(crate) fn build_route_dispatches(
    spec: &OpenApiSpec,
) -> std::collections::BTreeMap<String, RouteDispatch> {
    let mut routes = std::collections::BTreeMap::new();

    for (path, path_item) in &spec.paths {
        for (method_str, operation) in &path_item.operations {
            let extensions = ChioExtensions::from_operation(&operation.raw);
            if !extensions.should_publish() {
                continue;
            }

            let params = merge_parameters(&path_item.common_parameters, &operation.parameters);
            let query_parameters = params
                .iter()
                .filter(|param| param.location == ParameterLocation::Query)
                .map(|param| param.name.clone())
                .collect();
            let tool_name = operation
                .operation_id
                .clone()
                .unwrap_or_else(|| format!("{} {}", method_str.to_uppercase(), path));

            routes.insert(
                tool_name,
                RouteDispatch::new(
                    RouteBinding {
                        method: method_str.to_uppercase(),
                        path: path.clone(),
                    },
                    query_parameters,
                ),
            );
        }
    }

    routes
}

fn merge_parameters(path_params: &[Parameter], op_params: &[Parameter]) -> Vec<Parameter> {
    let mut merged: Vec<Parameter> = path_params.to_vec();

    for op_param in op_params {
        let existing = merged
            .iter()
            .position(|param| param.name == op_param.name && param.location == op_param.location);
        if let Some(index) = existing {
            merged[index] = op_param.clone();
        } else {
            merged.push(op_param.clone());
        }
    }

    merged
}

pub(crate) fn enforce_dispatch_contract<'a>(
    contract: Option<&'a HttpEgressContract>,
    url: &str,
) -> Result<&'a HttpEgressContract, BridgeError> {
    let contract = contract.ok_or_else(|| {
        BridgeError::UpstreamError(
            "OpenAPI bridge dispatcher requires an HttpEgressContract".to_string(),
        )
    })?;
    contract.enforce_url_with_dns(url, 0).map_err(|err| {
        BridgeError::UpstreamError(format!("HttpEgressContract rejects bridge URL: {err}"))
    })?;
    Ok(contract)
}

pub(crate) fn enforce_bridged_response_body(
    contract: &HttpEgressContract,
    response: &BridgedResponse,
) -> Result<(), BridgeError> {
    let body_bytes = serde_json::to_vec(&response.body)
        .map(|bytes| bytes.len() as u64)
        .map_err(|err| {
            BridgeError::UpstreamError(format!("failed to measure bridge response body: {err}"))
        })?;
    contract.enforce_response_bytes(body_bytes).map_err(|err| {
        BridgeError::UpstreamError(format!("HttpEgressContract rejects bridge response: {err}"))
    })
}

pub(crate) fn bridged_tool_response(binding: &RouteBinding, response: BridgedResponse) -> Value {
    let text = serde_json::to_string(&response.body).unwrap_or_else(|_| "{}".to_string());
    json!({
        "content": [{
            "type": "text",
            "text": text,
        }],
        "isError": response.is_error,
        "structuredContent": {
            "httpStatus": response.status,
            "method": binding.method,
            "path": binding.path,
            "body": response.body,
        }
    })
}

pub(crate) fn dispatch_url(
    base_url: &str,
    dispatch: &RouteDispatch,
    arguments: &Value,
) -> Result<String, BridgeError> {
    let path = expand_route_path(&dispatch.binding.path, arguments)?;
    let mut url = format!("{base_url}{path}");
    append_query_parameters(&mut url, &dispatch.query_parameters, arguments)?;
    Ok(url)
}

pub(crate) fn expand_route_path(template: &str, arguments: &Value) -> Result<String, BridgeError> {
    let mut expanded = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        expanded.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let close = after_open.find('}').ok_or_else(|| {
            BridgeError::UpstreamError(format!(
                "OpenAPI bridge route path `{template}` has an unterminated path parameter"
            ))
        })?;
        let name = &after_open[..close];
        if name.is_empty() {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge route path `{template}` has an empty path parameter"
            )));
        }
        let value = path_parameter_value(arguments, name)?;
        expanded.push_str(&percent_encode_component(&value));
        rest = &after_open[close + 1..];
    }

    if rest.contains('}') {
        return Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge route path `{template}` has an unmatched path parameter terminator"
        )));
    }
    expanded.push_str(rest);
    Ok(expanded)
}

fn append_query_parameters(
    url: &mut String,
    query_parameters: &[String],
    arguments: &Value,
) -> Result<(), BridgeError> {
    let mut first = !url.contains('?');
    for name in query_parameters {
        let Some(value) = arguments.get(name) else {
            continue;
        };
        append_query_value(url, &mut first, name, value)?;
    }
    Ok(())
}

fn append_query_value(
    url: &mut String,
    first: &mut bool,
    name: &str,
    value: &Value,
) -> Result<(), BridgeError> {
    match value {
        Value::String(value) => append_query_pair(url, first, name, value),
        Value::Number(value) => append_query_pair(url, first, name, &value.to_string()),
        Value::Bool(value) => append_query_pair(url, first, name, &value.to_string()),
        Value::Array(values) => {
            for value in values {
                let text = query_scalar_value(name, value)?;
                append_query_pair(url, first, name, &text);
            }
        }
        Value::Null => {}
        _ => {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge query parameter `{name}` must be a string, number, boolean, null, or array of scalar values"
            )));
        }
    }
    Ok(())
}

fn query_scalar_value(name: &str, value: &Value) -> Result<String, BridgeError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge query parameter `{name}` array entries must be scalar values"
        ))),
    }
}

fn append_query_pair(url: &mut String, first: &mut bool, name: &str, value: &str) {
    if *first {
        url.push('?');
        *first = false;
    } else {
        url.push('&');
    }
    url.push_str(&percent_encode_component(name));
    url.push('=');
    url.push_str(&percent_encode_component(value));
}

fn path_parameter_value(arguments: &Value, name: &str) -> Result<String, BridgeError> {
    let value = arguments.get(name).ok_or_else(|| {
        BridgeError::UpstreamError(format!("OpenAPI bridge missing path parameter `{name}`"))
    })?;
    let text = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge path parameter `{name}` must be a string, number, or boolean"
            )));
        }
    };
    if text.is_empty() {
        return Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge path parameter `{name}` must not be empty"
        )));
    }
    Ok(text)
}

fn percent_encode_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if is_unreserved_byte(*byte) {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

fn is_unreserved_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}
