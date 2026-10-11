use serde_json::{json, Value};

const MCP_CORE_SCENARIOS: &[&str] = &[
    "initialize",
    "tools-list",
    "tools-call-simple-text",
    "resources-list",
    "prompts-list",
];

// Peer failures can retain an entire response. Emit only fixed public
// classifications and scalar outcome fields, never the response or arguments.
fn public_failure_explanation(message: &str) -> &'static str {
    let diagnostic = message.split(" body: ").next().unwrap_or("");
    for (prefix, label) in [
        ("Timeout was reached", "HTTP transport timed out"),
        ("Operation timed out", "HTTP transport timed out"),
        ("Failed to connect", "HTTP transport connection failed"),
        ("Couldn't connect", "HTTP transport connection failed"),
        ("JSON-RPC error response", "JSON-RPC error response"),
        ("MCP request returned HTTP", "MCP HTTP error response"),
        (
            "MCP response did not include matching JSON-RPC terminal response",
            "matching JSON-RPC terminal response missing",
        ),
        ("failed to parse JSON response", "invalid JSON response"),
    ] {
        if diagnostic.starts_with(prefix) {
            return label;
        }
    }
    if let Ok(response) = serde_json::from_str::<Value>(message) {
        if response
            .pointer("/error/code")
            .and_then(Value::as_i64)
            .is_some()
        {
            return "JSON-RPC error response";
        }
        if response.pointer("/result/isError").and_then(Value::as_bool) == Some(true) {
            return "MCP error tool result";
        }
        if response.get("result").is_some() {
            return "MCP tool result did not match the expected text";
        }
    }
    "peer explanation withheld; inspect retained evidence"
}

pub(super) fn failed_scenario_details(results_json: &str) -> Value {
    let results = serde_json::from_str::<Vec<Value>>(results_json);
    Value::Array(
        MCP_CORE_SCENARIOS
            .iter()
            .filter_map(|scenario| {
                let row = results
                    .as_ref()
                    .ok()
                    .and_then(|rows| rows.iter().find(|row| row["scenarioId"] == *scenario));
                if row.is_some_and(|row| row["status"] == "pass") {
                    return None;
                }
                let message = row.and_then(|row| row["failureMessage"].as_str());
                let response =
                    message.and_then(|message| serde_json::from_str::<Value>(message).ok());
                let decision = response
                    .as_ref()
                    .and_then(|response| response.pointer("/result/_meta/chio/decision"))
                    .and_then(Value::as_str)
                    .filter(|decision| matches!(*decision, "allow" | "deny" | "pending_approval"));
                Some(json!({
                    "scenarioId": scenario,
                    "durationMs": row.and_then(|row| row["durationMs"].as_u64()),
                    "explanation": match message {
                        Some(message) => public_failure_explanation(message),
                        None if results.is_err() => "invalid peer results JSON",
                        None => "missing peer result or explanation",
                    },
                    "jsonrpcCode": response.as_ref()
                        .and_then(|response| response.pointer("/error/code"))
                        .and_then(Value::as_i64),
                    "isError": response.as_ref()
                        .and_then(|response| response.pointer("/result/isError"))
                        .and_then(Value::as_bool),
                    "decision": decision,
                }))
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_diagnostics_emit_only_six_public_scalar_fields() {
        let response = json!({
            "result": {
                "isError": true,
                "content": [{"type": "text", "text": "bearer-private-secret arguments-private-secret"}],
                "_meta": {"chio": {"decision": "deny", "receipt": "private-receipt"}},
                "structuredContent": {"arguments": {"message": "arguments-private-secret"}},
            }
        });
        let results = json!([{
            "scenarioId": "tools-call-simple-text",
            "status": "fail",
            "durationMs": 10000,
            "failureMessage": response.to_string(),
        }]);
        let details = failed_scenario_details(&results.to_string());
        let rows = details.as_array().expect("public detail rows");
        for row in rows {
            let fields = row.as_object().expect("public detail object");
            assert_eq!(fields.len(), 6);
            let mut keys = fields.keys().map(String::as_str).collect::<Vec<_>>();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "decision",
                    "durationMs",
                    "explanation",
                    "isError",
                    "jsonrpcCode",
                    "scenarioId"
                ]
            );
            assert!(fields
                .values()
                .all(|value| !value.is_array() && !value.is_object()));
        }
        let failed = rows
            .iter()
            .find(|row| row["scenarioId"] == "tools-call-simple-text")
            .expect("tool failure");
        assert_eq!(failed["explanation"], "MCP error tool result");
        assert_eq!(failed["decision"], "deny");
        assert_eq!(failed["durationMs"], 10000);
        let printed = details.to_string();
        for secret in [
            "bearer-private-secret",
            "arguments-private-secret",
            "private-receipt",
        ] {
            assert!(!printed.contains(secret));
        }
    }

    #[test]
    fn arbitrary_transport_details_and_response_bodies_are_withheld() {
        assert_eq!(
            public_failure_explanation("Timeout was reached body: bearer-private-secret"),
            "HTTP transport timed out",
        );
        assert_eq!(
            public_failure_explanation(
                "JSON-RPC error response: arguments-private-secret body: bearer-private-secret"
            ),
            "JSON-RPC error response",
        );
        assert_eq!(
            public_failure_explanation("unknown credentials bearer-private-secret"),
            "peer explanation withheld; inspect retained evidence",
        );
    }
}
