//! Adjacently tagged enums decoded from wire, IPC, signed or stored input
//! refuse a repeated tag or content key on raw input.

use serde::de::DeserializeOwned;

type Decode = fn(&str) -> Result<(), String>;

fn decode<T: DeserializeOwned>(raw: &str) -> Result<(), String> {
    serde_json::from_str::<T>(raw)
        .map(drop)
        .map_err(|error| error.to_string())
}

const ENUMS: [(&str, &str, &str, Decode); 13] = [
    (
        "kind",
        "bound_tool_invocation",
        "value",
        decode::<chio_core_types::capability::governance::GovernedTransactionIntentBody>,
    ),
    (
        "code",
        "capability_denied",
        "detail",
        decode::<chio_core_types::message::ToolCallError>,
    ),
    (
        "record_type",
        "requested",
        "record",
        decode::<chio_security_types::ResponseMutationRecord>,
    ),
    (
        "kind",
        "suspension",
        "snapshot",
        decode::<chio_security_types::response_simulation::ResponseSimulationState>,
    ),
    (
        "family",
        "premium_history",
        "claims",
        decode::<chio_credentials::FinancialCredentialSubjectV1>,
    ),
    (
        "kind",
        "financial",
        "credential",
        decode::<chio_credentials::FinancialPassportCredential>,
    ),
    (
        "state",
        "known",
        "value",
        decode::<chio_reputation::MetricValue>,
    ),
    (
        "kind",
        "capabilities",
        "request",
        decode::<chio_secret_broker::authority_ipc::AuthorityOperation>,
    ),
    (
        "kind",
        "capabilities",
        "response",
        decode::<chio_secret_broker::authority_ipc::AuthorityResult>,
    ),
    (
        "version",
        "v1",
        "context",
        decode::<chio_kernel::SecurityInvocationContext>,
    ),
    (
        "kind",
        "observed",
        "unix_ms",
        decode::<chio_kernel::stop::DecisionTime>,
    ),
    (
        "operation",
        "health",
        "input",
        decode::<chio_control_plane::security::ActiveResponseAuthorityOperation>,
    ),
    (
        "result",
        "ready",
        "output",
        decode::<chio_control_plane::security::ActiveResponseAuthorityResult>,
    ),
];

#[test]
fn reachable_tagged_enums_refuse_a_repeated_tag_or_content_key() {
    for (tag, variant, content, decode) in ENUMS {
        let head = format!(r#"{{"{tag}":"{variant}","{tag}""#);
        assert_eq!(
            decode(&format!(r#"{head}:"{variant}"}}"#)),
            Err(format!(
                "duplicate field `{tag}` at line 1 column {}",
                head.len()
            )),
            "{variant}"
        );
        let head = format!(r#"{{"{content}":null,"{content}""#);
        assert_eq!(
            decode(&format!(r#"{head}:null,"{tag}":"{variant}"}}"#)),
            Err(format!(
                "duplicate field `{content}` at line 1 column {}",
                head.len()
            )),
            "{variant}"
        );
    }
}
