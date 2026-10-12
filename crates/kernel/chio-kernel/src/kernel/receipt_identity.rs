//! Signed request identity state, selected by the transition producing a receipt.

use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IdentityDisposition {
    /// No persisted operation, retained custody or executed effect binds the id.
    Reusable,
    /// A submitted durable commit has not yielded an authoritative outcome.
    Retained,
    /// A terminal operation or an executed effect binds the id.
    Terminal,
}

pub(super) fn with_identity_disposition(
    metadata: Option<Value>,
    disposition: IdentityDisposition,
) -> Option<Value> {
    let mut metadata = match metadata {
        Some(Value::Object(object)) => object,
        _ => Map::new(),
    };
    let mut runtime = match metadata.remove("chio_runtime") {
        Some(Value::Object(object)) => object,
        _ => Map::new(),
    };
    let disposition = match disposition {
        IdentityDisposition::Reusable => "reusable",
        IdentityDisposition::Retained => "retained",
        IdentityDisposition::Terminal => "terminal",
    };
    runtime.insert(
        "identity_disposition".into(),
        Value::String(disposition.into()),
    );
    metadata.insert("chio_runtime".into(), Value::Object(runtime));
    Some(Value::Object(metadata))
}
