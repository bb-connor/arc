//! Bounded authentication of one current protected record projection.

use chio_core::canonical::canonical_json_bytes;
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};

use super::digest::{is_digest_hex, record_digest, RecordDigestInput};
use super::global_coverage::retains_global_ownership;
use super::history::{current_event, has_events, RecordEvent};
use super::{
    bounded_text, invariant, require_key, safe_integer, sqlite_error, stored_digest, stored_text,
    MAX_NATIVE_REQUEST_BYTES, MAX_NATIVE_REQUEST_CHARS, MAX_RECORD_KIND_CHARS,
    MAX_RECORD_PAYLOAD_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) enum RecordKind {
    Deployment,
    Workflow,
    Command,
}

impl RecordKind {
    pub(in crate::admission_operation_store) const fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Workflow => "workflow",
            Self::Command => "command",
        }
    }

    fn parse(value: &str) -> Result<Self, AdmissionOperationStoreError> {
        match value {
            "deployment" => Ok(Self::Deployment),
            "workflow" => Ok(Self::Workflow),
            "command" => Ok(Self::Command),
            _ => Err(invariant("recovery record kind is unknown")),
        }
    }
}

/// The native request a workflow record exclusively owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) struct NativeIdentity {
    pub namespace: String,
    pub request: String,
}

/// A bounded current projection authenticated against its latest local event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) struct ProtectedRecord {
    pub key: String,
    pub scope: String,
    pub kind: RecordKind,
    pub version: u64,
    pub payload: Vec<u8>,
    pub native: Option<NativeIdentity>,
    pub event: RecordEvent,
}

impl ProtectedRecord {
    /// Refuse payload bytes that the selected type cannot reproduce exactly.
    pub(in crate::admission_operation_store) fn decode_payload<T>(
        &self,
    ) -> Result<T, AdmissionOperationStoreError>
    where
        T: DeserializeOwned + Serialize,
    {
        decode_protected_payload(&self.payload)
    }
}

/// Refuse bytes that the selected payload type cannot reproduce exactly.
pub(in crate::admission_operation_store) fn decode_protected_payload<T>(
    payload: &[u8],
) -> Result<T, AdmissionOperationStoreError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(payload)
        .map_err(|_| invariant("recovery record payload does not decode"))?;
    let encoded = canonical_json_bytes(&value)
        .map_err(|_| invariant("recovery record payload does not encode"))?;
    if encoded != payload {
        return Err(invariant(
            "recovery record payload is not exact canonical data",
        ));
    }
    Ok(value)
}

/// Read inside a fenced transaction after startup has authenticated the local
/// and global histories. The current row and latest local event use indexed
/// point lookups. Absence requires both journals to have no retained owner.
pub(in crate::admission_operation_store) fn load_record(
    connection: &Connection,
    key: &str,
) -> Result<Option<ProtectedRecord>, AdmissionOperationStoreError> {
    require_key(key)?;
    if let Some(row) = stored_row(connection, key)? {
        return authenticate(connection, key, row).map(Some);
    }
    if retains_global_ownership(connection, key)? || has_events(connection, key)? {
        return Err(invariant(
            "recovery record disappeared with retained history",
        ));
    }
    Ok(None)
}

/// Columns are selected only within their storage type, text character and
/// NUL constraints, and byte ceilings; `within` is false otherwise.
struct StoredRecordRow {
    within: bool,
    version: i64,
    scope: Option<String>,
    kind: Option<String>,
    payload: Option<Vec<u8>>,
    namespace_null: bool,
    namespace: Option<String>,
    request_null: bool,
    request: Option<String>,
}

/// Authenticate the current row of `key` that the local verifier is iterating:
/// its stored bounds, canonical identity and payload, and the digest of its
/// authenticated latest event. No global catalog is read.
pub(super) fn verify_present_record(
    connection: &Connection,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    require_key(key)?;
    let row = stored_row(connection, key)?
        .ok_or_else(|| invariant("recovery record disappeared during verification"))?;
    authenticate(connection, key, row).map(|_| ())
}

fn stored_row(
    connection: &Connection,
    key: &str,
) -> Result<Option<StoredRecordRow>, AdmissionOperationStoreError> {
    let scope = stored_digest("scope_key");
    let kind = bounded_text(
        "kind",
        MAX_RECORD_KIND_CHARS,
        "kind IN ('deployment', 'workflow', 'command')",
    );
    let payload = format!(
        "(CASE WHEN typeof(payload) = 'blob' \
         THEN length(payload) BETWEEN 1 AND {MAX_RECORD_PAYLOAD_BYTES} ELSE 0 END)"
    );
    let namespace = stored_digest("native_namespace");
    let request = stored_text("native_request", 1, MAX_NATIVE_REQUEST_CHARS);
    connection
        .query_row(
            &format!(
                "SELECT
                    typeof(version) = 'integer' AND {scope} AND {kind} AND {payload}
                        AND (typeof(native_namespace) = 'null' OR {namespace})
                        AND (typeof(native_request) = 'null' OR {request}),
                    CASE WHEN typeof(version) = 'integer' THEN version ELSE 0 END,
                    CASE WHEN {scope} THEN scope_key END,
                    CASE WHEN {kind} THEN kind END,
                    CASE WHEN {payload} THEN payload END,
                    typeof(native_namespace) = 'null',
                    CASE WHEN {namespace} THEN native_namespace END,
                    typeof(native_request) = 'null',
                    CASE WHEN {request} THEN native_request END
                 FROM main.admission_operation_recovery_records
                 WHERE record_key = ?1"
            ),
            [key],
            |row| {
                Ok(StoredRecordRow {
                    within: row.get(0)?,
                    version: row.get(1)?,
                    scope: row.get(2)?,
                    kind: row.get(3)?,
                    payload: row.get(4)?,
                    namespace_null: row.get(5)?,
                    namespace: row.get(6)?,
                    request_null: row.get(7)?,
                    request: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)
}

fn authenticate(
    connection: &Connection,
    key: &str,
    row: StoredRecordRow,
) -> Result<ProtectedRecord, AdmissionOperationStoreError> {
    let (true, Some(scope), Some(kind), Some(payload)) =
        (row.within, row.scope, row.kind, row.payload)
    else {
        return Err(invariant("recovery record exceeds its bound"));
    };
    let version = safe_integer(row.version, "recovery record version")?;
    let kind = RecordKind::parse(&kind)?;
    let native = match (
        row.namespace_null,
        row.namespace,
        row.request_null,
        row.request,
    ) {
        (true, None, true, None) => None,
        (false, Some(namespace), false, Some(request)) if kind == RecordKind::Workflow => {
            if !is_digest_hex(&namespace) {
                return Err(invariant("recovery record identity is not canonical"));
            }
            let chars = request.chars().count();
            if !(1..=MAX_NATIVE_REQUEST_CHARS).contains(&chars)
                || request.len() > MAX_NATIVE_REQUEST_BYTES
            {
                return Err(invariant(
                    "recovery record native request exceeds its bound",
                ));
            }
            Some(NativeIdentity { namespace, request })
        }
        _ => return Err(invariant("recovery record native identity is malformed")),
    };
    if !is_digest_hex(&scope) {
        return Err(invariant("recovery record identity is not canonical"));
    }
    require_canonical_json(&payload)?;
    let digest = record_digest(&RecordDigestInput {
        key,
        scope: &scope,
        kind,
        version,
        payload: &payload,
        native: native.as_ref(),
    })?;
    let event = current_event(connection, key, version)?;
    if event.record_digest != digest {
        return Err(invariant("recovery record digest differs from its event"));
    }
    Ok(ProtectedRecord {
        key: key.to_owned(),
        scope,
        kind,
        version,
        payload,
        native,
        event,
    })
}

/// Every persisted payload is the canonical JSON encoding of its value.
fn require_canonical_json(payload: &[u8]) -> Result<(), AdmissionOperationStoreError> {
    let invalid = || invariant("recovery record payload is not canonical JSON");
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|_| invalid())?;
    let encoded = canonical_json_bytes(&value).map_err(|_| invalid())?;
    if encoded != payload {
        return Err(invalid());
    }
    Ok(())
}
