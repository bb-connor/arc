//! Deterministic generator for the signed broker execution receipt vectors.
//!
//! The receipt body vector is the source. The generator signs it with the
//! fixed broker test signer and derives the envelope vector and the execute
//! response's receipt, evidence and receipt reference from it.

use std::fs;
use std::path::Path;

use chio_core_types::{canonical_json_bytes, sha256_hex, CanonicalBytes, Keypair};
use serde_json::{json, Value};

use super::{display_path, freeze_vectors, workspace_root, XtaskError};

const VECTOR_DIR: &str = "tests/bindings/vectors/security/broker/positive";
const BODY: &str = "broker-execution-receipt-body-v1.json";
const EVIDENCE: &str = "broker-execution-evidence-v1.json";
const ENVELOPE: &str = "broker-execution-receipt-envelope-v1.json";
const RESPONSE: &str = "broker-execute-response-v1.json";
const SIGNER_SEED: [u8; 32] = [43; 32];
const RECEIPT_SCHEMA: &str = "chio.broker-execution-receipt.v1";

pub(crate) fn run(check: bool) -> Result<(), XtaskError> {
    let directory = workspace_root()?.join(VECTOR_DIR);
    let body = read(&directory.join(BODY))?;
    let evidence = read(&directory.join(EVIDENCE))?;
    if body.get("evidence") != Some(&evidence) {
        return Err(XtaskError::Validation(format!(
            "{BODY} evidence differs from {EVIDENCE}"
        )));
    }
    let signer = Keypair::from_seed(&SIGNER_SEED);
    let signature = CanonicalBytes::from_value(&body)
        .and_then(|canonical| signer.sign_wrapped(RECEIPT_SCHEMA, &canonical))
        .map_err(|err| XtaskError::Validation(format!("broker receipt signing failed: {err}")))?;
    let envelope = json!({
        "body": body,
        "signature": signature,
        "signer": signer.public_key(),
    });
    let envelope_bytes = canonical(&envelope)?;
    let mut response = read(&directory.join(RESPONSE))?;
    let fields = response
        .as_object_mut()
        .ok_or_else(|| XtaskError::Validation(format!("{RESPONSE} is not a JSON object")))?;
    fields.insert("evidence".to_owned(), evidence);
    fields.insert(
        "receiptReference".to_owned(),
        Value::String(format!(
            "broker-receipt-sha256-{}",
            sha256_hex(&envelope_bytes)
        )),
    );
    fields.insert("receipt".to_owned(), envelope);
    let outputs = [
        (directory.join(ENVELOPE), envelope_bytes),
        (directory.join(RESPONSE), canonical(&response)?),
    ];

    for (path, bytes) in &outputs {
        if check {
            let existing = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
            if &existing != bytes {
                return Err(XtaskError::Drift(format!(
                    "{} is stale; rerun `cargo xtask gen broker-receipt-vectors`",
                    display_path(path)
                )));
            }
        } else {
            fs::write(path, bytes).map_err(|err| XtaskError::Io(display_path(path), err))?;
            println!("wrote {}", display_path(path));
        }
    }
    if check {
        freeze_vectors(vec!["--check".to_owned()])
    } else {
        freeze_vectors(Vec::new())
    }
}

fn read(path: &Path) -> Result<Value, XtaskError> {
    let bytes = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    serde_json::from_slice(&bytes).map_err(|err| XtaskError::Json(display_path(path), err))
}

fn canonical(value: &Value) -> Result<Vec<u8>, XtaskError> {
    canonical_json_bytes(value).map_err(|err| XtaskError::Validation(err.to_string()))
}
