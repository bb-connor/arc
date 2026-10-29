//! Signed seeds projected from regenerated vectors: the browser demo receipt,
//! the `capability_receipt` and `fuzz_merkle_checkpoint` fuzz seeds from the
//! bindings receipt and capability vectors, and the `frost_round2_envelope`
//! fuzz seeds from the sealed FROST round-two vectors, with their
//! `fuzz/corpus_metadata.toml` digests.
//!
//! Each seed is a vector case copied unchanged, except the tenant receipt,
//! which re-signs the allow receipt body with a tenant id under the vectors'
//! kernel key.

use std::fs;
use std::path::{Path, PathBuf};

use chio_core_types::canonical::UntrustedJsonText;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::ChioReceipt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{display_path, support::digest_to_hex, workspace_root, XtaskError};

const RECEIPT_VECTORS: &str = "tests/bindings/vectors/receipt/v1.json";
const CAPABILITY_VECTORS: &str = "tests/bindings/vectors/capability/v1.json";
const DEMO_RECEIPT: &str = "docs/demo/fixtures/allow-receipt.json";
const CORPUS_METADATA: &str = "fuzz/corpus_metadata.toml";
const CAPABILITY_RECEIPT_CORPUS: &str = "fuzz/corpus/capability_receipt";
const MERKLE_CHECKPOINT_CORPUS: &str = "fuzz/corpus/fuzz_merkle_checkpoint";
const FROST_SEALED_VECTORS: &str =
    "crates/trust/chio-federation-authority/tests/fixtures/frost-round2-sealed-v1.json";
const FROST_ROUND2_CORPUS: &str = "fuzz/corpus/frost_round2_envelope";
const VECTOR_KERNEL_SEED: [u8; 32] = [7; 32];
const SEED_TENANT_ID: &str = "tenant-fuzz";

const RECEIPT_SEED_CASES: [&str; 4] = [
    "allow_receipt",
    "deny_receipt",
    "signed_receipt_with_invalid_parameter_hash",
    "tampered_receipt_signature",
];

const CAPABILITY_SEED_CASES: [&str; 5] = [
    "valid_delegated_capability",
    "expired_capability",
    "not_yet_valid_capability",
    "tampered_capability_signature",
    "broken_delegation_chain_signature",
];

/// Regenerate (or, with `check_only`, compare) every projected seed and its
/// corpus metadata digest.
pub fn run(check_only: bool) -> Result<(), XtaskError> {
    let root = workspace_root()?;
    let receipts = load_cases(&root.join(RECEIPT_VECTORS))?;
    let capabilities = load_cases(&root.join(CAPABILITY_VECTORS))?;
    let allow = find_case(&receipts, "allow_receipt")?;

    let mut outputs: Vec<(PathBuf, String)> = Vec::new();
    outputs.push((root.join(DEMO_RECEIPT), pretty(&demo_receipt(allow)?)?));
    let corpus = root.join(CAPABILITY_RECEIPT_CORPUS);
    for id in RECEIPT_SEED_CASES {
        outputs.push((
            corpus.join(format!("binding-{id}.json")),
            pretty(find_case(&receipts, id)?)?,
        ));
    }
    for id in CAPABILITY_SEED_CASES {
        outputs.push((
            corpus.join(format!("binding-{id}.json")),
            pretty(find_case(&capabilities, id)?)?,
        ));
    }
    let allow_receipt = receipt_of(allow)?;
    outputs.push((
        corpus.join("tenant-receipt.json"),
        pretty(&serde_json::to_value(tenant_receipt(&allow_receipt)?).map_err(json_error)?)?,
    ));
    let evidence_row = format!(
        "{{\"seq\":1,\"receipt\":{}}}\n",
        serde_json::to_string(&allow_receipt).map_err(json_error)?
    );
    outputs.push((corpus.join("minimal-receipts.ndjson"), evidence_row.clone()));
    outputs.push((
        root.join(MERKLE_CHECKPOINT_CORPUS)
            .join("minimal-receipts.ndjson"),
        evidence_row,
    ));

    let frost_path = root.join(FROST_SEALED_VECTORS);
    let frost: Vec<Value> = serde_json::from_str(&read(&frost_path)?)
        .map_err(|err| XtaskError::Json(display_path(&frost_path), err))?;
    for (index, envelope) in frost.iter().enumerate() {
        outputs.push((
            root.join(FROST_ROUND2_CORPUS)
                .join(format!("pair-{index:02}.json")),
            serde_json::to_string(envelope).map_err(json_error)?,
        ));
    }

    let metadata_path = root.join(CORPUS_METADATA);
    let mut metadata = read(&metadata_path)?;
    for (path, contents) in &outputs {
        if let Ok(relative) = path.strip_prefix(&root) {
            if relative.starts_with("fuzz/corpus") {
                metadata = with_seed_digest(&metadata, &relative.to_string_lossy(), contents)?;
            }
        }
    }
    outputs.push((metadata_path, metadata));

    let mut stale = Vec::new();
    for (path, contents) in &outputs {
        if path.exists() && read(path)? == *contents {
            continue;
        }
        if check_only {
            stale.push(display_path(path));
        } else {
            fs::write(path, contents).map_err(|err| XtaskError::Io(display_path(path), err))?;
            println!("wrote {}", display_path(path));
        }
    }
    if stale.is_empty() {
        Ok(())
    } else {
        Err(XtaskError::Drift(format!(
            "stale vector seeds: {}",
            stale.join(", ")
        )))
    }
}

fn demo_receipt(case: &Value) -> Result<Value, XtaskError> {
    let field = |name: &str| {
        case.get(name)
            .cloned()
            .ok_or_else(|| XtaskError::Validation(format!("allow_receipt case has no {name}")))
    };
    let expected = field("expected")?;
    Ok(json!({
        "description": field("description")?,
        "expected": {
            "decision": expected.get("decision").cloned().unwrap_or(Value::Null),
            "parameter_hash_valid": expected.get("parameter_hash_valid").cloned().unwrap_or(Value::Null),
            "signature_valid": expected.get("signature_valid").cloned().unwrap_or(Value::Null),
        },
        "receipt": field("receipt")?,
        "source": RECEIPT_VECTORS,
        "source_case_id": "allow_receipt",
        "verify_only": field("verify_only")?,
    }))
}

fn tenant_receipt(allow: &ChioReceipt) -> Result<ChioReceipt, XtaskError> {
    let mut body = allow.body();
    body.tenant_id = Some(SEED_TENANT_ID.to_owned());
    ChioReceipt::sign(body, &Keypair::from_seed(&VECTOR_KERNEL_SEED))
        .map_err(|err| XtaskError::Validation(format!("tenant receipt signing failed: {err}")))
}

fn receipt_of(case: &Value) -> Result<ChioReceipt, XtaskError> {
    let receipt = case
        .get("receipt")
        .cloned()
        .ok_or_else(|| XtaskError::Validation("allow_receipt case has no receipt".to_owned()))?;
    let text = serde_json::to_string(&receipt).map_err(json_error)?;
    let receipt: ChioReceipt = UntrustedJsonText::new(&text)
        .decode_signed()
        .map_err(|err| XtaskError::Validation(format!("allow_receipt does not decode: {err}")))?;
    match receipt.verify_integrity_embedded_key() {
        Ok(true) => Ok(receipt),
        _ => Err(XtaskError::Validation(
            "allow_receipt signature does not verify".to_owned(),
        )),
    }
}

/// Replace the `sha256` of the `[[seed]]` entry whose `path` is `seed_path`,
/// keeping each line's key alignment.
fn with_seed_digest(metadata: &str, seed_path: &str, contents: &str) -> Result<String, XtaskError> {
    let quoted_path = format!("\"{seed_path}\"");
    let mut lines: Vec<String> = metadata.lines().map(str::to_owned).collect();
    let index = lines
        .iter()
        .position(|line| {
            line.split_once('=')
                .is_some_and(|(key, value)| key.trim() == "path" && value.trim() == quoted_path)
        })
        .ok_or_else(|| {
            XtaskError::Drift(format!("{CORPUS_METADATA} has no entry for {seed_path}"))
        })?;
    let digest_line = lines
        .get_mut(index + 1)
        .filter(|line| {
            line.split_once('=')
                .is_some_and(|(key, _)| key.trim() == "sha256")
        })
        .ok_or_else(|| {
            XtaskError::Drift(format!(
                "{CORPUS_METADATA} entry for {seed_path} has no sha256 line"
            ))
        })?;
    let key = digest_line
        .split_once('=')
        .map(|(key, _)| key.to_owned())
        .unwrap_or_default();
    *digest_line = format!(
        "{key}= \"{}\"",
        digest_to_hex(&Sha256::digest(contents.as_bytes()))
    );
    let mut out = lines.join("\n");
    if metadata.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

fn load_cases(path: &Path) -> Result<Vec<Value>, XtaskError> {
    let value: Value = serde_json::from_str(&read(path)?)
        .map_err(|err| XtaskError::Json(display_path(path), err))?;
    value
        .get("cases")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| XtaskError::Validation(format!("{} has no cases", display_path(path))))
}

fn find_case<'a>(cases: &'a [Value], id: &str) -> Result<&'a Value, XtaskError> {
    cases
        .iter()
        .find(|case| case.get("id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| XtaskError::Validation(format!("vector case {id} is missing")))
}

fn pretty(value: &Value) -> Result<String, XtaskError> {
    let mut text = serde_json::to_string_pretty(value).map_err(json_error)?;
    text.push('\n');
    Ok(text)
}

fn read(path: &Path) -> Result<String, XtaskError> {
    fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn json_error(err: serde_json::Error) -> XtaskError {
    XtaskError::Json("vector seed".to_owned(), err)
}

#[cfg(test)]
mod tests {
    use super::with_seed_digest;

    #[test]
    fn seed_digest_rewrite_keeps_alignment_and_touches_only_its_entry() {
        let metadata = "[[seed]]\npath      = \"fuzz/corpus/a/x.json\"\nsha256    = \"00\"\n\n[[seed]]\npath = \"fuzz/corpus/b/y.json\"\nsha256 = \"11\"\n";
        let rewritten = with_seed_digest(metadata, "fuzz/corpus/b/y.json", "abc")
            .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(
            rewritten,
            "[[seed]]\npath      = \"fuzz/corpus/a/x.json\"\nsha256    = \"00\"\n\n[[seed]]\npath = \"fuzz/corpus/b/y.json\"\nsha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"\n"
        );
        assert!(with_seed_digest(metadata, "fuzz/corpus/c/z.json", "abc").is_err());
    }
}
