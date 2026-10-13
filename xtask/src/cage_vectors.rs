//! Deterministic signer for the cage launch policy binding vector.

use std::fs;

use chio_core_types::crypto::Keypair;

use super::{display_path, freeze_vectors, workspace_root, XtaskError};

const VECTOR_PATH: &str =
    "tests/bindings/vectors/security/cage/positive/mcp-cage-launch-policy-v1.json";
const SIGNER_SEED: [u8; 32] = [0x63; 32];

/// Re-sign the vector's body with the fixed test signer. The body is the
/// authored input; the signature and signer key are always derived.
pub fn run(check_only: bool) -> Result<(), XtaskError> {
    let path = workspace_root()?.join(VECTOR_PATH);
    let existing =
        fs::read_to_string(&path).map_err(|err| XtaskError::Io(display_path(&path), err))?;
    let vector: serde_json::Value = serde_json::from_str(&existing)
        .map_err(|err| XtaskError::Drift(format!("{}: {err}", display_path(&path))))?;
    let body = vector
        .get("body")
        .cloned()
        .ok_or_else(|| XtaskError::Drift(format!("{} has no body", display_path(&path))))?;
    let signer = Keypair::from_seed(&SIGNER_SEED);
    let (signature, _) = signer
        .sign_canonical(&body)
        .map_err(|err| XtaskError::Drift(format!("cage policy signing failed: {err}")))?;
    let signed = serde_json::json!({
        "body": body,
        "signature": signature,
        "signer_public_key": signer.public_key(),
    });
    let mut generated = String::from_utf8(
        chio_core_types::canonical_json_bytes(&signed)
            .map_err(|err| XtaskError::Drift(format!("cage policy canonical form: {err}")))?,
    )
    .map_err(|err| XtaskError::Drift(format!("cage policy canonical form: {err}")))?;
    generated.push('\n');
    if check_only {
        if existing != generated {
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask gen cage-vectors`",
                display_path(&path)
            )));
        }
        freeze_vectors(vec!["--check".to_owned()])?;
        println!("{} in sync", display_path(&path));
    } else {
        fs::write(&path, generated).map_err(|err| XtaskError::Io(display_path(&path), err))?;
        freeze_vectors(Vec::new())?;
        println!("wrote {}", display_path(&path));
    }
    Ok(())
}
