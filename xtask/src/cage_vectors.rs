//! Deterministic signers for the cage binding vectors.
//!
//! The signed tool manifest is built from a fixed sample and signed with a
//! fixed server key. The cage launch policy embeds that signed manifest and is
//! then re-signed with the fixed policy signer. Every other part of the policy
//! body is authored input.

use std::fs;
use std::path::Path;

use chio_core_types::crypto::Keypair;
use chio_manifest::{
    sign_manifest, EnvironmentVariableName, LatencyHint, NativeSyscallProfile, NetworkDestination,
    RequiredPermissions, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
    TOOL_MANIFEST_SCHEMA,
};

use super::{display_path, freeze_vectors, workspace_root, XtaskError};

const POLICY_VECTOR_PATH: &str =
    "tests/bindings/vectors/security/cage/positive/mcp-cage-launch-policy-v1.json";
const MANIFEST_VECTOR_PATH: &str =
    "tests/bindings/vectors/security/cage/positive/signed-tool-manifest-v1.json";
const POLICY_SIGNER_SEED: [u8; 32] = [0x63; 32];
const MANIFEST_SERVER_SEED: [u8; 32] = [21; 32];

/// Regenerate the signed tool manifest vector and the launch policy vector
/// that embeds it.
pub fn run(check_only: bool) -> Result<(), XtaskError> {
    let root = workspace_root()?;
    let manifest_path = root.join(MANIFEST_VECTOR_PATH);
    let policy_path = root.join(POLICY_VECTOR_PATH);

    let signed_manifest = signed_manifest_vector()?;
    let manifest_bytes = canonical_text(&signed_manifest, "signed tool manifest")?;

    let existing_policy = read(&policy_path)?;
    let policy: serde_json::Value = serde_json::from_str(&existing_policy)
        .map_err(|err| XtaskError::Drift(format!("{}: {err}", display_path(&policy_path))))?;
    let mut body = policy
        .get("body")
        .cloned()
        .ok_or_else(|| XtaskError::Drift(format!("{} has no body", display_path(&policy_path))))?;
    let body_object = body.as_object_mut().ok_or_else(|| {
        XtaskError::Drift(format!(
            "{} body is not an object",
            display_path(&policy_path)
        ))
    })?;
    body_object.insert("signed_manifest".to_owned(), signed_manifest);
    let signer = Keypair::from_seed(&POLICY_SIGNER_SEED);
    let signature = chio_core_types::CanonicalBytes::from_value(&body)
        .and_then(|canonical| signer.sign_wrapped("chio.mcp.cage-launch-policy.v1", &canonical))
        .map_err(|err| XtaskError::Drift(format!("cage policy signing failed: {err}")))?;
    let signed_policy = serde_json::json!({
        "body": body,
        "signature": signature,
        "signer_public_key": signer.public_key(),
    });
    let mut policy_bytes = canonical_text(&signed_policy, "cage policy")?;
    policy_bytes.push('\n');

    let outputs = [(manifest_path, manifest_bytes), (policy_path, policy_bytes)];
    if check_only {
        for (path, generated) in &outputs {
            if !path.exists() || read(path)? != *generated {
                return Err(XtaskError::Drift(format!(
                    "{} is stale; rerun `cargo xtask gen cage-vectors`",
                    display_path(path)
                )));
            }
        }
        freeze_vectors(vec!["--check".to_owned()])?;
        for (path, _) in &outputs {
            println!("{} in sync", display_path(path));
        }
    } else {
        for (path, generated) in &outputs {
            fs::write(path, generated).map_err(|err| XtaskError::Io(display_path(path), err))?;
        }
        freeze_vectors(Vec::new())?;
        for (path, _) in &outputs {
            println!("wrote {}", display_path(path));
        }
    }
    Ok(())
}

fn signed_manifest_vector() -> Result<serde_json::Value, XtaskError> {
    let server = Keypair::from_seed(&MANIFEST_SERVER_SEED);
    let invalid = |label: &str, err: &dyn std::fmt::Display| {
        XtaskError::Drift(format!("sample manifest {label}: {err}"))
    };
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_owned(),
        server_id: "srv-bindings-demo".to_owned(),
        name: "Bindings Demo".to_owned(),
        description: Some("Manifest vector for bindings-core SDK fixtures".to_owned()),
        version: "1.0.0".to_owned(),
        tools: vec![ToolDefinition {
            name: "file_read".to_owned(),
            description: "Tool definition for file_read".to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]
            }),
            output_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {"ok": {"type": "boolean"}}
            })),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: Some(LatencyHint::Fast),
            flow: Some(ToolFlowDeclaration::public_egress()),
        }],
        server_tools: Vec::new(),
        required_permissions: Some(RequiredPermissions {
            read_paths: Some(vec!["/workspace".to_owned()]),
            write_paths: Some(vec!["/workspace/output".to_owned()]),
            network_destinations: Some(vec![NetworkDestination::new("api.example.com", 443)
                .map_err(|err| invalid("network destination", &err))?]),
            environment_variables: Some(vec![EnvironmentVariableName::new("CHIO_ENV")
                .map_err(|err| invalid("environment variable", &err))?]),
            native_syscall_profile: NativeSyscallProfile::NativeStandardV1,
        }),
        public_key: server.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, &server).map_err(|err| invalid("signing", &err))?;
    serde_json::to_value(&signed).map_err(|err| invalid("encoding", &err))
}

fn canonical_text(value: &serde_json::Value, label: &str) -> Result<String, XtaskError> {
    let bytes = chio_core_types::canonical_json_bytes(value)
        .map_err(|err| XtaskError::Drift(format!("{label} canonical form: {err}")))?;
    String::from_utf8(bytes)
        .map_err(|err| XtaskError::Drift(format!("{label} canonical form: {err}")))
}

fn read(path: &Path) -> Result<String, XtaskError> {
    fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))
}
