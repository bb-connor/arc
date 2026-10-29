//! Re-signing and digest rebinding for runtime-security proof fixtures.

use super::*;

pub(super) fn normalize_runtime_reused_nonce_fixture(
    _descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    let mut evidence_graph_paths = Vec::new();
    collect_evidence_graph_paths(out, &mut evidence_graph_paths)?;
    for evidence_graph_path in evidence_graph_paths {
        let Some(bundle) = evidence_graph_path.parent() else {
            continue;
        };
        if !bundle.join("tool-server-ack.json").is_file() {
            continue;
        }
        let evidence_graph = read_json_value(&evidence_graph_path)?;
        let has_replay_node = json_array(&evidence_graph, "nodes", &evidence_graph_path)?
            .iter()
            .any(|node| {
                node.get("path").and_then(serde_json::Value::as_str)
                    == Some("tool-server-ack-replay.json")
                    || node.get("id").and_then(serde_json::Value::as_str)
                        == Some("ack-runtime-replay")
            });
        let is_reused_nonce_case = evidence_graph_path.components().any(|component| {
            component.as_os_str() == std::ffi::OsStr::new("runtime-reused-nonce")
                || component.as_os_str() == std::ffi::OsStr::new("reused-nonce")
        });
        if has_replay_node || is_reused_nonce_case {
            normalize_runtime_reused_nonce_bundle(bundle, &evidence_graph_path, evidence_graph)?;
        }
    }
    Ok(())
}

/// Every fixture signer: the committed fixtures sign only with keys whose
/// seed is one byte repeated.
fn fixture_signers() -> Vec<Keypair> {
    (0..=u8::MAX)
        .map(|byte| Keypair::from_seed(&[byte; 32]))
        .collect()
}

/// Passes after which re-signing and digest rebinding must have settled.
const MAX_RESIGN_PASSES: usize = 8;

/// Re-signs every runtime-security and swarm-authority artifact under `out`
/// through the signing wrapper with the seed key its signer identity names,
/// nested ones first. A stale signature on an artifact both verifiers read
/// (task graph, route plan, join receipt) takes the swarm-authority domain
/// in `swarm-authority/` fixtures and the runtime-security domain elsewhere.
/// Every digest string that named a rewritten file, by file bytes or by
/// canonical JSON, moves to the rewritten one until nothing changes.
pub(super) fn normalize_runtime_security_signatures(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if !out.is_dir() {
        return Ok(());
    }
    let swarm_domain = installed_fixture_path(descriptor).starts_with("swarm-authority/");
    let signers = fixture_signers();
    let json_paths: Vec<PathBuf> = crate::input::collection::paths(out)?
        .into_iter()
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("json"))
        .collect();
    let mut moved: BTreeMap<String, String> = BTreeMap::new();
    for _ in 0..MAX_RESIGN_PASSES {
        let mut changed = false;
        for path in &json_paths {
            let original = read_json_value(path)?;
            let mut value = original.clone();
            sign_fixture_values(&mut value, &signers, swarm_domain, path)?;
            rebind_digests(&mut value, &moved);
            if value != original {
                let previous_file = sha256_file(path)?;
                write_json_line_file(path, &value)?;
                record_move(&mut moved, previous_file, sha256_file(path)?);
                record_move(&mut moved, canonical_sha256(&original)?, canonical_sha256(&value)?);
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
    }
    Err(CliError::cli_other_error(format!(
        "fixture signatures under {} did not settle in {MAX_RESIGN_PASSES} passes",
        out.display()
    )))
}

fn canonical_sha256(value: &serde_json::Value) -> Result<String, CliError> {
    let canonical = chio_core_types::canonical_json_bytes(value).map_err(|error| {
        CliError::cli_other_error(format!("fixture canonicalization failed: {error}"))
    })?;
    Ok(chio_core::sha256_hex(&canonical))
}

/// Maps `previous` and every digest that already led to it onto `current`.
/// A digest already mapped keeps its first target, so a file whose bytes are
/// its canonical JSON follows its file digest.
fn record_move(moved: &mut BTreeMap<String, String>, previous: String, current: String) {
    if previous == current || moved.contains_key(&previous) {
        return;
    }
    for target in moved.values_mut() {
        if *target == previous {
            target.clone_from(&current);
        }
    }
    moved.insert(previous, current);
}

fn rebind_digests(value: &mut serde_json::Value, moved: &BTreeMap<String, String>) {
    match value {
        serde_json::Value::String(text) => {
            if let Some(current) = moved.get(text.as_str()) {
                text.clone_from(current);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                rebind_digests(item, moved);
            }
        }
        serde_json::Value::Object(object) => {
            for child in object.values_mut() {
                rebind_digests(child, moved);
            }
        }
        _ => {}
    }
}

/// `value` re-signed through the signing wrapper when it carries a signed
/// evidence role `schema` and a bare hex `signature` that a fixture key made
/// over its other members, wrapped or not. A signature no fixture key made
/// stays as it is. `None` otherwise.
fn evidence_role_signed(
    value: &serde_json::Value,
    signers: &[Keypair],
) -> Result<Option<serde_json::Value>, String> {
    let Some(schema) = value.get("schema").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if !chio_transaction_passport::SIGNED_EVIDENCE_ROLE_SCHEMAS.contains(&schema) {
        return Ok(None);
    }
    let Some(Ok(signature)) = value
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .map(chio_core::Signature::from_hex)
    else {
        return Ok(None);
    };
    let mut payload = value.clone();
    if let Some(object) = payload.as_object_mut() {
        object.remove("signature");
    }
    let Some(key) = signers.iter().find(|key| {
        let public_key = key.public_key();
        chio_core_types::crypto::verify_wrapped(&public_key, schema, &payload, &signature).is_ok()
    }) else {
        return Ok(None);
    };
    let signature =
        fixture_wrapped_signature(key, schema, &payload).map_err(|error| error.to_string())?;
    let mut signed = value.clone();
    signed["signature"] = serde_json::Value::String(signature.to_hex());
    Ok(Some(signed))
}

/// Re-signs a crypto context report that names the disclosure lineage
/// fixture signer through the typed report signer.
fn crypto_context_report_signed(
    value: &serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    let lineage_key = Keypair::from_seed(&DISCLOSURE_LINEAGE_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    let names_lineage_key = value
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .and_then(|signature| signature.strip_prefix("sig-ed25519:"))
        .and_then(|reference| reference.split_once(':'))
        .is_some_and(|(key_hex, _)| key_hex == lineage_key);
    if !names_lineage_key {
        return Ok(None);
    }
    let mut resigned = value.clone();
    sign_disclosure_crypto_report_json(&mut resigned).map_err(|error| error.to_string())?;
    Ok((resigned != *value).then_some(resigned))
}

/// `value` re-signed when it is a trust-market or risk artifact whose inline
/// `sig-ed25519:<key>:<signature>` covers its other members under its
/// `schema` and `<key>` is a fixture key, or a crypto context report signed by
/// the disclosure lineage fixture key. `None` otherwise.
fn inline_signed(
    value: &serde_json::Value,
    signers: &[Keypair],
) -> Result<Option<serde_json::Value>, String> {
    let Some(schema) = value.get("schema").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if schema == chio_selective_disclosure::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1 {
        return crypto_context_report_signed(value);
    }
    if !is_trust_market_signed_artifact_schema(schema) {
        return Ok(None);
    }
    let Some(key_hex) = value
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .and_then(|signature| signature.strip_prefix("sig-ed25519:"))
        .and_then(|reference| reference.split_once(':'))
        .map(|(key_hex, _)| key_hex)
    else {
        return Ok(None);
    };
    let Some(key) = signers
        .iter()
        .find(|key| key.public_key().to_hex() == key_hex)
    else {
        return Ok(None);
    };
    let mut payload = value.clone();
    if let Some(object) = payload.as_object_mut() {
        object.remove("signature");
    }
    let signature =
        fixture_wrapped_signature(key, schema, &payload).map_err(|error| error.to_string())?;
    let mut signed = value.clone();
    signed["signature"] = serde_json::Value::String(format!(
        "sig-ed25519:{key_hex}:{}",
        signature.to_hex()
    ));
    Ok(Some(signed))
}

fn sign_fixture_values(
    value: &mut serde_json::Value,
    signers: &[Keypair],
    swarm_domain: bool,
    path: &Path,
) -> Result<(), CliError> {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                sign_fixture_values(item, signers, swarm_domain, path)?;
            }
        }
        serde_json::Value::Object(object) => {
            for child in object.values_mut() {
                sign_fixture_values(child, signers, swarm_domain, path)?;
            }
        }
        _ => return Ok(()),
    }
    let fail = |error: String| {
        CliError::cli_other_error(format!("fixture {} signing failed: {error}", path.display()))
    };
    let mut runtime = value.clone();
    let runtime_signed =
        chio_transaction_passport::sign_runtime_security_artifact(&mut runtime, signers)
            .map_err(|error| fail(error.to_string()))?;
    let swarm = swarm_signed(value, signers).map_err(fail)?;
    match (runtime_signed, swarm) {
        (false, None) => {
            if let Some(signed) = export_envelope_signed(value, signers).map_err(fail)? {
                *value = signed;
            } else if let Some(signed) = inline_signed(value, signers).map_err(fail)? {
                *value = signed;
            } else if let Some(signed) = evidence_role_signed(value, signers).map_err(fail)? {
                *value = signed;
            }
        }
        (true, None) => *value = runtime,
        (false, Some(swarm)) => *value = swarm,
        (true, Some(swarm)) => {
            if runtime != *value && swarm != *value {
                *value = if swarm_domain { swarm } else { runtime };
            }
        }
    }
    Ok(())
}

/// Envelope members that name the signer key.
const ENVELOPE_SIGNER_KEYS: &[&str] = &["signerKey", "signer_key"];
/// Payload members that name the signer key when the envelope does not.
const PAYLOAD_SIGNER_KEYS: &[&str] = &["chio_public_key", "chioPublicKey"];

/// `value` signed as a payload envelope: one payload object whose `schema`
/// is a registered wrapper id, a `signature`, and at most a signer key
/// member, signed over the payload under that id. `None` when `value` is not
/// such an envelope.
fn export_envelope_signed(
    value: &serde_json::Value,
    signers: &[Keypair],
) -> Result<Option<serde_json::Value>, String> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    if !object.contains_key("signature") {
        return Ok(None);
    }
    let mut payload = None;
    for (name, member) in object {
        if name == "signature" || ENVELOPE_SIGNER_KEYS.contains(&name.as_str()) {
            continue;
        }
        if payload.is_some() {
            return Ok(None);
        }
        payload = Some(member);
    }
    let Some(payload) = payload else {
        return Ok(None);
    };
    let Some(schema) = payload.get("schema").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if !chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS.contains(&schema) {
        return Ok(None);
    }
    let Some(signer) = ENVELOPE_SIGNER_KEYS
        .iter()
        .find_map(|name| object.get(*name))
        .or_else(|| PAYLOAD_SIGNER_KEYS.iter().find_map(|name| payload.get(*name)))
    else {
        return Ok(None);
    };
    let signer_key: chio_core_types::PublicKey = crate::input::project(signer.clone())
        .map_err(|error| format!("envelope signer key invalid: {error}"))?;
    let key = signers
        .iter()
        .find(|key| key.public_key() == signer_key)
        .ok_or_else(|| format!("no fixture key for envelope signer {}", signer_key.to_hex()))?;
    let canonical =
        chio_core_types::CanonicalBytes::from_serializable(payload).map_err(|error| error.to_string())?;
    let signature = key
        .sign_wrapped(schema, &canonical)
        .map_err(|error| error.to_string())?;
    let mut signed = value.clone();
    signed["signature"] = serde_json::Value::String(signature.to_hex());
    Ok(Some(signed))
}

fn swarm_artifact<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> Option<T> {
    crate::input::project(value.clone()).ok()
}

fn sign_with_any<T>(
    signers: &[Keypair],
    label: &str,
    sign: impl Fn(&Keypair) -> Result<T, chio_swarm_authority::SwarmAuthorityError>,
) -> Result<T, String> {
    signers
        .iter()
        .find_map(|key| sign(key).ok())
        .ok_or_else(|| format!("no fixture key signs this {label}"))
}

/// `value` signed as a swarm-authority artifact, or `None` when it is not
/// one.
fn swarm_signed(
    value: &serde_json::Value,
    signers: &[Keypair],
) -> Result<Option<serde_json::Value>, String> {
    use chio_swarm_authority as swarm;
    let Some(schema) = value.get("schema").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    let signature = match schema {
        swarm::CHIO_SWARM_TASK_GRAPH_SCHEMA => {
            let Some(graph) = swarm_artifact::<swarm::SwarmTaskGraph>(value) else {
                return Ok(None);
            };
            sign_with_any(signers, "task graph", |key| swarm::sign_swarm_task_graph(&graph, key))?
        }
        swarm::CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA => {
            let Some(plan) = swarm_artifact::<swarm::SwarmRoutePlanReceipt>(value) else {
                return Ok(None);
            };
            sign_with_any(signers, "route plan", |key| {
                swarm::sign_swarm_route_plan_receipt(&plan, key)
            })?
        }
        swarm::CHIO_SWARM_JOIN_RECEIPT_SCHEMA => {
            let Some(receipt) = swarm_artifact::<swarm::SwarmJoinReceipt>(value) else {
                return Ok(None);
            };
            sign_with_any(signers, "join receipt", |key| {
                swarm::sign_swarm_join_receipt(&receipt, key)
            })?
        }
        swarm::CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA => {
            let Some(token) = swarm_artifact::<swarm::SwarmContinuationToken>(value) else {
                return Ok(None);
            };
            sign_with_any(signers, "continuation token", |key| {
                swarm::sign_swarm_continuation_token(&token, key)
            })?
        }
        swarm::CHIO_SWARM_REVOCATION_EPOCH_SCHEMA => {
            let Some(epoch) = swarm_artifact::<swarm::SwarmRevocationEpoch>(value) else {
                return Ok(None);
            };
            sign_with_any(signers, "revocation epoch", |key| {
                swarm::sign_swarm_revocation_epoch(&epoch, key)
            })?
        }
        swarm::CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA => {
            let Some(receipt) = swarm_artifact::<swarm::SwarmTerminalGraphReceipt>(value) else {
                return Ok(None);
            };
            sign_with_any(signers, "terminal graph receipt", |key| {
                swarm::sign_swarm_terminal_graph_receipt(&receipt, key)
            })?
        }
        swarm::CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA => {
            let Some(mut chain) = swarm_artifact::<swarm::SwarmDelegationWitnessChain>(value)
            else {
                return Ok(None);
            };
            for index in 0..chain.hops.len() {
                let Some(hop) = chain.hops.get(index).cloned() else {
                    continue;
                };
                let signature = sign_with_any(signers, "witness hop", |key| {
                    swarm::sign_swarm_delegation_witness_hop(&chain, &hop, key)
                })?;
                if let Some(hop) = chain.hops.get_mut(index) {
                    hop.witness_signature = signature;
                }
            }
            return serde_json::to_value(&chain)
                .map(Some)
                .map_err(|error| error.to_string());
        }
        _ => return Ok(None),
    };
    let mut signed = value.clone();
    signed["signature"] = serde_json::Value::String(signature);
    Ok(Some(signed))
}

fn normalize_runtime_reused_nonce_bundle(
    bundle: &Path,
    evidence_graph_path: &Path,
    mut evidence_graph: serde_json::Value,
) -> Result<(), CliError> {
    let source_ack_path = bundle.join("tool-server-ack.json");
    let replay_ack_path = bundle.join("tool-server-ack-replay.json");
    let mut replay_ack = read_json_value(&source_ack_path)?;
    replay_ack["ack_id"] = serde_json::Value::String("ack-runtime-replay".to_string());
    replay_ack["issued_at"] = serde_json::Value::String("2026-06-10T00:00:03Z".to_string());
    chio_transaction_passport::sign_runtime_security_artifact(
        &mut replay_ack,
        &fixture_signers(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "runtime tool-server acknowledgement signing failed: {error}"
        ))
    })?;
    write_json_line_file(&replay_ack_path, &replay_ack)?;

    let replay_sha256 = sha256_file(&replay_ack_path)?;
    let nodes = json_array_mut(&mut evidence_graph, "nodes", evidence_graph_path)?;
    let replay_node = if let Some(index) = nodes.iter().position(|node| {
        node.get("path").and_then(serde_json::Value::as_str) == Some("tool-server-ack-replay.json")
            || node.get("id").and_then(serde_json::Value::as_str) == Some("ack-runtime-replay")
    }) {
        &mut nodes[index]
    } else {
        nodes.push(serde_json::json!({
            "id": replay_sha256,
            "path": "tool-server-ack-replay.json",
            "role": "tool-server-ack",
            "schema": "chio.runtime.tool-server-ack.v1",
            "sha256": replay_sha256
        }));
        nodes.last_mut().ok_or_else(|| {
            CliError::cli_other_error("runtime replay ack node missing".to_string())
        })?
    };
    let old_id = replay_node
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string);
    let old_sha256 = replay_node
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string);
    replay_node["id"] = serde_json::Value::String(replay_sha256.clone());
    replay_node["path"] = serde_json::Value::String("tool-server-ack-replay.json".to_string());
    replay_node["sha256"] = serde_json::Value::String(replay_sha256.clone());
    for edge in json_array_mut(&mut evidence_graph, "edges", evidence_graph_path)? {
        for field in ["from", "to"] {
            let Some(current) = edge.get(field).and_then(serde_json::Value::as_str) else {
                continue;
            };
            if old_id.as_deref() == Some(current) || old_sha256.as_deref() == Some(current) {
                edge[field] = serde_json::Value::String(replay_sha256.clone());
            }
        }
    }
    write_json_line_file(evidence_graph_path, &evidence_graph)?;
    Ok(())
}
