//! Offline checking under explicitly supplied roots. Never derive trusted roots
//! from the bundle being checked. This verifies bindings and recomputes the
//! native scope contract; it does not prove a global absence of duplicate work.

use chio_core_types::receipt::{body::ChioReceipt, decision::Decision};
use chio_runtime_core::outcome_continuation::OutcomeEffectClaim;
use serde::de::DeserializeOwned;

use super::*;

fn read(root: &Path, name: &str) -> DemoResult<Vec<u8>> {
    let file = std::fs::File::open(root.join(name))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 1024 * 1024 + 1), &mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(format!("{name} exceeds export bound").into());
    }
    Ok(bytes)
}

fn load<T: DeserializeOwned>(root: &Path, name: &str) -> DemoResult<T> {
    Ok(serde_json::from_slice(&read(root, name)?)?)
}

fn hash(value: &impl Serialize) -> DemoResult<String> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn require(condition: bool, message: &str) -> DemoResult<()> {
    if !condition {
        return Err(message.to_string().into());
    }
    Ok(())
}

fn receipt(
    root: &Path,
    name: &str,
    key: &PublicKey,
    server: &str,
    tool: &str,
) -> DemoResult<ChioReceipt> {
    let receipt: ChioReceipt = load(root, name)?;
    require(
        receipt.kernel_key == *key,
        "receipt key differs from supplied trusted root",
    )?;
    require(
        receipt.verify_signature()? && receipt.action.verify_hash()?,
        "receipt signature or action hash invalid",
    )?;
    require(
        receipt.decision == Some(Decision::Allow),
        "receipt does not attest an allowed invocation",
    )?;
    require(
        receipt.tool_server == server && receipt.tool_name == tool,
        "receipt target mismatch",
    )?;
    Ok(receipt)
}

pub(super) fn export(
    root: &Path,
    publisher: &PublicKey,
    verifier: &PublicKey,
) -> DemoResult<Value> {
    let rule: OutcomeEffectRule = load(root, "receiver-rule.json")?;
    let contract: ScopeContract = load(root, "owner-contract.json")?;
    let evidence: SignedArtifactOutcome = load(root, "verified-outcome.json")?;
    let result: Value = load(root, "publication-result.json")?;
    let claim: OutcomeEffectClaim = serde_json::from_value(
        result
            .get("effectClaim")
            .cloned()
            .ok_or("effect claim absent")?,
    )?;
    let artifact = read(root, "approved.scope.json")?;
    let artifact_sha256 = sha256_hex(&artifact);
    require(
        contract.schema == "scope-contract.experimental.v1",
        "unsupported scope contract schema",
    )?;

    require(
        rule.verifier_key == *verifier && rule.slot.receiver_id == publisher.to_hex(),
        "receiver rule differs from supplied roots",
    )?;
    require(
        evidence.body.schema == ARTIFACT_OUTCOME_SCHEMA,
        "unsupported outcome schema",
    )?;
    require(
        verifier.verify_strict(&canonical_json_bytes(&evidence.body)?, &evidence.signature),
        "invalid artifact outcome signature",
    )?;
    require(
        evidence.body.passed && contract.accepts(&artifact),
        "artifact does not satisfy the owner contract",
    )?;
    require(
        evidence.body.slot == rule.slot
            && evidence.body.predecessor_step_id == rule.predecessor_step_id,
        "outcome workflow or predecessor mismatch",
    )?;
    require(
        evidence.body.contract_sha256 == rule.contract_sha256
            && hash(&contract)? == rule.contract_sha256,
        "owner contract digest mismatch",
    )?;
    require(
        evidence.body.artifact_sha256 == artifact_sha256,
        "approved artifact digest mismatch",
    )?;
    require(
        claim.slot == rule.slot
            && claim.rule_sha256 == hash(&rule)?
            && claim.evidence_sha256 == hash(&evidence)?,
        "claim does not bind the rule and outcome",
    )?;
    require(
        claim.arguments.artifact_sha256 == artifact_sha256
            && claim.arguments.resource == rule.resource,
        "claim effect binding mismatch",
    )?;
    require(
        rule.valid_from_unix_ms <= evidence.body.verified_at_unix_ms
            && evidence.body.verified_at_unix_ms <= claim.claimed_at_unix_ms
            && claim.claimed_at_unix_ms < rule.valid_until_unix_ms,
        "claim or outcome outside the rule interval",
    )?;
    require(
        result["publishedArtifactSha256"] == artifact_sha256 && result["resource"] == rule.resource,
        "publication result differs from claim",
    )?;

    let publication = receipt(
        root,
        "publication-receipt.json",
        publisher,
        &rule.server_id,
        &rule.tool_name,
    )?;
    require(
        publication.content_hash == hash(&result)?,
        "publication result is not signed into the receipt",
    )?;
    let request: OutcomeEffectRequest = serde_json::from_value(publication.action.parameters)?;
    require(
        request.evidence == evidence && request.arguments == claim.arguments,
        "publication receipt input differs from the claimed effect",
    )?;

    let verification = receipt(
        root,
        "passed-verification-receipt.json",
        verifier,
        "contract-verifier",
        "verify_scope",
    )?;
    require(
        verification.content_hash == hash(&evidence)?,
        "verifier receipt does not bind the outcome",
    )?;
    require(
        verification
            .action
            .parameters
            .get("artifact")
            .and_then(Value::as_str)
            .map(str::as_bytes)
            == Some(artifact.as_slice()),
        "verifier receipt does not bind the approved bytes",
    )?;
    Ok(json!({
        "verified": true, "artifactSha256": artifact_sha256,
        "publisherKey": publisher, "verifierKey": verifier,
        "scopeContractRecomputed": true,
        "claimAndReceiptsBound": true,
        "globalNonDuplicationProved": false,
    }))
}
