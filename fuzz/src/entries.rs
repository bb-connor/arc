//! In-process entry points shared by libFuzzer binaries and corpus smoke tests.

use std::sync::OnceLock;

use chio_core_types::crypto::{Keypair, PublicKey};
use chio_federation::bilateral_dsse::{
    verify_chio_bilateral_dsse_envelope, verify_dsse_envelope, DsseEnvelope, DsseStatement,
};
use chio_federation::trust_establishment::{
    FederationPeer, HandshakeChallenge, KernelTrustExchange, KernelTrustExchangeConfig,
    PeerHandshakeEnvelope,
};
use chio_finding_worker::{
    FindingWorkerAttestedResult, FindingWorkerCapabilityBody, FindingWorkerInputDescriptor,
    FindingWorkerInputEnd, FindingWorkerJobSpec, FindingWorkerRequest, FindingWorkerResult,
    SignedFindingWorkerCapability, SignedFindingWorkerResult,
};
use chio_underwriting::{
    build_underwriting_decision_artifact, compute_marketplace_credit_limit,
    evaluate_underwriting_policy_input, price_premium, LookbackWindow,
    MarketplaceCreditLimitRequest, PremiumInputs, UnderwritingAppealCreateRequest,
    UnderwritingAppealResolveRequest, UnderwritingDecisionArtifact, UnderwritingDecisionListReport,
    UnderwritingDecisionPolicy, UnderwritingDecisionQuery, UnderwritingPolicyInput,
    UnderwritingPolicyInputQuery, UnderwritingSimulationReport, UnderwritingSimulationRequest,
};

pub fn eval_receipt_bundle(data: &[u8]) {
    if let Ok(bundle_json) = core::str::from_utf8(data) {
        let _ = chio_eval_receipt::verify_bundle(bundle_json);
    }
}

/// Exercise every untrusted canonical-JSON shape accepted at the isolated
/// worker boundary. Parsing success is never sufficient: each shape that has
/// an independent invariant validator is driven through it before any
/// reserialization path.
pub fn finding_worker_protocol(data: &[u8]) {
    if let Ok(capability) = serde_json::from_slice::<FindingWorkerCapabilityBody>(data) {
        let _ = capability.validate();
        let _ = serde_json::to_vec(&capability);
    }
    if let Ok(capability) = serde_json::from_slice::<SignedFindingWorkerCapability>(data) {
        let _ = capability.body.validate();
        let _ = capability.verify_signature();
        let _ = serde_json::to_vec(&capability);
    }
    if let Ok(job) = serde_json::from_slice::<FindingWorkerJobSpec>(data) {
        let _ = job.validate();
        let _ = job.sha256();
        let _ = serde_json::to_vec(&job);
    }
    if let Ok(request) = serde_json::from_slice::<FindingWorkerRequest>(data) {
        let _ = request.validate();
        let _ = serde_json::to_vec(&request);
    }
    if let Ok(descriptor) = serde_json::from_slice::<FindingWorkerInputDescriptor>(data) {
        let _ = descriptor.validate();
        let _ = serde_json::to_vec(&descriptor);
    }
    if let Ok(end) = serde_json::from_slice::<FindingWorkerInputEnd>(data) {
        let _ = end.validate();
        let _ = serde_json::to_vec(&end);
    }
    if let Ok(result) = serde_json::from_slice::<FindingWorkerResult>(data) {
        let _ = serde_json::to_vec(&result);
    }
    if let Ok(result) = serde_json::from_slice::<FindingWorkerAttestedResult>(data) {
        let _ = serde_json::to_vec(&result);
    }
    if let Ok(envelope) = serde_json::from_slice::<SignedFindingWorkerResult>(data) {
        let _ = envelope.verify_signature();
        let _ = serde_json::to_vec(&envelope);
    }
}

fn seed_at(data: &[u8], start: usize) -> Option<[u8; 32]> {
    if data.len() < start.saturating_add(32) {
        return None;
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&data[start..start + 32]);
    Some(seed)
}

fn u64_at(data: &[u8], start: usize, fallback: u64) -> u64 {
    if data.len() < start.saturating_add(8) {
        return fallback;
    }
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&data[start..start + 8]);
    u64::from_le_bytes(bytes)
}

fn nonce_from(data: &[u8]) -> &str {
    match core::str::from_utf8(data) {
        Ok(value) if !value.is_empty() => value,
        _ => "fuzz-nonce",
    }
}

pub fn federation_trust_establishment(data: &[u8]) {
    if let Ok(challenge) = serde_json::from_slice::<HandshakeChallenge>(data) {
        let _ = challenge.canonical_bytes();
        let _ = serde_json::to_vec(&challenge);
    }

    if let Ok(envelope) = serde_json::from_slice::<PeerHandshakeEnvelope>(data) {
        let _ = envelope.verify_signature();
        let _ = serde_json::to_vec(&envelope);
    }

    if let Ok(peer) = serde_json::from_slice::<FederationPeer>(data) {
        let now = u64_at(data, 0, 0);
        let _ = peer.is_fresh(now);
        let _ = serde_json::to_vec(&peer);
    }

    let Some(local_seed) = seed_at(data, 0) else {
        return;
    };
    let Some(remote_seed) = seed_at(data, 32) else {
        return;
    };

    let local_keypair = Keypair::from_seed(&local_seed);
    let remote_keypair = Keypair::from_seed(&remote_seed);
    let now = u64_at(data, 64, 1);
    let rotation_window_secs = u64_at(data, 72, 1);
    let max_handshake_skew_secs = u64_at(data, 80, 0);
    let nonce_tail = match data.get(88..) {
        Some(bytes) => bytes,
        None => &[],
    };
    let nonce = nonce_from(nonce_tail);

    let exchange = KernelTrustExchange::new("kernel.local", local_keypair)
        .with_config(KernelTrustExchangeConfig {
            rotation_window_secs,
            max_handshake_skew_secs,
        })
        .with_trusted_peer("kernel.remote", remote_keypair.public_key());

    let remote_envelope = match PeerHandshakeEnvelope::sign(
        "kernel.remote",
        "kernel.local",
        nonce,
        now,
        &remote_keypair,
    ) {
        Ok(envelope) => envelope,
        Err(_) => return,
    };

    let _ = remote_envelope.verify_signature();
    if exchange
        .accept_envelope(&remote_envelope, "kernel.remote", now)
        .is_ok()
    {
        let _ = exchange.resolve("kernel.remote", now);
        let _ = exchange.peers();
        let _ = exchange.forget("kernel.remote");
    }
}

/// Org A verifier seed for `bilateral_dsse_verify`. The committed corpus
/// under `fuzz/corpus/bilateral_dsse_verify/` is co-signed by the keypairs
/// derived from this seed and [`BILATERAL_DSSE_ORG_B_SEED`], so a mutation
/// that leaves both signatures intact still reaches the Ed25519 checks.
const BILATERAL_DSSE_ORG_A_SEED: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

/// Org B verifier seed for `bilateral_dsse_verify`.
const BILATERAL_DSSE_ORG_B_SEED: [u8; 32] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
];

fn bilateral_dsse_verifier_keys() -> &'static (PublicKey, PublicKey) {
    static KEYS: OnceLock<(PublicKey, PublicKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        (
            Keypair::from_seed(&BILATERAL_DSSE_ORG_A_SEED).public_key(),
            Keypair::from_seed(&BILATERAL_DSSE_ORG_B_SEED).public_key(),
        )
    })
}

/// Drive the strict bilateral invocation envelope verifier and its decode
/// surface with arbitrary bytes. Both organisation keys are fixed so the
/// committed corpus exercises the full gate order through the two Ed25519
/// checks; the swapped-key call covers the fingerprint and keyid mismatch
/// branches on the same input, and the signature-slice verifier covers the
/// sibling predicate profile.
pub fn bilateral_dsse_verify(data: &[u8]) {
    if let Ok(statement) = serde_json::from_slice::<DsseStatement>(data) {
        let _ = statement.canonical_bytes();
        let _ = serde_json::to_vec(&statement);
    }

    let Ok(envelope) = serde_json::from_slice::<DsseEnvelope>(data) else {
        return;
    };
    let _ = envelope.pae_bytes();
    if let Ok((statement, _)) = envelope.decode_statement() {
        let _ = statement.canonical_bytes();
        let _ = serde_json::to_vec(&statement);
    }
    let _ = serde_json::to_vec(&envelope);

    let (org_a, org_b) = bilateral_dsse_verifier_keys();
    let _ = verify_chio_bilateral_dsse_envelope(&envelope, org_a, org_b);
    let _ = verify_chio_bilateral_dsse_envelope(&envelope, org_b, org_a);
    let _ = verify_dsse_envelope(&envelope, org_a, org_b);
}

pub fn underwriting_policy_input(data: &[u8]) {
    if let Ok(query) = serde_json::from_slice::<UnderwritingPolicyInputQuery>(data) {
        let normalized = query.normalized();
        let _ = normalized.validate();
    }

    if let Ok(query) = serde_json::from_slice::<UnderwritingDecisionQuery>(data) {
        let _ = query.normalized();
    }

    if let Ok(policy) = serde_json::from_slice::<UnderwritingDecisionPolicy>(data) {
        let _ = policy.validate();
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingSimulationRequest>(data) {
        let _ = request.query.normalized().validate();
        let _ = request.policy.validate();
    }

    if let Ok(input) = serde_json::from_slice::<UnderwritingPolicyInput>(data) {
        let policy = match serde_json::from_slice::<UnderwritingDecisionPolicy>(data) {
            Ok(policy) if policy.validate().is_ok() => policy,
            _ => UnderwritingDecisionPolicy::default(),
        };

        if let Ok(report) = evaluate_underwriting_policy_input(input, &policy) {
            let issued_at = report.generated_at;
            let _ = serde_json::to_vec(&report);
            let _ = build_underwriting_decision_artifact(report, issued_at, None, None);
        }
    }

    if let Ok(artifact) = serde_json::from_slice::<UnderwritingDecisionArtifact>(data) {
        let _ = serde_json::to_vec(&artifact);
    }

    if let Ok(report) = serde_json::from_slice::<UnderwritingDecisionListReport>(data) {
        let _ = serde_json::to_vec(&report);
    }

    if let Ok(report) = serde_json::from_slice::<UnderwritingSimulationReport>(data) {
        let _ = serde_json::to_vec(&report);
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingAppealCreateRequest>(data) {
        let _ = serde_json::to_vec(&request);
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingAppealResolveRequest>(data) {
        let _ = serde_json::to_vec(&request);
    }

    if let Ok(request) = serde_json::from_slice::<MarketplaceCreditLimitRequest>(data) {
        let _ = compute_marketplace_credit_limit(&request);
    }

    if let Ok(inputs) = serde_json::from_slice::<PremiumInputs>(data) {
        let _ = inputs.validate();
        let window = LookbackWindow { since: 0, until: 0 };
        let _ = price_premium("fuzz-agent", "fuzz-scope", window, &inputs);
    }
}
