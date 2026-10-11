//! Deterministic schema fixtures for the runtime policy facet.

use serde_json::Value;

pub(super) fn policy_peer_weights_fixture() -> Value {
    serde_json::json!({
        "body": {
            "schema": "chio.runtime.peer-weights.v1",
            "verifierId": "did:chio:buyer-verifier",
            "keyId": "verifier-key-1",
            "reputationEpoch": 7,
            "issuedAtUnixMs": 1_800_000_000_000_i64,
            "expiresAtUnixMs": 1_800_003_600_000_i64,
            "weights": [ { "peerKernelId": "kernel.vendor-b", "weight": 1.0 } ]
        },
        "signerKey": "a".repeat(64),
        "signature": "b".repeat(128),
    })
}

pub(super) fn policy_envelope_fixture() -> Value {
    serde_json::json!({
        "body": {
            "schema": "chio.runtime.pheromone-policy.v1",
            "policyId": "policy-runtime-risk",
            "verifierId": "did:chio:buyer-verifier",
            "keyId": "verifier-key-1",
            "policyVersion": 1,
            "mode": "enforce",
            "issuedAtUnixMs": 1_800_000_000_000_i64,
            "expiresAtUnixMs": 1_800_003_600_000_i64,
            "allowedReputationEpochs": [7],
            "maxQueryReportAgeMs": 60000,
            "minDistinctOriginPairs": 1,
            "runtimeTrustBundleSha256": "b".repeat(64),
            "peerWeightsSha256": "c".repeat(64),
            "rules": [
                {
                    "ruleId": "deny-high-runtime-risk",
                    "subjectClass": "workflow.destructive_step",
                    "subjectClassNamespace": "chio.runtime",
                    "actionClassId": "*",
                    "direction": "deny_if_at_or_above",
                    "thresholdTotalStrength": 0.75,
                    "effect": "deny"
                }
            ]
        },
        "signerKey": "a".repeat(64),
        "signature": "b".repeat(128),
    })
}

pub(super) fn policy_decision_fixture() -> Value {
    serde_json::json!({
        "schema": "chio.runtime.pheromone-policy-decision.v1",
        "enforced": true,
        "decision": "deny",
        "policyId": "policy-runtime-risk",
        "policySha256": "a".repeat(64),
        "queryReportSha256": "b".repeat(64),
        "peerWeightsSha256": "c".repeat(64),
        "reputationEpoch": 7,
        "matchedRuleId": "deny-high-runtime-risk",
        "reasonCode": "runtime_pheromone_policy_deny"
    })
}

pub(super) fn policy_trust_floor_fixture() -> Value {
    serde_json::json!({
        "schema": "chio.runtime.trust-floor-state.v1",
        "entries": [
            {
                "verifierId": "did:chio:buyer-verifier",
                "keyId": "verifier-key-1",
                "highestVersion": 2,
                "latestBundleSha256": "a".repeat(64),
                "latestRevocationCheckpointSha256": "d".repeat(64)
            }
        ]
    })
}
