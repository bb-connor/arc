use super::Result;
use chio_security_types::recovery::{RecoveryRemedyRegistryV1, RecoverySnapshotV1};
use serde_json::{json, Value};

const OBSERVED_AT: u64 = 1000;
const EXPIRES_AT: u64 = 20000;
pub struct Fixture {
    pub snapshot: RecoverySnapshotV1,
    pub registry: RecoveryRemedyRegistryV1,
}

fn public_label() -> Value {
    json!({"kind": "known", "owners": {}, "compartments": []})
}

fn scope() -> Value {
    json!({"authority_domain": "dry-domain", "tenant_id": "tenant", "process_id": "process"})
}

fn fact(id: &str, fact: &str, target: Value, version: u64) -> Value {
    json!({
        "id": id,
        "scope": scope(),
        "object": format!("native:{id}"),
        "source": "native_authority",
        "fact": fact,
        "target": target,
        "integrity": "native_owned",
        "label": public_label(),
        "observed_at_unix_ms": OBSERVED_AT,
        "expires_at_unix_ms": EXPIRES_AT,
        "state": {
            "kind": "known",
            "version": version,
            "evidence": format!("evidence:{id}"),
            "satisfied": true
        }
    })
}

/// Facts in order: capability, policy, recipient (destination ACL), coverage.
fn snapshot() -> Value {
    let intent = vec![4_u8; 32];
    json!({
        "schema": "chio.recovery.explanation-snapshot.v1",
        "version": 1,
        "scope": scope(),
        "deployment_digest": vec![1_u8; 32],
        "policy_digest": vec![2_u8; 32],
        "contract_digest": vec![3_u8; 32],
        "intent_digest": &intent,
        "context_label": public_label(),
        "influence": {"kind": "unknown"},
        "observed_at_unix_ms": OBSERVED_AT,
        "expires_at_unix_ms": EXPIRES_AT,
        "effect": {"kind": "never_admitted"},
        "observations": [
            fact("capability", "capability", json!({"kind": "intent", "intent": &intent}), 5),
            fact("policy", "policy", json!({"kind": "intent", "intent": &intent}), 7),
            fact(
                "recipient",
                "destination_acl",
                json!({"kind": "destination", "destination": "public-destination"}),
                3
            ),
            fact(
                "coverage",
                "authority_coverage",
                json!({"kind": "authority", "scope": vec![5_u8; 32]}),
                11
            ),
        ]
    })
}

fn registry() -> Value {
    json!({
        "schema": "chio.recovery.remedy-registry.v1",
        "version": 1,
        "scope": scope(),
        "deployment_digest": vec![1_u8; 32],
        "policy_digest": vec![2_u8; 32],
        "contract_digest": vec![3_u8; 32],
        "classification": public_label(),
        "templates": [{
            "template_id": "public-remedy",
            "kind": "exact_approval",
            "family": vec![3_u8; 32],
            "authority_scope": vec![5_u8; 32],
            "destination": "public-destination",
            "disclosure_label": public_label(),
            "classification": public_label(),
            "satisfies_task": true,
            "requires_integrity": false,
            "cost": {
                "approvals": 0,
                "irreversible_effects": 1,
                "budget_units": 1,
                "latency": "remote",
                "evidence": "estimate:1"
            },
            "requirements": ["capability", "policy", "recipient", "coverage"]
        }]
    })
}

impl Fixture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            snapshot: serde_json::from_value(snapshot())?,
            registry: serde_json::from_value(registry())?,
        })
    }
}
