use chio_core_types::recovery::SignedRecoveryExplanationReportV1;
use chio_core_types::{Keypair, PublicKey};
use chio_recovery::{
    prepare_explanation_report, verify_explanation_report, ExplanationAudience,
    ExplanationExpectedTrust, ExplanationReportInputs,
};
use chio_security_types::recovery::{
    ActorId, AuthorityDomainId, BoundedList, ContractError, ExplanationLimitsV1, ExplanationRef,
    IssuerId, RecoveryExplanationFactV1, RecoveryExplanationReportV1, RecoveryExplanationViewV1,
    RecoveryRemedyRegistryV1, RecoveryRemedyTemplateV1, RecoverySnapshotV1, SafeInteger,
};
use chio_security_types::InformationLabel;
use serde_json::{json, Value};

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Observed at 1000 ms. The snapshot and every fact expire at 20000 ms and the
/// recipient's validity ceiling is 31000 ms.
pub const OBSERVED_AT: u64 = 1000;
pub const EXPIRES_AT: u64 = 20000;
pub const VALIDITY_CEILING: u64 = 31000;

pub struct Fixture {
    pub snapshot: RecoverySnapshotV1,
    pub registry: RecoveryRemedyRegistryV1,
    pub limits: ExplanationLimitsV1,
    pub key: Keypair,
    pub recipient: ActorId,
    pub domain: AuthorityDomainId,
    pub issuer: IssuerId,
    pub clearance: InformationLabel,
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
            limits: ExplanationLimitsV1 {
                offers: SafeInteger::new(16)?,
                work: SafeInteger::new(4096)?,
            },
            key: Keypair::from_seed(&[29; 32]),
            recipient: ActorId::new("viewer")?,
            domain: AuthorityDomainId::new("advisory-domain")?,
            issuer: IssuerId::new("advisory-issuer")?,
            clearance: InformationLabel::bottom(),
        })
    }

    pub fn audience(&self) -> std::result::Result<ExplanationAudience<'_>, ContractError> {
        Ok(ExplanationAudience {
            recipient: &self.recipient,
            clearance: &self.clearance,
            validity_ceiling_unix_ms: SafeInteger::new(VALIDITY_CEILING)?,
        })
    }

    pub fn payloads(
        &self,
    ) -> std::result::Result<(RecoveryExplanationViewV1, RecoveryExplanationReportV1), ContractError>
    {
        prepare_explanation_report(
            &self.snapshot,
            &self.registry,
            self.limits,
            &self.audience()?,
            &self.domain,
            &self.issuer,
            ExplanationRef::new("advice:synthetic")?,
        )
    }

    /// The verifier's trust selection for this fixture's deployment.
    pub fn expected<'a>(&'a self, key: &'a PublicKey) -> ExplanationExpectedTrust<'a> {
        ExplanationExpectedTrust {
            key,
            trust_domain: &self.domain,
            issuer: &self.issuer,
            scope: &self.snapshot.scope,
            deployment_digest: self.snapshot.deployment_digest,
            policy_digest: self.snapshot.policy_digest,
            contract_digest: self.snapshot.contract_digest,
            intent_digest: self.snapshot.intent_digest,
            limits: self.limits,
        }
    }

    pub fn verify_with(
        &self,
        report: &SignedRecoveryExplanationReportV1,
        view: &RecoveryExplanationViewV1,
        expected: &ExplanationExpectedTrust<'_>,
        now: u64,
    ) -> std::result::Result<(), ContractError> {
        let inputs = ExplanationReportInputs {
            snapshot: &self.snapshot,
            registry: &self.registry,
            view,
            audience: self.audience()?,
        };
        verify_explanation_report(report, &inputs, expected, SafeInteger::new(now)?)
    }

    pub fn verify(
        &self,
        report: &SignedRecoveryExplanationReportV1,
        view: &RecoveryExplanationViewV1,
        now: u64,
    ) -> std::result::Result<(), ContractError> {
        let key = self.key.public_key();
        self.verify_with(report, view, &self.expected(&key), now)
    }

    pub fn mutate_fact(
        &mut self,
        index: usize,
        f: impl FnOnce(&mut RecoveryExplanationFactV1),
    ) -> Result {
        let mut facts = self.snapshot.observations.as_slice().to_vec();
        f(facts.get_mut(index).ok_or("fact index is out of range")?);
        self.snapshot.observations = BoundedList::new(facts)?;
        Ok(())
    }

    pub fn mutate_template(&mut self, f: impl FnOnce(&mut RecoveryRemedyTemplateV1)) -> Result {
        let mut templates = self.registry.templates.as_slice().to_vec();
        f(templates.first_mut().ok_or("registry has no template")?);
        self.registry.templates = BoundedList::new(templates)?;
        Ok(())
    }

    pub fn fact(&self, index: usize) -> Result<RecoveryExplanationFactV1> {
        Ok(self
            .snapshot
            .observations
            .as_slice()
            .get(index)
            .ok_or("fact index is out of range")?
            .clone())
    }

    pub fn template(&self) -> Result<RecoveryRemedyTemplateV1> {
        Ok(self
            .registry
            .templates
            .as_slice()
            .first()
            .ok_or("registry has no template")?
            .clone())
    }
}

pub fn private() -> Result<InformationLabel> {
    Ok(serde_json::from_value(
        json!({"kind": "known", "owners": {}, "compartments": ["secret-group"]}),
    )?)
}
