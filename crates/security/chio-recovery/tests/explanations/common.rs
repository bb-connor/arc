use chio_core_types::{recovery::*, Keypair};
use chio_recovery::*;
use chio_security_types::{recovery::*, InformationLabel};
pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
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
impl Fixture {
    pub fn new() -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../spec/vectors/recovery/v1/explanation-inputs.json"
        ))?;
        Ok(Self {
            snapshot: serde_json::from_value(value["snapshot"].clone())?,
            registry: serde_json::from_value(value["registry"].clone())?,
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
    pub fn audience(&self) -> Result<ExplanationAudience<'_>> {
        Ok(ExplanationAudience {
            recipient: &self.recipient,
            clearance: &self.clearance,
            validity_ceiling_unix_ms: SafeInteger::new(31000)?,
        })
    }
    pub fn payloads(&self) -> Result<(RecoveryExplanationViewV1, RecoveryExplanationReportV1)> {
        Ok(prepare_explanation_report(
            &self.snapshot,
            &self.registry,
            self.limits,
            &self.audience()?,
            &self.domain,
            &self.issuer,
            ExplanationRef::new("advice:synthetic")?,
        )?)
    }
    pub fn verify(
        &self,
        report: &SignedRecoveryExplanationReportV1,
        view: &RecoveryExplanationViewV1,
        now: u64,
    ) -> Result {
        let inputs = ExplanationReportInputs {
            snapshot: &self.snapshot,
            registry: &self.registry,
            view,
            audience: self.audience()?,
        };
        let key = self.key.public_key();
        let expected = ExplanationExpectedTrust {
            key: &key,
            trust_domain: &self.domain,
            issuer: &self.issuer,
            scope: &self.snapshot.scope,
            deployment_digest: self.snapshot.deployment_digest,
            policy_digest: self.snapshot.policy_digest,
            contract_digest: self.snapshot.contract_digest,
            intent_digest: self.snapshot.intent_digest,
            limits: self.limits,
        };
        Ok(verify_explanation_report(
            report,
            &inputs,
            &expected,
            SafeInteger::new(now)?,
        )?)
    }
    pub fn mutate_fact(
        &mut self,
        index: usize,
        f: impl FnOnce(&mut RecoveryExplanationFactV1),
    ) -> Result {
        let mut facts = self.snapshot.observations.as_slice().to_vec();
        f(&mut facts[index]);
        self.snapshot.observations = BoundedList::new(facts)?;
        Ok(())
    }
    pub fn mutate_template(&mut self, f: impl FnOnce(&mut RecoveryRemedyTemplateV1)) -> Result {
        let mut templates = self.registry.templates.as_slice().to_vec();
        f(&mut templates[0]);
        self.registry.templates = BoundedList::new(templates)?;
        Ok(())
    }
}
pub fn private() -> Result<InformationLabel> {
    Ok(serde_json::from_value(
        serde_json::json!({"kind":"known","owners":{},"compartments":["secret-group"]}),
    )?)
}
