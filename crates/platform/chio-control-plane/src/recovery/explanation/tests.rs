use super::service::*;
use chio_core_types::{Ed25519Backend, Keypair};
use chio_recovery::ExplanationAudience;
use chio_security_types::{recovery::*, InformationLabel};
use std::sync::Arc;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn fixture() -> Result<(
    RecoveryExplanationService,
    RecoverySnapshotV1,
    RecoveryRemedyRegistryV1,
)> {
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../spec/vectors/recovery/v1/explanation-inputs.json"
    ))?;
    let snapshot: RecoverySnapshotV1 = serde_json::from_value(data["snapshot"].clone())?;
    let registry = serde_json::from_value(data["registry"].clone())?;
    let service = RecoveryExplanationService::new(
        snapshot.scope.clone(),
        AuthorityDomainId::new("advisory")?,
        IssuerId::new("adviser")?,
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[33; 32]))),
        ExplanationLimitsV1 {
            offers: SafeInteger::new(16)?,
            work: SafeInteger::new(4096)?,
        },
    )?;
    Ok((service, snapshot, registry))
}
#[test]
fn recovery_dry_service_constructs_without_runtime_or_effect_ports() -> Result {
    let (service, snapshot, registry) = fixture()?;
    let recipient = ActorId::new("reader")?;
    let clearance = InformationLabel::bottom();
    let audience = || -> Result<ExplanationAudience<'_>> {
        Ok(ExplanationAudience {
            recipient: &recipient,
            clearance: &clearance,
            validity_ceiling_unix_ms: SafeInteger::new(31000)?,
        })
    };
    let first = service.evaluate(snapshot.clone(), registry.clone(), audience()?)?;
    let second = service.evaluate(snapshot, registry, audience()?)?;
    assert_ne!(first.view.body().report_ref, second.view.body().report_ref);
    assert!(first.report.verify_signature()?);
    assert!(first.view.verify_signature()?);
    assert_eq!(first.view.body().projection, second.view.body().projection);
    assert!(!format!("{first:?}").contains("public-remedy"));
    Ok(())
}
#[test]
fn recovery_probe_quota_is_fixed_actor_scoped_and_lifetime_bounded() -> Result {
    let (service, _, _) = fixture()?;
    let actor = ActorId::new("reader")?;
    for _ in 0..32 {
        service.admit(&actor, 1000)?;
    }
    assert!(service.admit(&actor, 1001).is_err());
    assert!(service.admit(&actor, 999).is_err());
    service.admit(&actor, 61000)?;
    for index in 0..63 {
        service.admit(&ActorId::new(&format!("reader:{index}"))?, 61000)?;
    }
    service.admit(&ActorId::new("new-reader")?, 1000000)?;
    // Fully elapsed windows release identity capacity without evicting an
    // active actor or renewing its probe allowance.
    service.admit(&actor, 1000000)?;
    Ok(())
}
