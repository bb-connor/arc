use crate::{
    common::{self, Result},
    funded_work::{authority_enrollment as enrollment, native::Native},
};
use chio_core_types::{canonical_json_bytes, Keypair};

fn setup() -> Result<(tempfile::TempDir, tempfile::TempDir, enrollment::Pins)> {
    let provider = tempfile::tempdir()?;
    let roles = tempfile::tempdir()?;
    let pins = enrollment::Pins {
        buyer: common::init(&roles.path().join("buyer"))?,
        provider: common::init(provider.path())?,
        verifier: common::init(&roles.path().join("verifier"))?,
        checkpoint: common::init(&roles.path().join("checkpoint"))?,
        status: common::init(&roles.path().join("status"))?,
        governance: common::init(&roles.path().join("governance"))?,
    };
    Ok((provider, roles, pins))
}

#[test]
fn public_enrollment_provisions_only_original_provider_authority() -> Result<()> {
    let (provider, roles, pins) = setup()?;
    let context = enrollment::context(
        &roles.path().join("governance"),
        &roles.path().join("status"),
        &pins,
        common::now()? + 3600,
    )?;
    let (domain, _, observation, _) = super::observer::fixture()?;
    let first = enrollment::enroll(provider.path(), &pins, &context, &domain)?;
    let again = enrollment::enroll(provider.path(), &pins, &context, &domain)?;
    assert_eq!(canonical_json_bytes(&first)?, canonical_json_bytes(&again)?);
    assert_eq!(first.verifier_key, pins.verifier);
    for role in ["buyer", "verifier", "checkpoint", "status", "governance"] {
        assert!(!provider.path().join(role).exists());
        assert!(roles.path().join(role).join("key.seed").exists());
    }
    let source = std::sync::Arc::new(super::native::Source(
        std::sync::Mutex::new(observation),
        std::sync::atomic::AtomicBool::new(true),
    ));
    let native = Native::open(provider.path(), source)?;
    assert_eq!(native.policy.authority_uuid, first.authority_uuid);
    assert!(native
        .request("independent-provisioning", "{}", common::now()? + 90)
        .is_ok());
    Ok(())
}

#[test]
fn substituted_public_roles_cannot_provision_native_authority() -> Result<()> {
    let (provider, roles, pins) = setup()?;
    let context = enrollment::context(
        &roles.path().join("governance"),
        &roles.path().join("status"),
        &pins,
        common::now()? + 3600,
    )?;
    let (domain, _, _, _) = super::observer::fixture()?;
    for role in [
        "buyer",
        "provider",
        "verifier",
        "checkpoint",
        "status",
        "governance",
    ] {
        let mut changed = serde_json::to_value(&pins)?;
        changed[role] = serde_json::to_value(Keypair::generate().public_key())?;
        let changed = serde_json::from_value(changed)?;
        if role == "buyer" {
            // Buyer identity is an independent administrative input, not in the context.
            continue;
        }
        assert!(
            enrollment::enroll(provider.path(), &changed, &context, &domain).is_err(),
            "{role}"
        );
        assert!(!provider.path().join("authority.sqlite").exists());
    }
    let mut changed = pins.clone();
    changed.buyer = changed.governance.clone();
    assert!(enrollment::enroll(provider.path(), &changed, &context, &domain).is_err());
    assert!(!provider.path().join("authority.sqlite").exists());
    Ok(())
}

#[test]
fn enrolled_authority_cannot_recover_by_replacing_missing_state_or_keys() -> Result<()> {
    let (provider, roles, pins) = setup()?;
    let context = enrollment::context(
        &roles.path().join("governance"),
        &roles.path().join("status"),
        &pins,
        common::now()? + 3600,
    )?;
    let (domain, _, _, _) = super::observer::fixture()?;
    enrollment::enroll(provider.path(), &pins, &context, &domain)?;
    let seed = std::fs::read(provider.path().join("key.seed"))?;
    std::fs::write(
        provider.path().join("key.seed"),
        Keypair::generate().seed_hex(),
    )?;
    assert!(enrollment::enroll(provider.path(), &pins, &context, &domain).is_err());
    std::fs::write(provider.path().join("key.seed"), seed)?;
    std::fs::remove_file(provider.path().join("funding.sqlite"))?;
    assert!(enrollment::enroll(provider.path(), &pins, &context, &domain).is_err());
    assert!(!provider.path().join("funding.sqlite").exists());
    Ok(())
}

#[test]
fn valid_foreign_governance_signature_cannot_replace_selected_public_authority() -> Result<()> {
    let (provider, roles, pins) = setup()?;
    let foreign = roles.path().join("foreign-governance");
    let mut foreign_pins = pins.clone();
    foreign_pins.governance = common::init(&foreign)?;
    let context = enrollment::context(
        &foreign,
        &roles.path().join("status"),
        &foreign_pins,
        common::now()? + 3600,
    )?;
    let (domain, _, _, _) = super::observer::fixture()?;
    assert!(enrollment::enroll(provider.path(), &pins, &context, &domain).is_err());
    assert!(!provider.path().join("authority-enrollment.json").exists());
    Ok(())
}

#[test]
fn incomplete_enrollment_cannot_replace_original_native_store() -> Result<()> {
    let (provider, roles, pins) = setup()?;
    let context = enrollment::context(
        &roles.path().join("governance"),
        &roles.path().join("status"),
        &pins,
        common::now()? + 3600,
    )?;
    let (domain, _, _, _) = super::observer::fixture()?;
    enrollment::enroll(provider.path(), &pins, &context, &domain)?;
    std::fs::remove_file(provider.path().join("funding-policy.json"))?;
    let before = std::fs::read(provider.path().join("authority.sqlite"))?;
    assert!(enrollment::enroll(provider.path(), &pins, &context, &domain).is_err());
    assert_eq!(
        std::fs::read(provider.path().join("authority.sqlite"))?,
        before
    );
    assert!(!provider.path().join("funding-policy.json").exists());
    Ok(())
}

#[test]
fn every_pair_of_authority_roles_must_be_distinct() -> Result<()> {
    let (_, _, pins) = setup()?;
    let roles = [
        "buyer",
        "provider",
        "verifier",
        "checkpoint",
        "status",
        "governance",
    ];
    for (index, first) in roles.iter().enumerate() {
        for second in &roles[index + 1..] {
            let mut value = serde_json::to_value(&pins)?;
            value[first] = value[second].clone();
            let changed: enrollment::Pins = serde_json::from_value(value)?;
            assert!(changed.validate().is_err(), "{first}/{second}");
        }
    }
    Ok(())
}

#[test]
fn governance_draft_can_be_attested_without_either_role_reading_peer_seed() -> Result<()> {
    let (provider, roles, pins) = setup()?;
    let draft = enrollment::draft(
        &roles.path().join("governance"),
        &pins,
        common::now()? + 3600,
    )?;
    assert!(draft.governance_standing.signed_statuses.is_empty());
    let context = enrollment::attest(&roles.path().join("status"), &pins, &draft)?;
    let (domain, _, _, _) = super::observer::fixture()?;
    enrollment::enroll(provider.path(), &pins, &context, &domain)?;
    let again = enrollment::draft(
        &roles.path().join("governance"),
        &pins,
        context.profile.body.expires_at,
    )?;
    assert_eq!(canonical_json_bytes(&draft)?, canonical_json_bytes(&again)?);
    let mut changed = pins.clone();
    changed.governance = Keypair::generate().public_key();
    assert!(enrollment::attest(&roles.path().join("status"), &changed, &draft).is_err());
    Ok(())
}
