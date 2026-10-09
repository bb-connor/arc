use super::*;
use crate::signed_input::{ISSUANCE_RESERVE_BYTES, MAX_SIGNED_FILE_BYTES};
use chio_credentials::{
    build_agent_passport, default_oid4vci_passport_issuer_metadata, issue_reputation_credential,
    AttestationWindow, ChioCredentialEvidence, OID4VCI_PRE_AUTHORIZED_GRANT_TYPE,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ISSUED_AT: u64 = 1_710_000_000;
const OFFER_TTL: u64 = 3_600;

fn passport() -> Result<AgentPassport, Box<dyn std::error::Error>> {
    let subject = Keypair::from_seed(&[93; 32]);
    let scorecard = chio_reputation::compute_local_scorecard(
        &subject.public_key().to_hex(),
        ISSUED_AT,
        &chio_reputation::LocalReputationCorpus::default(),
        &chio_reputation::ReputationConfig::default(),
    );
    let credential = issue_reputation_credential(
        &Keypair::from_seed(&[94; 32]),
        scorecard,
        ChioCredentialEvidence {
            query: AttestationWindow {
                since: None,
                until: ISSUED_AT,
            },
            receipt_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_roots: Vec::new(),
            receipt_log_urls: Vec::new(),
            lineage_records: 0,
            uncheckpointed_receipts: 0,
            runtime_attestation: None,
        },
        ISSUED_AT,
        ISSUED_AT + 7_200,
    )?;
    let subject_did = credential.unsigned.credential_subject.id.clone();
    Ok(build_agent_passport(&subject_did, vec![credential])?)
}

fn metadata() -> Result<Oid4vciCredentialIssuerMetadata, Box<dyn std::error::Error>> {
    Ok(default_oid4vci_passport_issuer_metadata(
        "https://wallet.example.test",
    )?)
}

fn compact_len(registry: &PassportIssuanceOfferRegistry) -> Result<usize, serde_json::Error> {
    Ok(serde_json::to_vec(registry)?.len())
}

/// Registry of `count` copies of one live offer under distinct fixed-width ids.
fn registry_of(
    template: &PassportIssuanceOfferRecord,
    count: usize,
) -> PassportIssuanceOfferRegistry {
    let mut registry = PassportIssuanceOfferRegistry::default();
    for index in 0..count {
        let mut record = template.clone();
        record.offer_id = format!("{index:064x}");
        registry.offers.insert(record.offer_id.clone(), record);
    }
    registry
}

/// Smallest copy count whose compact encoding exceeds `target` bytes.
fn count_exceeding(
    template: &PassportIssuanceOfferRecord,
    target: usize,
) -> Result<usize, serde_json::Error> {
    let one = compact_len(&registry_of(template, 1))?;
    let two = compact_len(&registry_of(template, 2))?;
    let per_record = two - one;
    Ok((target.saturating_sub(one)) / per_record + 2)
}

fn template() -> Result<PassportIssuanceOfferRecord, Box<dyn std::error::Error>> {
    let mut seed = PassportIssuanceOfferRegistry::default();
    Ok(seed.issue_offer(&metadata()?, passport()?, None, OFFER_TTL, ISSUED_AT)?)
}

fn oversize_error(limit: usize) -> String {
    format!(
        "registry file would exceed the {limit} byte limit; the existing file was left unchanged"
    )
}

#[test]
fn offer_registry_save_over_read_cap_is_refused_and_prior_file_survives() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("offers.json");
    let template = template()?;
    let small = registry_of(&template, 2);
    small.save(&path)?;
    let before = fs::read(&path)?;

    let oversized = registry_of(
        &template,
        count_exceeding(&template, MAX_SIGNED_FILE_BYTES)?,
    );
    let len = compact_len(&oversized)?;
    assert!(len > MAX_SIGNED_FILE_BYTES);
    let error = oversized
        .save(&path)
        .err()
        .ok_or("oversized save must be refused")?;
    assert!(error
        .to_string()
        .contains(&oversize_error(MAX_SIGNED_FILE_BYTES)));
    assert_eq!(fs::read(&path)?, before);
    assert_eq!(PassportIssuanceOfferRegistry::load(&path)?, small);
    let leftovers = fs::read_dir(directory.path())?.count();
    assert_eq!(leftovers, 1, "no temporary file may remain");
    Ok(())
}

#[test]
fn issuing_prunes_expired_offers_so_the_registry_stays_loadable() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("offers.json");
    let template = template()?;
    let mut registry = registry_of(
        &template,
        count_exceeding(&template, MAX_SIGNED_FILE_BYTES)?,
    );
    let later = ISSUED_AT + OFFER_TTL + 1;
    if let Some(record) = registry.offers.values_mut().next() {
        record.state = PassportIssuanceOfferState::CredentialIssued;
        record.credential_issued_at = Some(ISSUED_AT);
    }
    let record = registry.issue_offer(&metadata()?, passport()?, None, 1_000, later)?;
    assert_eq!(registry.offers.len(), 1);
    registry.save_for_issuance(&path)?;
    let loaded = PassportIssuanceOfferRegistry::load(&path);
    assert_eq!(loaded?.offers.get(&record.offer_id), Some(&record));
    Ok(())
}

#[test]
fn prune_keeps_live_offers_and_drops_only_dead_ones() -> TestResult {
    let template = template()?;
    let mut registry = registry_of(&template, 3);
    let ids: Vec<String> = registry.offers.keys().cloned().collect();
    if let Some(record) = registry.offers.get_mut(&ids[0]) {
        record.state = PassportIssuanceOfferState::CredentialIssued;
    }
    if let Some(record) = registry.offers.get_mut(&ids[1]) {
        record.state = PassportIssuanceOfferState::Expired;
    }
    assert_eq!(registry.prune_dead(ISSUED_AT + 10), 2);
    assert_eq!(
        registry.offers.keys().cloned().collect::<Vec<_>>(),
        vec![ids[2].clone()]
    );
    assert_eq!(registry.prune_dead(ISSUED_AT + OFFER_TTL + 1), 1);
    assert!(registry.offers.is_empty());
    Ok(())
}

#[test]
fn live_registry_at_cap_refuses_issuance_but_redemption_still_persists() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("offers.json");
    let template = template()?;
    let target = MAX_SIGNED_FILE_BYTES - ISSUANCE_RESERVE_BYTES;
    let registry = registry_of(&template, count_exceeding(&template, target)?);
    let len = compact_len(&registry)?;
    assert!(len > target && len <= MAX_SIGNED_FILE_BYTES);

    let error = registry
        .save_for_issuance(&path)
        .err()
        .ok_or("issuance past the reserve must be refused")?;
    assert!(error.to_string().contains(&oversize_error(target)));
    assert!(!path.exists());

    registry.save(&path)?;
    let mut loaded = PassportIssuanceOfferRegistry::load(&path)?;
    let metadata = metadata()?;
    let code = template.offer.pre_authorized_code()?.to_string();
    let token = loaded.redeem_pre_authorized_code(
        &metadata,
        &Oid4vciTokenRequest {
            grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.into(),
            pre_authorized_code: code,
        },
        ISSUED_AT + 10,
        300,
    )?;
    assert!(!token.access_token.is_empty());
    loaded.save(&path)?;
    assert_eq!(PassportIssuanceOfferRegistry::load(&path)?, loaded);
    Ok(())
}

#[cfg(unix)]
mod custody {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn saved_registry_is_owner_only_and_never_widens_a_stricter_prior_mode() -> TestResult {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("offers.json");
        let registry = registry_of(&template()?, 1);
        registry.save(&path)?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        registry.save(&path)?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o400);
        Ok(())
    }

    #[test]
    fn save_never_follows_or_clobbers_planted_temporary_names() -> TestResult {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("offers.json");
        let victim = directory.path().join("victim");
        fs::write(&victim, b"keep")?;
        for planted in [
            "offers.json.tmp",
            "offers.json.tmp-1",
            ".offers.json.tmp",
            ".offers.json.0.tmp",
        ] {
            symlink(&victim, directory.path().join(planted))?;
        }
        let registry = registry_of(&template()?, 1);
        registry.save(&path)?;
        registry.save(&path)?;
        assert_eq!(fs::read(&victim)?, b"keep");
        assert_eq!(PassportIssuanceOfferRegistry::load(&path)?, registry);
        let temporaries = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| !kind.is_symlink()))
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(temporaries, 0);
        Ok(())
    }

    #[test]
    fn failed_save_leaves_prior_bytes_and_no_temporary() -> TestResult {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("offers.json");
        let template = template()?;
        registry_of(&template, 2).save(&path)?;
        let before = fs::read(&path)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o500))?;
        let outcome = registry_of(&template, 3).save(&path);
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        if let Err(error) = outcome {
            assert!(matches!(error, CliError::Io(_)));
            assert_eq!(fs::read(&path)?, before);
            assert_eq!(fs::read_dir(directory.path())?.count(), 1);
        }
        Ok(())
    }
}
