use std::os::unix::fs::PermissionsExt;

use super::*;

#[test]
fn cage_receipt_persistence_requires_the_independent_anchor() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let seed = root.path().join("signer.seed");
    std::fs::write(&seed, "37".repeat(32))?;
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600))?;
    let key = chio_core::Keypair::from_seed(&[0x37; 32]);
    let mut policy = CageReceiptRuntimePolicy {
        database_path: root.path().join("receipts.db"), rollback_anchor_root: None,
        signer_seed_path: seed, trusted_signer_public_key: key.public_key().to_hex(),
        capability_id: "test-cage-launch".into(), tenant_id: None,
    };
    let profile = "1".repeat(64);
    let plan = "2".repeat(64);
    let missing = cage_receipt_persistence(&policy, "test-server", &profile, &plan, &"a".repeat(64))
        .err().ok_or("missing receipt anchor was accepted")?;
    assert!(missing.to_string().contains("signed receipt rollback anchor"));
    assert!(!policy.database_path.exists());
    policy.rollback_anchor_root = Some(root.path().to_path_buf());
    let colocated = cage_receipt_persistence(&policy, "test-server", &profile, &plan, &"a".repeat(64))
        .err().ok_or("co-located receipt anchor was accepted")?;
    assert!(colocated.to_string().contains("snapshot domain"));
    let independent = tempfile::Builder::new().prefix("chio-cage-receipt-anchor-").tempdir_in("/dev/shm")?;
    policy.rollback_anchor_root = Some(independent.path().to_path_buf());
    let qualified = cage_receipt_persistence(&policy, "test-server", &profile, &plan, &"a".repeat(64))?;
    drop(qualified);
    Ok(())
}
