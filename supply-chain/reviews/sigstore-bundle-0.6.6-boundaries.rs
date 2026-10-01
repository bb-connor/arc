// Run as an additional integration target against the checksum-verified archive.
use sigstore_bundle::validate_bundle;
use sigstore_types::{Bundle, CanonicalizedBody, LogIndex, Sha256Hash};

fn one_leaf_bundle() -> Result<Bundle, Box<dyn std::error::Error>> {
    let root = sigstore_merkle::hash_leaf(b"{}").to_base64();
    let checkpoint = format!("audit.example\n1\n{root}\n\n\u{2014} audit.example AQIDBAU=\n");
    Ok(serde_json::from_value(serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": "AA=="},
            "tlogEntries": [{
                "logId": {"keyId": "AA=="},
                "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                "canonicalizedBody": "e30=",
                "inclusionProof": {
                    "rootHash": root, "treeSize": "1", "hashes": [],
                    "checkpoint": {"envelope": checkpoint}
                }
            }]
        },
        "messageSignature": {"signature": "AA=="}
    }))?)
}

#[test]
fn bundle_validation_is_not_checkpoint_or_artifact_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    // Deliberately invalid certificate and signature bytes still pass this API.
    let bundle = one_leaf_bundle()?;
    validate_bundle(&bundle)?;

    // In this release, the proof's duplicate root and checkpoint size are not
    // joined here. Chio's owned cryptographic verifier must enforce both joins.
    let mut unjoined = bundle;
    let proof = unjoined.verification_material.tlog_entries[0]
        .inclusion_proof
        .as_mut()
        .ok_or("missing fixture proof")?;
    proof.root_hash = Sha256Hash::from_bytes([9_u8; 32]);
    proof.checkpoint.envelope = proof.checkpoint.envelope.replacen("\n1\n", "\n2\n", 1);
    validate_bundle(&unjoined)?;
    Ok(())
}

#[test]
fn proof_validation_rejects_changed_leaf_and_invalid_positions(
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline = one_leaf_bundle()?;
    let mut changed_leaf = baseline.clone();
    changed_leaf.verification_material.tlog_entries[0].canonicalized_body =
        CanonicalizedBody::from_bytes(b"changed");
    assert!(validate_bundle(&changed_leaf).is_err());

    for (index, size) in [(-1, 1), (1, 1), (0, 0), (0, -1), (0, i64::MAX)] {
        let mut changed = baseline.clone();
        let proof = changed.verification_material.tlog_entries[0]
            .inclusion_proof
            .as_mut()
            .ok_or("missing fixture proof")?;
        proof.log_index = LogIndex::new(index);
        proof.tree_size = size;
        assert!(validate_bundle(&changed).is_err());
    }
    Ok(())
}
