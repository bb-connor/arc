//! Committed BBS selective-disclosure proofs kept across fixture regeneration.
//!
//! BBS proof generation draws fresh blinding scalars, so a regenerated fixture
//! keeps a committed proof that still proves exactly the derived disclosure.
use super::*;

thread_local! {
    static COMMITTED_SELECTIVE_DISCLOSURE_PROOFS: std::cell::RefCell<
        Vec<chio_selective_disclosure::SelectiveDisclosureProof>,
    > = const { std::cell::RefCell::new(Vec::new()) };
}

/// Offers committed BBS proofs to [`keep_committed_selective_disclosure_proof`]
/// for the rest of this thread's fixture generation.
pub(super) fn offer_committed_selective_disclosure_proofs(
    proofs: Vec<chio_selective_disclosure::SelectiveDisclosureProof>,
) {
    COMMITTED_SELECTIVE_DISCLOSURE_PROOFS.with(|committed| *committed.borrow_mut() = proofs);
}

/// BBS proof generation draws fresh blinding scalars, so generation keeps a
/// committed proof (the bundle's own or one offered by a regeneration) that
/// proves exactly the derived disclosure. Any field drift or a proof that no
/// longer verifies takes the freshly derived proof.
pub(super) fn keep_committed_selective_disclosure_proof(
    proof_path: &Path,
    derived: chio_selective_disclosure::SelectiveDisclosureProof,
) -> Result<chio_selective_disclosure::SelectiveDisclosureProof, CliError> {
    let mut candidates = Vec::new();
    match crate::input::read(proof_path) {
        Ok(bytes) => candidates.extend(
            crate::input::json::<chio_selective_disclosure::SelectiveDisclosureProof>(&bytes).ok(),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(CliError::from(error)),
    }
    COMMITTED_SELECTIVE_DISCLOSURE_PROOFS
        .with(|committed| candidates.extend(committed.borrow().iter().cloned()));

    let mut registry = chio_selective_disclosure::InMemoryIssuerRegistry::default();
    registry.insert(
        derived.issuer_fingerprint.clone(),
        derived.issuer_public_key_hex.clone(),
    );
    let kept = candidates.into_iter().find(|committed| {
        let mut comparable = committed.clone();
        comparable
            .proof_bytes_hex
            .clone_from(&derived.proof_bytes_hex);
        comparable == derived
            && chio_selective_disclosure::verify_selective_disclosure_proof(committed, &registry)
                .is_ok()
    });
    Ok(kept.unwrap_or(derived))
}

pub(super) fn committed_selective_disclosure_proofs(
    root: &Path,
    descriptors: &[ProofFixtureDescriptor],
) -> Result<Vec<chio_selective_disclosure::SelectiveDisclosureProof>, CliError> {
    let mut proofs = Vec::new();
    for descriptor in descriptors {
        let fixture = root.join(installed_fixture_path(descriptor));
        if !fixture.is_dir() {
            continue;
        }
        crate::input::collection::walk_files(&fixture, |path, budget| {
            if path.file_name() == Some(std::ffi::OsStr::new("selective-disclosure-proof.json")) {
                if let Ok(proof) = crate::input::json(&budget.read(path)?) {
                    proofs.push(proof);
                }
            }
            Ok(())
        })?;
    }
    Ok(proofs)
}
