use super::native::{bind_observation, fixture, native_counts};
#[cfg(unix)]
use crate::funded_work::{child, evidence};
use crate::{
    common::{self, digest, Result},
    funded_work::waiver_terms,
};
use chio_core_types::Keypair;
use chio_kernel::payment::{SignedContractualCaptureWaiverTermsV1, CAPTURE_WAIVER_TERMS_ARGUMENT};
use serde_json::json;
use std::sync::Arc;

#[test]
fn altered_original_waiver_authority_denies_before_reservation() -> Result<()> {
    let mut f = fixture()?;
    let provider = common::key(f.directory.path())?;
    let terms = waiver_terms::authorize(
        &f.native.policy,
        &f.agreement.body.work,
        &mut f.request,
        &provider,
        &f.buyer,
    )?;
    let mut original = f.agreement.body.clone();
    original.capture_waiver_terms = Some(terms.clone());
    original.request_sha256 = digest(&f.request)?;
    f.agreement = original.clone().sign(&f.buyer, &provider)?;
    f.agreement.validate(&f.native.policy, &f.request)?;
    for case in 0..11 {
        let mut request = f.request.clone();
        let mut agreement = original.clone();
        let mut body = terms.body.clone();
        match case {
            0 => body.contract_context_digest = "a".repeat(64),
            1 => body.capability_digest = "a".repeat(64),
            2 => body.request_id = "substituted-request".into(),
            3 => body.policy_digest = "a".repeat(64),
            4 => body.issued_at_unix_ms += 172_800_000,
            5 => body.expires_at_unix_ms += 1,
            _ => {}
        }
        let mut changed = SignedContractualCaptureWaiverTermsV1::sign(body, &provider, &f.buyer)?;
        if case == 6 {
            changed.counterparty_signature = Keypair::generate().sign(b"forged consent");
        }
        if case == 7 {
            changed.receiver_signature = Keypair::generate().sign(b"forged waiver");
        }
        request.arguments[CAPTURE_WAIVER_TERMS_ARGUMENT] = json!(digest(&changed)?);
        agreement.capture_waiver_terms = Some(changed);
        match case {
            8 => agreement.capture_waiver_terms = None,
            9 => request.arguments[CAPTURE_WAIVER_TERMS_ARGUMENT] = json!("a".repeat(64)),
            10 => {
                request
                    .arguments
                    .as_object_mut()
                    .ok_or("request object")?
                    .remove(CAPTURE_WAIVER_TERMS_ARGUMENT);
            }
            _ => {}
        }
        agreement.request_sha256 = digest(&request)?;
        let signed = agreement.sign(&f.buyer, &provider)?;
        assert!(
            signed.validate(&f.native.policy, &request).is_err(),
            "waiver validation accepted case {case}"
        );
        assert!(
            f.native.execute(&signed, &request).is_err(),
            "accepted case {case}"
        );
        assert_eq!(native_counts(&f)?, (0, 0), "reserved for case {case}");
        assert_eq!(f.native.journal.execution_count()?, 0);
    }
    bind_observation(&f.source, &f.agreement)?;
    assert_eq!(f.native.execute(&f.agreement, &f.request)?["executions"], 1);
    Ok(())
}

#[test]
fn legacy_funding_cannot_acquire_a_waiver_after_execution() -> Result<()> {
    let f = fixture()?;
    f.native.execute(&f.agreement, &f.request)?;
    let before = f.native.report(&f.request)?;
    let checkpoint: crate::funded_work::Checkpoint = Arc::new(|_| Ok(()));
    let error = crate::funded_work::capture_resolution::resolve(
        f.directory.path(),
        &f.native,
        &f.request,
        &checkpoint,
    )
    .err()
    .ok_or("legacy agreement acquired waiver authority")?;
    assert!(error
        .to_string()
        .contains("did not authorize capture waiver"));
    assert_eq!(f.native.report(&f.request)?, before);
    assert_eq!(native_counts(&f)?, (1, 1));
    Ok(())
}

#[cfg(unix)]
#[test]
fn substituted_dependency_denies_before_opening_the_child_kernel() -> Result<()> {
    let parent = fixture()?;
    let child_fixture = fixture()?;
    let parent_key = common::key(parent.directory.path())?;
    let child_key = common::key(child_fixture.directory.path())?;
    let mut child_agreement = child_fixture.agreement.body.clone();
    child_agreement.buyer_key = parent_key.public_key();
    let child_agreement = child_agreement.sign(&parent_key, &child_key)?;
    let body = json!({
        "schema":"chio.experimental.native-funded-dependency.v1",
        "parentAgreement":digest(&parent.agreement)?,
        "childAgreement":digest(&child_agreement)?,
        "parentRequest":digest(&parent.request)?,
        "childRequest":digest(&child_fixture.request)?,
        "parentAuthority":parent.native.policy.authority_uuid,
        "childAuthority":child_fixture.native.policy.authority_uuid,
        "inputSha256":chio_core_types::sha256_hex(parent.request.arguments["input"].as_str().ok_or("input")?.as_bytes()),
    });
    let root = tempfile::tempdir()?;
    for (role, agreement, request) in [
        ("parent", &parent.agreement, &parent.request),
        ("child", &child_agreement, &child_fixture.request),
    ] {
        std::fs::create_dir(root.path().join(role))?;
        write(
            root.path().join(role).join("original-agreement.json"),
            agreement,
        )?;
        write(
            root.path().join(role).join("original-request.json"),
            request,
        )?;
    }
    let fields = [
        "schema",
        "parentAgreement",
        "childAgreement",
        "parentRequest",
        "childRequest",
        "parentAuthority",
        "childAuthority",
        "inputSha256",
    ];
    for case in 0..=fields.len() {
        let mut changed = body.clone();
        if let Some(field) = fields.get(case) {
            changed[*field] = json!("substituted");
        }
        let mut signed = evidence::sign(
            serde_json::from_value::<child::Dependency>(changed)?,
            &parent_key,
        )?;
        if case == fields.len() {
            signed.signature = Keypair::generate().sign(b"substituted signature");
        }
        write(root.path().join("dependency.json"), &signed)?;
        assert!(
            child::executor(
                root.path(),
                child_fixture.source.clone(),
                Arc::new(|_| Ok(()))
            )
            .is_err(),
            "accepted changed dependency {case}"
        );
        assert_eq!(native_counts(&parent)?, (0, 0));
        assert_eq!(native_counts(&child_fixture)?, (0, 0));
    }
    let signed = evidence::sign(
        serde_json::from_value::<child::Dependency>(body)?,
        &parent_key,
    )?;
    write(root.path().join("dependency.json"), &signed)?;
    let execute = child::executor(
        root.path(),
        child_fixture.source.clone(),
        Arc::new(|_| Ok(())),
    )?;
    let error = execute("substituted input")
        .err()
        .ok_or("accepted changed child input")?;
    assert!(error
        .to_string()
        .contains("substituted the agreed subcontract input"));
    assert_eq!(native_counts(&child_fixture)?, (0, 0));
    Ok(())
}

#[cfg(unix)]
fn write(path: std::path::PathBuf, value: &impl serde::Serialize) -> Result<()> {
    std::fs::write(path, chio_core_types::canonical_json_bytes(value)?)?;
    Ok(())
}
