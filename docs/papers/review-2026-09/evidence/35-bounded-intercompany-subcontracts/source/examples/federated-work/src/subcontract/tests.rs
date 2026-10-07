use super::*;
use chio_core_types::{receipt::lineage::SignedExportEnvelope, Keypair};

fn vectors() -> Result<Value> {
    Ok(serde_json::from_slice(include_bytes!(
        "../../fixtures/subcontract-vectors.json"
    ))?)
}

#[test]
fn disclosure_reconstructs_authentication_without_nested_private_data() -> Result<()> {
    let mut doc: Value = serde_json::from_str(include_str!("../../fixtures/openapi.json"))?;
    doc["info"] = json!({"private":"secret"});
    doc["paths"]["/accounts"]["get"]["description"] = json!("secret");
    doc["components"]["securitySchemes"]["serviceToken"]["description"] = json!("secret");
    let projected = project(
        &serde_json::to_string(&doc)?,
        &["/accounts".into(), "/refunds".into()],
    )?;
    assert_eq!(
        serde_json::from_str::<Value>(&projected)?,
        json!({"openapi":"3.1.0", "paths":{
        "/accounts":{"get":{"security":[{"serviceToken":[]}]}}, "/refunds":{"post":{"security":[]}}},
        "components":{"securitySchemes":{"serviceToken":{"type":"http","scheme":"bearer"}}}})
    );
    assert!(!projected.contains("secret"));
    let fixture = vectors()?;
    let request: review::ReviewRequest = serde_json::from_value(fixture["request"].clone())?;
    assert_eq!(projected, disclosure(&request)?);
    Ok(())
}

#[test]
fn four_keys_and_exact_disclosure_are_required() -> Result<()> {
    let fixture = vectors()?;
    let request: review::ReviewRequest = serde_json::from_value(fixture["request"].clone())?;
    let parent = request.acceptance.quote.agreement;
    let policy = parent.subcontract.as_ref().ok_or("policy missing")?;
    for (delegate, specialist) in [
        (parent.buyer.clone(), policy.specialist.clone()),
        (parent.provider.clone(), policy.specialist.clone()),
        (policy.specialist.clone(), policy.specialist.clone()),
        (policy.delegate.clone(), parent.buyer.clone()),
        (policy.delegate.clone(), parent.provider.clone()),
    ] {
        let mut changed = parent.clone();
        let policy = changed.subcontract.as_mut().ok_or("policy missing")?;
        policy.delegate = delegate;
        policy.specialist = specialist;
        assert!(child_agreement(&changed).is_err());
    }
    for paths in [
        vec![],
        vec!["/refunds".into(), "/accounts".into()],
        vec!["/accounts".into(), "/accounts".into()],
        vec!["relative".into()],
    ] {
        let mut changed = parent.clone();
        changed.subcontract.as_mut().ok_or("policy missing")?.paths = paths;
        assert!(child_agreement(&changed).is_err());
    }
    let mut another = parent.clone();
    another.job_id = "another-parent".into();
    assert_ne!(
        child_agreement(&parent)?.job_id,
        child_agreement(&another)?.job_id
    );
    Ok(())
}

#[test]
fn even_valid_promisor_signatures_cannot_widen_the_exact_procurement() -> Result<()> {
    let fixture = vectors()?;
    let request: review::ReviewRequest = serde_json::from_value(fixture["request"].clone())?;
    let child = child_agreement(&request.acceptance.quote.agreement)?;
    let body = permit::terms(&request)?;
    let signer = Keypair::generate();
    let signed = SignedExportEnvelope::sign(body.clone(), &signer)?;
    permit::verify(
        &signed,
        &child,
        &signer.public_key(),
        Some(body.expires_at - 1),
    )?;
    assert!(permit::verify(&signed, &child, &signer.public_key(), Some(body.expires_at)).is_err());
    for case in 0..8 {
        let mut altered = body.clone();
        match case {
            0 => altered.parent_agreement_sha256 = "b".repeat(64),
            1 => altered.child_agreement_sha256 = "b".repeat(64),
            2 => altered.delegate = signer.public_key(),
            3 => altered.specialist = signer.public_key(),
            4 => altered.price_ceiling = 200,
            5 => altered.currency = "USD".into(),
            6 => altered.expires_at += 1,
            7 => altered.parent_request_sha256 = "A".repeat(64),
            _ => unreachable!(),
        }
        let altered = SignedExportEnvelope::sign(altered, &signer)?;
        assert!(altered.verify_signature()?);
        assert!(
            permit::verify(&altered, &child, &signer.public_key(), None).is_err(),
            "case {case}"
        );
    }
    assert!(permit::verify(&signed, &child, &Keypair::generate().public_key(), None).is_err());
    Ok(())
}

#[test]
fn parent_signature_cannot_replace_specialist_evidence() -> Result<()> {
    let fixture = vectors()?;
    let request: review::ReviewRequest = serde_json::from_value(fixture["request"].clone())?;
    review::verify_report(&request, &serde_json::from_value(fixture["valid"].clone())?)?;
    for case in fixture["cases"].as_array().ok_or("no adversarial cases")? {
        let raw: SignedExportEnvelope<Value> = serde_json::from_value(case["report"].clone())?;
        assert!(raw.verify_signature()?);
        let report: review::SignedReport = serde_json::from_value(case["report"].clone())?;
        assert!(
            review::verify_report(&request, &report).is_err(),
            "{}",
            case["case"]
        );
    }
    Ok(())
}
