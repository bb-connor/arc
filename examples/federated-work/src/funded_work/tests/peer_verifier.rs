use crate::{
    common::{self, Result},
    funded_work::{evidence, peer_verifier as peer},
};
use chio_core_types::{canonical_json_bytes, Keypair};

#[test]
fn authenticated_call_binds_exact_origin_enrollment_and_complete_request() -> Result<()> {
    let (f, enrollment, request) = super::verifier_handoff::fixture()?;
    let origin = "https://verifier.example:8443";
    let body = peer::CallBody {
        schema: peer::SCHEMA.into(),
        origin: origin.into(),
        enrollment_sha256: common::digest(&enrollment)?,
        request,
    };
    let call = evidence::sign(body, &common::key(f.directory.path())?)?;
    let bytes = canonical_json_bytes(&call)?;
    assert_eq!(
        canonical_json_bytes(&peer::authenticate(&bytes, &enrollment, origin)?)?,
        bytes
    );
    assert!(peer::authenticate(&bytes, &enrollment, "https://other.example:8443").is_err());
    let mut changed = enrollment.clone();
    changed.policy.authority_uuid = "changed".into();
    assert!(peer::authenticate(&bytes, &changed, origin).is_err());
    let wrong_signer = evidence::sign(call.body.clone(), &Keypair::generate())?;
    assert!(
        peer::authenticate(&canonical_json_bytes(&wrong_signer)?, &enrollment, origin).is_err()
    );
    for field in ["input", "output", "claim", "observation"] {
        let mut changed = serde_json::to_value(&call)?;
        changed["body"]["request"][field] = serde_json::json!("substitution");
        assert!(
            peer::authenticate(&canonical_json_bytes(&changed)?, &enrollment, origin).is_err(),
            "{field}"
        );
    }
    for raw in [
        [bytes.as_slice(), b"\n"].concat(),
        [b"{\"signature\":\"duplicate\",".as_slice(), &bytes[1..]].concat(),
        vec![b' '; 256 * 1024 + 1],
    ] {
        assert!(peer::authenticate(&raw, &enrollment, origin).is_err());
    }
    Ok(())
}

#[test]
fn bounded_http_response_rejects_redirects_ambiguous_framing_and_truncation() -> Result<()> {
    use crate::funded_work::peer_client::response;
    let good = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}";
    assert_eq!(response(&mut good.as_slice())?, b"{}");
    let text = std::str::from_utf8(good)?;
    for changed in [
        text.replace("200 OK", "307 Temporary Redirect"),
        text.replace(
            "Content-Length: 2",
            "Content-Length: 2\r\nContent-Length: 2",
        ),
        text.replace("Content-Length: 2", "Content-Length: 262145"),
        text.replace("Content-Length: 2", "Content-Length: 02"),
        text.replace("Content-Length: 2", "Transfer-Encoding: chunked"),
        text.replace("Content-Type: application/json", "Content-Encoding: gzip"),
        text.replace(
            "Content-Type: application/json",
            "Content-Type: application/json\r\nContent-Type: application/json",
        ),
        text.replace("{}", "{"),
        "a".repeat(8193),
    ] {
        assert!(response(&mut changed.as_bytes()).is_err());
    }
    Ok(())
}

#[test]
fn authenticated_call_custody_preserves_destination_and_historical_retries() -> Result<()> {
    let (f, _, request) = super::verifier_handoff::fixture()?;
    let allocation = request.submission.body.binding.allocation_id;
    let original = serde_json::json!({"origin":"https://first.example"});
    f.native
        .journal
        .retain_before(&allocation, "verifier-call", &original, &["decision"])?;
    f.native
        .journal
        .retain_before(&allocation, "verifier-call", &original, &["decision"])?;
    assert!(f
        .native
        .journal
        .retain_before(
            &allocation,
            "verifier-call",
            &serde_json::json!({"origin":"https://other.example"}),
            &["decision"]
        )
        .is_err());
    f.native
        .journal
        .retain(&allocation, "decision", &serde_json::json!("retained"))?;
    f.native
        .journal
        .retain_before(&allocation, "verifier-call", &original, &["decision"])?;
    let retained: serde_json::Value = f
        .native
        .journal
        .retained(&allocation, "verifier-call")?
        .ok_or("missing call")?;
    assert_eq!(retained, original);
    Ok(())
}

#[test]
fn service_enrollment_requires_existing_versioned_custody_without_seed() -> Result<()> {
    use crate::funded_work::verifier_operator as operator;
    let (f, enrollment, _) = super::verifier_handoff::fixture()?;
    let missing = f.directory.path().join("missing");
    std::fs::create_dir(&missing)?;
    assert!(operator::enrollment(&missing).is_err());
    assert!(!missing.join(operator::DATABASE).exists());
    let state = f.directory.path().join("verifier");
    operator::initialize(&state, &enrollment)?;
    std::fs::remove_file(state.join("key.seed"))?;
    assert_eq!(
        canonical_json_bytes(&operator::enrollment(&state)?)?,
        canonical_json_bytes(&enrollment)?
    );
    rusqlite::Connection::open(state.join(operator::DATABASE))?
        .execute_batch("PRAGMA user_version=99;")?;
    assert!(operator::enrollment(&state).is_err());
    Ok(())
}
