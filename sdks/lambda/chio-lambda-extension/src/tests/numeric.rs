use super::*;

const SIGNED_INPUT: &str = "urn:chio:error:attest:signed-json-invalid-input";

#[test]
fn unsigned_envelope_numbers_keep_document_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let capability = signed_capability(&issuer);
    let token = serde_json::to_string(&capability)?;
    for (number, expected) in [
        ("10.50", 10.5),
        ("1e3", 1000.0),
        ("1E-7", 1e-7),
        ("0.250", 0.25),
    ] {
        for field in ["arguments", "metadata"] {
            for credential in [
                format!(r#", "capability":{token}"#),
                String::new(),
                r#", "capability":null"#.into(),
            ] {
                let body = format!(
                    r#"{{"capability_id":"cap","tool_server":"srv","tool_name":"tool","{field}":{{"amount":{number}}}{credential}}}"#
                );
                let request = decode_evaluate_request(body.as_bytes())?;
                let observed = if field == "arguments" {
                    request.arguments.as_ref()
                } else {
                    request.metadata.as_ref()
                };
                assert_eq!(
                    observed.and_then(|value| value["amount"].as_f64()),
                    Some(expected)
                );
                if request.capability.is_some() {
                    assert!(resolve_capability(&request)?.verify_signature_at(FIXTURE_NOW_SECS)?);
                    assert_eq!(
                        decode_evaluate_request(exponent_issued_at(&body).as_bytes()).err(),
                        Some(format!("failed to decode evaluate request: {SIGNED_INPUT}"))
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn unsigned_envelope_members_still_refuse_duplicate_keys() {
    for field in ["arguments", "metadata"] {
        let body = format!(
            r#"{{"tool_server":"srv","tool_name":"tool","{field}":{{"amount":10.50,"amount":1e3}}}}"#
        );
        assert_eq!(
            decode_evaluate_request(body.as_bytes()).err(),
            Some(format!("failed to decode evaluate request: {SIGNED_INPUT}"))
        );
    }
}

fn exponent_issued_at(json: &str) -> String {
    let member = r#""issued_at":1,"#;
    assert_eq!(json.matches(member).count(), 1);
    json.replacen(member, r#""issued_at":1e0,"#, 1)
}

#[test]
fn body_refuses_non_writer_numeric_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let capability = signed_capability(&issuer);
    assert!(capability.verify_signature_at(FIXTURE_NOW_SECS)?);
    let body = serde_json::json!({
        "capability_id": "cap",
        "tool_server": "srv",
        "tool_name": "tool",
        "capability": capability,
    })
    .to_string();
    let request = decode_evaluate_request(body.as_bytes())?;
    assert!(resolve_capability(&request)?.verify_signature_at(FIXTURE_NOW_SECS)?);
    assert_eq!(
        decode_evaluate_request(exponent_issued_at(&body).as_bytes()).err(),
        Some(format!("failed to decode evaluate request: {SIGNED_INPUT}"))
    );
    Ok(())
}

#[test]
fn header_refuses_non_writer_numeric_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let capability = signed_capability(&issuer);
    assert!(capability.verify_signature_at(FIXTURE_NOW_SECS)?);
    let token = serde_json::to_string(&capability)?;
    let bare = br#"{"tool_server":"srv","tool_name":"tool"}"#;
    let mut headers = hyper::HeaderMap::new();
    headers.insert("x-chio-capability", token.parse()?);
    let mut request = decode_evaluate_request(bare)?;
    hydrate_request_from_headers(&headers, &mut request)?;
    assert_eq!(request.capability_id, "cap");
    assert!(resolve_capability(&request)?.verify_signature_at(FIXTURE_NOW_SECS)?);

    headers.insert("x-chio-capability", exponent_issued_at(&token).parse()?);
    for id in ["cap", ""] {
        let mut request = decode_evaluate_request(bare)?;
        request.capability_id = id.into();
        assert_eq!(
            hydrate_request_from_headers(&headers, &mut request).err(),
            Some(format!("invalid x-chio-capability JSON: {SIGNED_INPUT}"))
        );
        assert!(request.capability.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn configured_tokens_refuse_non_writer_numeric_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let capability = signed_capability(&issuer);
    assert!(capability.verify_signature_at(FIXTURE_NOW_SECS)?);
    let token = serde_json::to_string(&capability)?;
    let mut request = request_for(&capability);
    request.capability = None;
    let configured = format!(r#"{{"cap":{token}}}"#);
    let resolved = with_env_var(CAPABILITY_TOKENS_ENV, &configured, async {
        resolve_capability(&request)
    })
    .await?;
    assert!(resolved.verify_signature_at(FIXTURE_NOW_SECS)?);

    let configured = exponent_issued_at(&configured);
    let result = with_env_var(CAPABILITY_TOKENS_ENV, &configured, async {
        resolve_capability(&request)
    })
    .await;
    assert_eq!(
        result.err(),
        Some(format!("invalid {CAPABILITY_TOKENS_ENV}: {SIGNED_INPUT}"))
    );
    Ok(())
}
