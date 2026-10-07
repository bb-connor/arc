use crate::{common::*, market::*};
use chio_core_types::{
    capability::{scope::Operation, token::CapabilityToken},
    Keypair,
};
use chio_open_market::bidding::*;

#[test]
fn authentication_review_observes_inheritance_and_explicit_anonymous_alternatives() -> Result<()> {
    let input = include_str!("../fixtures/openapi.json");
    let report = crate::review::check_openapi(input)?;
    assert_eq!(
        report
            .iter()
            .map(|v| (v.path.as_str(), v.authentication_required))
            .collect::<Vec<_>>(),
        vec![
            ("/accounts", true),
            ("/health", false),
            ("/refunds", false),
            ("/sessions", true)
        ]
    );
    let mut value: serde_json::Value = serde_json::from_str(input)?;
    value["paths"]["/refunds"]["post"]
        .as_object_mut()
        .ok_or("operation missing")?
        .remove("security");
    let report = crate::review::check_openapi(&serde_json::to_string(&value)?)?;
    assert!(
        report
            .iter()
            .find(|v| v.path == "/refunds")
            .ok_or("refund missing")?
            .authentication_required
    );
    Ok(())
}

#[test]
fn authentication_review_rejects_ambiguous_or_unsupported_security_semantics() -> Result<()> {
    let input = include_str!("../fixtures/openapi.json");
    for (pointer, value) in [
        ("/security", serde_json::json!({})),
        ("/security", serde_json::json!([{"missing":[]}])),
        ("/security", serde_json::json!([{"serviceToken":false}])),
        (
            "/components/securitySchemes/serviceToken",
            serde_json::json!({"$ref":"https://outside.invalid/key"}),
        ),
        (
            "/paths/~1refunds/$ref",
            serde_json::json!("https://outside.invalid/path"),
        ),
        ("/paths/~1refunds/post/callbacks", serde_json::json!({})),
        ("/webhooks", serde_json::json!({})),
    ] {
        let mut doc: serde_json::Value = serde_json::from_str(input)?;
        if let Some(existing) = doc.pointer_mut(pointer) {
            *existing = value;
        } else {
            let (parent, name) = pointer.rsplit_once('/').ok_or("pointer")?;
            let parent = if parent.is_empty() {
                &mut doc
            } else {
                doc.pointer_mut(parent).ok_or("parent")?
            };
            parent
                .as_object_mut()
                .ok_or("object")?
                .insert(name.into(), value);
        }
        assert!(
            crate::review::check_openapi(&serde_json::to_string(&doc)?).is_err(),
            "{pointer}"
        );
    }
    let duplicate = input.replacen(
        "\"openapi\": \"3.1.0\"",
        "\"openapi\": \"3.0.0\", \"openapi\": \"3.1.0\"",
        1,
    );
    assert!(crate::review::check_openapi(&duplicate).is_err());
    Ok(())
}

#[test]
fn buyer_rejects_widened_offers_even_when_provider_resigns_them() -> Result<()> {
    let buyer = Keypair::generate();
    let provider = Keypair::generate();
    let peers = Peers {
        buyer: buyer.public_key(),
        provider: provider.public_key(),
    };
    let agreement = Agreement {
        profile: PROFILE.into(),
        job_id: "review-1".into(),
        input_sha256: "a".repeat(64),
        buyer: buyer.public_key(),
        provider: provider.public_key(),
        price_ceiling: 200,
        deadline: now()? + 600,
        checker: "openapi-explicit-auth-v1".into(),
        subcontracting: false,
        subcontract: None,
        credit_profile: "buyer-local-credit-promise-v1".into(),
    };
    let quote = QuoteRequest {
        subcontract_permit: None,
        bid: make_bid(&agreement, &buyer)?,
        agreement,
    };
    quote.validate(&peers)?;
    let time = quote.bid.body.issued_at;
    let listing = listing(&provider, time)?;
    let ask = bid(
        &quote.bid,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &provider,
            agent_subject: buyer.public_key(),
            token_id: "review-1".into(),
            now: time,
            grant_constraints: vec![],
            dpop_required: Some(true),
        },
    )?;
    verify_ask(&quote, &ask, &provider.public_key())?;
    for case in 0..13 {
        let mut body = ask.body.clone();
        match case {
            0 => body.listing_id = "different-listing".into(),
            1 => body.agent_id = "different-buyer".into(),
            2 => body.bid_digest = "b".repeat(64),
            3 => body.quoted_price.units = 200,
            4 => {
                body.expires_at += 1;
                body.token_offer.expires_at += 1;
            }
            5 => body.token_offer.scope.grants[0].tool_name = "delete".into(),
            6 => body.token_offer.scope.grants[0]
                .operations
                .push(Operation::Delegate),
            7 => body.token_offer.scope.grants[0].dpop_required = None,
            8 => body.token_offer.scope.grants[0].max_total_cost = Some(amount(200)),
            9 => body.token_offer.scope.grants[0].max_invocations = None,
            10 => {
                let grant = body.token_offer.scope.grants[0].clone();
                body.token_offer.scope.grants.push(grant);
            }
            11 => body.token_offer.scope.grants[0].max_cost_per_invocation = Some(amount(200)),
            12 => body.token_offer.subject = provider.public_key(),
            _ => unreachable!(),
        }
        body.token_offer = CapabilityToken::sign(body.token_offer.body(), &provider)?;
        let changed = SignedAskResponse::sign(body, &provider)?;
        assert!(changed.verify_signature()?);
        assert!(changed.body.token_offer.verify_signature()?);
        assert!(
            verify_ask(&quote, &changed, &provider.public_key()).is_err(),
            "case {case}"
        );
    }
    Ok(())
}

#[test]
fn release_vectors_require_exact_joint_authority_and_completed_receipt() -> Result<()> {
    let vectors: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/release-vectors.json"))?;
    let peers: Peers = serde_json::from_value(vectors["peers"].clone())?;
    let valid: crate::resolution::PublicRelease = serde_json::from_value(vectors["valid"].clone())?;
    crate::resolution::verify(&peers, &valid)?;
    for case in vectors["cases"]
        .as_array()
        .ok_or("release cases are absent")?
    {
        let result =
            serde_json::from_value::<crate::resolution::PublicRelease>(case["public"].clone())
                .map_err(|e| -> Error { e.into() })
                .and_then(|public| crate::resolution::verify(&peers, &public));
        assert!(
            result.is_err(),
            "accepted malformed release: {}",
            case["case"]
        );
    }
    Ok(())
}
