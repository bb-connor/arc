use crate::{common::*, market::*};
use chio_core_types::{
    capability::{scope::Operation, token::CapabilityToken},
    Keypair,
};
use chio_open_market::bidding::*;

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
        credit_profile: "buyer-local-credit-promise-v1".into(),
    };
    let quote = QuoteRequest {
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
