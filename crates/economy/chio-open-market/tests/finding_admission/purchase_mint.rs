//! Purchase mint and accept bind the delivery grant to the signed finding and committed terms.

use super::*;

pub(crate) fn purchase_mint_context<'a>(
    listing: &'a Listing,
    operator: &'a Keypair,
    agent: &Keypair,
) -> BidMintContext<'a> {
    BidMintContext {
        listing,
        issuer_keypair: operator,
        agent_subject: agent.public_key(),
        token_id: "finding-token-0002".to_string(),
        now: NOW,
        grant_constraints: Vec::new(),
        dpop_required: None,
    }
}

pub(crate) fn signed_purchase_ask(
    web: &Web,
    resolver: &FiscalResolver<'_>,
    agent: &Keypair,
    price_units: u64,
) -> VerifiedFindingPurchaseAsk {
    let witness =
        verify_finding_admission(&web.admission, &web.context(resolver)).test_expect("admission");
    let expected_scope = format!("finding:{}", web.finding.finding_id);
    let listing = finding_listing_entry(&web.operator, &web.finding, &expected_scope, price_units);
    let request = SignedBidRequest::sign(finding_bid_request(&web.finding, price_units), agent)
        .test_expect("sign purchase bid");
    bid_with_finding_purchase(
        &request,
        purchase_mint_context(&listing, &web.operator, agent),
        &witness,
        &web.finding,
    )
    .test_expect("purchase mint")
}

#[test]
fn purchase_mint_authors_the_delivery_committed_grant() {
    with_fiscal(|resolver| {
        let web = base_web();
        let agent = keypair(31);
        let ask = signed_purchase_ask(&web, resolver, &agent, 900);

        let grant = &ask.body.token_offer.scope.grants[0];
        assert_eq!(grant.max_invocations, Some(1));
        assert_eq!(grant.dpop_required, Some(true));
        assert_eq!(grant.constraints.len(), 2);
        assert!(grant.constraints.iter().any(|constraint| matches!(
            constraint,
            chio_open_market::capability::scope::Constraint::OutputDigestSha256(digest)
                if digest == &web.finding.payload_sha256
        )));
        assert!(grant.constraints.iter().any(|constraint| matches!(
            constraint,
            chio_open_market::capability::scope::Constraint::RequireFindingPurchase(marker)
                if marker.finding_id == web.finding.finding_id
                    && marker.listing_id == FINDING_LISTING_ID
        )));
    });
}

#[test]
fn purchase_mint_rejects_a_preoccupied_context_and_bad_cardinality() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let expected_scope = format!("finding:{}", web.finding.finding_id);
        let listing = finding_listing_entry(&web.operator, &web.finding, &expected_scope, 900);
        let agent = keypair(31);
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign purchase bid");

        let mut preoccupied = purchase_mint_context(&listing, &web.operator, &agent);
        preoccupied.dpop_required = Some(false);
        assert_eq!(
            bid_with_finding_purchase(&request, preoccupied, &witness, &web.finding).err(),
            Some(FindingAdmissionError::MintContextPreoccupied)
        );

        let mut multi = finding_bid_request(&web.finding, 900);
        multi.requested_scope.max_invocations = Some(2);
        let multi = SignedBidRequest::sign(multi, &agent).test_expect("sign multi bid");
        assert_eq!(
            bid_with_finding_purchase(
                &multi,
                purchase_mint_context(&listing, &web.operator, &agent),
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::InvocationCardinality)
        );
    });
}

#[test]
fn purchase_mint_rechecks_finding_liveness_at_the_mint_clock() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let expected_scope = format!("finding:{}", web.finding.finding_id);
        let listing = finding_listing_entry(&web.operator, &web.finding, &expected_scope, 900);
        let agent = keypair(31);
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign purchase bid");

        for (mint_now, expected) in [
            (
                web.finding.issued_at - 1,
                FindingAdmissionError::FindingNotYetLive,
            ),
            (
                web.finding.expires_at,
                FindingAdmissionError::FindingExpired,
            ),
        ] {
            let mut context = purchase_mint_context(&listing, &web.operator, &agent);
            context.now = mint_now;
            let result = bid_with_finding_purchase(&request, context, &witness, &web.finding);
            assert_eq!(result.err(), Some(expected), "mint clock {mint_now}");
        }
    });
}

#[test]
fn purchase_mint_rejects_a_modified_signed_finding() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let scope = format!("finding:{}", web.finding.finding_id);
        let listing = finding_listing_entry(&web.operator, &web.finding, &scope, 900);
        let agent = keypair(31);
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign purchase bid");
        let mut modified = web.finding.clone();
        modified.payload_sha256 = hex64('f');

        assert!(matches!(
            bid_with_finding_purchase(
                &request,
                purchase_mint_context(&listing, &web.operator, &agent),
                &witness,
                &modified,
            ),
            Err(FindingAdmissionError::FindingArtifact(_))
        ));
    });
}

#[test]
fn purchase_accept_requires_exact_amounts_and_the_committed_profile() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let agent = keypair(31);
        let ask = signed_purchase_ask(&web, resolver, &agent, 900);
        let reservation_authority = keypair(41);
        let sign_reservation = |units: u64| {
            let ask_digest = chio_open_market::crypto::sha256_hex(
                &chio_open_market::canonical_json_bytes(&ask.body).test_expect("ask bytes"),
            );
            let receipt = chio_open_market::bidding::ReservationReceipt {
                schema: chio_open_market::bidding::RESERVATION_RECEIPT_SCHEMA.to_string(),
                receipt_id: "reservation-0001".to_string(),
                agent_id: "buyer-agent-7".to_string(),
                listing_id: FINDING_LISTING_ID.to_string(),
                ask_digest,
                reserved_amount: usd(units),
            };
            let signed = chio_open_market::bidding::SignedReservationReceipt::sign(
                receipt,
                &reservation_authority,
            )
            .test_expect("sign reservation");
            chio_open_market::bidding::VerifiedReservationReceipt::from_signed(
                &signed,
                &reservation_authority.public_key(),
            )
            .test_expect("verify reservation")
        };

        let accepted = accept_finding_purchase(
            &ask,
            &sign_reservation(900),
            &agent,
            NOW + 60,
            &witness,
            &web.finding,
        )
        .test_expect("exact purchase accept");
        assert_eq!(accepted.body.quoted_price, usd(900));
        assert_eq!(accepted.body.bid_receipt_id, "reservation-0001");

        assert_eq!(
            accept_finding_purchase(
                &ask,
                &sign_reservation(900),
                &agent,
                witness.expires_at(),
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::AdmissionExpired),
            "an ask cannot outlive the admission that authorized its mint"
        );
        assert_eq!(
            accept_finding_purchase(
                &ask,
                &sign_reservation(900),
                &agent,
                web.finding.expires_at,
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::FindingExpired),
            "an ask cannot outlive the signed Finding"
        );

        let mut modified = web.finding.clone();
        modified.expires_at = modified.expires_at.saturating_add(1);
        assert!(matches!(
            accept_finding_purchase(
                &ask,
                &sign_reservation(900),
                &agent,
                NOW + 60,
                &witness,
                &modified,
            ),
            Err(FindingAdmissionError::FindingArtifact(_))
        ));

        assert_eq!(
            accept_finding_purchase(
                &ask,
                &sign_reservation(1_000),
                &agent,
                NOW + 60,
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::AmountMismatch),
            "an oversized reservation must not mask a mispriced purchase"
        );
    });
}
