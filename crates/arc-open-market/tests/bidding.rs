//! Integration coverage for the capability marketplace bid/ask protocol.

use arc_open_market::{
    accept, bid, canonical_json_bytes,
    capability::MonetaryAmount,
    crypto::Keypair,
    listing::{
        GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
        GenericListingCompatibilityReference, GenericListingFreshnessState,
        GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
        GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole, Listing,
        ListingPricingHint, ListingSla, SignedGenericListing, SignedListingPricingHint,
        GENERIC_LISTING_ARTIFACT_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    },
    BidMintContext, BidRequest, BiddingError, RequestedScope, ACCEPTED_BID_SCHEMA,
    ASK_RESPONSE_SCHEMA, BID_REQUEST_SCHEMA,
};

fn namespace(keypair: &Keypair) -> GenericNamespaceOwnership {
    GenericNamespaceOwnership {
        namespace: "https://registry.arc.example".to_string(),
        owner_id: "operator-a".to_string(),
        owner_name: Some("Operator A".to_string()),
        registry_url: "https://registry.arc.example".to_string(),
        signer_public_key: keypair.public_key(),
        registered_at: 1,
        transferred_from_owner_id: None,
    }
}

fn signed_listing(
    keypair: &Keypair,
    listing_id: &str,
    status: GenericListingStatus,
) -> SignedGenericListing {
    let body = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: listing_id.to_string(),
        namespace: "https://registry.arc.example".to_string(),
        published_at: 10,
        expires_at: Some(5_000),
        status,
        namespace_ownership: namespace(keypair),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: format!("server-{listing_id}"),
            display_name: None,
            metadata_url: None,
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "arc.certify.check.v1".to_string(),
            source_artifact_id: format!("artifact-{listing_id}"),
            source_artifact_sha256: format!("sha-{listing_id}"),
        },
        boundary: GenericListingBoundary::default(),
    };
    SignedGenericListing::sign(body, keypair).expect("sign listing")
}

fn publisher() -> GenericRegistryPublisher {
    GenericRegistryPublisher {
        role: GenericRegistryPublisherRole::Origin,
        operator_id: "operator-a".to_string(),
        operator_name: Some("Operator A".to_string()),
        registry_url: "https://operator-a.arc.example".to_string(),
        upstream_registry_urls: Vec::new(),
    }
}

fn fresh() -> GenericListingReplicaFreshness {
    GenericListingReplicaFreshness {
        state: GenericListingFreshnessState::Fresh,
        age_secs: 20,
        max_age_secs: 300,
        valid_until: 1_000,
        generated_at: 100,
    }
}

fn pricing_hint(
    operator: &Keypair,
    listing_id: &str,
    units: u64,
    issued_at: u64,
    expires_at: u64,
) -> SignedListingPricingHint {
    SignedListingPricingHint::sign(
        ListingPricingHint {
            schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
            listing_id: listing_id.to_string(),
            namespace: "https://registry.arc.example".to_string(),
            provider_operator_id: "operator-a".to_string(),
            capability_scope: "tools:search".to_string(),
            price_per_call: MonetaryAmount {
                units,
                currency: "USD".to_string(),
            },
            sla: ListingSla {
                max_latency_ms: 200,
                availability_bps: 9_995,
                throughput_rps: 100,
            },
            revocation_rate_bps: 5,
            recent_receipts_volume: 2_500,
            issued_at,
            expires_at,
        },
        operator,
    )
    .expect("sign hint")
}

fn listing_entry(
    registry_keypair: &Keypair,
    operator_keypair: &Keypair,
    status: GenericListingStatus,
    price_units: u64,
    pricing_expires_at: u64,
) -> Listing {
    Listing {
        rank: 1,
        listing: signed_listing(registry_keypair, "listing-1", status),
        pricing: pricing_hint(
            operator_keypair,
            "listing-1",
            price_units,
            110,
            pricing_expires_at,
        ),
        publisher: publisher(),
        freshness: fresh(),
    }
}

fn bid_request(agent_id: &str, max_units: u64, window_seconds: u64, now: u64) -> BidRequest {
    BidRequest {
        schema: BID_REQUEST_SCHEMA.to_string(),
        agent_id: agent_id.to_string(),
        listing_id: "listing-1".to_string(),
        max_price_per_call: MonetaryAmount {
            units: max_units,
            currency: "USD".to_string(),
        },
        window_seconds,
        requested_scope: RequestedScope {
            server_id: "demo-server".to_string(),
            tool_name: "search".to_string(),
            max_invocations: Some(10),
            capability_scope_prefix: "tools:search".to_string(),
        },
        issued_at: now,
    }
}

#[test]
fn bid_happy_path_mints_token_and_accept_records_settlement() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = Keypair::generate();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = bid_request("agent-alpha", 200, 600, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
        },
    )
    .expect("bid succeeds");

    assert_eq!(ask.body.schema, ASK_RESPONSE_SCHEMA);
    assert_eq!(ask.body.quoted_price.units, 100);
    assert!(ask.verify_signature().expect("verify ask"));

    let accepted = accept(&ask, "receipt-from-settlement", 130).expect("accept succeeds");
    assert_eq!(accepted.schema, ACCEPTED_BID_SCHEMA);
    assert_eq!(accepted.bid_receipt_id, "receipt-from-settlement");
    assert_eq!(accepted.quoted_price.units, 100);

    // The AcceptedBid body is canonical-JSON signable.
    let bytes = canonical_json_bytes(&accepted).expect("canonical accepted bytes");
    assert!(!bytes.is_empty());
}

#[test]
fn bid_fails_closed_on_stale_listing_freshness() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = Keypair::generate();
    let agent_keypair = Keypair::generate();
    let mut listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    listing.freshness.state = GenericListingFreshnessState::Stale;
    let request = bid_request("agent-alpha", 200, 300, 120);
    let error = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
        },
    )
    .expect_err("stale listing rejected");
    assert_eq!(error, BiddingError::ListingStale);
}

#[test]
fn bid_fails_closed_on_revoked_listing() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = Keypair::generate();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Revoked,
        100,
        600,
    );
    let request = bid_request("agent-alpha", 200, 300, 120);
    let error = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
        },
    )
    .expect_err("revoked listing rejected");
    assert_eq!(error, BiddingError::ListingNotActive);
}

#[test]
fn bid_refuses_mismatched_listing_id() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = Keypair::generate();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let mut request = bid_request("agent-alpha", 200, 300, 120);
    request.listing_id = "listing-999".to_string();

    let error = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
        },
    )
    .expect_err("mismatched listing rejected");
    assert_eq!(error, BiddingError::ListingMismatch);
}

#[test]
fn accept_refuses_empty_bid_receipt_id() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = Keypair::generate();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = bid_request("agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
        },
    )
    .expect("bid succeeds");
    let error = accept(&ask, "", 130).expect_err("empty receipt rejected");
    matches!(error, BiddingError::InvalidRequest(_));
}
