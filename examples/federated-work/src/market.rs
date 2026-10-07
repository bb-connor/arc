use crate::common::*;
use chio_core_types::{Keypair, PublicKey};
use chio_open_market::{bidding::*, capability::scope::MonetaryAmount, listing::*};
use serde::{Deserialize, Serialize};

pub fn listing(provider: &Keypair, now: u64) -> Result<Listing> {
    let namespace = "https://security-review.example".to_string();
    let ownership = GenericNamespaceOwnership {
        namespace: namespace.clone(),
        owner_id: "review-provider".into(),
        owner_name: None,
        registry_url: namespace.clone(),
        signer_public_key: provider.public_key(),
        registered_at: now,
        transferred_from_owner_id: None,
    };
    let body = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.into(),
        listing_id: "security-review-v1".into(),
        namespace: namespace.clone(),
        published_at: now,
        expires_at: Some(now + 3600),
        status: GenericListingStatus::Active,
        namespace_ownership: ownership,
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: SERVER.into(),
            display_name: None,
            metadata_url: None,
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: PROFILE.into(),
            source_artifact_id: "openapi-explicit-auth-v1".into(),
            source_artifact_sha256: chio_core_types::sha256_hex(b"openapi-explicit-auth-v1"),
        },
        boundary: GenericListingBoundary::default(),
    };
    let pricing = ListingPricingHint {
        schema: LISTING_PRICING_HINT_SCHEMA.into(),
        listing_id: body.listing_id.clone(),
        namespace: namespace.clone(),
        provider_operator_id: "review-provider".into(),
        capability_scope: "tools:security-review".into(),
        price_per_call: amount(100),
        sla: ListingSla {
            max_latency_ms: 1000,
            availability_bps: 9900,
            throughput_rps: 1,
        },
        revocation_rate_bps: 0,
        recent_receipts_volume: 0,
        issued_at: now,
        expires_at: now + 3600,
    };
    Ok(Listing {
        rank: 1,
        listing: SignedGenericListing::sign(body, provider)?,
        pricing: SignedListingPricingHint::sign(pricing, provider)?,
        publisher: GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: "review-provider".into(),
            operator_name: None,
            registry_url: namespace,
            upstream_registry_urls: Vec::new(),
        },
        freshness: GenericListingReplicaFreshness {
            state: GenericListingFreshnessState::Fresh,
            age_secs: 0,
            max_age_secs: 300,
            valid_until: now + 300,
            generated_at: now,
        },
    })
}

pub fn amount(units: u64) -> MonetaryAmount {
    // Experimental accounting units, never an external currency balance.
    MonetaryAmount {
        units,
        currency: "TST".into(),
    }
}

pub fn make_bid(agreement: &Agreement, buyer: &Keypair) -> Result<SignedBidRequest> {
    let time = now()?;
    Ok(SignedBidRequest::sign(
        BidRequest {
            schema: BID_REQUEST_SCHEMA.into(),
            agent_id: buyer.public_key().to_hex(),
            payout_destination: None,
            listing_id: "security-review-v1".into(),
            max_price_per_call: amount(agreement.price_ceiling),
            window_seconds: agreement
                .deadline
                .checked_sub(time)
                .ok_or("agreement expired")?,
            requested_scope: RequestedScope {
                server_id: SERVER.into(),
                tool_name: "review".into(),
                max_invocations: Some(1),
                capability_scope_prefix: format!("tools:security-review:{}", digest(agreement)?),
            },
            issued_at: time,
        },
        buyer,
    )?)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuoteRequest {
    pub agreement: Agreement,
    pub bid: SignedBidRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subcontract_permit: Option<crate::subcontract::permit::SignedPermit>,
}

impl QuoteRequest {
    pub fn validate(&self, peers: &Peers) -> Result<()> {
        validate_agreement(&self.agreement, peers)?;
        if let Some(permit) = &self.subcontract_permit {
            crate::subcontract::permit::verify(permit, &self.agreement, &permit.signer_key, None)?;
        }
        let bid = &self.bid;
        bid.body.validate()?;
        if bid.signer_key != peers.buyer
            || !bid.verify_signature()?
            || bid.body.agent_id != peers.buyer.to_hex()
            || bid.body.listing_id != "security-review-v1"
            || bid.body.payout_destination.is_some()
            || bid.body.issued_at.checked_add(bid.body.window_seconds)
                != Some(self.agreement.deadline)
            || bid.body.max_price_per_call != amount(self.agreement.price_ceiling)
            || bid.body.requested_scope.server_id != SERVER
            || bid.body.requested_scope.tool_name != "review"
            || bid.body.requested_scope.max_invocations != Some(1)
            || bid.body.requested_scope.capability_scope_prefix
                != format!("tools:security-review:{}", digest(&self.agreement)?)
        {
            return Err("bid does not bind the agreed job".into());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Acceptance {
    pub quote: QuoteRequest,
    pub ask: SignedAskResponse,
    pub reservation: SignedReservationReceipt,
    pub accepted: SignedAcceptedBid,
}

pub const ACK_SCHEMA: &str = "chio.example.work-acknowledgement.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Acknowledgement {
    pub schema: String,
    pub job_id: String,
    pub agreement_sha256: String,
    pub accepted_bid_sha256: String,
    pub state: String,
    pub work_executed: bool,
    pub settled: bool,
}

impl Acceptance {
    pub fn verify(&self, peers: &Peers) -> Result<()> {
        self.quote.validate(peers)?;
        let reservation = VerifiedReservationReceipt::from_signed(&self.reservation, &peers.buyer)?;
        verify_acceptance(
            &self.accepted,
            &self.ask,
            &reservation,
            &peers.provider,
            &peers.buyer,
        )?;
        verify_ask(&self.quote, &self.ask, &peers.provider)?;
        Ok(())
    }
}

pub fn verify_ask(
    quote: &QuoteRequest,
    ask: &SignedAskResponse,
    provider: &PublicKey,
) -> Result<()> {
    if &ask.signer_key != provider
        || !ask.verify_signature()?
        || ask.body.schema != ASK_RESPONSE_SCHEMA
        || ask.body.listing_id != quote.bid.body.listing_id
        || ask.body.agent_id != quote.bid.body.agent_id
        || ask.body.bid_digest != digest(&quote.bid.body)?
        || ask.body.token_offer.issuer != *provider
        || !ask.body.token_offer.verify_signature()?
        || ask.body.token_offer.subject != quote.bid.signer_key
        || ask.body.quoted_price != amount(100)
        || ask.body.expires_at > quote.agreement.deadline
        || ask.body.issued_at < quote.bid.body.issued_at
        || ask.body.expires_at <= ask.body.issued_at
        || ask.body.token_offer.issued_at != ask.body.issued_at
        || ask.body.token_offer.expires_at != ask.body.expires_at
        || !ask.body.token_offer.delegation_chain.is_empty()
        || !ask.body.token_offer.caveats.is_empty()
        || ask.body.token_offer.scope_attenuations.is_some()
        || ask.body.token_offer.attenuation_proof.is_some()
        || ask.body.token_offer.budget_share_bps.is_some()
        || ask.body.token_offer.aggregate_invocation_budget.is_some()
        || !ask.body.token_offer.scope.resource_grants.is_empty()
        || !ask.body.token_offer.scope.prompt_grants.is_empty()
        || ask.body.token_offer.scope.grants.len() != 1
    {
        return Err("offer differs from buyer's pinned agreement".into());
    }
    let grant = &ask.body.token_offer.scope.grants[0];
    if grant.server_id != SERVER
        || grant.tool_name != "review"
        || grant.max_invocations != Some(1)
        || grant.operations != vec![chio_core_types::capability::scope::Operation::Invoke]
        || !grant.constraints.is_empty()
        || grant.dpop_required != Some(true)
        || grant.max_total_cost != Some(amount(100))
        || grant.max_cost_per_invocation != Some(amount(100))
    {
        return Err("offer changes authorized work or liability".into());
    }
    Ok(())
}
