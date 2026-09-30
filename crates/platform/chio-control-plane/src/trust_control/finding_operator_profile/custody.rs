//! Partial and complete profile decoding retains wiping ownership of secrets.
use super::*;
use zeroize::Zeroize;

struct SecretText(String);
impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        String::deserialize(input).map(Self)
    }
}
impl SecretText {
    fn into_owned(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}
impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        {
            assert!(self.0.is_empty());
            WIPED.with(|count| count.set(count.get() + 1));
        }
    }
}
#[cfg(test)]
std::thread_local! { static WIPED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BuyerClientProfileCustody {
    schema: String,
    endpoint: String,
    market: FindingMarketConfig,
    principal_id: String,
    payer: String,
    bearer_token: SecretText,
    signing_seed: SecretText,
    payout_destination: String,
}
impl From<BuyerClientProfileCustody> for FindingOperatorBuyerClientProfile {
    fn from(value: BuyerClientProfileCustody) -> Self {
        Self {
            schema: value.schema,
            endpoint: value.endpoint,
            market: value.market,
            principal_id: value.principal_id,
            payer: value.payer,
            bearer_token: value.bearer_token.into_owned(),
            signing_seed: value.signing_seed.into_owned(),
            payout_destination: value.payout_destination,
        }
    }
}
impl Zeroize for FindingOperatorBuyerClientProfile {
    fn zeroize(&mut self) {
        self.bearer_token.zeroize();
        self.signing_seed.zeroize();
    }
}
impl Drop for FindingOperatorBuyerClientProfile {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SellerClientProfileCustody {
    schema: String,
    endpoint: String,
    market: FindingMarketConfig,
    principal_id: String,
    bearer_token: SecretText,
    payout_destination: String,
}
impl From<SellerClientProfileCustody> for FindingOperatorSellerClientProfile {
    fn from(value: SellerClientProfileCustody) -> Self {
        Self {
            schema: value.schema,
            endpoint: value.endpoint,
            market: value.market,
            principal_id: value.principal_id,
            bearer_token: value.bearer_token.into_owned(),
            payout_destination: value.payout_destination,
        }
    }
}
impl Zeroize for FindingOperatorSellerClientProfile {
    fn zeroize(&mut self) {
        self.bearer_token.zeroize();
    }
}
impl Drop for FindingOperatorSellerClientProfile {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SecretSeedsCustody {
    venue: SecretText,
    listing: SecretText,
    governance_root: SecretText,
    authority_status: SecretText,
    verifier_report: SecretText,
    collateral: SecretText,
    purchase: SecretText,
    failed_delivery: SecretText,
    challenge_evaluator: SecretText,
    venue_finalization: SecretText,
    market_penalty: SecretText,
    settlement_observer: SecretText,
    anchor_publisher: SecretText,
    audit_authority: SecretText,
    audit_randomness_witness: SecretText,
    status_feed_operator: SecretText,
    fee_schedule_operator: SecretText,
    kernel: SecretText,
}
impl From<SecretSeedsCustody> for FindingOperatorSecretSeeds {
    fn from(value: SecretSeedsCustody) -> Self {
        Self {
            venue: value.venue.into_owned(),
            listing: value.listing.into_owned(),
            governance_root: value.governance_root.into_owned(),
            authority_status: value.authority_status.into_owned(),
            verifier_report: value.verifier_report.into_owned(),
            collateral: value.collateral.into_owned(),
            purchase: value.purchase.into_owned(),
            failed_delivery: value.failed_delivery.into_owned(),
            challenge_evaluator: value.challenge_evaluator.into_owned(),
            venue_finalization: value.venue_finalization.into_owned(),
            market_penalty: value.market_penalty.into_owned(),
            settlement_observer: value.settlement_observer.into_owned(),
            anchor_publisher: value.anchor_publisher.into_owned(),
            audit_authority: value.audit_authority.into_owned(),
            audit_randomness_witness: value.audit_randomness_witness.into_owned(),
            status_feed_operator: value.status_feed_operator.into_owned(),
            fee_schedule_operator: value.fee_schedule_operator.into_owned(),
            kernel: value.kernel.into_owned(),
        }
    }
}
impl Zeroize for FindingOperatorSecretSeeds {
    fn zeroize(&mut self) {
        self.venue.zeroize();
        self.listing.zeroize();
        self.governance_root.zeroize();
        self.authority_status.zeroize();
        self.verifier_report.zeroize();
        self.collateral.zeroize();
        self.purchase.zeroize();
        self.failed_delivery.zeroize();
        self.challenge_evaluator.zeroize();
        self.venue_finalization.zeroize();
        self.market_penalty.zeroize();
        self.settlement_observer.zeroize();
        self.anchor_publisher.zeroize();
        self.audit_authority.zeroize();
        self.audit_randomness_witness.zeroize();
        self.status_feed_operator.zeroize();
        self.fee_schedule_operator.zeroize();
        self.kernel.zeroize();
    }
}
impl Drop for FindingOperatorSecretSeeds {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BuyerProfileCustody {
    principal_id: String,
    bearer_token: SecretText,
    signing_seed: SecretText,
    payout_destination: String,
}
impl From<BuyerProfileCustody> for FindingOperatorBuyerProfile {
    fn from(value: BuyerProfileCustody) -> Self {
        Self {
            principal_id: value.principal_id,
            bearer_token: value.bearer_token.into_owned(),
            signing_seed: value.signing_seed.into_owned(),
            payout_destination: value.payout_destination,
        }
    }
}
impl Zeroize for FindingOperatorBuyerProfile {
    fn zeroize(&mut self) {
        self.bearer_token.zeroize();
        self.signing_seed.zeroize();
    }
}
impl Drop for FindingOperatorBuyerProfile {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SellerProfileCustody {
    principal_id: String,
    bearer_token: SecretText,
    signing_seed: SecretText,
    payout_destination: String,
}
impl From<SellerProfileCustody> for FindingOperatorSellerProfile {
    fn from(value: SellerProfileCustody) -> Self {
        Self {
            principal_id: value.principal_id,
            bearer_token: value.bearer_token.into_owned(),
            signing_seed: value.signing_seed.into_owned(),
            payout_destination: value.payout_destination,
        }
    }
}
impl Zeroize for FindingOperatorSellerProfile {
    fn zeroize(&mut self) {
        self.bearer_token.zeroize();
        self.signing_seed.zeroize();
    }
}
impl Drop for FindingOperatorSellerProfile {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProfileCustody {
    schema: String,
    listen: SocketAddr,
    seller_repository_root: String,
    service_token: SecretText,
    paths: FindingOperatorPaths,
    market: FindingMarketConfig,
    secrets: FindingOperatorSecretSeeds,
    payload_key_hex: SecretText,
    buyers: Vec<FindingOperatorBuyerProfile>,
    sellers: Vec<FindingOperatorSellerProfile>,
}
impl From<ProfileCustody> for FindingOperatorProfile {
    fn from(value: ProfileCustody) -> Self {
        Self {
            schema: value.schema,
            listen: value.listen,
            seller_repository_root: value.seller_repository_root,
            service_token: value.service_token.into_owned(),
            paths: value.paths,
            market: value.market,
            secrets: value.secrets,
            payload_key_hex: value.payload_key_hex.into_owned(),
            buyers: value.buyers,
            sellers: value.sellers,
        }
    }
}
impl Zeroize for FindingOperatorProfile {
    fn zeroize(&mut self) {
        self.service_token.zeroize();
        self.payload_key_hex.zeroize();
        self.secrets.zeroize();
        self.buyers.zeroize();
        self.sellers.zeroize();
    }
}
impl Drop for FindingOperatorProfile {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_private_profile_failure_wipes_already_decoded_seeds() {
        WIPED.with(|count| count.set(0));
        let outcome = serde_json::from_str::<FindingOperatorSecretSeeds>(
            r#"{"venue":"private-marker","listing":7}"#,
        );
        assert!(
            matches!(outcome, Err(ref error) if error.classify() == serde_json::error::Category::Data)
        );
        assert_eq!(WIPED.with(|count| count.get()), 1);
    }
}
