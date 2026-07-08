// Seller-to-rail resolver for the EIP-3009 off-chain lane.
//
// The kernel `SimPaymentAdapter` stays rail-agnostic. EVM-rail bridging lives
// here, at the control-plane layer: the operator config declares which
// (seller, token_symbol) pair maps to which on-chain rail, and this module
// resolves that mapping and derives a deterministic sim pseudo-broadcast
// reference from the governed approval digest. No custody, no broadcast.

use chio_core::capability::governance::GovernedApprovalToken;
use chio_settle::{approval_binding_from_governed, RailBinding, SettlementError};

/// One entry in the operator-configured seller-to-rail table.
#[derive(Debug, Clone)]
pub struct SellerRailEntry {
    /// Seller identifier (matches `GovernedCommerceContext.seller`).
    pub seller: String,
    /// Token symbol this entry applies to (compared case-insensitively).
    pub token_symbol: String,
    /// Resolved EVM rail parameters for this seller and token.
    pub rail: RailBinding,
}

/// Operator config holding the full set of seller-to-rail mappings.
#[derive(Debug, Clone, Default)]
pub struct SellerRailConfig {
    pub entries: Vec<SellerRailEntry>,
}

/// Look up the rail for a (seller, token_symbol) pair from operator config.
///
/// Returns `None` when no matching entry is found, treating a missing rail as
/// an unconfigured lane rather than an error (the caller decides whether to
/// deny or fall through to a different payment path).
pub fn resolve_seller_rail<'a>(
    config: &'a SellerRailConfig,
    seller: &str,
    token_symbol: &str,
) -> Option<&'a RailBinding> {
    config
        .entries
        .iter()
        .find(|entry| {
            entry.seller == seller
                && entry
                    .token_symbol
                    .trim()
                    .eq_ignore_ascii_case(token_symbol.trim())
        })
        .map(|entry| &entry.rail)
}

/// Derive a deterministic sim pseudo-broadcast reference from an EIP-712
/// authorization digest.
///
/// The sim lane never broadcasts on-chain. This function derives a stable,
/// short reference from the digest so the kernel `SimPaymentAdapter` can
/// carry a traceable identifier without touching any EVM node.
pub fn sim_pseudo_ref_from_digest(authorization_digest: &str) -> String {
    let hex = authorization_digest.trim_start_matches("0x");
    format!("sim-eip3009-{hex}")
}

/// Bridge a governed approval token over a resolved EVM rail to a sim
/// pseudo-broadcast reference (prepare-only, no actual broadcast).
///
/// Calls [`approval_binding_from_governed`] at the control-plane layer
/// (keeping the kernel adapter rail-agnostic), then derives a deterministic
/// reference from the binding parameters. Fails closed when the token is not
/// approved or the rail fields are invalid.
pub fn governed_eip3009_sim_ref(
    token: &GovernedApprovalToken,
    rail: &RailBinding,
    amount_minor_units: u128,
) -> Result<String, SettlementError> {
    let binding =
        approval_binding_from_governed(token, rail, amount_minor_units, token.expires_at)?;
    let digest_input = format!(
        "{}:{}:{}",
        binding.chain_id, binding.payee_address, binding.amount_minor_units
    );
    let digest_hex = chio_core::hashing::sha256(digest_input.as_bytes()).to_hex();
    Ok(sim_pseudo_ref_from_digest(&digest_hex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_core::crypto::Keypair;
    use chio_test_support::prelude::*;

    const TEST_CHAIN_ID: u64 = 8453;
    const TEST_TOKEN_CONTRACT: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    const TEST_PAYEE: &str = "0x1000000000000000000000000000000000000002";

    fn test_rail() -> RailBinding {
        RailBinding {
            chain_id: TEST_CHAIN_ID,
            token_contract: TEST_TOKEN_CONTRACT.to_string(),
            payee_address: TEST_PAYEE.to_string(),
            token_decimals: 6,
            token_symbol: "USDC".to_string(),
        }
    }

    fn test_approval_token() -> GovernedApprovalToken {
        let kp = Keypair::generate();
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "seller-rail-test-1".to_string(),
                approver: kp.public_key(),
                subject: kp.public_key(),
                governed_intent_hash: "test-intent-hash".to_string(),
                request_id: "req-seller-rail-1".to_string(),
                issued_at: 1_744_000_000,
                expires_at: 1_744_000_600,
                decision: GovernedApprovalDecision::Approved,
            },
            &kp,
        )
        .test_unwrap()
    }

    #[test]
    fn resolve_seller_rail_finds_matching_entry() {
        let config = SellerRailConfig {
            entries: vec![SellerRailEntry {
                seller: "seller-abc".to_string(),
                token_symbol: "USDC".to_string(),
                rail: test_rail(),
            }],
        };
        let rail = resolve_seller_rail(&config, "seller-abc", "USDC");
        assert!(rail.is_some(), "matching entry must be found");
        assert_eq!(rail.test_unwrap().chain_id, TEST_CHAIN_ID);
    }

    #[test]
    fn resolve_seller_rail_is_case_insensitive_for_token_symbol() {
        let config = SellerRailConfig {
            entries: vec![SellerRailEntry {
                seller: "seller-abc".to_string(),
                token_symbol: "USDC".to_string(),
                rail: test_rail(),
            }],
        };
        assert!(resolve_seller_rail(&config, "seller-abc", "usdc").is_some());
        assert!(resolve_seller_rail(&config, "seller-abc", "USDC").is_some());
        assert!(resolve_seller_rail(&config, "seller-abc", "EURC").is_none());
        assert!(resolve_seller_rail(&config, "unknown-seller", "USDC").is_none());
    }

    #[test]
    fn pseudo_ref_derives_from_authorization_digest() {
        let digest_a = "0xaabbccdd1122334455667788aabbccdd1122334455667788aabbccdd11223344";
        let digest_b = "0x9900112233445566778899001122334455667788990011223344556677889900";
        let ref_a = sim_pseudo_ref_from_digest(digest_a);
        let ref_b = sim_pseudo_ref_from_digest(digest_b);
        assert_eq!(ref_a, sim_pseudo_ref_from_digest(digest_a));
        assert_ne!(ref_a, ref_b);
        assert!(
            ref_a.contains("aabbccdd"),
            "pseudo ref must contain the authorization_digest content, got: {ref_a}"
        );
    }

    #[test]
    fn governed_eip3009_sim_ref_derives_from_binding() {
        let token = test_approval_token();
        let ref1 = governed_eip3009_sim_ref(&token, &test_rail(), 1_000_000).test_unwrap();
        let ref2 = governed_eip3009_sim_ref(&token, &test_rail(), 1_000_000).test_unwrap();
        assert_eq!(ref1, ref2, "sim pseudo ref must be deterministic");
        assert!(
            ref1.starts_with("sim-eip3009-"),
            "sim pseudo ref must carry the sim-eip3009 prefix"
        );
        let ref_other = governed_eip3009_sim_ref(&token, &test_rail(), 2_000_000).test_unwrap();
        assert_ne!(
            ref1, ref_other,
            "different amounts must produce different refs"
        );
    }
}
