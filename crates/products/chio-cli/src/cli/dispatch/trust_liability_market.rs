// Dispatch handler for the `chio trust liability-market` command group.

use super::*;

pub(super) fn dispatch_liability_market(
    command: TrustLiabilityMarketCommands,
    json_output: bool,
    receipt_db: Option<PathBuf>,
    authority_seed_file: Option<PathBuf>,
    authority_db: Option<PathBuf>,
    control_url: Option<String>,
    control_token: Option<String>,
    egress: &std::sync::Arc<chio_egress_contract::EgressAllowanceSet>,
) -> Result<(), CliError> {
    match command {
            TrustLiabilityMarketCommands::QuoteRequestIssue { input_file } => {
                cmd_trust_liability_quote_request_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::QuoteResponseIssue { input_file } => {
                cmd_trust_liability_quote_response_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::PricingAuthorityIssue { input_file } => {
                cmd_trust_liability_pricing_authority_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::PlacementIssue { input_file } => {
                cmd_trust_liability_placement_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::BoundCoverageIssue { input_file } => {
                cmd_trust_liability_bound_coverage_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::AutoBindIssue { input_file } => {
                cmd_trust_liability_auto_bind_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::ClaimIssue { input_file } => {
                cmd_trust_liability_claim_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::ClaimResponseIssue { input_file } => {
                cmd_trust_liability_claim_response_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::DisputeIssue { input_file } => {
                cmd_trust_liability_claim_dispute_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::AdjudicationIssue {
                input_file,
                roster_policy_file,
            } => cmd_trust_liability_claim_adjudication_issue(
                &input_file,
                json_output,
                receipt_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                roster_policy_file.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
                egress,
            ),
            TrustLiabilityMarketCommands::ClaimPayoutInstructionIssue {
                input_file,
                roster_policy_file,
            } => cmd_trust_liability_claim_payout_instruction_issue(
                &input_file,
                json_output,
                receipt_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                roster_policy_file.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
                egress,
            ),
            TrustLiabilityMarketCommands::ClaimPayoutReceiptIssue { input_file } => {
                cmd_trust_liability_claim_payout_receipt_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::ClaimSettlementInstructionIssue {
                input_file,
                roster_policy_file,
                capital_authority_keys,
            } => cmd_trust_liability_claim_settlement_instruction_issue(
                &input_file,
                json_output,
                receipt_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                roster_policy_file.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
                &capital_authority_keys,
                egress,
            ),
            TrustLiabilityMarketCommands::ClaimSettlementReceiptIssue { input_file } => {
                cmd_trust_liability_claim_settlement_receipt_issue(
                    &input_file,
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                        egress,
                )
            }
            TrustLiabilityMarketCommands::List {
                quote_request_id,
                provider_id,
                agent_subject,
                jurisdiction,
                coverage_class,
                currency,
                limit,
            } => cmd_trust_liability_market_list(
                LiabilityMarketListArgs {
                    quote_request_id: quote_request_id.as_deref(),
                    provider_id: provider_id.as_deref(),
                    agent_subject: agent_subject.as_deref(),
                    jurisdiction: jurisdiction.as_deref(),
                    coverage_class: coverage_class.as_deref(),
                    currency: currency.as_deref(),
                    limit,
                },
                QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                        egress,
                },
            ),
            TrustLiabilityMarketCommands::ClaimsList {
                claim_id,
                provider_id,
                agent_subject,
                jurisdiction,
                policy_number,
                limit,
            } => cmd_trust_liability_claims_list(
                LiabilityClaimsListArgs {
                    claim_id: claim_id.as_deref(),
                    provider_id: provider_id.as_deref(),
                    agent_subject: agent_subject.as_deref(),
                    jurisdiction: jurisdiction.as_deref(),
                    policy_number: policy_number.as_deref(),
                    limit,
                },
                QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                        egress,
                },
            ),
    }
}
