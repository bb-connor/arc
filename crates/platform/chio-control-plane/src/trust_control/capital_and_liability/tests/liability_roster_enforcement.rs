#[cfg(test)]
mod roster_enforcement {
    use super::*;
    use chio_core::receipt::lineage::SignedExportEnvelope;
    use chio_kernel::{
        CapitalExecutionRailKind, CreditLossLifecycleSummary, LiabilityClaimSettlementRoleBinding,
    };
    use chio_test_support::ctx::{TestUnwrap, TestUnwrapErr};

    // Pinned adjudication_id for fixed inputs used in the golden regression test.
    // If this value changes, verify that the id-fold tuple change was intentional
    // and update this const. Construction-time goldens change when the tuple fields
    // change; wire-format signature goldens are unaffected.
    const ADJUDICATION_ID_GOLDEN_ANCHOR_A: &str =
        "lca-96d5df5192950bcfbd3d140286c79347d800dce8d945dffd4da9752530e9a038";

    fn sign_export<T: serde::Serialize + Clone>(body: T) -> SignedExportEnvelope<T> {
        let kp = Keypair::generate();
        SignedExportEnvelope::sign(body, &kp).test_unwrap("sign export")
    }

    fn usd(units: u64) -> MonetaryAmount {
        MonetaryAmount {
            units,
            currency: "USD".to_string(),
        }
    }

    fn fixture_exposure_report() -> SignedExposureLedgerReport {
        let kp = Keypair::generate();
        SignedExposureLedgerReport::sign(
            ExposureLedgerReport {
                schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
                generated_at: 1,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: ExposureLedgerSupportBoundary::default(),
                summary: ExposureLedgerSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    active_decisions: 0,
                    superseded_decisions: 0,
                    actionable_receipts: 0,
                    pending_settlement_receipts: 0,
                    failed_settlement_receipts: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    truncated_receipts: false,
                    truncated_decisions: false,
                },
                positions: vec![ExposureLedgerCurrencyPosition {
                    currency: "USD".to_string(),
                    governed_max_exposure_units: 10_000,
                    reserved_units: 0,
                    settled_units: 0,
                    pending_units: 0,
                    failed_units: 0,
                    provisional_loss_units: 0,
                    recovered_units: 0,
                    quoted_premium_units: 0,
                    active_quoted_premium_units: 0,
                }],
                receipts: Vec::new(),
                decisions: Vec::new(),
            },
            &kp,
        )
        .test_unwrap("sign exposure report")
    }

    fn fixture_credit_bond() -> SignedCreditBond {
        let kp = Keypair::generate();
        let exposure = fixture_exposure_report();
        SignedCreditBond::sign(
            CreditBondArtifact {
                schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
                bond_id: "bond-1".to_string(),
                issued_at: 10,
                expires_at: 1_800_000_000,
                lifecycle_state: CreditBondLifecycleState::Active,
                supersedes_bond_id: None,
                report: CreditBondReport {
                    schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
                    generated_at: 10,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    exposure: exposure.body.summary.clone(),
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditBondDisposition::Hold,
                    prerequisites: CreditBondPrerequisites {
                        active_facility_required: false,
                        active_facility_met: true,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        currency_coherent: true,
                    },
                    support_boundary: CreditBondSupportBoundary::default(),
                    latest_facility_id: None,
                    terms: None,
                    findings: Vec::new(),
                },
            },
            &kp,
        )
        .test_unwrap("sign credit bond")
    }

    fn fixture_credit_loss_lifecycle() -> SignedCreditLossLifecycle {
        let kp = Keypair::generate();
        SignedCreditLossLifecycle::sign(
            CreditLossLifecycleArtifact {
                schema: CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
                event_id: "loss-t1".to_string(),
                issued_at: 11,
                bond_id: "bond-1".to_string(),
                event_kind: CreditLossLifecycleEventKind::Delinquency,
                projected_bond_lifecycle_state: CreditBondLifecycleState::Active,
                reserve_control_source_id: None,
                authority_chain: Vec::new(),
                execution_window: None,
                rail: None,
                observed_execution: None,
                reconciled_state: None,
                execution_state: None,
                appeal_state: None,
                appeal_window_ends_at: None,
                description: Some("test loss marker".to_string()),
                report: CreditLossLifecycleReport {
                    schema: CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
                    generated_at: 11,
                    query: CreditLossLifecycleQuery {
                        bond_id: "bond-1".to_string(),
                        event_kind: CreditLossLifecycleEventKind::Delinquency,
                        amount: Some(usd(1_000)),
                    },
                    summary: CreditLossLifecycleSummary {
                        bond_id: "bond-1".to_string(),
                        facility_id: None,
                        capability_id: None,
                        agent_subject: Some("subject-1".to_string()),
                        tool_server: None,
                        tool_name: None,
                        current_bond_lifecycle_state: CreditBondLifecycleState::Active,
                        projected_bond_lifecycle_state: CreditBondLifecycleState::Active,
                        current_delinquent_amount: Some(usd(1_000)),
                        current_recovered_amount: None,
                        current_written_off_amount: None,
                        current_released_reserve_amount: None,
                        current_slashed_reserve_amount: None,
                        outstanding_delinquent_amount: Some(usd(1_000)),
                        releaseable_reserve_amount: Some(usd(2_000)),
                        reserve_control_source_id: None,
                        execution_state: None,
                        appeal_state: None,
                        appeal_window_ends_at: None,
                        event_amount: Some(usd(1_000)),
                    },
                    support_boundary: CreditLossLifecycleSupportBoundary::default(),
                    findings: Vec::new(),
                },
            },
            &kp,
        )
        .test_unwrap("sign credit loss lifecycle")
    }

    fn fixture_risk_package() -> SignedCreditProviderRiskPackage {
        let kp = Keypair::generate();
        let exposure = fixture_exposure_report();
        let scorecard = SignedCreditScorecardReport::sign(
            CreditScorecardReport {
                schema: CREDIT_SCORECARD_SCHEMA.to_string(),
                generated_at: 2,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: CreditScorecardSupportBoundary::default(),
                summary: CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: CreditScorecardConfidence::High,
                    band: CreditScorecardBand::Prime,
                    overall_score: 0.95,
                    anomaly_count: 0,
                    probationary: false,
                },
                reputation: CreditScorecardReputationContext {
                    effective_score: 0.95,
                    probationary: false,
                    resolved_tier: None,
                    imported_signal_count: 0,
                    accepted_imported_signal_count: 0,
                },
                positions: exposure.body.positions.clone(),
                probation: CreditScorecardProbationStatus {
                    probationary: false,
                    reasons: Vec::new(),
                    receipt_count: 1,
                    span_days: 1,
                    target_receipt_count: 1,
                    target_span_days: 1,
                },
                dimensions: Vec::new(),
                anomalies: Vec::new(),
            },
            &kp,
        )
        .test_unwrap("sign scorecard");
        SignedCreditProviderRiskPackage::sign(
            CreditProviderRiskPackage {
                schema: CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
                generated_at: 3,
                subject_key: "subject-1".to_string(),
                filters: CreditProviderRiskPackageQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CreditProviderRiskPackageQuery::default()
                },
                support_boundary: CreditProviderRiskPackageSupportBoundary::default(),
                exposure,
                scorecard,
                facility_report: CreditFacilityReport {
                    schema: CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
                    generated_at: 3,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditFacilityDisposition::Grant,
                    prerequisites: CreditFacilityPrerequisites {
                        minimum_runtime_assurance_tier: RuntimeAssuranceTier::Verified,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        manual_review_required: false,
                    },
                    support_boundary: CreditFacilitySupportBoundary::default(),
                    terms: None,
                    findings: Vec::new(),
                },
                compliance_score: None,
                latest_facility: None,
                runtime_assurance: None,
                certification: CreditCertificationState {
                    required: false,
                    state: None,
                    artifact_id: None,
                    checked_at: None,
                    published_at: None,
                },
                recent_loss_history: CreditRecentLossHistory {
                    summary: CreditRecentLossSummary {
                        matching_loss_events: 0,
                        returned_loss_events: 0,
                        failed_settlement_events: 0,
                        provisional_loss_events: 0,
                        recovered_events: 0,
                    },
                    entries: Vec::new(),
                },
                evidence_refs: Vec::new(),
            },
            &kp,
        )
        .test_unwrap("sign risk package")
    }

    /// Build a signed adjudication whose adjudicator is NOT on the roster.
    /// The nested chain just needs to type-check; it is never validated because
    /// the roster gate fires first.
    fn sample_signed_off_roster_adjudication() -> SignedLiabilityClaimAdjudication {
        let risk_package = fixture_risk_package();
        let provider_policy = LiabilityProviderPolicyReference {
            provider_id: "provider-1".to_string(),
            provider_record_id: "lpr-1".to_string(),
            display_name: "Provider One".to_string(),
            jurisdiction: "us-ny".to_string(),
            coverage_class: LiabilityCoverageClass::ToolExecution,
            currency: "USD".to_string(),
            required_evidence: Vec::new(),
            max_coverage_amount: Some(usd(10_000)),
            claims_supported: true,
            quote_ttl_seconds: 3_600,
            bound_coverage_supported: true,
        };
        let quote_request = sign_export(LiabilityQuoteRequestArtifact {
            schema: LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
            quote_request_id: "lqr-t1".to_string(),
            issued_at: 1_700_000_000,
            provider_policy,
            requested_coverage_amount: usd(10_000),
            requested_effective_from: 1_700_010_000,
            requested_effective_until: 1_700_020_000,
            risk_package,
            notes: None,
        });
        let quote_response = sign_export(LiabilityQuoteResponseArtifact {
            schema: LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA.to_string(),
            quote_response_id: "lqp-t1".to_string(),
            issued_at: 1_700_000_120,
            quote_request: quote_request.clone(),
            provider_quote_ref: "quote-ref-t1".to_string(),
            disposition: LiabilityQuoteDisposition::Quoted,
            supersedes_quote_response_id: None,
            quoted_terms: Some(LiabilityQuoteTerms {
                quoted_coverage_amount: usd(10_000),
                quoted_premium_amount: usd(500),
                quoted_deductible_amount: None,
                expires_at: 1_700_003_000,
            }),
            decline_reason: None,
        });
        let placement = sign_export(LiabilityPlacementArtifact {
            schema: LIABILITY_PLACEMENT_ARTIFACT_SCHEMA.to_string(),
            placement_id: "lpl-t1".to_string(),
            issued_at: 1_700_000_160,
            quote_response: quote_response.clone(),
            selected_coverage_amount: usd(10_000),
            selected_premium_amount: usd(500),
            effective_from: quote_response
                .body
                .quote_request
                .body
                .requested_effective_from,
            effective_until: quote_response
                .body
                .quote_request
                .body
                .requested_effective_until,
            placement_ref: None,
            notes: None,
        });
        let bound_coverage = sign_export(LiabilityBoundCoverageArtifact {
            schema: LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA.to_string(),
            bound_coverage_id: "lbc-t1".to_string(),
            issued_at: 1_700_000_170,
            placement: placement.clone(),
            policy_number: "POL-T1".to_string(),
            carrier_reference: None,
            bound_at: 1_700_000_171,
            effective_from: placement.body.effective_from,
            effective_until: placement.body.effective_until,
            coverage_amount: placement.body.selected_coverage_amount.clone(),
            premium_amount: placement.body.selected_premium_amount.clone(),
        });
        let claim_package = sign_export(LiabilityClaimPackageArtifact {
            schema: LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA.to_string(),
            claim_id: "clm-t1".to_string(),
            issued_at: 1_700_010_400,
            bound_coverage: bound_coverage.clone(),
            exposure: fixture_exposure_report(),
            bond: fixture_credit_bond(),
            loss_event: fixture_credit_loss_lifecycle(),
            claimant: "subject-1".to_string(),
            claim_event_at: 1_700_010_500,
            claim_amount: usd(9_000),
            claim_ref: None,
            narrative: "tool execution loss".to_string(),
            receipt_ids: vec!["rcpt-t1".to_string()],
            evidence_refs: Vec::new(),
        });
        let claim_response = sign_export(LiabilityClaimResponseArtifact {
            schema: LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA.to_string(),
            claim_response_id: "clr-t1".to_string(),
            issued_at: 1_700_010_600,
            claim: claim_package.clone(),
            provider_response_ref: "provider-t1".to_string(),
            disposition: LiabilityClaimResponseDisposition::Denied,
            covered_amount: None,
            response_note: None,
            denial_reason: Some("policy exclusion".to_string()),
            evidence_refs: Vec::new(),
        });
        let dispute = sign_export(LiabilityClaimDisputeArtifact {
            schema: LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA.to_string(),
            dispute_id: "lcd-t1".to_string(),
            issued_at: 1_700_010_700,
            provider_response: claim_response.clone(),
            opened_by: "subject-1".to_string(),
            reason: "disputed denial".to_string(),
            note: None,
            evidence_refs: Vec::new(),
        });
        sign_export(LiabilityClaimAdjudicationArtifact {
            schema: LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA.to_string(),
            adjudication_id: "lca-off-roster-t1".to_string(),
            issued_at: 1_700_010_800,
            dispute,
            adjudicator: "off.roster.adjudicator".to_string(),
            outcome: LiabilityClaimAdjudicationOutcome::PartialSettlement,
            awarded_amount: Some(usd(5_000)),
            note: None,
            decision_rule_ref: Some("rule.partial-settlement.v1".to_string()),
            roster_anchor_ref: Some("roster-anchor-abc".to_string()),
            evidence_refs: Vec::new(),
        })
    }

    fn fixture_capital_instruction() -> SignedCapitalExecutionInstruction {
        sign_export(CapitalExecutionInstructionArtifact {
            schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            instruction_id: "cei-fixture-t1".to_string(),
            issued_at: 1_700_010_850,
            query: CapitalBookQuery {
                agent_subject: Some("subject-1".to_string()),
                ..CapitalBookQuery::default()
            },
            subject_key: "subject-1".to_string(),
            source_id: "src-fixture-1".to_string(),
            source_kind: CapitalBookSourceKind::FacilityCommitment,
            governed_receipt_id: None,
            completion_flow_row_id: None,
            action: CapitalExecutionInstructionAction::TransferFunds,
            owner_role: CapitalExecutionRole::FacilityProvider,
            counterparty_role: CapitalExecutionRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            amount: Some(usd(5_000)),
            authority_chain: Vec::new(),
            execution_window: CapitalExecutionWindow {
                not_before: 1_700_010_850,
                not_after: 1_800_000_000,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Api,
                rail_id: "rail-fixture-1".to_string(),
                custody_provider_id: "custody-fixture-1".to_string(),
                source_account_ref: None,
                destination_account_ref: None,
                jurisdiction: None,
            },
            intended_state: CapitalExecutionIntendedState::PendingExecution,
            reconciled_state: CapitalExecutionReconciledState::NotObserved,
            related_instruction_id: None,
            observed_execution: None,
            support_boundary: CapitalExecutionInstructionSupportBoundary::default(),
            evidence_refs: Vec::new(),
            description: "fixture transfer".to_string(),
        })
    }

    fn build_payout_instruction_with_policy(
        adjudication: &SignedLiabilityClaimAdjudication,
        policy: &RosterPolicy,
    ) -> Result<LiabilityClaimPayoutInstructionArtifact, CliError> {
        let request = LiabilityClaimPayoutInstructionIssueRequest {
            adjudication: adjudication.clone(),
            capital_instruction: fixture_capital_instruction(),
            note: None,
        };
        build_liability_claim_payout_instruction_artifact(&request, 1_700_010_900, policy)
    }

    fn fixture_payout_receipt_wrapping(
        adjudication: &SignedLiabilityClaimAdjudication,
    ) -> SignedLiabilityClaimPayoutReceipt {
        let payout_instruction = sign_export(LiabilityClaimPayoutInstructionArtifact {
            schema: LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            payout_instruction_id: "lpi-fixture-t1".to_string(),
            issued_at: 1_700_010_900,
            adjudication: adjudication.clone(),
            capital_instruction: fixture_capital_instruction(),
            payout_amount: usd(5_000),
            note: None,
        });
        sign_export(LiabilityClaimPayoutReceiptArtifact {
            schema: LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
            payout_receipt_id: "lprc-fixture-t1".to_string(),
            issued_at: 1_700_011_000,
            payout_instruction,
            payout_receipt_ref: "receipt-fixture-t1".to_string(),
            reconciliation_state: LiabilityClaimPayoutReconciliationState::Matched,
            observed_execution: CapitalExecutionObservation {
                observed_at: 1_700_011_000,
                external_reference_id: "exec-fixture-t1".to_string(),
                amount: usd(5_000),
            },
            note: None,
        })
    }

    fn fixture_capital_book() -> SignedCapitalBookReport {
        let kp = Keypair::generate();
        SignedCapitalBookReport::sign(
            CapitalBookReport {
                schema: CAPITAL_BOOK_REPORT_SCHEMA.to_string(),
                generated_at: 1_700_000_100,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                support_boundary: CapitalBookSupportBoundary::default(),
                summary: CapitalBookSummary {
                    matching_receipts: 0,
                    returned_receipts: 0,
                    matching_facilities: 0,
                    returned_facilities: 0,
                    matching_bonds: 0,
                    returned_bonds: 0,
                    matching_loss_events: 0,
                    returned_loss_events: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    funding_sources: 0,
                    ledger_events: 0,
                    truncated_receipts: false,
                    truncated_facilities: false,
                    truncated_bonds: false,
                    truncated_loss_events: false,
                },
                sources: Vec::new(),
                events: Vec::new(),
            },
            &kp,
        )
        .test_unwrap("sign capital book")
    }

    fn build_settlement_instruction_with_policy(
        adjudication: &SignedLiabilityClaimAdjudication,
        policy: &RosterPolicy,
    ) -> Result<LiabilityClaimSettlementInstructionArtifact, CliError> {
        let payout_receipt = fixture_payout_receipt_wrapping(adjudication);
        let kp = Keypair::generate();
        let facility_provider_id = kp.public_key().to_hex();
        let request = LiabilityClaimSettlementInstructionIssueRequest {
            payout_receipt,
            capital_book: fixture_capital_book(),
            settlement_kind: LiabilityClaimSettlementKind::FacilityReimbursement,
            settlement_amount: usd(5_000),
            topology: LiabilityClaimSettlementRoleTopology {
                payer: LiabilityClaimSettlementRoleBinding {
                    role: CapitalExecutionRole::FacilityProvider,
                    party_id: facility_provider_id.clone(),
                    jurisdiction: None,
                    note: None,
                },
                payee: LiabilityClaimSettlementRoleBinding {
                    role: CapitalExecutionRole::AgentCounterparty,
                    party_id: "subject-1".to_string(),
                    jurisdiction: None,
                    note: None,
                },
                beneficiary: None,
            },
            authority_chain: Vec::new(),
            execution_window: CapitalExecutionWindow {
                not_before: 1_700_011_100,
                not_after: 1_800_000_000,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Api,
                rail_id: "rail-settle-fixture-t1".to_string(),
                custody_provider_id: "custody-fixture-1".to_string(),
                source_account_ref: None,
                destination_account_ref: None,
                jurisdiction: None,
            },
            settlement_reference: None,
            note: None,
        };
        build_liability_claim_settlement_instruction_artifact(&request, 1_700_011_100, policy)
    }

    #[test]
    fn payout_and_settlement_constructors_reject_off_roster_adjudication() {
        let policy = RosterPolicy {
            roster: vec!["arbiter.on-roster".to_string()],
            allowed_decision_rules: vec!["rule.partial-settlement.v1".to_string()],
            roster_anchor: "roster-anchor-abc".to_string(),
        };
        let off_roster = sample_signed_off_roster_adjudication();
        let payout_err = build_payout_instruction_with_policy(&off_roster, &policy)
            .test_unwrap_err("off-roster adjudication must be denied at payout construction");
        assert!(
            payout_err
                .to_string()
                .contains("not on the predeclared roster"),
            "expected roster error, got: {payout_err}",
        );
        let settle_err = build_settlement_instruction_with_policy(&off_roster, &policy)
            .test_unwrap_err("off-roster adjudication must be denied at settlement construction");
        assert!(
            settle_err
                .to_string()
                .contains("not on the predeclared roster"),
            "expected roster error, got: {settle_err}",
        );
    }

    #[test]
    fn adjudication_id_folds_decision_rule_and_roster_anchor() {
        // Verifies that changing decision_rule_ref or roster_anchor changes the derived id,
        // and pins the id for a fixed input so regressions in the derivation are caught.
        let policy_a = RosterPolicy {
            roster: vec!["arbiter.on-roster".to_string()],
            allowed_decision_rules: vec![
                "rule.partial-settlement.v1".to_string(),
                "rule.full-settlement.v1".to_string(),
            ],
            roster_anchor: "anchor-a".to_string(),
        };
        let policy_b = RosterPolicy {
            roster: vec!["arbiter.on-roster".to_string()],
            allowed_decision_rules: vec![
                "rule.partial-settlement.v1".to_string(),
                "rule.full-settlement.v1".to_string(),
            ],
            roster_anchor: "anchor-b".to_string(),
        };
        let off_roster = sample_signed_off_roster_adjudication();
        // Build a request whose adjudicator IS on the roster so the gate passes.
        let on_roster_dispute = off_roster.body.dispute.clone();
        // request_base uses rule-a; request_rule_b uses rule-b but same anchor.
        let request_base = LiabilityClaimAdjudicationIssueRequest {
            dispute: on_roster_dispute.clone(),
            adjudicator: "arbiter.on-roster".to_string(),
            outcome: LiabilityClaimAdjudicationOutcome::PartialSettlement,
            awarded_amount: Some(usd(5_000)),
            decision_rule_ref: Some("rule.partial-settlement.v1".to_string()),
            note: None,
        };
        let request_rule_b = LiabilityClaimAdjudicationIssueRequest {
            decision_rule_ref: Some("rule.full-settlement.v1".to_string()),
            ..request_base.clone()
        };
        let artifact_anchor_a =
            build_liability_claim_adjudication_artifact(&request_base, 1_700_010_800, &policy_a)
                .test_unwrap("build with anchor-a");
        let artifact_anchor_b =
            build_liability_claim_adjudication_artifact(&request_base, 1_700_010_800, &policy_b)
                .test_unwrap("build with anchor-b");
        let artifact_rule_b =
            build_liability_claim_adjudication_artifact(&request_rule_b, 1_700_010_800, &policy_a)
                .test_unwrap("build with rule-b");

        // Varying roster_anchor must change the id.
        assert_ne!(
            artifact_anchor_a.adjudication_id, artifact_anchor_b.adjudication_id,
            "different roster_anchor must produce different adjudication_id",
        );
        // Varying decision_rule_ref must independently change the id.
        assert_ne!(
            artifact_anchor_a.adjudication_id, artifact_rule_b.adjudication_id,
            "different decision_rule_ref must produce different adjudication_id",
        );
        assert_eq!(
            artifact_anchor_a.roster_anchor_ref.as_deref(),
            Some("anchor-a")
        );
        assert_eq!(
            artifact_anchor_b.roster_anchor_ref.as_deref(),
            Some("anchor-b")
        );

        // Golden: pin the derivation for the fixed-input artifact_anchor_a so any change
        // to the id-fold tuple is immediately caught.
        // Construction-time goldens change when the tuple fields change; wire-format
        // signature goldens are unaffected.
        assert_eq!(
            artifact_anchor_a.adjudication_id, ADJUDICATION_ID_GOLDEN_ANCHOR_A,
            "adjudication_id derivation changed for fixed inputs",
        );
    }
}
