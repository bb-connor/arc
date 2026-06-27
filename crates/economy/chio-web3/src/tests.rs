use crate::anchors::{
    checkpoint_statement_body, sign_oracle_conversion_evidence, validate_anchor_inclusion_proof,
    validate_oracle_conversion_evidence, verify_anchor_inclusion_proof, AnchorInclusionProof,
    OracleConversionEvidence, Web3ChainAnchorRecord, Web3CheckpointStatement, Web3ReceiptInclusion,
    CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA, CHIO_CHECKPOINT_STATEMENT_SCHEMA,
    CHIO_LINK_ORACLE_AUTHORITY, CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA,
};
use crate::canonical::canonical_json_bytes;
use crate::capability::scope::{MonetaryAmount, Operation, ToolGrant};
use crate::chain::{validate_web3_chain_configuration, Web3ChainConfiguration};
use crate::contracts::{validate_web3_contract_package, Web3ContractPackage};
use crate::credit::{
    CapitalBookEvidenceKind, CapitalBookEvidenceReference, CapitalBookQuery, CapitalBookSourceKind,
    CapitalExecutionAuthorityStep, CapitalExecutionInstructionAction,
    CapitalExecutionInstructionSupportBoundary, CapitalExecutionIntendedState,
    CapitalExecutionObservation, CapitalExecutionRail, CapitalExecutionRailKind,
    CapitalExecutionReconciledState, CapitalExecutionRole, CapitalExecutionWindow,
    SignedCapitalExecutionInstruction, CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
};
use crate::crypto::{sha256_hex, Keypair, Signature};
use crate::error::Web3ContractError;
use crate::identity::{
    validate_web3_identity_binding, verify_web3_identity_binding, SignedWeb3IdentityBinding,
    Web3IdentityBindingCertificate, Web3KeyBindingPurpose, CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
};
use crate::merkle::MerkleTree;
use crate::qualification::{validate_web3_qualification_matrix, Web3QualificationMatrix};
use crate::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use crate::settlement::{
    settlement_anchor_receipt_content_hash_parts, validate_web3_settlement_dispatch,
    validate_web3_settlement_execution_receipt, Web3SettlementDispatchArtifact,
    Web3SettlementExecutionReceiptArtifact, Web3SettlementLifecycleState,
    Web3SettlementSupportBoundary, CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA,
    CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA,
};
use crate::settlement_proof::{
    public_settlement_witness_body_hash, verify_public_settlement_proof,
    PublicSettlementDeploymentProvenance, PublicSettlementDisputePosture,
    PublicSettlementDisputeSnapshot, PublicSettlementIndependentChainHead,
    PublicSettlementOrderBinding, PublicSettlementProofBundle, PublicSettlementTrustMarketContext,
    PublicSettlementVerifierReport, PublicSettlementVerifierTrust, PublicSettlementWitnessMode,
    PublicSettlementWitnessReport, ToolCallAuthorization,
    CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA, CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA,
    CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA, CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED,
    CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND, CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED,
    CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND,
    CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED,
    CLAIM_PUBLIC_SETTLEMENT_PUBLIC_WITNESS_VERIFIED,
    CLAIM_PUBLIC_SETTLEMENT_TRUST_MARKET_REFS_BOUND, PUBLIC_SETTLEMENT_FINALITY_REPORT_STATUSES,
};
use crate::trust_profile::{
    validate_web3_trust_profile, Web3ChainFinalityRule, Web3DisputePolicy, Web3DisputeWindow,
    Web3FinalityMode, Web3RegulatedRole, Web3RegulatedRoleAssumption, Web3SettlementPath,
    Web3TrustProfile, CHIO_WEB3_TRUST_PROFILE_SCHEMA,
};
use crate::x402_signing::{
    prepare_x402_broadcast_intent, sign_x402_settlement_attestation,
    verify_x402_settlement_attestation, ValueMovementAuthorization, X402CustodyModel,
    X402LiveMoneyMovementLeg, CHIO_X402_PREPARE_ONLY_BROADCAST_INTENT_SCHEMA,
    CHIO_X402_SETTLEMENT_ATTESTATION_SCHEMA,
};
use serde_json::json;
use std::collections::BTreeSet;

fn operator_keypair() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

fn treasury_keypair() -> Keypair {
    Keypair::from_seed(&[9u8; 32])
}

fn custodian_keypair() -> Keypair {
    Keypair::from_seed(&[11u8; 32])
}

fn beneficiary_keypair() -> Keypair {
    Keypair::from_seed(&[13u8; 32])
}

fn oracle_keypair() -> Keypair {
    Keypair::from_seed(&[15u8; 32])
}

fn signed_identity_binding(
    signer: Keypair,
    settlement_address: &str,
    purpose: Vec<Web3KeyBindingPurpose>,
    chain_scope: Vec<&str>,
    nonce: &str,
) -> SignedWeb3IdentityBinding {
    signed_identity_binding_with_window(
        signer,
        settlement_address,
        purpose,
        chain_scope,
        nonce,
        1_743_292_800,
        1_774_828_800,
    )
}

fn signed_identity_binding_with_window(
    signer: Keypair,
    settlement_address: &str,
    purpose: Vec<Web3KeyBindingPurpose>,
    chain_scope: Vec<&str>,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> SignedWeb3IdentityBinding {
    let public_key = signer.public_key();
    let certificate = Web3IdentityBindingCertificate {
        schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        chio_identity: format!("did:chio:{}", public_key.to_hex()),
        chio_public_key: public_key,
        chain_scope: chain_scope.into_iter().map(str::to_string).collect(),
        purpose,
        settlement_address: settlement_address.to_string(),
        issued_at,
        expires_at,
        nonce: nonce.to_string(),
    };
    let Ok((signature, _)) = signer.sign_canonical(&certificate) else {
        panic!("sample identity binding signs");
    };
    SignedWeb3IdentityBinding {
        certificate,
        signature,
    }
}

fn sample_binding() -> SignedWeb3IdentityBinding {
    signed_identity_binding(
        operator_keypair(),
        "0x1111111111111111111111111111111111111111",
        vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
        vec!["eip155:8453", "eip155:42161"],
        "0123456789abcdef0123456789abcdef",
    )
}

fn sample_beneficiary_binding() -> SignedWeb3IdentityBinding {
    signed_identity_binding(
        beneficiary_keypair(),
        "0x2222222222222222222222222222222222222222",
        vec![Web3KeyBindingPurpose::Settle],
        vec!["eip155:8453"],
        "beneficiary-identity-binding-0001",
    )
}

fn sample_trust_profile() -> Web3TrustProfile {
    Web3TrustProfile {
        schema: CHIO_WEB3_TRUST_PROFILE_SCHEMA.to_string(),
        profile_id: "chio.official-web3-stack".to_string(),
        chio_contract_version: "2.0".to_string(),
        primary_chain_id: "eip155:8453".to_string(),
        secondary_chain_ids: vec!["eip155:42161".to_string()],
        operator_binding: sample_binding(),
        proof_bundle_required: true,
        dispute_windows: vec![
            Web3DisputeWindow {
                settlement_path: Web3SettlementPath::DualSignature,
                challenge_window_secs: 600,
                recovery_window_secs: 3_600,
                dispute_policy: Web3DisputePolicy::OffChainArbitration,
            },
            Web3DisputeWindow {
                settlement_path: Web3SettlementPath::MerkleProof,
                challenge_window_secs: 900,
                recovery_window_secs: 86_400,
                dispute_policy: Web3DisputePolicy::TimeoutRefund,
            },
        ],
        finality_rules: vec![
            Web3ChainFinalityRule {
                chain_id: "eip155:8453".to_string(),
                mode: Web3FinalityMode::OptimisticL2,
                min_confirmations: 20,
            },
            Web3ChainFinalityRule {
                chain_id: "eip155:42161".to_string(),
                mode: Web3FinalityMode::L1Finalized,
                min_confirmations: 12,
            },
        ],
        regulated_roles: vec![
            Web3RegulatedRoleAssumption {
                role: Web3RegulatedRole::Operator,
                actor_id: "chio-operator-main".to_string(),
                responsibility: "Originates governed dispatch and maintains local policy activation."
                    .to_string(),
                custody_boundary_explicit: true,
            },
            Web3RegulatedRoleAssumption {
                role: Web3RegulatedRole::Custodian,
                actor_id: "custodian-base-main".to_string(),
                responsibility: "Holds settlement-side keys and custody accounts for the official stack."
                    .to_string(),
                custody_boundary_explicit: true,
            },
            Web3RegulatedRoleAssumption {
                role: Web3RegulatedRole::Arbitrator,
                actor_id: "settlement-dispute-panel".to_string(),
                responsibility: "Handles off-chain challenge and reversal review during dispute windows."
                    .to_string(),
                custody_boundary_explicit: true,
            },
        ],
        custody_boundary_note:
            "Chio governs intent, proofs, and policy admission; custodians and payment institutions remain explicit operators of record."
                .to_string(),
        local_policy_activation_required: true,
    }
}

fn sample_oracle_evidence() -> OracleConversionEvidence {
    let mut evidence = OracleConversionEvidence {
        schema: CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA.to_string(),
        base: "ETH".to_string(),
        quote: "USD".to_string(),
        authority: CHIO_LINK_ORACLE_AUTHORITY.to_string(),
        rate_numerator: 300_000,
        rate_denominator: 100,
        source: "chainlink".to_string(),
        feed_address: "0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612".to_string(),
        updated_at: 1_743_292_740,
        max_age_seconds: 3_600,
        cache_age_seconds: 45,
        converted_cost_units: 300,
        original_cost_units: 1_000_000_000_000_000,
        original_currency: "ETH".to_string(),
        grant_currency: "USD".to_string(),
        oracle_public_key: None,
        signature: None,
    };
    if let Err(error) = sign_oracle_conversion_evidence(&mut evidence, &oracle_keypair()) {
        panic!("sample oracle evidence must sign: {error}");
    }
    evidence
}

fn sample_receipt() -> ChioReceipt {
    sample_receipt_with_nonce("rcpt-web3-1")
}

fn sample_receipt_with_nonce(nonce: &str) -> ChioReceipt {
    let content_hash = match settlement_anchor_receipt_content_hash_parts(
        "receipt-web3-1",
        "settlement-web3-1",
        "dispatch-web3-1",
        "rcpt-web3-1",
    ) {
        Ok(hash) => hash,
        Err(error) => panic!("sample settlement anchor receipt binding must hash: {error}"),
    };
    sample_receipt_with_nonce_and_content_hash(nonce, content_hash)
}

fn sample_receipt_with_nonce_and_content_hash(nonce: &str, content_hash: String) -> ChioReceipt {
    let operator = operator_keypair();
    let parameters = json!({
        "to": "0x2222222222222222222222222222222222222222",
        "amount": 150,
        "currency": "USDC"
    });
    let action = ToolCallAction::from_parameters(parameters).unwrap();
    let body = ChioReceiptBody {
        id: nonce.to_string(),
        timestamp: 1_743_292_800,
        capability_id: "cap-web3-1".to_string(),
        tool_server: "chio-settle".to_string(),
        tool_name: "release_escrow".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash,
        policy_hash: sha256_hex(b"policy-web3"),
        evidence: vec![],
        metadata: Some(json!({
            "financial": {
                "grant_index": 0,
                "cost_charged": 150,
                "currency": "USD",
                "budget_remaining": 850,
                "budget_total": 1000,
                "delegation_depth": 1,
                "root_budget_holder": "subject-1",
                "payment_reference": "escrow-1",
                "settlement_status": "pending",
                "oracle_evidence": sample_oracle_evidence()
            }
        })),
        trust_level: chio_core_types::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key: operator.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, &operator).unwrap()
}

fn sample_anchor_inclusion_proof() -> AnchorInclusionProof {
    sample_anchor_inclusion_proof_for_receipt(sample_receipt())
}

fn sample_anchor_inclusion_proof_for_receipt(receipt: ChioReceipt) -> AnchorInclusionProof {
    let operator = operator_keypair();
    let receipt_body = receipt.body();
    let receipt_bytes = canonical_json_bytes(&receipt_body).unwrap();
    let tree = MerkleTree::from_leaves(&[receipt_bytes]).unwrap();
    let merkle_root = tree.root();
    let inclusion = Web3ReceiptInclusion {
        checkpoint_seq: 1_042,
        merkle_root,
        proof: tree.inclusion_proof(0).unwrap(),
    };
    let mut statement = Web3CheckpointStatement {
        schema: CHIO_CHECKPOINT_STATEMENT_SCHEMA.to_string(),
        checkpoint_seq: 1_042,
        batch_start_seq: 104_101,
        batch_end_seq: 104_200,
        tree_size: 1,
        merkle_root,
        issued_at: 1_743_292_800,
        previous_checkpoint_sha256: None,
        kernel_key: operator.public_key(),
        signature: Signature::from_hex(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
    };
    let body = checkpoint_statement_body(&statement);
    let (signature, _) = operator.sign_canonical(&body).unwrap();
    statement.signature = signature;

    AnchorInclusionProof {
        schema: CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA.to_string(),
        receipt,
        receipt_inclusion: inclusion,
        checkpoint_statement: statement,
        chain_anchor: Some(Web3ChainAnchorRecord {
            chain_id: "eip155:8453".to_string(),
            contract_address: "0x1000000000000000000000000000000000000001".to_string(),
            operator_address: "0x1111111111111111111111111111111111111111".to_string(),
            tx_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            block_number: 12_345_678,
            block_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            anchored_merkle_root: merkle_root,
            anchored_checkpoint_seq: 1_042,
        }),
        bitcoin_anchor: None,
        super_root_inclusion: None,
        key_binding_certificate: sample_binding(),
    }
}

fn sample_capital_instruction() -> SignedCapitalExecutionInstruction {
    let signer = treasury_keypair();
    let custodian = custodian_keypair();
    let custodian_id = custodian.public_key().to_hex();
    SignedCapitalExecutionInstruction::sign(
        crate::credit::CapitalExecutionInstructionArtifact {
            schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            instruction_id: "cei-web3-1".to_string(),
            issued_at: 1_743_292_800,
            query: CapitalBookQuery {
                agent_subject: Some("subject-1".to_string()),
                ..CapitalBookQuery::default()
            },
            subject_key: "subject-1".to_string(),
            source_id: "capital-source:facility:facility-1".to_string(),
            source_kind: CapitalBookSourceKind::FacilityCommitment,
            governed_receipt_id: Some("rcpt-web3-1".to_string()),
            completion_flow_row_id: Some("economic-completion-flow:rcpt-web3-1".to_string()),
            action: CapitalExecutionInstructionAction::TransferFunds,
            owner_role: CapitalExecutionRole::OperatorTreasury,
            counterparty_role: CapitalExecutionRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            amount: Some(MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            }),
            authority_chain: vec![
                CapitalExecutionAuthorityStep::signed(
                    CapitalExecutionRole::OperatorTreasury,
                    &signer,
                    1_743_292_790,
                    1_743_293_800,
                    Some("governed release".to_string()),
                )
                .unwrap(),
                CapitalExecutionAuthorityStep::signed(
                    CapitalExecutionRole::Custodian,
                    &custodian,
                    1_743_292_795,
                    1_743_293_800,
                    Some("official web3 stack".to_string()),
                )
                .unwrap(),
            ],
            execution_window: CapitalExecutionWindow {
                not_before: 1_743_292_800,
                not_after: 1_743_293_800,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Web3,
                rail_id: "base-mainnet-usdc".to_string(),
                custody_provider_id: custodian_id,
                source_account_ref: Some("vault:facility-main".to_string()),
                destination_account_ref: Some(
                    "0x2222222222222222222222222222222222222222".to_string(),
                ),
                jurisdiction: Some("US".to_string()),
            },
            intended_state: CapitalExecutionIntendedState::PendingExecution,
            reconciled_state: CapitalExecutionReconciledState::NotObserved,
            related_instruction_id: None,
            observed_execution: None,
            support_boundary: CapitalExecutionInstructionSupportBoundary {
                capital_book_authoritative: true,
                external_execution_authoritative: false,
                automatic_dispatch_supported: true,
                custody_neutral_instruction_supported: false,
            },
            evidence_refs: vec![
                CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::Receipt,
                    reference_id: "rcpt-web3-1".to_string(),
                    observed_at: Some(1_743_292_800),
                    locator: Some("receipt:rcpt-web3-1".to_string()),
                },
                CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CommerceOrder,
                    reference_id: "order-public-settlement-1".to_string(),
                    observed_at: Some(1_743_292_800),
                    locator: Some("commerce-order:order-public-settlement-1".to_string()),
                },
            ],
            description: "release escrow over the official web3 rail".to_string(),
        },
        &signer,
    )
    .unwrap()
}

fn resign_dispatch_capital_instruction(dispatch: &mut Web3SettlementDispatchArtifact) {
    dispatch.capital_instruction = SignedCapitalExecutionInstruction::sign(
        dispatch.capital_instruction.body.clone(),
        &treasury_keypair(),
    )
    .unwrap();
}

fn sample_dispatch() -> Web3SettlementDispatchArtifact {
    Web3SettlementDispatchArtifact {
        schema: CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA.to_string(),
        dispatch_id: "dispatch-web3-1".to_string(),
        issued_at: 1_743_292_800,
        trust_profile_id: "chio.official-web3-stack".to_string(),
        contract_package_id: "chio.official-web3-contracts".to_string(),
        chain_id: "eip155:8453".to_string(),
        capital_instruction: sample_capital_instruction(),
        bond: None,
        settlement_path: Web3SettlementPath::MerkleProof,
        settlement_amount: MonetaryAmount {
            units: 150,
            currency: "USD".to_string(),
        },
        escrow_id: "escrow-web3-1".to_string(),
        escrow_contract: "0x1000000000000000000000000000000000000002".to_string(),
        bond_vault_contract: "0x1000000000000000000000000000000000000003".to_string(),
        beneficiary_address: "0x2222222222222222222222222222222222222222".to_string(),
        support_boundary: Web3SettlementSupportBoundary {
            real_dispatch_supported: true,
            anchor_proof_required: true,
            oracle_evidence_required_for_fx: true,
            custody_boundary_explicit: true,
            reversal_supported: true,
        },
        note: Some(
            "Dispatches one governed escrow release over the official Base-first contract stack."
                .to_string(),
        ),
    }
}

fn sample_execution_receipt() -> Web3SettlementExecutionReceiptArtifact {
    Web3SettlementExecutionReceiptArtifact {
        schema: CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id: "receipt-web3-1".to_string(),
        issued_at: 1_743_292_860,
        dispatch: sample_dispatch(),
        observed_execution: CapitalExecutionObservation {
            observed_at: 1_743_292_860,
            external_reference_id:
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            amount: MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            },
        },
        lifecycle_state: Web3SettlementLifecycleState::Settled,
        settlement_reference: "settlement-web3-1".to_string(),
        reconciled_anchor_proof: Some(sample_anchor_inclusion_proof()),
        oracle_evidence: Some(sample_oracle_evidence()),
        settled_amount: MonetaryAmount {
            units: 150,
            currency: "USD".to_string(),
        },
        reversal_of: None,
        failure_reason: None,
        note: Some(
            "Settled against an anchored receipt root and retained oracle provenance for the FX conversion."
                .to_string(),
        ),
    }
}

fn sample_public_settlement_proof_bundle() -> PublicSettlementProofBundle {
    PublicSettlementProofBundle {
        schema: CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA.to_string(),
        bundle_id: "public-settlement-proof-web3-1".to_string(),
        transaction_passport_id: "passport-public-settlement-1".to_string(),
        commerce_order_id: "order-public-settlement-1".to_string(),
        order_binding: sample_public_settlement_order_binding(),
        chain_id: "eip155:8453".to_string(),
        settlement_receipt: sample_execution_receipt(),
        deployment_provenance: Some(sample_public_settlement_deployment_provenance()),
        public_witness: Some(sample_public_settlement_witness_report()),
        chain_snapshot: serde_json::from_value(sample_public_settlement_chain_snapshot_json())
            .unwrap(),
        dispute_snapshot: Some(sample_public_settlement_dispute_snapshot()),
        collateral_position_ref: None,
        guarantee_decision_ref: None,
        sla_remedy_ref: None,
        slash_authority_ref: None,
        required_confirmations: 20,
        observed_confirmations: 24,
        dispute_posture: PublicSettlementDisputePosture::Undisputed,
    }
}

fn sample_public_settlement_deployment_provenance() -> PublicSettlementDeploymentProvenance {
    PublicSettlementDeploymentProvenance {
        provenance_id: "deployment-provenance-public-settlement-1".to_string(),
        chain_id: "eip155:8453".to_string(),
        contract_package_id: "chio.official-web3-contracts".to_string(),
        reviewed_manifest_hash:
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
        approval_hash: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .to_string(),
        create2_factory: "0x1000000000000000000000000000000000000000".to_string(),
        salt_namespace: "chio-official-web3-stack-v1".to_string(),
        root_registry_address: "0x1000000000000000000000000000000000000001".to_string(),
        escrow_contract: "0x1000000000000000000000000000000000000002".to_string(),
        bond_vault_contract: "0x1000000000000000000000000000000000000003".to_string(),
    }
}

fn sample_public_settlement_witness_report() -> PublicSettlementWitnessReport {
    let anchor = sample_anchor_inclusion_proof()
        .chain_anchor
        .expect("sample public settlement anchor exists");
    let mut witness = PublicSettlementWitnessReport {
        witness_id: "public-witness-base-cache-1".to_string(),
        mode: PublicSettlementWitnessMode::VerifiedCache,
        body_hash: String::new(),
        chain_id: anchor.chain_id,
        registry_root: anchor.anchored_merkle_root.to_hex_prefixed(),
        anchor_tx_hash: anchor.tx_hash,
        anchored_merkle_root: anchor.anchored_merkle_root.to_hex_prefixed(),
        anchored_checkpoint_seq: anchor.anchored_checkpoint_seq,
        observed_at: 1_743_293_500,
    };
    witness.body_hash =
        public_settlement_witness_body_hash(&witness).expect("sample witness body hashes");
    witness
}

fn sample_public_settlement_order_binding() -> PublicSettlementOrderBinding {
    PublicSettlementOrderBinding {
        transaction_passport_id: "passport-public-settlement-1".to_string(),
        commerce_order_id: "order-public-settlement-1".to_string(),
        chain_id: "eip155:8453".to_string(),
        settlement_reference: "settlement-web3-1".to_string(),
        settlement_tx_hash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        beneficiary_address: "0x2222222222222222222222222222222222222222".to_string(),
        escrow_id: "escrow-web3-1".to_string(),
        settlement_amount: MonetaryAmount {
            units: 150,
            currency: "USD".to_string(),
        },
    }
}

fn sample_public_settlement_verifier_trust() -> PublicSettlementVerifierTrust {
    PublicSettlementVerifierTrust {
        trusted_capital_signer_keys: vec![treasury_keypair().public_key()],
        trusted_anchor_kernel_keys: vec![operator_keypair().public_key()],
        trusted_beneficiary_identity_keys: vec![beneficiary_keypair().public_key()],
        trusted_oracle_keys: vec![oracle_keypair().public_key()],
        allowed_chain_ids: vec!["eip155:8453".to_string()],
        mainnet_blocked: false,
        minimum_confirmations: Some(20),
        expected_trust_market_context: None,
        independent_chain_head: None,
    }
}

fn verify_sample_public_settlement_proof(
    bundle: &PublicSettlementProofBundle,
) -> Result<crate::settlement_proof::PublicSettlementVerifierReport, Web3ContractError> {
    verify_public_settlement_proof(bundle, &sample_public_settlement_verifier_trust())
}

fn sample_public_settlement_dispute_snapshot() -> PublicSettlementDisputeSnapshot {
    PublicSettlementDisputeSnapshot {
        schema: CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA.to_string(),
        dispute_id: "dispute-public-settlement-none".to_string(),
        posture: PublicSettlementDisputePosture::Undisputed,
        observed_at: 1_743_293_460,
        challenge_window_secs: 600,
        window_closed_at: 1_743_293_460,
        open_dispute_count: 0,
        linked_receipt_ids: Vec::new(),
        chain_event_tx_hashes: Vec::new(),
    }
}

fn sample_public_settlement_chain_snapshot_json() -> serde_json::Value {
    let registry_root = sample_anchor_inclusion_proof()
        .checkpoint_statement
        .merkle_root
        .to_hex_prefixed();
    let mut snapshot = json!({
        "chain_id": "eip155:8453",
        "observed_block_number": 12_345_678,
        "latest_block_number": 12_345_701,
        "max_block_lag": 128,
        "root_registry_address": "0x1000000000000000000000000000000000000001",
        "registry_root": registry_root,
        "block": {
            "block_number": 12_345_678,
            "block_hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "transaction_hashes": [
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            ]
        },
        "escrow": {
            "escrow_id": "escrow-web3-1",
            "escrow_contract": "0x1000000000000000000000000000000000000002",
            "beneficiary_address": "0x2222222222222222222222222222222222222222",
            "locked_amount": {
                "units": 150,
                "currency": "USD"
            },
            "released_amount": {
                "units": 150,
                "currency": "USD"
            }
        },
        "bond": {
            "bond_vault_contract": "0x1000000000000000000000000000000000000003",
            "posted_amount": {
                "units": 150,
                "currency": "USD"
            },
            "minimum_required_amount": {
                "units": 150,
                "currency": "USD"
            }
        }
    });
    let Ok(binding) = serde_json::to_value(sample_beneficiary_binding()) else {
        panic!("sample beneficiary identity binding serializes");
    };
    snapshot["beneficiary_identity_binding"] = binding;
    snapshot
}

fn sample_public_settlement_proof_bundle_with_chain_snapshot(
    mutate: impl FnOnce(&mut serde_json::Value),
) -> PublicSettlementProofBundle {
    let Ok(mut bundle) = serde_json::to_value(sample_public_settlement_proof_bundle()) else {
        panic!("sample public settlement proof bundle serializes");
    };
    bundle["chain_snapshot"] = sample_public_settlement_chain_snapshot_json();
    mutate(&mut bundle);
    let Ok(bundle) = serde_json::from_value(bundle) else {
        panic!("sample public settlement proof bundle parses");
    };
    bundle
}

fn sample_public_settlement_proof_bundle_with_order_ref(
    order_id: &str,
) -> PublicSettlementProofBundle {
    let Ok(mut bundle_value) = serde_json::to_value(sample_public_settlement_proof_bundle()) else {
        panic!("sample public settlement proof bundle serializes");
    };
    let Some(evidence_refs) = bundle_value["settlement_receipt"]["dispatch"]["capital_instruction"]
        ["body"]["evidenceRefs"]
        .as_array_mut()
    else {
        panic!("sample public settlement proof bundle has evidence refs");
    };
    evidence_refs.push(json!({
        "kind": "commerce_order",
        "referenceId": order_id,
        "observedAt": 1_743_292_800,
        "locator": format!("commerce-order:{order_id}")
    }));
    let Ok(mut bundle) = serde_json::from_value::<PublicSettlementProofBundle>(bundle_value) else {
        panic!("sample public settlement proof bundle parses");
    };
    resign_dispatch_capital_instruction(&mut bundle.settlement_receipt.dispatch);
    bundle
}

fn sample_chain_configuration() -> Web3ChainConfiguration {
    serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json"
    ))
    .unwrap()
}

fn public_settlement_report_schema_statuses() -> BTreeSet<String> {
    let Ok(schema) = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../../spec/schemas/chio-web3/v1/public-settlement-verifier-report.schema.json"
    )) else {
        panic!("public settlement verifier report schema parses");
    };
    let Some(status_values) = schema
        .pointer("/properties/finality_decision/properties/status/enum")
        .and_then(serde_json::Value::as_array)
    else {
        panic!("public settlement verifier report schema has finality status enum");
    };
    status_values
        .iter()
        .map(|value| {
            let Some(status) = value.as_str() else {
                panic!("public settlement verifier report status enum values are strings");
            };
            status.to_string()
        })
        .collect()
}

#[test]
fn trust_profile_requires_local_policy_activation() {
    let mut profile = sample_trust_profile();
    profile.local_policy_activation_required = false;
    assert!(matches!(
        validate_web3_trust_profile(&profile),
        Err(Web3ContractError::InvalidBinding(_))
    ));
}

#[test]
fn identity_binding_signature_verifies() {
    verify_web3_identity_binding(&sample_binding()).unwrap();
}

#[test]
fn identity_binding_rejects_padded_chain_scope() {
    let mut binding = sample_binding();
    binding.certificate.chain_scope[0] = " eip155:8453".to_string();
    assert!(matches!(
        validate_web3_identity_binding(&binding),
        Err(Web3ContractError::InvalidBinding(message))
            if message.contains("binding.chain_scope")
    ));
}

#[test]
fn anchor_inclusion_proof_verifies_receipt_and_merkle_root() {
    verify_anchor_inclusion_proof(&sample_anchor_inclusion_proof()).unwrap();
}

#[test]
fn oracle_evidence_requires_non_zero_denominator() {
    let mut evidence = sample_oracle_evidence();
    evidence.rate_denominator = 0;
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(_))
    ));
}

#[test]
fn oracle_evidence_rejects_unknown_authority() {
    let mut evidence = sample_oracle_evidence();
    evidence.authority = "unknown_authority".to_string();
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(_))
    ));
}

#[test]
fn oracle_evidence_rejects_stale_cache_age() {
    let mut evidence = sample_oracle_evidence();
    evidence.cache_age_seconds = evidence.max_age_seconds + 1;
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("oracle conversion evidence is stale")
    ));
}

#[test]
fn oracle_evidence_rejects_converted_amount_mismatch() {
    let mut evidence = sample_oracle_evidence();
    evidence.converted_cost_units += 1;
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("oracle conversion evidence converted_cost_units")
    ));
}

#[test]
fn oracle_evidence_rejects_currency_pair_mismatch() {
    let mut evidence = sample_oracle_evidence();
    evidence.quote = "EUR".to_string();
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("oracle conversion evidence quote must match grant_currency")
    ));
}

#[test]
fn web3_chain_configuration_rejects_placeholder_addresses() {
    for address in [
        "0x0000000000000000000000000000000000000000",
        "0x1111111111111111111111111111111111111111",
        "0x1000000000000000000000000000000000000001",
        "0x2000000000000000000000000000000000000005",
        "0xnot-a-valid-address",
        "0x1234",
    ] {
        let mut configuration = sample_chain_configuration();
        configuration.deployments[0].root_registry_address = address.to_string();
        assert!(matches!(
            validate_web3_chain_configuration(&configuration),
            Err(Web3ContractError::InvalidBinding(message))
                if message.contains("web3_chain_configuration.deployments.root_registry_address")
        ));
    }
}

#[test]
fn web3_dispatch_requires_web3_rail_kind() {
    let mut dispatch = sample_dispatch();
    dispatch.capital_instruction.body.rail.kind = CapitalExecutionRailKind::Api;
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
}

#[test]
fn web3_dispatch_rejects_lowercase_settlement_currency() {
    let mut dispatch = sample_dispatch();
    dispatch.settlement_amount.currency = "usd".to_string();
    dispatch
        .capital_instruction
        .body
        .amount
        .as_mut()
        .unwrap()
        .currency = "usd".to_string();

    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("currency")
    ));
}

#[test]
fn web3_dispatch_requires_completion_flow_binding_for_transfers() {
    let mut dispatch = sample_dispatch();
    dispatch.capital_instruction.body.completion_flow_row_id = None;
    resign_dispatch_capital_instruction(&mut dispatch);
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::MissingField(
            "web3_settlement_dispatch.capital_instruction.completion_flow_row_id"
        ))
    ));
}

#[test]
fn web3_dispatch_rejects_mismatched_completion_flow_binding() {
    let mut dispatch = sample_dispatch();
    dispatch.capital_instruction.body.completion_flow_row_id =
        Some("economic-completion-flow:other-receipt".to_string());
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
}

#[test]
fn merkle_settlement_receipt_requires_anchor_proof() {
    let mut receipt = sample_execution_receipt();
    receipt.reconciled_anchor_proof = None;
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
}

#[test]
fn merkle_settlement_receipt_rejects_tampered_anchor_signature() {
    let mut receipt = sample_execution_receipt();
    let Some(anchor_proof) = receipt.reconciled_anchor_proof.as_mut() else {
        panic!("sample execution receipt has anchor proof");
    };
    anchor_proof.checkpoint_statement.signature = Signature::from_hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("checkpoint statement signature verification failed")
    ));
}

#[test]
fn merkle_settlement_receipt_rejects_unrelated_anchor_receipt() {
    let mut receipt = sample_execution_receipt();
    receipt.reconciled_anchor_proof = Some(sample_anchor_inclusion_proof_for_receipt(
        sample_receipt_with_nonce("rcpt-web3-unrelated"),
    ));

    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("anchor proof receipt must match governed receipt")
    ));
}

#[test]
fn merkle_settlement_receipt_rejects_anchor_receipt_with_unrelated_content_hash() {
    let mut receipt = sample_execution_receipt();
    receipt.reconciled_anchor_proof = Some(sample_anchor_inclusion_proof_for_receipt(
        sample_receipt_with_nonce_and_content_hash("rcpt-web3-1", sha256_hex(b"other-settlement")),
    ));

    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("anchor proof receipt content hash must bind settlement execution")
    ));
}

#[test]
fn fx_sensitive_settlement_receipt_requires_oracle_evidence() {
    let mut receipt = sample_execution_receipt();
    receipt.oracle_evidence = None;
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
}

#[test]
fn timed_out_settlement_receipt_allows_refund_after_execution_window() {
    let mut receipt = sample_execution_receipt();
    receipt.lifecycle_state = Web3SettlementLifecycleState::TimedOut;
    receipt.failure_reason = Some("escrow refunded after deadline".to_string());
    receipt.reconciled_anchor_proof = None;
    receipt.observed_execution.observed_at = receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;
    receipt.issued_at = receipt.observed_execution.observed_at;

    validate_web3_settlement_execution_receipt(&receipt).unwrap();
}

#[test]
fn settlement_receipt_rejects_oracle_grant_currency_mismatch() {
    let mut receipt = sample_execution_receipt();
    let oracle_evidence = receipt.oracle_evidence.as_mut().unwrap();
    oracle_evidence.quote = "EUR".to_string();
    oracle_evidence.grant_currency = "EUR".to_string();
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("oracle conversion grant_currency must match settlement currency")
    ));
}

fn sample_matching_independent_chain_head() -> PublicSettlementIndependentChainHead {
    // Matches the sample bundle's chain snapshot so finality grounds on an
    // independent head (RPI-1). Same values the offline-finality fixture pins.
    PublicSettlementIndependentChainHead {
        chain_id: "eip155:8453".to_string(),
        observed_block_number: 12_345_678,
        observed_block_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string(),
        latest_block_number: 12_345_701,
    }
}

#[test]
fn public_settlement_proof_emits_verifier_report() {
    let bundle = sample_public_settlement_proof_bundle();
    // RPI-1: the finality claim is grounded on an independent chain head.
    let mut trust = sample_public_settlement_verifier_trust();
    trust.independent_chain_head = Some(sample_matching_independent_chain_head());
    let report = verify_public_settlement_proof(&bundle, &trust).unwrap();

    assert_eq!(report.schema, CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA);
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.bundle_id, bundle.bundle_id);
    assert_eq!(report.chain_context.chain_id, "eip155:8453");
    assert_eq!(
        report.chain_context.bond_vault_contract,
        "0x1000000000000000000000000000000000000003"
    );
    assert_eq!(report.chain_context.posted_bond_amount.units, 150);
    assert_eq!(report.chain_context.minimum_bond_amount.units, 150);
    assert_eq!(
        report.chain_context.block_hash,
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        report.chain_context.anchor_tx_hash,
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        report.chain_context.settlement_tx_hash,
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );
    let beneficiary_binding = sample_beneficiary_binding();
    assert_eq!(
        report.chain_context.beneficiary_address,
        beneficiary_binding.certificate.settlement_address
    );
    assert_eq!(
        report.chain_context.beneficiary_chio_identity,
        beneficiary_binding.certificate.chio_identity
    );
    assert_eq!(report.finality_decision.status, "final");
    assert_eq!(report.recomputed_settlement_state, "settled");
    assert_eq!(
        report.public_witness.witness_id,
        "public-witness-base-cache-1"
    );
    assert_eq!(
        report.public_witness.mode,
        PublicSettlementWitnessMode::VerifiedCache
    );
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_PUBLIC_WITNESS_VERIFIED.to_string()));
}

/// M2-2 (WS-CL-RECOMPUTE-GATE) fail-closed negative: a fully verified x402
/// settlement RECEIPT binds settlement and payment claims ONLY. It never
/// authorizes a tool call. Payment success is not authorization; tool-call
/// authority belongs to the capability/governance lane, so a "verified"
/// settlement verdict must not leak any capability grant or tool-call claim.
#[test]
fn verified_x402_settlement_receipt_does_not_authorize_tool_call() {
    // A settlement proof the recompute lane accepts: payment settled and
    // every settlement claim recomputes from the kernel-signed anchor.
    let bundle = sample_public_settlement_proof_bundle();
    let report = verify_sample_public_settlement_proof(&bundle).unwrap();
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.recomputed_settlement_state, "settled");

    // Every claim a verified settlement proof can emit lives on the
    // settlement/payment axis (`claim.public_settlement.*`). None of them
    // grants capability or tool-call authority.
    let settlement_claims: BTreeSet<&str> = BTreeSet::from([
        CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED,
        CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED,
        CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED,
        CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND,
        CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND,
        CLAIM_PUBLIC_SETTLEMENT_TRUST_MARKET_REFS_BOUND,
        CLAIM_PUBLIC_SETTLEMENT_PUBLIC_WITNESS_VERIFIED,
    ]);
    assert!(!report.verified_claims.is_empty());
    for claim in &report.verified_claims {
        assert!(
            claim.starts_with("claim.public_settlement."),
            "settlement proof emitted a non-settlement claim: {claim}"
        );
        assert!(
            settlement_claims.contains(claim.as_str()),
            "settlement proof emitted an unexpected claim: {claim}"
        );
        for forbidden in ["tool_call", "capability", "authoriz", "invoke"] {
            assert!(
                !claim.contains(forbidden),
                "settlement claim must not carry tool-call authority: {claim}"
            );
        }
    }

    // The verifier report speaks only to settlement: there is no
    // authorization verdict and no capability grant to be mistaken for one.
    assert_ne!(report.verdict, "authorized");

    // M2-12 structural inversion: the report cannot occupy an authorization
    // position. Its tool-call authorization is the fail-closed DENY decision.
    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );
}

/// M2-12 (WS-CL-X402-VERIFY): a tool-call authorization is fail-closed BY
/// CONSTRUCTION. Its `Default` and `denied()` are DENY, and an authorized
/// state is unrepresentable except via an explicit positive capability grant.
#[test]
fn tool_call_authorization_defaults_to_denied() {
    assert!(!ToolCallAuthorization::default().is_authorized());
    assert!(!ToolCallAuthorization::denied().is_authorized());
    assert_eq!(
        ToolCallAuthorization::default(),
        ToolCallAuthorization::denied()
    );
}

/// M2-12: the ONLY path to an authorized decision is an explicit positive
/// capability grant. A matching grant carrying `Invoke` authorizes; every other
/// case (wrong tool, no `Invoke` operation) fails closed to DENY.
#[test]
fn tool_call_authorization_requires_explicit_capability_grant() {
    let invoke_grant = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool_a".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    // A matching grant with Invoke authorizes the tool call.
    assert!(
        ToolCallAuthorization::from_capability_grant(&invoke_grant, "srv", "tool_a")
            .is_authorized()
    );
    // Wrong tool fails closed.
    assert!(
        !ToolCallAuthorization::from_capability_grant(&invoke_grant, "srv", "tool_b")
            .is_authorized()
    );
    // A grant without the Invoke operation fails closed.
    let read_only = ToolGrant {
        operations: vec![Operation::ReadResult],
        ..invoke_grant.clone()
    };
    assert!(
        !ToolCallAuthorization::from_capability_grant(&read_only, "srv", "tool_a").is_authorized()
    );
}

/// PR959 codex P2 (5th re-review, class closure): an INVOCATION cap cannot be
/// evaluated without the grant's running call count, which lives in the kernel
/// budget lane, not in this argument-less helper. `max_invocations = Some(0)`
/// permits zero calls outright, and even a positive cap (`Some(n)`) cannot be
/// confirmed unexhausted without the usage count, so ANY `Some(_)` fails closed
/// and must route through the budget lane. Only an uncapped grant (`None`,
/// bounded elsewhere) is evaluable here.
#[test]
fn tool_call_authorization_denies_invocation_capped_grant() {
    let base = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool_a".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: Some(0),
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    // A zero-invocation cap fails closed even though every other axis matches.
    assert!(
        !ToolCallAuthorization::from_capability_grant(&base, "srv", "tool_a").is_authorized(),
        "a grant that permits zero invocations must not authorize a tool call"
    );
    // A positive cap is still unconfirmable without the running usage count, so it
    // fails closed and must route through the budget lane.
    let one_call = ToolGrant {
        max_invocations: Some(1),
        ..base.clone()
    };
    assert!(
        !ToolCallAuthorization::from_capability_grant(&one_call, "srv", "tool_a").is_authorized(),
        "an invocation-capped grant must route through the budget lane, not authorize here"
    );
    // An uncapped grant (None) stays usable; the budget lane bounds it elsewhere.
    let uncapped = ToolGrant {
        max_invocations: None,
        ..base
    };
    assert!(
        ToolCallAuthorization::from_capability_grant(&uncapped, "srv", "tool_a").is_authorized(),
        "an uncapped grant authorizes the matching tool call"
    );
}

/// PR959 codex P2 (5th re-review): a grant that REQUIRES a DPoP proof
/// (`dpop_required = Some(true)`) cannot be authorized by this argument-less
/// helper, which holds no proof. The ACP/edge lane denies a DPoP-required grant
/// without a valid proof, so authorizing it here would advertise a capability the
/// edge lane would deny: it fails closed. `None`/`Some(false)` require no proof
/// and stay usable.
#[test]
fn tool_call_authorization_denies_dpop_required_grant() {
    let base = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool_a".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    // A grant that requires DPoP fails closed: the proof lives in the edge lane.
    let dpop_required = ToolGrant {
        dpop_required: Some(true),
        ..base.clone()
    };
    assert!(
        !ToolCallAuthorization::from_capability_grant(&dpop_required, "srv", "tool_a")
            .is_authorized(),
        "a DPoP-required grant must fail closed without a proof, not authorize here"
    );
    // Some(false) explicitly does not require a proof and stays usable.
    let dpop_optional = ToolGrant {
        dpop_required: Some(false),
        ..base.clone()
    };
    assert!(
        ToolCallAuthorization::from_capability_grant(&dpop_optional, "srv", "tool_a")
            .is_authorized(),
        "a grant that does not require DPoP (Some(false)) authorizes the matching tool call"
    );
    // None likewise does not require a proof and stays usable.
    assert!(
        ToolCallAuthorization::from_capability_grant(&base, "srv", "tool_a").is_authorized(),
        "a grant with no DPoP requirement authorizes the matching tool call"
    );
}

/// PR959 codex P2 (re-review): a capability whose MONETARY budget is unusable or
/// unconfirmable authorizes nothing here. The argument-less helper has no per-call
/// cost and no running-total usage, so it cannot evaluate a monetary cap: a
/// `max_cost_per_invocation = Some(0)` cap denies every non-zero-cost call, an
/// exhausted `max_total_cost` denies further calls, and even a positive cap is
/// unconfirmable. Like the constraint lane, a monetary-capped grant fails closed
/// and must route through the kernel budget lane. A grant with no monetary cap
/// (both `None`) remains usable.
#[test]
fn tool_call_authorization_denies_monetary_capped_grant() {
    let base = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool_a".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    // A zero per-invocation cost cap denies every non-zero-cost call: fail closed.
    let zero_cost = ToolGrant {
        max_cost_per_invocation: Some(MonetaryAmount {
            units: 0,
            currency: "USD".to_string(),
        }),
        ..base.clone()
    };
    assert!(
        !ToolCallAuthorization::from_capability_grant(&zero_cost, "srv", "tool_a").is_authorized(),
        "a grant with max_cost_per_invocation Some(0) must not authorize a tool call"
    );
    // A positive per-invocation cost cap is still unconfirmable without the call
    // cost, so it fails closed and must route through the budget lane.
    let positive_cost = ToolGrant {
        max_cost_per_invocation: Some(MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        }),
        ..base.clone()
    };
    assert!(
        !ToolCallAuthorization::from_capability_grant(&positive_cost, "srv", "tool_a")
            .is_authorized(),
        "a monetary-capped grant must route through the budget lane, not authorize here"
    );
    // A total-cost cap is likewise unconfirmable without running usage: fail closed.
    let total_cap = ToolGrant {
        max_total_cost: Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        }),
        ..base.clone()
    };
    assert!(
        !ToolCallAuthorization::from_capability_grant(&total_cap, "srv", "tool_a").is_authorized(),
        "a max_total_cost-capped grant must route through the budget lane, not authorize here"
    );
    // A grant with no monetary cap (both None) stays usable.
    assert!(
        ToolCallAuthorization::from_capability_grant(&base, "srv", "tool_a").is_authorized(),
        "a grant with no monetary cap authorizes the matching tool call"
    );
}

/// M2-12: a fully verified settlement report NEVER authorizes a tool call, and
/// this holds STRUCTURALLY rather than as a runtime string check. Even after
/// forging a `"authorized"` verdict and injecting capability-shaped claims, the
/// decision stays DENY, because `authorizes_tool_call` reads no field of the
/// report. The settlement lane and the capability lane are disjoint: only the
/// capability lane can mint a grant.
#[test]
fn settlement_report_never_authorizes_tool_call_by_construction() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut report: PublicSettlementVerifierReport =
        verify_sample_public_settlement_proof(&bundle).unwrap();
    assert_eq!(report.verdict, "verified");

    // Baseline: a verified settlement report denies tool-call authority.
    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );

    // Forge the verdict and inject capability-shaped claims. If authorization
    // were a runtime check over `verdict`/`verified_claims`, this would flip
    // it. It does not: the guard is structural, so the decision stays DENY.
    report.verdict = "authorized".to_string();
    report.verified_claims = vec![
        "claim.capability.tool_call_authorized".to_string(),
        "authorized".to_string(),
    ];
    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );

    // The settlement-derived decision is not the GRANT a real capability grant
    // mints: the two lanes are disjoint and only the capability lane authorizes.
    let capability_grant = ToolGrant {
        server_id: "*".to_string(),
        tool_name: "*".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let granted = ToolCallAuthorization::from_capability_grant(&capability_grant, "srv", "tool_a");
    assert!(granted.is_authorized());
    assert_ne!(report.tool_call_authorization(), granted);
}

#[test]
fn public_settlement_proof_rejects_missing_trusted_oracle_keys() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_oracle_keys.clear();

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("trusted public settlement oracle keys missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_untrusted_oracle_signer() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_oracle_keys = vec![operator_keypair().public_key()];

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("oracle conversion evidence signer key is not trusted")
    ));
}

#[test]
fn public_settlement_proof_rejects_tampered_oracle_signature() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let Some(oracle_evidence) = bundle.settlement_receipt.oracle_evidence.as_mut() else {
        panic!("sample public settlement proof includes oracle evidence");
    };
    oracle_evidence.feed_address = "0x0000000000000000000000000000000000000000".to_string();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("oracle conversion evidence signature verification failed")
    ));
}

#[test]
fn public_settlement_proof_binds_trust_market_refs_when_present() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.collateral_position_ref = Some("collateral-trust-market-valid".to_string());
    bundle.guarantee_decision_ref = Some("guarantee-trust-market-valid".to_string());
    bundle.sla_remedy_ref = Some("remedy-policy-market-valid".to_string());
    bundle.slash_authority_ref = Some("did:chio:slash-authority".to_string());
    let mut trust = sample_public_settlement_verifier_trust();
    trust.expected_trust_market_context = Some(PublicSettlementTrustMarketContext {
        collateral_position_ref: "collateral-trust-market-valid".to_string(),
        guarantee_decision_ref: "guarantee-trust-market-valid".to_string(),
        sla_remedy_ref: "remedy-policy-market-valid".to_string(),
        slash_authority_ref: "did:chio:slash-authority".to_string(),
    });

    let report = verify_public_settlement_proof(&bundle, &trust).unwrap();

    let trust_market_context = report.trust_market_context.unwrap();
    assert_eq!(
        trust_market_context.collateral_position_ref,
        "collateral-trust-market-valid"
    );
    assert_eq!(
        trust_market_context.guarantee_decision_ref,
        "guarantee-trust-market-valid"
    );
    assert_eq!(
        trust_market_context.sla_remedy_ref,
        "remedy-policy-market-valid"
    );
    assert_eq!(
        trust_market_context.slash_authority_ref,
        "did:chio:slash-authority"
    );
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_TRUST_MARKET_REFS_BOUND.to_string()));
}

#[test]
fn public_settlement_proof_reports_trust_market_refs_without_verified_context() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.collateral_position_ref = Some("collateral-trust-market-valid".to_string());
    bundle.guarantee_decision_ref = Some("guarantee-trust-market-valid".to_string());
    bundle.sla_remedy_ref = Some("remedy-policy-market-valid".to_string());
    bundle.slash_authority_ref = Some("did:chio:slash-authority".to_string());

    let report = verify_sample_public_settlement_proof(&bundle).unwrap();

    assert!(report.trust_market_context.is_some());
    assert!(!report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_TRUST_MARKET_REFS_BOUND.to_string()));
}

#[test]
fn public_settlement_proof_rejects_partial_trust_market_refs() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.guarantee_decision_ref = Some("guarantee-trust-market-valid".to_string());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement trust-market refs incomplete")
    ));
}

#[test]
fn public_settlement_proof_rejects_trust_market_ref_mismatch_against_expected_context() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.collateral_position_ref = Some("collateral-trust-market-valid".to_string());
    bundle.guarantee_decision_ref = Some("guarantee-trust-market-valid".to_string());
    bundle.sla_remedy_ref = Some("remedy-policy-market-valid".to_string());
    bundle.slash_authority_ref = Some("did:chio:slash-authority".to_string());

    let mut trust = sample_public_settlement_verifier_trust();
    trust.expected_trust_market_context = Some(PublicSettlementTrustMarketContext {
        collateral_position_ref: "collateral-trust-market-valid".to_string(),
        guarantee_decision_ref: "guarantee-trust-market-valid".to_string(),
        sla_remedy_ref: "remedy-policy-market-valid".to_string(),
        slash_authority_ref: "did:chio:different-slash-authority".to_string(),
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement trust-market ref mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_deployment_provenance() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.deployment_provenance = None;

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement deployment provenance missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_public_witness_report() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.public_witness = None;

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement witness report missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_advisory_public_witness_report() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let witness = bundle
        .public_witness
        .as_mut()
        .expect("sample public settlement proof has witness");
    witness.mode = PublicSettlementWitnessMode::Advisory;
    witness.body_hash =
        public_settlement_witness_body_hash(witness).expect("sample witness body hashes");

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement witness mode advisory")
    ));
}

#[test]
fn public_settlement_proof_rejects_stale_verified_cache_public_witness_report() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let settlement_observed_at = bundle.settlement_receipt.observed_execution.observed_at;
    let witness = bundle
        .public_witness
        .as_mut()
        .expect("sample public settlement proof has witness");
    witness.observed_at = settlement_observed_at
        - crate::settlement_proof::MAX_VERIFIED_CACHE_WITNESS_AGE_SECONDS
        - 1;
    witness.body_hash =
        public_settlement_witness_body_hash(witness).expect("sample witness body hashes");

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement verified-cache witness is stale")
    ));
}

#[test]
fn public_settlement_proof_rejects_public_witness_body_hash_mismatch() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .public_witness
        .as_mut()
        .expect("sample public settlement proof has witness")
        .body_hash =
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement witness body hash mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_deployment_contract_package_mismatch() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .deployment_provenance
        .as_mut()
        .unwrap()
        .contract_package_id = "chio.other-web3-contracts".to_string();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement deployment contract package mismatch")
    ));
}

#[test]
fn public_settlement_verifier_report_schema_allows_emitted_finality_statuses() {
    let schema_statuses = public_settlement_report_schema_statuses();

    for status in PUBLIC_SETTLEMENT_FINALITY_REPORT_STATUSES {
        assert!(
            schema_statuses.contains(*status),
            "public settlement verifier report schema rejects emitted finality status {status}"
        );
    }
}

#[test]
fn public_settlement_proof_rejects_missing_trusted_signers() {
    let bundle = sample_public_settlement_proof_bundle();
    let trust = PublicSettlementVerifierTrust::default();

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("trusted public settlement capital signer keys missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_untrusted_capital_signer() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_capital_signer_keys = vec![custodian_keypair().public_key()];

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement capital signer key is not trusted")
    ));
}

#[test]
fn public_settlement_proof_rejects_untrusted_anchor_kernel() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_anchor_kernel_keys = vec![custodian_keypair().public_key()];

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement anchor kernel key is not trusted")
    ));
}

#[test]
fn public_settlement_proof_rejects_untrusted_beneficiary_identity() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_beneficiary_identity_keys = vec![custodian_keypair().public_key()];

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement beneficiary identity key is not trusted")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_chain_allow_list() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.allowed_chain_ids.clear();

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement verifier chain allow-list missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_disallowed_chain_id() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.allowed_chain_ids = vec!["eip155:84532".to_string()];

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement chain id is not allowed")
    ));
}

#[test]
fn public_settlement_proof_rejects_mainnet_when_policy_hold_enabled() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.mainnet_blocked = true;

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement mainnet chain is blocked by verifier policy")
    ));
}

#[test]
fn public_settlement_proof_rejects_confirmations_below_verifier_minimum() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.minimum_confirmations = Some(bundle.required_confirmations + 1);

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement verifier minimum confirmations not met")
    ));
}

#[test]
fn public_settlement_proof_rejects_wrong_chain_id() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.chain_id = "eip155:42161".to_string();
    bundle.order_binding.chain_id = bundle.chain_id.clone();
    bundle.deployment_provenance.as_mut().unwrap().chain_id = bundle.chain_id.clone();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.allowed_chain_ids.push("eip155:42161".to_string());

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("settlement chain id mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_tampered_capital_instruction_signature() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .counterparty_id = "subject-tampered".to_string();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("capital instruction signature verification failed")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_commerce_order_binding() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.commerce_order_id.clear();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::MissingField(
            "public_settlement.commerce_order_id"
        ))
    ));
}

#[test]
fn public_settlement_proof_rejects_mismatched_commerce_order_evidence_ref() {
    let bundle = sample_public_settlement_proof_bundle_with_order_ref("order-public-settlement-2");

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement commerce order evidence mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_order_binding_settlement_tx_mismatch() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.order_binding.settlement_tx_hash =
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement order binding settlement tx mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_finality_below_threshold() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.observed_confirmations = 19;
    let mut trust = sample_public_settlement_verifier_trust();
    trust.minimum_confirmations = None;

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("settlement finality below threshold")
    ));
}

#[test]
fn public_settlement_proof_rejects_inflated_observed_confirmations() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.observed_confirmations = 25;

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement observed confirmations exceed chain snapshot")
    ));
}

#[test]
fn public_settlement_proof_rejects_reorged_snapshot_when_independent_head_disagrees() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.independent_chain_head = Some(PublicSettlementIndependentChainHead {
        chain_id: "eip155:8453".to_string(),
        observed_block_number: 12_345_678,
        observed_block_hash: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            .to_string(),
        latest_block_number: 12_345_701,
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement independent head block hash mismatch")
    ));
}

#[test]
fn public_settlement_proof_accepts_matching_independent_head() {
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.independent_chain_head = Some(PublicSettlementIndependentChainHead {
        chain_id: "eip155:8453".to_string(),
        observed_block_number: 12_345_678,
        observed_block_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string(),
        latest_block_number: 12_345_701,
    });

    assert!(verify_public_settlement_proof(&bundle, &trust).is_ok());
}

/// RPI-1 (fail-closed finality grounding): a bundle whose producer fabricates
/// the chain-snapshot confirmation depth still verifies structurally, but
/// WITHOUT an independent chain head the verifier does NOT emit the
/// `finality_verified` claim. Finality must be grounded on an independent head,
/// never on the unsigned, producer-supplied `latest_block_number` /
/// `observed_confirmations`. A downstream policy that requires the finality
/// claim then fails closed.
#[test]
fn public_settlement_proof_withholds_finality_without_independent_head() {
    // Producer inflates the unsigned chain-snapshot depth and observed
    // confirmations to manufacture a deep, "final"-looking settlement.
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|snapshot| {
        snapshot["chain_snapshot"]["latest_block_number"] = json!(12_345_700);
    });
    let mut bundle = bundle;
    bundle.observed_confirmations = 23;

    // No independent chain head: the verifier cannot independently observe the
    // chain tip, so finality is NOT vouched for.
    let mut trust = sample_public_settlement_verifier_trust();
    trust.independent_chain_head = None;

    let report = verify_public_settlement_proof(&bundle, &trust)
        .expect("the bundle still recomputes structurally");
    assert!(
        !report
            .verified_claims
            .contains(&CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED.to_string()),
        "finality must not be claimed without an independent chain head"
    );
    // PR959 codex P2 (5th re-review): the STATUS field must not assert grounded
    // finality either. The Settled bundle would read `final`, but without an
    // independent head it is downgraded so a consumer keying off the status (not
    // the withheld claim) cannot accept ungrounded finality.
    assert_ne!(
        report.finality_decision.status, "final",
        "the status field must not assert grounded finality without an independent head"
    );
    assert_eq!(
        report.finality_decision.status, "ungrounded",
        "an affirmative-finality status is downgraded to ungrounded without an independent head"
    );

    // Supplying a matching independent head restores the finality claim AND the
    // grounded `final` status.
    trust.independent_chain_head = Some(sample_matching_independent_chain_head());
    let grounded = sample_public_settlement_proof_bundle();
    let grounded_report =
        verify_public_settlement_proof(&grounded, &trust).expect("a head-grounded bundle verifies");
    assert!(grounded_report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED.to_string()));
    assert_eq!(
        grounded_report.finality_decision.status, "final",
        "a head-grounded Settled bundle reports the grounded final status"
    );
}

/// PR959 codex P2 (honor grant constraints): the argument-less tool-call
/// authorization helper cannot evaluate a grant's parameter constraints against
/// a request it never sees, so a CONSTRAINED grant must fail closed rather than
/// authorize every invocation of the tool.
#[test]
fn tool_call_authorization_denies_constrained_grant() {
    use crate::capability::scope::Constraint;

    let mut constrained = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool_a".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![Constraint::PathPrefix("/safe".to_string())],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };

    // A grant narrowed to one parameter set cannot authorize via this helper.
    assert!(
        !ToolCallAuthorization::from_capability_grant(&constrained, "srv", "tool_a")
            .is_authorized(),
        "a constrained grant must fail closed in the argument-less helper"
    );

    // Dropping the constraints restores the (otherwise matching) authorization.
    constrained.constraints.clear();
    assert!(
        ToolCallAuthorization::from_capability_grant(&constrained, "srv", "tool_a").is_authorized()
    );
}

#[test]
fn public_settlement_proof_rejects_stale_chain_snapshot() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["latest_block_number"] = json!(12_345_900);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement chain snapshot is stale")
    ));
}

#[test]
fn public_settlement_proof_rejects_wrong_registry_root() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["registry_root"] =
            json!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement registry root mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_escrow_balance_below_required_amount() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["escrow"]["locked_amount"]["units"] = json!(149);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement escrow balance below required amount")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_block_snapshot() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        let Some(chain_snapshot) = bundle["chain_snapshot"].as_object_mut() else {
            panic!("sample public settlement chain snapshot is an object");
        };
        chain_snapshot.remove("block");
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement block snapshot missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_settlement_tx_not_included_in_block() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["block"]["transaction_hashes"] =
            json!(["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement tx hash not included in block")
    ));
}

#[test]
fn public_settlement_proof_rejects_dispute_event_tx_not_included_in_block() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["dispute_snapshot"]["chain_event_tx_hashes"] =
            json!(["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute event tx hash not included in block")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_beneficiary_identity_binding() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        let Some(chain_snapshot) = bundle["chain_snapshot"].as_object_mut() else {
            panic!("sample public settlement chain snapshot is an object");
        };
        chain_snapshot.remove("beneficiary_identity_binding");
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement beneficiary identity binding missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_dispute_snapshot() {
    let Ok(mut bundle) = serde_json::to_value(sample_public_settlement_proof_bundle()) else {
        panic!("sample public settlement proof bundle serializes");
    };
    let Some(bundle_object) = bundle.as_object_mut() else {
        panic!("sample public settlement proof bundle is an object");
    };
    bundle_object.remove("dispute_snapshot");
    let Ok(bundle) = serde_json::from_value(bundle) else {
        panic!("sample public settlement proof bundle parses");
    };

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute snapshot missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_beneficiary_identity_address_mismatch() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        let wrong_binding = signed_identity_binding(
            beneficiary_keypair(),
            "0x3333333333333333333333333333333333333333",
            vec![Web3KeyBindingPurpose::Settle],
            vec!["eip155:8453"],
            "beneficiary-identity-binding-wrong-address",
        );
        let Ok(binding) = serde_json::to_value(wrong_binding) else {
            panic!("sample beneficiary identity binding serializes");
        };
        bundle["chain_snapshot"]["beneficiary_identity_binding"] = binding;
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidBinding(message))
            if message.contains("public settlement beneficiary identity binding address mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_beneficiary_binding_issued_after_execution() {
    let mut bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        let binding = signed_identity_binding_with_window(
            beneficiary_keypair(),
            "0x2222222222222222222222222222222222222222",
            vec![Web3KeyBindingPurpose::Settle],
            vec!["eip155:8453"],
            "beneficiary-identity-binding-after-execution",
            1_743_292_890,
            1_743_296_460,
        );
        let Ok(binding) = serde_json::to_value(binding) else {
            panic!("sample beneficiary identity binding serializes");
        };
        bundle["chain_snapshot"]["beneficiary_identity_binding"] = binding;
    });
    bundle.settlement_receipt.issued_at =
        bundle.settlement_receipt.observed_execution.observed_at + 60;

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidBinding(message))
            if message.contains("public settlement beneficiary identity binding not valid at settlement time")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_bond_snapshot() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.chain_snapshot.bond = None;

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement bond snapshot missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_bond_below_policy() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["bond"]["posted_amount"]["units"] = json!(149);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement bond below policy")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_oracle_evidence() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.oracle_evidence = None;

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("receipt requires oracle_evidence")
    ));
}

#[test]
fn public_settlement_proof_rejects_observed_execution_outside_dispatch_window() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.observed_execution.observed_at = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("observed execution timestamp falls outside dispatch execution window")
    ));
}

#[test]
fn public_settlement_proof_rejects_failed_settlement_before_finality_claims() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Failed;
    bundle.settlement_receipt.failure_reason = Some("provider execution failed".to_string());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement finality requires successful settlement state")
    ));
}

#[test]
fn public_settlement_proof_rejects_reorged_settlement_before_finality_claims() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Reorged;
    bundle.settlement_receipt.failure_reason = Some("settlement transaction reorged".to_string());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement finality requires successful settlement state")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_observed_execution_reference() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id
        .clear();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::MissingField(
            "web3_settlement_receipt.observed_execution.external_reference_id"
        ))
    ));
}

#[test]
fn public_settlement_proof_rejects_malformed_observed_execution_tx_hash() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id = "settlement-web3-reference".to_string();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("observed execution reference must be an eip155 transaction hash")
    ));
}

#[test]
fn public_settlement_proof_rejects_finality_with_active_dispute() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Challenged;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Challenged;
    dispute_snapshot.dispute_id = "dispute-public-settlement-challenged".to_string();
    dispute_snapshot.open_dispute_count = 1;
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement active dispute blocks finality")
    ));
}

#[test]
fn public_settlement_proof_rejects_dispute_not_linked_to_settlement_receipt() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Challenged;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Challenged;
    dispute_snapshot.dispute_id = "dispute-public-settlement-challenged".to_string();
    dispute_snapshot.open_dispute_count = 1;
    dispute_snapshot
        .linked_receipt_ids
        .push("receipt-web3-unrelated".to_string());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute not linked to settlement receipt")
    ));
}

#[test]
fn public_settlement_proof_rejects_closed_posture_with_open_dispute() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Closed;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Closed;
    dispute_snapshot.dispute_id = "dispute-public-settlement-closed".to_string();
    dispute_snapshot.open_dispute_count = 1;
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement active dispute blocks finality")
    ));
}

#[test]
fn public_settlement_proof_rejects_refunded_posture_without_reversal() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-refunded".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("refunded dispute posture requires reversed or timed out settlement")
    ));
}

#[test]
fn public_settlement_proof_reports_refunded_reversal_status() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Reversed;
    bundle.settlement_receipt.reversal_of = Some("receipt-web3-original".to_string());
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-refunded".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());

    let report = verify_sample_public_settlement_proof(&bundle).unwrap();

    assert_eq!(report.finality_decision.status, "refunded");
    assert_eq!(report.recomputed_settlement_state, "reversed");
    assert_eq!(
        report.dispute_posture,
        PublicSettlementDisputePosture::Refunded
    );
}

#[test]
fn invalid_settlement_constructor_preserves_message() {
    let error = Web3ContractError::invalid_settlement("settlement amount must match");
    assert!(matches!(
        error,
        Web3ContractError::InvalidSettlement(message)
            if message == "settlement amount must match"
    ));
}

#[test]
fn reference_artifacts_parse_and_validate() {
    let trust_profile: Web3TrustProfile = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_TRUST_PROFILE.json"
    ))
    .unwrap();
    let contract_package: Web3ContractPackage = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json"
    ))
    .unwrap();
    let chain_configuration: Web3ChainConfiguration = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json"
    ))
    .unwrap();
    let anchor_proof: AnchorInclusionProof = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
    ))
    .unwrap();
    let dispatch: Web3SettlementDispatchArtifact = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
    ))
    .unwrap();
    let receipt: Web3SettlementExecutionReceiptArtifact = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json"
    ))
    .unwrap();
    let matrix: Web3QualificationMatrix = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_QUALIFICATION_MATRIX.json"
    ))
    .unwrap();

    validate_web3_trust_profile(&trust_profile).unwrap();
    verify_web3_identity_binding(&trust_profile.operator_binding).unwrap();
    validate_web3_contract_package(&contract_package).unwrap();
    validate_web3_chain_configuration(&chain_configuration).unwrap();
    validate_anchor_inclusion_proof(&anchor_proof).unwrap();
    verify_anchor_inclusion_proof(&anchor_proof).unwrap();
    validate_web3_settlement_dispatch(&dispatch).unwrap();
    validate_web3_settlement_execution_receipt(&receipt).unwrap();
    validate_web3_qualification_matrix(&matrix).unwrap();
}

// ---------------------------------------------------------------------------
// M2-14 (WS-CL-X402-VERIFY): custody-neutral, prepare-only x402 signing path.
// ---------------------------------------------------------------------------

/// Base Sepolia testnet chain id used for the prepare-only x402 signing tests.
const X402_TESTNET_CHAIN_ID: &str = "eip155:84532";

/// Rebuild the sample public settlement proof bundle on a TESTNET chain
/// (Base Sepolia), rewriting every chain-id-bearing field and re-signing the
/// two identity bindings so their `chain_scope` covers the testnet chain. The
/// kernel-signed checkpoint statement and the receipt Merkle root do not carry
/// a chain id, so they remain valid unchanged.
fn sample_testnet_public_settlement_proof_bundle() -> PublicSettlementProofBundle {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.chain_id = X402_TESTNET_CHAIN_ID.to_string();
    bundle.order_binding.chain_id = X402_TESTNET_CHAIN_ID.to_string();
    if let Some(provenance) = bundle.deployment_provenance.as_mut() {
        provenance.chain_id = X402_TESTNET_CHAIN_ID.to_string();
    }
    bundle.chain_snapshot.chain_id = X402_TESTNET_CHAIN_ID.to_string();
    bundle.settlement_receipt.dispatch.chain_id = X402_TESTNET_CHAIN_ID.to_string();
    if let Some(anchor_proof) = bundle.settlement_receipt.reconciled_anchor_proof.as_mut() {
        if let Some(chain_anchor) = anchor_proof.chain_anchor.as_mut() {
            chain_anchor.chain_id = X402_TESTNET_CHAIN_ID.to_string();
        }
        anchor_proof.key_binding_certificate = signed_identity_binding(
            operator_keypair(),
            "0x1111111111111111111111111111111111111111",
            vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
            vec![X402_TESTNET_CHAIN_ID],
            "0123456789abcdef0123456789abcdef",
        );
    }
    if let Some(witness) = bundle.public_witness.as_mut() {
        witness.chain_id = X402_TESTNET_CHAIN_ID.to_string();
        witness.body_hash =
            public_settlement_witness_body_hash(witness).expect("testnet witness body hashes");
    }
    bundle.chain_snapshot.beneficiary_identity_binding = Some(signed_identity_binding(
        beneficiary_keypair(),
        "0x2222222222222222222222222222222222222222",
        vec![Web3KeyBindingPurpose::Settle],
        vec![X402_TESTNET_CHAIN_ID],
        "beneficiary-identity-binding-0001",
    ));
    bundle
}

/// Verifier trust for the prepare-only x402 signing path: the testnet chain is
/// allow-listed and mainnet is blocked.
fn sample_testnet_x402_verifier_trust() -> PublicSettlementVerifierTrust {
    let mut trust = sample_public_settlement_verifier_trust();
    trust.allowed_chain_ids = vec![X402_TESTNET_CHAIN_ID.to_string()];
    trust.mainnet_blocked = true;
    // Ground finality on an independent chain head matching the testnet bundle so
    // the recompute emits the finality claim the signing path now requires
    // (RPI-1 follow-on). Without this the report carries no grounded finality and
    // the kernel must refuse to sign.
    trust.independent_chain_head = Some(PublicSettlementIndependentChainHead {
        chain_id: X402_TESTNET_CHAIN_ID.to_string(),
        observed_block_number: 12_345_678,
        observed_block_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string(),
        latest_block_number: 12_345_701,
    });
    trust
}

/// M2-14: the custody-neutral prepare-only signing path produces a kernel-signed
/// attestation that explicitly moves NO value on chain. The signed body carries
/// `value_moved_on_chain = false`, `prepare_only = true`, `testnet_gated = true`,
/// and the custody-neutral model. The attestation verifies and round-trips
/// through serde unchanged.
#[test]
fn x402_prepare_only_signing_is_value_neutral_and_recompute_bound() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let trust = sample_testnet_x402_verifier_trust();
    let kernel = operator_keypair();

    let attestation = sign_x402_settlement_attestation(
        &bundle,
        &trust,
        &kernel,
        "x402-attestation-1",
        1_743_293_900,
    )
    .unwrap();

    assert_eq!(
        attestation.body.schema,
        CHIO_X402_SETTLEMENT_ATTESTATION_SCHEMA
    );
    assert_eq!(attestation.body.chain_id, X402_TESTNET_CHAIN_ID);
    assert_eq!(
        attestation.body.custody_model,
        X402CustodyModel::CustodyNeutral
    );
    // Prepare-only and value-neutral: NO value moves on chain.
    assert!(!attestation.body.value_moved_on_chain);
    assert!(!attestation.value_moved_on_chain());
    assert!(attestation.body.prepare_only);
    assert!(attestation.body.testnet_gated);
    // Recompute-bound: the attestation binds the recomputed settlement report.
    let report = verify_public_settlement_proof(&bundle, &trust).unwrap();
    assert_eq!(
        attestation.body.recomputed_settlement_state,
        report.recomputed_settlement_state
    );
    assert_eq!(
        attestation.body.settlement_reference,
        report.chain_context.settlement_reference
    );
    assert_eq!(
        attestation.body.verifier_report_digest,
        sha256_hex(&canonical_json_bytes(&report).unwrap())
    );

    // The signed attestation verifies, and round-trips through serde unchanged.
    verify_x402_settlement_attestation(&attestation, &trust).unwrap();
    let encoded = serde_json::to_vec(&attestation).unwrap();
    let decoded: crate::x402_signing::X402SignedSettlementAttestation =
        serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, attestation);
    verify_x402_settlement_attestation(&decoded, &trust).unwrap();
}

/// M2-14: the signing path is custody-neutral. The signed attestation carries NO
/// value-movement authority and NO tool-call authority; both are fail-closed BY
/// CONSTRUCTION (composing with M2-12). The signed body has no authority field
/// at all, and flipping the value-moved flag is rejected fail-closed on verify.
#[test]
fn x402_attestation_carries_no_value_movement_authority_by_construction() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let trust = sample_testnet_x402_verifier_trust();
    let kernel = operator_keypair();
    let attestation = sign_x402_settlement_attestation(
        &bundle,
        &trust,
        &kernel,
        "x402-attestation-1",
        1_743_293_900,
    )
    .unwrap();

    // Value-movement and tool-call authority are DENY by construction.
    assert!(!attestation.authorizes_value_movement());
    assert_eq!(
        attestation.value_movement_authorization(),
        ValueMovementAuthorization::denied()
    );
    assert!(!attestation.authorizes_tool_call());
    assert_eq!(
        attestation.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );

    // The signed body contains no authority field of any kind: it records only
    // that the proof recomputes and that no value moved.
    let body_json = String::from_utf8(canonical_json_bytes(&attestation.body).unwrap()).unwrap();
    assert!(body_json.contains("\"value_moved_on_chain\":false"));
    assert!(body_json.contains("\"custody_model\":\"custody_neutral\""));
    for forbidden in ["authoriz", "grant", "tool_call", "value_movement_authoriz"] {
        assert!(
            !body_json.contains(forbidden),
            "x402 attestation body must carry no authority field, found {forbidden}: {body_json}"
        );
    }

    // Fail-closed: an attestation that claims value moved on chain is rejected,
    // before any signature check, so it can never pass as custody-neutral.
    let mut tampered = attestation.clone();
    tampered.body.value_moved_on_chain = true;
    assert!(matches!(
        verify_x402_settlement_attestation(&tampered, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("must not move value on chain")
    ));
}

/// M2-14: testnet-gated, fail-closed. A mainnet chain (here Base mainnet) is
/// rejected by the prepare-only signing path even when the proof itself would
/// recompute and the chain is allow-listed.
#[test]
fn x402_prepare_only_signing_rejects_mainnet_chain() {
    // The default sample bundle settles on Base MAINNET (eip155:8453).
    let bundle = sample_public_settlement_proof_bundle();
    let mut trust = sample_public_settlement_verifier_trust();
    trust.mainnet_blocked = true;
    trust.allowed_chain_ids = vec!["eip155:8453".to_string()];
    let kernel = operator_keypair();

    assert!(matches!(
        sign_x402_settlement_attestation(&bundle, &trust, &kernel, "x402-attestation-1", 1_743_293_900),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("testnet-gated; mainnet chain rejected")
    ));
}

/// PR959 codex P2: the testnet gate does not rely on the partial mainnet
/// deny-list. An allow-listed chain that the mainnet detector does not enumerate
/// (here Gnosis mainnet `eip155:100`, which is not a known testnet either) fails
/// closed instead of being signed for, even on a mainnet-blocked policy.
#[test]
fn x402_prepare_only_signing_rejects_unknown_chain_fail_closed() {
    let mut bundle = sample_testnet_public_settlement_proof_bundle();
    // A real mainnet the partial deny-list omits; not a known testnet either.
    bundle.chain_id = "eip155:100".to_string();
    let mut trust = sample_testnet_x402_verifier_trust();
    trust.mainnet_blocked = true;
    trust.allowed_chain_ids = vec!["eip155:100".to_string()];
    let kernel = operator_keypair();

    assert!(matches!(
        sign_x402_settlement_attestation(&bundle, &trust, &kernel, "x402-attestation-1", 1_743_293_900),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("only known testnets are allowed")
    ));
}

/// M2-14: testnet-gated, fail-closed. A chain that is not on the verifier
/// allow-list is rejected by the prepare-only signing path.
#[test]
fn x402_prepare_only_signing_rejects_non_allowed_chain() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let mut trust = sample_testnet_x402_verifier_trust();
    // Allow a DIFFERENT testnet, not the bundle chain.
    trust.allowed_chain_ids = vec!["eip155:11155111".to_string()];
    let kernel = operator_keypair();

    assert!(matches!(
        sign_x402_settlement_attestation(&bundle, &trust, &kernel, "x402-attestation-1", 1_743_293_900),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("x402 prepare-only chain id is not allowed")
    ));
}

/// M2-14: testnet-gated, fail-closed. The path refuses to sign unless the
/// verifier policy explicitly blocks mainnet.
#[test]
fn x402_prepare_only_signing_requires_mainnet_blocked_policy() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let mut trust = sample_testnet_x402_verifier_trust();
    trust.mainnet_blocked = false;
    let kernel = operator_keypair();

    assert!(matches!(
        sign_x402_settlement_attestation(&bundle, &trust, &kernel, "x402-attestation-1", 1_743_293_900),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("requires a mainnet-blocked verifier policy")
    ));
}

/// M2-14: an empty attestation id is rejected fail-closed.
#[test]
fn x402_prepare_only_signing_rejects_blank_attestation_id() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let trust = sample_testnet_x402_verifier_trust();
    let kernel = operator_keypair();

    assert!(matches!(
        sign_x402_settlement_attestation(&bundle, &trust, &kernel, "  ", 1_743_293_900),
        Err(Web3ContractError::MissingField(
            "x402_settlement_attestation.attestation_id"
        ))
    ));
}

/// PR959 codex P2 (RPI-1 follow-on): the signing path refuses to attest a report
/// that carries NO grounded finality claim. With a trust config that has no
/// independent chain head, the recompute lane WITHHOLDS
/// `claim.public_settlement.finality_verified` (its confirmation depth is then
/// only producer-asserted), so the kernel must NOT lend its signature to that
/// report. A bundle that inflates `observed_confirmations` cannot ride a
/// kernel-signed attestation without an independent head.
#[test]
fn x402_prepare_only_signing_requires_grounded_finality_claim() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let mut trust = sample_testnet_x402_verifier_trust();
    // Strip the independent chain head: finality can no longer be grounded.
    trust.independent_chain_head = None;
    let kernel = operator_keypair();

    // Sanity: the recompute still SUCCEEDS (a verified settlement report), it just
    // does not emit the grounded finality claim.
    let report = verify_public_settlement_proof(&bundle, &trust).unwrap();
    assert!(
        !report.verified_claims.iter().any(
            |claim| claim == crate::settlement_proof::CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED
        ),
        "without an independent head the finality claim must be withheld"
    );

    // But signing is DENIED fail-closed: no grounded finality, no attestation.
    assert!(matches!(
        sign_x402_settlement_attestation(&bundle, &trust, &kernel, "x402-attestation-1", 1_743_293_900),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("grounded finality claim")
    ));

    // Re-attaching the independent head restores the grounded path and signing
    // succeeds, confirming the head (not some unrelated gate) is the control.
    let grounded = sample_testnet_x402_verifier_trust();
    sign_x402_settlement_attestation(
        &bundle,
        &grounded,
        &kernel,
        "x402-attestation-1",
        1_743_293_900,
    )
    .expect("a grounded finality claim permits signing");
}

/// M2-14: verification is fail-closed on the attesting key. An attestation
/// signed by a key that is not a trusted kernel key is rejected, even though the
/// underlying settlement proof recomputes.
#[test]
fn x402_verify_rejects_untrusted_kernel_key() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let trust = sample_testnet_x402_verifier_trust();
    // Sign with a key that is NOT in trusted_anchor_kernel_keys.
    let attestation = sign_x402_settlement_attestation(
        &bundle,
        &trust,
        &custodian_keypair(),
        "x402-attestation-1",
        1_743_293_900,
    )
    .unwrap();

    assert!(matches!(
        verify_x402_settlement_attestation(&attestation, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("kernel key is not trusted")
    ));
}

/// M2-14: a tampered signature is rejected fail-closed by the recompute-and-check
/// signature verification over the canonical body.
#[test]
fn x402_verify_rejects_tampered_signature() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let trust = sample_testnet_x402_verifier_trust();
    let kernel = operator_keypair();
    let mut attestation = sign_x402_settlement_attestation(
        &bundle,
        &trust,
        &kernel,
        "x402-attestation-1",
        1_743_293_900,
    )
    .unwrap();
    attestation.signature = Signature::from_hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    assert!(matches!(
        verify_x402_settlement_attestation(&attestation, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("signature verification failed")
    ));
}

/// M2-14: the prepare-only broadcast intent moves NO value. It records
/// `value_moved_on_chain = false`, is prepare-only and testnet-gated, and marks
/// the live money-movement leg (the CDP leg, M2-16) as out of scope and blocked.
#[test]
fn x402_prepare_only_broadcast_intent_moves_no_value() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let trust = sample_testnet_x402_verifier_trust();
    let kernel = operator_keypair();
    let attestation = sign_x402_settlement_attestation(
        &bundle,
        &trust,
        &kernel,
        "x402-attestation-1",
        1_743_293_900,
    )
    .unwrap();

    let intent = prepare_x402_broadcast_intent(
        &attestation,
        &trust,
        "x402-broadcast-intent-1",
        1_743_293_950,
    )
    .unwrap();

    assert_eq!(
        intent.schema,
        CHIO_X402_PREPARE_ONLY_BROADCAST_INTENT_SCHEMA
    );
    assert_eq!(intent.chain_id, X402_TESTNET_CHAIN_ID);
    assert_eq!(intent.attestation_id, attestation.body.attestation_id);
    assert_eq!(
        intent.attestation_digest,
        sha256_hex(&canonical_json_bytes(&attestation).unwrap())
    );
    // NO value moves: prepare-only, testnet-gated, live leg out of scope/blocked.
    assert!(!intent.value_moved_on_chain);
    assert!(!intent.would_move_value());
    assert!(intent.prepare_only);
    assert!(intent.testnet_gated);
    assert_eq!(
        intent.live_money_movement_leg,
        X402LiveMoneyMovementLeg::OutOfScopeBlockedPendingPartner
    );
}

/// M2-14: building a broadcast intent re-verifies the attestation fail-closed.
/// A trust context that no longer allows the chain rejects the intent.
#[test]
fn x402_prepare_only_broadcast_intent_rejects_unverifiable_attestation() {
    let bundle = sample_testnet_public_settlement_proof_bundle();
    let trust = sample_testnet_x402_verifier_trust();
    let kernel = operator_keypair();
    let attestation = sign_x402_settlement_attestation(
        &bundle,
        &trust,
        &kernel,
        "x402-attestation-1",
        1_743_293_900,
    )
    .unwrap();

    let mut hostile_trust = trust.clone();
    hostile_trust.allowed_chain_ids = vec!["eip155:11155111".to_string()];

    assert!(matches!(
        prepare_x402_broadcast_intent(&attestation, &hostile_trust, "x402-broadcast-intent-1", 1_743_293_950),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("x402 prepare-only chain id is not allowed")
    ));
}
