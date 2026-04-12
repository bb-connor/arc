use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_anchor::{
    ensure_anchor_operation_allowed, AnchorAlertSeverity, AnchorControlState,
    AnchorEmergencyControls, AnchorEmergencyMode, AnchorIncidentAlert, AnchorIndexerCursor,
    AnchorLaneKind, AnchorLaneRuntimeStatus, AnchorOperationKind, AnchorRuntimeReport,
};
use arc_link::config::{
    OracleBackendKind, PairConfig, PairRuntimeOverride, PriceOracleConfig, ARBITRUM_ONE_CHAIN_ID,
};
use arc_link::control::ArcLinkControlState;
use arc_link::{ArcLinkOracle, ExchangeRate, OracleBackend, OracleFuture, PriceOracleError};
use arc_settle::{
    ensure_settlement_operation_allowed, SettlementAlertSeverity, SettlementControlState,
    SettlementEmergencyControls, SettlementEmergencyMode, SettlementFinalityStatus,
    SettlementIncidentAlert, SettlementIndexerCursor, SettlementIndexerStatus,
    SettlementLaneRuntimeStatus, SettlementOperationKind, SettlementRecoveryAction,
    SettlementRecoveryRecord, SettlementRuntimeReport,
};
use serde::Serialize;
use serde_json::json;

struct StaticBackend {
    kind: OracleBackendKind,
    responses: BTreeMap<String, Result<ExchangeRate, PriceOracleError>>,
}

impl StaticBackend {
    fn new(
        kind: OracleBackendKind,
        responses: impl IntoIterator<Item = (String, Result<ExchangeRate, PriceOracleError>)>,
    ) -> Self {
        Self {
            kind,
            responses: responses.into_iter().collect(),
        }
    }
}

impl OracleBackend for StaticBackend {
    fn kind(&self) -> OracleBackendKind {
        self.kind
    }

    fn read_rate<'a>(&'a self, pair: &'a PairConfig, _now: u64) -> OracleFuture<'a> {
        let response = self
            .responses
            .get(&pair.pair())
            .cloned()
            .unwrap_or_else(|| {
                Err(PriceOracleError::NoPairAvailable {
                    base: pair.base.clone(),
                    quote: pair.quote.clone(),
                })
            });
        Box::pin(async move { response })
    }
}

fn sample_rate(pair: &PairConfig, source: &str, numerator: u128, updated_at: u64) -> ExchangeRate {
    ExchangeRate {
        base: pair.base.clone(),
        quote: pair.quote.clone(),
        rate_numerator: numerator,
        rate_denominator: 100,
        updated_at,
        fetched_at: updated_at.saturating_add(15),
        source: source.to_string(),
        feed_reference: pair
            .chainlink
            .as_ref()
            .map(|feed| feed.address.clone())
            .or_else(|| pair.pyth.as_ref().map(|feed| feed.id.clone()))
            .unwrap_or_else(|| "feed-unavailable".to_string()),
        max_age_seconds: pair.policy.max_age_seconds,
        conversion_margin_bps: pair.policy.exchange_rate_margin_bps,
        confidence_numerator: None,
        confidence_denominator: None,
    }
}

fn output_root() -> PathBuf {
    if let Ok(path) = std::env::var("ARC_WEB3_OPS_OUTPUT_DIR") {
        return PathBuf::from(path);
    }
    std::env::temp_dir().join("arc-web3-ops-qualification")
}

fn write_json(path: &Path, value: &impl Serialize) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create output directory");
    }
    let payload = serde_json::to_vec_pretty(value).expect("serialize json");
    fs::write(path, payload).expect("write json output");
}

#[tokio::test]
async fn web3_ops_qualification_emits_generated_runtime_reports_and_control_audits() {
    let generated_at = 1_764_620_000;
    let base_rpc = "https://base-mainnet.example.invalid";
    let mut config = PriceOracleConfig::base_mainnet_default(base_rpc);
    for chain in &mut config.operator.chains {
        chain.sequencer_uptime_feed = None;
    }
    let initial_operator = config.operator.clone();

    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        config.pairs.iter().map(|pair| {
            let numerator = match pair.pair().as_str() {
                "ETH/USD" => 300_000,
                "BTC/USD" => 6_800_000,
                "USDC/USD" => 100,
                "LINK/USD" => 1_800,
                _ => 100,
            };
            (
                pair.pair(),
                Ok(sample_rate(
                    pair,
                    "chainlink:twap",
                    numerator,
                    generated_at - 45,
                )),
            )
        }),
    ));
    let fallback = Arc::new(StaticBackend::new(
        OracleBackendKind::Pyth,
        config.pairs.iter().filter_map(|pair| {
            pair.pyth.as_ref().map(|_| {
                (
                    pair.pair(),
                    Ok(sample_rate(pair, "pyth", 299_500, generated_at - 60)),
                )
            })
        }),
    ));
    let oracle = ArcLinkOracle::new_with_backends(config, primary, Some(fallback)).expect("oracle");

    let mut link_state = ArcLinkControlState::new(generated_at - 120, initial_operator);
    oracle
        .set_global_pause(true, Some("investigating price-source drift".to_string()))
        .await
        .expect("set global pause");
    link_state.record_global_pause(
        true,
        Some("investigating price-source drift".to_string()),
        "ops-oncall",
        "qualification_drill",
        generated_at - 110,
        "pause all conversions while chain and pair controls are reviewed",
    );
    oracle
        .set_global_pause(false, None)
        .await
        .expect("clear global pause");
    link_state.record_global_pause(
        false,
        None,
        "ops-oncall",
        "qualification_drill",
        generated_at - 105,
        "resume conversions after explicit pair and chain controls are set",
    );
    oracle
        .set_chain_enabled(ARBITRUM_ONE_CHAIN_ID, true)
        .await
        .expect("enable standby chain");
    link_state
        .record_chain_enabled(
            ARBITRUM_ONE_CHAIN_ID,
            true,
            "ops-oncall",
            "qualification_drill",
            generated_at - 95,
            "verify standby chain can be toggled before final disable",
        )
        .expect("record chain enable");
    oracle
        .set_chain_enabled(ARBITRUM_ONE_CHAIN_ID, false)
        .await
        .expect("disable standby chain");
    link_state
        .record_chain_enabled(
            ARBITRUM_ONE_CHAIN_ID,
            false,
            "ops-oncall",
            "qualification_drill",
            generated_at - 90,
            "leave standby chain disabled after the drill",
        )
        .expect("record chain disable");
    let btc_pair = oracle
        .config()
        .pairs
        .iter()
        .find(|pair| pair.base == "BTC" && pair.quote == "USD")
        .expect("btc pair")
        .clone();
    let disabled_btc = PairRuntimeOverride {
        enabled: false,
        ..PairRuntimeOverride::from_pair(&btc_pair)
    };
    oracle
        .set_pair_override(disabled_btc.clone())
        .await
        .expect("disable btc/usd pair");
    link_state
        .record_pair_override(
            disabled_btc,
            "ops-oncall",
            "qualification_drill",
            generated_at - 80,
            "freeze BTC/USD while operator incident review remains open",
        )
        .expect("record pair override");
    let link_report = oracle.runtime_report().await.expect("runtime report");
    assert!(!link_report.global_pause);
    assert!(link_report
        .alerts
        .iter()
        .any(|alert| alert.code == "pair_paused" && alert.pair.as_deref() == Some("BTC/USD")));
    assert!(link_report
        .chains
        .iter()
        .any(|chain| chain.chain_id == ARBITRUM_ONE_CHAIN_ID && !chain.enabled));

    let mut anchor_state = AnchorControlState::new(
        generated_at - 120,
        AnchorEmergencyControls::normal(generated_at - 120),
    );
    anchor_state.apply_change(
        AnchorEmergencyMode::PublishPaused,
        generated_at - 70,
        "ops-oncall",
        Some("pause new root publication during replay drill".to_string()),
        "qualification_drill",
    );
    anchor_state.apply_change(
        AnchorEmergencyMode::RecoveryOnly,
        generated_at - 60,
        "ops-oncall",
        Some("keep only canonical confirmation actions available".to_string()),
        "qualification_drill",
    );
    ensure_anchor_operation_allowed(
        anchor_state.controls.clone(),
        AnchorOperationKind::PublishRoot,
    )
    .expect_err("publish root denied during recovery");
    ensure_anchor_operation_allowed(
        anchor_state.controls.clone(),
        AnchorOperationKind::ConfirmPublication,
    )
    .expect("confirm publication allowed");

    let root_registry_indexer = AnchorIndexerCursor::from_sequences(
        "root-registry-indexer",
        AnchorLaneKind::EvmPrimary,
        Some("eip155:8453".to_string()),
        9_182,
        9_184,
        Some(29_920_123),
        true,
        false,
        generated_at - 10,
        Some("Indexer is replaying publishRoot events after a canonical rollback.".to_string()),
    );
    let ots_indexer = AnchorIndexerCursor::from_sequences(
        "ots-import-monitor",
        AnchorLaneKind::BitcoinOts,
        Some("bitcoin:mainnet".to_string()),
        9_182,
        9_184,
        None,
        false,
        false,
        generated_at - 12,
        Some("OTS attachment remains behind the canonical EVM head during replay.".to_string()),
    );
    let mut anchor_report = AnchorRuntimeReport::new(generated_at, anchor_state.controls.clone());
    anchor_report.indexers = vec![root_registry_indexer.clone(), ots_indexer.clone()];
    anchor_report.lanes = vec![
        AnchorLaneRuntimeStatus::from_indexer(
            AnchorLaneKind::EvmPrimary,
            Some("eip155:8453".to_string()),
            9_184,
            &root_registry_indexer,
            anchor_state.controls.clone(),
            2,
            Some(generated_at - 40),
            Some(
                "confirm the canonical publishRoot event for checkpoint 9184 before resuming new publication"
                    .to_string(),
            ),
            Some("Primary publication remains in recovery-only mode.".to_string()),
        ),
        AnchorLaneRuntimeStatus::from_indexer(
            AnchorLaneKind::BitcoinOts,
            Some("bitcoin:mainnet".to_string()),
            9_184,
            &ots_indexer,
            anchor_state.controls.clone(),
            0,
            Some(generated_at - 50),
            Some("hold imported OTS attachment until the EVM lane reconverges".to_string()),
            Some("Secondary proof import is gated behind canonical replay.".to_string()),
        ),
    ];
    anchor_report.incidents = vec![
        AnchorIncidentAlert {
            code: "root_registry_reorg".to_string(),
            severity: AnchorAlertSeverity::Critical,
            lane: AnchorLaneKind::EvmPrimary,
            chain_id: Some("eip155:8453".to_string()),
            checkpoint_seq: Some(9_184),
            observed_at: generated_at - 60,
            message:
                "Observed root publication disappeared from canonical Base history and requires replay."
                    .to_string(),
        },
        AnchorIncidentAlert {
            code: "secondary_proof_import_paused".to_string(),
            severity: AnchorAlertSeverity::Warning,
            lane: AnchorLaneKind::BitcoinOts,
            chain_id: Some("bitcoin:mainnet".to_string()),
            checkpoint_seq: Some(9_184),
            observed_at: generated_at - 55,
            message:
                "Secondary proof import remains paused until the primary EVM lane is canonical again."
                    .to_string(),
        },
    ];
    assert_eq!(
        anchor_report.controls.mode,
        AnchorEmergencyMode::RecoveryOnly
    );

    let mut settlement_state = SettlementControlState::new(
        generated_at - 120,
        SettlementEmergencyControls::normal(generated_at - 120),
    );
    settlement_state.apply_change(
        SettlementEmergencyMode::DispatchPaused,
        generated_at - 50,
        "ops-oncall",
        Some(
            "pause new escrow dispatch while canonical settlement history is reviewed".to_string(),
        ),
        "qualification_drill",
    );
    settlement_state.apply_change(
        SettlementEmergencyMode::RefundOnly,
        generated_at - 40,
        "ops-oncall",
        Some("keep only refund and impairment actions writable during replay".to_string()),
        "qualification_drill",
    );
    ensure_settlement_operation_allowed(
        settlement_state.controls.clone(),
        SettlementOperationKind::DispatchEscrow,
    )
    .expect_err("dispatch denied during refund-only mode");
    ensure_settlement_operation_allowed(
        settlement_state.controls.clone(),
        SettlementOperationKind::RefundEscrow,
    )
    .expect("refund allowed");

    let escrow_indexer = SettlementIndexerCursor::from_blocks(
        "escrow-release-indexer",
        "eip155:8453",
        Some(29_920_145),
        29_920_148,
        true,
        false,
        generated_at - 15,
        Some("Escrow release events are being replayed against the canonical head.".to_string()),
    );
    let bond_indexer = SettlementIndexerCursor::from_blocks(
        "bond-watchdog-indexer",
        "eip155:8453",
        Some(29_920_148),
        29_920_148,
        false,
        false,
        generated_at - 14,
        Some("Bond lifecycle observation is current.".to_string()),
    );
    let recovery = SettlementRecoveryRecord {
        execution_receipt_id: "arc.web3-execution-receipt.replay-001".to_string(),
        chain_id: "eip155:8453".to_string(),
        tx_hash: "0x9c4c7e6af6a876d4dd9d9a4e66d60b7222d7c23bb0b4f5a0f2d43c1d3f0ac7bb".to_string(),
        finality_status: SettlementFinalityStatus::Reorged,
        recovery_action: Some(SettlementRecoveryAction::ResubmitAfterReorg),
        reorg_depth: Some(2),
        observed_at: generated_at - 20,
        note: Some(
            "Merkle release disappeared from canonical Base history and must be rebuilt."
                .to_string(),
        ),
    };
    let mut settlement_report =
        SettlementRuntimeReport::new(generated_at, settlement_state.controls.clone());
    settlement_report.indexers = vec![escrow_indexer.clone(), bond_indexer];
    settlement_report.lanes = vec![SettlementLaneRuntimeStatus::new(
        "eip155:8453",
        "Base Mainnet",
        SettlementIndexerStatus::Replaying,
        Some(SettlementFinalityStatus::Reorged),
        settlement_state.controls.clone(),
        1,
        Some(generated_at - 15),
        Some(
            "New dispatch is paused; refunds and expiry remain allowed while replay completes."
                .to_string(),
        ),
    )];
    settlement_report.recoveries = vec![recovery.clone()];
    settlement_report.incidents = vec![
        SettlementIncidentAlert {
            code: "settlement_reorg".to_string(),
            severity: SettlementAlertSeverity::Critical,
            chain_id: "eip155:8453".to_string(),
            execution_receipt_id: Some(recovery.execution_receipt_id.clone()),
            observed_at: generated_at - 20,
            message:
                "Confirmed settlement receipt no longer matches canonical chain history."
                    .to_string(),
        },
        SettlementIncidentAlert {
            code: "refund_only_mode".to_string(),
            severity: SettlementAlertSeverity::Warning,
            chain_id: "eip155:8453".to_string(),
            execution_receipt_id: None,
            observed_at: generated_at - 40,
            message:
                "New dispatch and beneficiary release remain paused while refund-first recovery is active."
                    .to_string(),
        },
    ];
    assert_eq!(
        settlement_report.controls.mode,
        SettlementEmergencyMode::RefundOnly
    );

    let root = output_root();
    let runtime_reports_dir = root.join("runtime-reports");
    let control_state_dir = root.join("control-state");
    let control_traces_dir = root.join("control-traces");
    write_json(
        &runtime_reports_dir.join("arc-link-runtime-report.json"),
        &link_report,
    );
    write_json(
        &runtime_reports_dir.join("arc-anchor-runtime-report.json"),
        &anchor_report,
    );
    write_json(
        &runtime_reports_dir.join("arc-settle-runtime-report.json"),
        &settlement_report,
    );
    write_json(
        &control_state_dir.join("arc-link-control-state.json"),
        &link_state,
    );
    write_json(
        &control_state_dir.join("arc-anchor-control-state.json"),
        &anchor_state,
    );
    write_json(
        &control_state_dir.join("arc-settle-control-state.json"),
        &settlement_state,
    );
    write_json(
        &control_traces_dir.join("arc-link-control-trace.json"),
        &link_state.history,
    );
    write_json(
        &control_traces_dir.join("arc-anchor-control-trace.json"),
        &anchor_state.history,
    );
    write_json(
        &control_traces_dir.join("arc-settle-control-trace.json"),
        &settlement_state.history,
    );
    let incident_audit = json!({
        "schema": "arc.web3-ops-incident-audit.v1",
        "generatedAt": generated_at,
        "drill": "phase-175-operator-controls",
        "artifacts": {
            "runtimeReports": [
                "runtime-reports/arc-link-runtime-report.json",
                "runtime-reports/arc-anchor-runtime-report.json",
                "runtime-reports/arc-settle-runtime-report.json"
            ],
            "controlState": [
                "control-state/arc-link-control-state.json",
                "control-state/arc-anchor-control-state.json",
                "control-state/arc-settle-control-state.json"
            ],
            "controlTraces": [
                "control-traces/arc-link-control-trace.json",
                "control-traces/arc-anchor-control-trace.json",
                "control-traces/arc-settle-control-trace.json"
            ]
        },
        "assertions": [
            {
                "component": "arc-link",
                "result": "pass",
                "details": "runtime report reflects pair pause and disabled standby chain after explicit operator actions"
            },
            {
                "component": "arc-anchor",
                "result": "pass",
                "details": "recovery-only mode denies new publication while preserving confirmation actions"
            },
            {
                "component": "arc-settle",
                "result": "pass",
                "details": "refund-only mode blocks dispatch and retains explicit reorg recovery records"
            }
        ]
    });
    write_json(&root.join("incident-audit.json"), &incident_audit);

    let written_link: arc_link::monitor::OracleRuntimeReport = serde_json::from_slice(
        &fs::read(runtime_reports_dir.join("arc-link-runtime-report.json"))
            .expect("read link report"),
    )
    .expect("parse link report");
    assert!(written_link
        .pairs
        .iter()
        .any(|pair| pair.pair == "BTC/USD"
            && pair.status == arc_link::monitor::PairHealthStatus::Paused));
    let written_anchor: AnchorRuntimeReport = serde_json::from_slice(
        &fs::read(runtime_reports_dir.join("arc-anchor-runtime-report.json"))
            .expect("read anchor report"),
    )
    .expect("parse anchor report");
    assert_eq!(
        written_anchor.controls.mode,
        AnchorEmergencyMode::RecoveryOnly
    );
    let written_settlement: SettlementRuntimeReport = serde_json::from_slice(
        &fs::read(runtime_reports_dir.join("arc-settle-runtime-report.json"))
            .expect("read settlement report"),
    )
    .expect("parse settlement report");
    assert_eq!(
        written_settlement.controls.mode,
        SettlementEmergencyMode::RefundOnly
    );
    let written_audit: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("incident-audit.json")).expect("read incident audit"),
    )
    .expect("parse incident audit");
    assert_eq!(written_audit["schema"], "arc.web3-ops-incident-audit.v1");
}
