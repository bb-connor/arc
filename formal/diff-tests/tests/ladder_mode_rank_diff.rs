#![cfg(not(target_arch = "wasm32"))]

//! Differential evidence that `chio-federation` and `chio-runtime-core`
//! parse the governance ladder mode vocabulary identically.
//!
//! The federation parser is called directly. The runtime parser sits behind
//! the exported manifest validator, so it is observed the way admission
//! observes it: a string is a mode iff the validator accepts it as the
//! destructive floor, and mode `b` ranks at or above mode `a` iff a
//! destructive action in mode `b` clears a destructive floor of `a`.

use chio_federation::treaty::ladder_mode_rank;
use chio_runtime_core::{
    validate_governance_ladder_manifest, GovernanceLadderActionClass, GovernanceLadderManifest,
    CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

const CANONICAL_MODES: [&str; 5] = [
    "observation",
    "guarded",
    "receipt_backed",
    "partition_contingency",
    "maintenance",
];

const FIXED_INPUTS: [&str; 16] = [
    "observation",
    "guarded",
    "receipt_backed",
    "partition_contingency",
    "maintenance",
    "quorum_required",
    "quorum-required",
    "receipt-backed",
    "partition-contingency",
    "receiptBacked",
    "Observation",
    "MAINTENANCE",
    "maintenance ",
    " maintenance",
    "maintenance\0",
    "",
];

const FEDERATION_INVALID_MODE: &str = "chio_federation_ladder_invalid_mode";
const RUNTIME_INVALID_MODE: &str = "chio_ladder_invalid_mode";

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 2_048,
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

fn manifest(floor: &str, action_mode: &str, destructive: bool) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: "ladder-diff".to_string(),
        kernel_id: "kernel.diff".to_string(),
        issuer: "did:chio:kernel.diff".to_string(),
        key_id: "ladder-key-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        destructive_floor: floor.to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![GovernanceLadderActionClass {
            action_class_id: "workflow.diff".to_string(),
            mode: action_mode.to_string(),
            destructive,
            consistency_model: "totally-ordered".to_string(),
            co_sign: "bilateral_required".to_string(),
            co_sign_quorum: None,
            evidence_required: vec!["governance_receipt".to_string()],
            aliases: Vec::new(),
        }],
    }
}

fn federation_verdict(mode: &str) -> Result<u8, &'static str> {
    ladder_mode_rank(mode).map_err(|error| error.code())
}

fn runtime_verdict(mode: &str) -> Result<(), &'static str> {
    validate_governance_ladder_manifest(&manifest(mode, "observation", false))
        .map_err(|error| error.code())
}

fn runtime_ranks_at_least(mode: &str, floor: &str) -> bool {
    validate_governance_ladder_manifest(&manifest(floor, mode, true)).is_ok()
}

fn assert_same_verdict(mode: &str) {
    match (federation_verdict(mode), runtime_verdict(mode)) {
        (Ok(_), Ok(())) => {}
        (Err(federation), Err(runtime)) => {
            assert_eq!(federation, FEDERATION_INVALID_MODE, "{mode:?}");
            assert_eq!(runtime, RUNTIME_INVALID_MODE, "{mode:?}");
        }
        (federation, runtime) => {
            panic!("{mode:?}: federation {federation:?}, runtime {runtime:?}")
        }
    }
}

fn arb_mode_candidate() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => "[a-z_-]{0,24}",
        2 => "[ -~]{0,24}",
        4 => (
            prop::sample::select(&CANONICAL_MODES[..]),
            0_u8..5,
            "[ -~]{1,2}",
        )
            .prop_map(|(base, edit, extra)| match edit {
                0 => base.replace('_', "-"),
                1 => format!("{base}{extra}"),
                2 => format!("{extra}{base}"),
                3 => base.to_ascii_uppercase(),
                _ => base.chars().rev().collect(),
            }),
    ]
}

#[test]
fn canonical_modes_rank_zero_to_four_in_both_crates() {
    for (expected, mode) in CANONICAL_MODES.iter().enumerate() {
        let rank = match federation_verdict(mode) {
            Ok(rank) => rank,
            Err(code) => panic!("{mode} rejected by federation with {code}"),
        };
        assert_eq!(usize::from(rank), expected, "{mode}");
        assert_eq!(runtime_verdict(mode), Ok(()), "{mode}");
    }
    for floor in CANONICAL_MODES {
        for mode in CANONICAL_MODES {
            let federation = federation_verdict(mode) >= federation_verdict(floor);
            assert_eq!(
                runtime_ranks_at_least(mode, floor),
                federation,
                "mode {mode} against floor {floor}"
            );
        }
    }
}

#[test]
fn fixed_spellings_get_the_same_verdict() {
    for mode in FIXED_INPUTS {
        assert_same_verdict(mode);
    }
    for mode in ["quorum_required", "quorum-required", ""] {
        assert_eq!(
            federation_verdict(mode),
            Err(FEDERATION_INVALID_MODE),
            "{mode:?}"
        );
        assert_eq!(runtime_verdict(mode), Err(RUNTIME_INVALID_MODE), "{mode:?}");
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn short_ascii_strings_get_the_same_verdict(mode in arb_mode_candidate()) {
        assert_same_verdict(&mode);
    }
}
