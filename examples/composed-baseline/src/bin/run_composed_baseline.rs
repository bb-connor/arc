//! Drives both corpora and both measurements and writes one JSON document.
//!
//! Usage: run-composed-baseline --work-dir DIR --out FILE [--calls N] [--warmup N]

use chio_composed_baseline::carriers;
use chio_composed_baseline::harness::Runner;
use chio_composed_baseline::measure;
use chio_composed_baseline::negative;
use chio_composed_baseline::properties;
use chio_composed_baseline::receiver::{
    BaselineProfile, DurabilityMode, PrivateProfile, DENIAL_CODES,
};
use chio_composed_baseline::scenario::Keys;
use chio_composed_baseline::spec;
use chio_composed_baseline::substitution;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(path) => {
            println!("composed baseline written: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("composed baseline failed: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<PathBuf, String> {
    let mut work_dir: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut calls: u64 = 200;
    let mut warmup: u64 = 20;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--work-dir" => work_dir = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--calls" => {
                calls = value()?
                    .parse()
                    .map_err(|_| "--calls must be a nonnegative integer".to_string())?;
            }
            "--warmup" => {
                warmup = value()?
                    .parse()
                    .map_err(|_| "--warmup must be a nonnegative integer".to_string())?;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }

    let work_dir = work_dir.ok_or_else(|| "--work-dir is required".to_string())?;
    let out = out.ok_or_else(|| "--out is required".to_string())?;
    std::fs::create_dir_all(&work_dir).map_err(|error| error.to_string())?;

    let keys = Keys::fixed();

    let composed = Runner::new(
        &keys,
        BaselineProfile::Composed,
        DurabilityMode::BeforeDispatch,
        &work_dir,
    );
    let hardened = Runner::new(
        &keys,
        BaselineProfile::Hardened,
        DurabilityMode::BeforeDispatch,
        &work_dir,
    );

    // The same hardened wiring with an operator's own agreed name installed.
    // Neither shipped wiring carries one; this runner exists to measure what
    // agreeing on one buys.
    let private = Runner::new(
        &keys,
        BaselineProfile::Hardened,
        DurabilityMode::BeforeDispatch,
        &work_dir,
    )
    .with_private_profile(PrivateProfile::agreement_version());

    let negative_results = negative::run(&composed, &hardened)?;
    let substitution_results = substitution::run(&composed, &hardened)?;
    let carrier_ledger = carriers::run(&composed, &hardened, &private)?;
    let property_results = properties::evaluate(&negative_results)?;

    // The null case must admit, or every denial in the corpus is unattributable.
    let null_case = negative_results
        .iter()
        .find(|result| result.baseline_case_id == "unmodified-admissible-call")
        .ok_or_else(|| "the corpus did not carry its null case".to_string())?;
    for (label, observed) in [
        ("composed", null_case.composed.as_ref()),
        ("hardened", null_case.hardened.as_ref()),
    ] {
        let observed =
            observed.ok_or_else(|| format!("the null case did not run under {label}"))?;
        if !observed.dispatched {
            return Err(format!(
                "the null case was denied under {label} ({:?}); every other denial in the corpus is then unattributable",
                observed.denial_code
            ));
        }
    }

    let measurements = vec![
        measure::measure(
            &keys,
            &Runner::new(
                &keys,
                BaselineProfile::Composed,
                DurabilityMode::BeforeDispatch,
                &work_dir,
            ),
            &work_dir,
            calls,
            warmup,
        )?,
        measure::measure(
            &keys,
            &Runner::new(
                &keys,
                BaselineProfile::Composed,
                DurabilityMode::AfterDispatch,
                &work_dir,
            ),
            &work_dir,
            calls,
            warmup,
        )?,
        measure::measure(
            &keys,
            &Runner::new(
                &keys,
                BaselineProfile::Hardened,
                DurabilityMode::BeforeDispatch,
                &work_dir,
            ),
            &work_dir,
            calls,
            warmup,
        )?,
    ];

    let document = json!({
        "schema": "chio.programmable-sovereignty.composed-baseline.v1",
        "baseline": {
            "parts": [
                "a tool call as the Model Context Protocol defines it",
                "an agent-to-agent message as the A2A protocol defines it",
                "a delegated credential as OAuth 2.0 token exchange defines it",
                "a workload identity as SPIFFE defines it",
            ],
            "documents": spec::DOCUMENTS
                .iter()
                .map(|document| {
                    json!({
                        "id": document.id,
                        "name": document.name,
                        "version": document.version,
                        "url": document.url,
                    })
                })
                .collect::<Vec<_>>(),
            "requestFields": spec::REQUEST_FIELDS
                .iter()
                .chain(spec::CREDENTIAL_FIELDS.iter())
                .chain(spec::CLAIM_FIELDS.iter())
                .chain(spec::HEADER_FIELDS.iter())
                .map(|field| {
                    json!({
                        "path": field.path,
                        "document": field.document,
                        "section": field.section,
                    })
                })
                .collect::<Vec<_>>(),
            "freeFormSlots": spec::FREE_FORM_SLOTS
                .iter()
                .map(|slot| {
                    json!({
                        "path": slot.path,
                        "document": slot.document,
                        "section": slot.section,
                        "attestedBy": slot.attested_by.as_str(),
                        "note": slot.note,
                    })
                })
                .collect::<Vec<_>>(),
            "profiles": {
                "composed": "each part wired the way its specification documents",
                "hardened": "the same parts with every operator-authored check written in",
            },
            "store": "SQLite, WAL, synchronous = FULL",
            "signatures": "Ed25519 and RFC 8785 canonical JSON, from the same Chio crate the receiver under comparison uses",
            "denialCodes": DENIAL_CODES
                .iter()
                .map(|(code, step)| json!({ "code": code, "step": step }))
                .collect::<Vec<_>>(),
        },
        "negativeCorpus": negative_results,
        "substitutionCorpus": substitution_results,
        "carrierLedger": carrier_ledger,
        "properties": property_results,
        "measurements": measurements,
        "method": {
            "percentile": "linear interpolation between order statistics",
            "confidence": 0.95,
            "bootstrap": { "resamples": 10_000, "seed": 1 },
            "latency": "the receiver's whole admission path in one process, from the arrival of a call to the return of a decision, including the durable append",
            "carriers": "for every field of the Chio binding reference, the document and section that carries it, or the slot an operator would have to agree on and the work that would take",
            "storage": "growth of the SQLite store, checkpointed before and after, divided by the calls measured",
        },
    });

    let encoded = serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?;
    std::fs::write(&out, format!("{encoded}\n")).map_err(|error| error.to_string())?;
    Ok(out)
}
