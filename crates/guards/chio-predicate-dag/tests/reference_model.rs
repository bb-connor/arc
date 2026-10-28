//! The reference-dimension model (537 atoms, 236 rules, 2124 clauses) is
//! compiled by `cargo xtask gen decision-model` from
//! `fixtures/reference-rules.json` and `fixtures/reference-thresholds.json`.
//! `fixtures/reference-cells.bin` holds atom trit planes with the rule trits
//! and outcome computed by an independent strong Kleene evaluator over the
//! JSON rules: magic `CDC1`, version `1`, reserved `0`, a `u32` cell count,
//! then per cell 16 atom-positive words, 16 atom-negative words, 8
//! rule-positive words, 8 rule-negative words and an outcome byte (`0`
//! Allow, `1` Hold, `2` Deny) padded to 8 bytes, little-endian.

mod common;

use chio_predicate_dag::{DagError, Outcome, TriSet, ATOM_WORDS, RULE_WORDS};
use common::storage;
use sha2::{Digest, Sha256};

const MODEL: &[u8] = include_bytes!("fixtures/reference-model.cdm");
const MODEL_SHA256: &str = include_str!("fixtures/reference-model.sha256");
const CELLS: &[u8] = include_bytes!("fixtures/reference-cells.bin");
const CELLS_HEADER: usize = 12;
const CELL_LEN: usize = (2 * ATOM_WORDS + 2 * RULE_WORDS) * 8 + 8;

fn words<const W: usize>(bytes: &[u8]) -> [u64; W] {
    let mut out = [0u64; W];
    for (word, chunk) in out.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(chunk);
        *word = u64::from_le_bytes(raw);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn reference_model_matches_its_digest_and_dimensions() -> Result<(), DagError> {
    let digest = hex(&Sha256::digest(MODEL));
    assert_eq!(
        MODEL_SHA256.split_whitespace().next(),
        Some(digest.as_str())
    );
    let mut guard = storage();
    guard.decode(MODEL)?;
    let schedule = guard.schedule()?;
    assert_eq!(schedule.atom_count(), 537);
    assert_eq!(schedule.rule_count(), 236);
    let ops = (MODEL.len() - 16 - 537 * 8) / 12;
    assert_eq!(usize::try_from(schedule.op_count()).ok(), Some(ops));
    let clauses = MODEL[16 + 537 * 8..]
        .chunks_exact(12)
        .filter(|op| op[0] == 5)
        .count();
    assert_eq!(clauses, 2124);
    Ok(())
}

#[test]
fn reference_cells_have_zero_mismatches() -> Result<(), DagError> {
    assert_eq!(&CELLS[..4], b"CDC1");
    assert_eq!(&CELLS[4..8], &[1, 0, 0, 0]);
    let count = usize::try_from(u32::from_le_bytes([
        CELLS[8], CELLS[9], CELLS[10], CELLS[11],
    ]))
    .unwrap_or(usize::MAX);
    assert_eq!(CELLS.len(), CELLS_HEADER + count * CELL_LEN);
    assert!(count >= 256);

    let mut guard = storage();
    guard.decode(MODEL)?;
    let schedule = guard.schedule()?;
    let mut seen = [0usize; 3];
    let mut mismatches = 0usize;
    for cell in CELLS[CELLS_HEADER..].chunks_exact(CELL_LEN) {
        let (atoms, rest) = cell.split_at(2 * ATOM_WORDS * 8);
        let (rules, outcome) = rest.split_at(2 * RULE_WORDS * 8);
        let (pos, neg) = atoms.split_at(ATOM_WORDS * 8);
        let input = TriSet::new(words(pos), words(neg), 537)?;
        let (rule_pos, rule_neg) = rules.split_at(RULE_WORDS * 8);
        let expected_rules = TriSet::new(words(rule_pos), words(rule_neg), 236)?;
        let expected = match outcome[0] {
            0 => Outcome::Allow,
            1 => Outcome::Hold,
            2 => Outcome::Deny,
            other => panic!("outcome byte {other}"),
        };
        seen[usize::from(outcome[0])] += 1;
        let evaluation = schedule.evaluate(&input, schedule.op_count())?;
        if evaluation.rules != expected_rules || evaluation.outcome != expected {
            mismatches += 1;
        }
        assert_eq!(evaluation.work_ops, schedule.op_count());
    }
    assert_eq!(mismatches, 0);
    assert!(
        seen.iter().all(|n| *n > 0),
        "cells cover every outcome: {seen:?}"
    );
    Ok(())
}
