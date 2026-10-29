//! `cargo xtask gen decision-model`: compiles a rules file and a thresholds
//! file into a canonical `chio.decision-model.v1` artifact.
//!
//! The rules file is `{"atoms": N, "rules": [{"polarity": "deny" | "hold" |
//! "advisory", "clauses": [[{"atom": i, "negated": bool} | {"rule": j,
//! "negated": bool}, ...], ...]}, ...]}`; `negated` defaults to false. The
//! thresholds file is `{"thresholds": [{"tau_neg": bits, "tau_pos": bits},
//! ...]}` with Q16.16 bits, one entry per atom. Literals in a clause and
//! clauses in a rule are sorted and deduplicated, and atom literals of one
//! word and polarity are merged into one mask. Anything else that is not
//! canonical is refused: an empty rule or clause, an atom or rule id out of
//! range, a rule literal that does not name an earlier rule, an inverted
//! threshold pair, or a count over the crate caps. The output is decoded by
//! `chio-predicate-dag` before it is written, and `--check` compares it with
//! the existing file byte for byte.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use chio_predicate_dag::{
    DagError, ScheduleStorage, ARTIFACT_MAGIC, ARTIFACT_VERSION, MAX_ATOMS, MAX_CLAUSES,
    MAX_CLAUSES_PER_RULE, MAX_LITERALS_PER_CLAUSE, MAX_RULES, MAX_SCHEDULE_OPS,
};
use serde::Deserialize;

use super::{display_path, XtaskError};

const CODE_ATOM_POS: u8 = 1;
const CODE_ATOM_NEG: u8 = 2;
const CODE_RULE_POS: u8 = 3;
const CODE_RULE_NEG: u8 = 4;
const CODE_END_CLAUSE: u8 = 5;
const CODE_END_RULE: u8 = 6;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    atoms: u16,
    rules: Vec<RuleSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    polarity: Polarity,
    clauses: Vec<Vec<LiteralSpec>>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Polarity {
    Deny,
    Hold,
    Advisory,
}

impl Polarity {
    fn word(self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::Hold => 1,
            Self::Advisory => 2,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiteralSpec {
    #[serde(default)]
    atom: Option<u16>,
    #[serde(default)]
    rule: Option<u16>,
    #[serde(default)]
    negated: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdsFile {
    thresholds: Vec<ThresholdSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdSpec {
    tau_neg: i32,
    tau_pos: i32,
}

/// One encoded op: opcode, word, argument, mask.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct WireOp {
    code: u8,
    word: u8,
    arg: u16,
    mask: u64,
}

impl WireOp {
    /// The decoder's canonical ordering key: atoms before rules, then word,
    /// then rule bit (zero for atoms), then positive before negated, then mask.
    fn key(&self) -> (u8, u8, u64, bool, u64) {
        match self.code {
            CODE_ATOM_POS | CODE_ATOM_NEG => {
                (0, self.word, 0, self.code == CODE_ATOM_NEG, self.mask)
            }
            _ => {
                let bit = 1u64 << (self.arg % 64);
                let word = u8::try_from(self.arg / 64).unwrap_or(u8::MAX);
                (1, word, bit, self.code == CODE_RULE_NEG, bit)
            }
        }
    }
}

fn refuse(detail: impl Into<String>) -> XtaskError {
    XtaskError::DecisionModel(detail.into())
}

fn clause_ops(
    rule: usize,
    clause: usize,
    literals: &[LiteralSpec],
    atoms: u16,
) -> Result<Vec<WireOp>, XtaskError> {
    if literals.is_empty() {
        return Err(refuse(format!("rule {rule} clause {clause} is empty")));
    }
    let mut atom_masks = std::collections::BTreeMap::<(u8, bool), u64>::new();
    let mut rule_literals = BTreeSet::<(u16, bool)>::new();
    for literal in literals {
        match (literal.atom, literal.rule) {
            (Some(atom), None) => {
                if atom >= atoms {
                    return Err(refuse(format!(
                        "rule {rule} clause {clause} names atom {atom} of {atoms}"
                    )));
                }
                let word = u8::try_from(atom / 64)
                    .map_err(|_| refuse(format!("atom {atom} word out of range")))?;
                *atom_masks.entry((word, literal.negated)).or_default() |= 1u64 << (atom % 64);
            }
            (None, Some(earlier)) => {
                if usize::from(earlier) >= rule {
                    return Err(refuse(format!(
                        "rule {rule} clause {clause} names rule {earlier}, which is not earlier"
                    )));
                }
                rule_literals.insert((earlier, literal.negated));
            }
            _ => {
                return Err(refuse(format!(
                    "rule {rule} clause {clause} has a literal without exactly one of atom or rule"
                )))
            }
        }
    }
    let mut ops: Vec<WireOp> = atom_masks
        .into_iter()
        .map(|((word, negated), mask)| WireOp {
            code: if negated {
                CODE_ATOM_NEG
            } else {
                CODE_ATOM_POS
            },
            word,
            arg: 0,
            mask,
        })
        .chain(rule_literals.into_iter().map(|(id, negated)| WireOp {
            code: if negated {
                CODE_RULE_NEG
            } else {
                CODE_RULE_POS
            },
            word: 0,
            arg: id,
            mask: 0,
        }))
        .collect();
    ops.sort_by_key(WireOp::key);
    if ops.len() > MAX_LITERALS_PER_CLAUSE {
        return Err(refuse(format!(
            "rule {rule} clause {clause} has {} literal ops, over {MAX_LITERALS_PER_CLAUSE}",
            ops.len()
        )));
    }
    Ok(ops)
}

/// Compiles parsed rule and threshold files into artifact bytes.
fn compile(rules: &RulesFile, thresholds: &ThresholdsFile) -> Result<Vec<u8>, XtaskError> {
    let atoms = usize::from(rules.atoms);
    if atoms == 0 || atoms > MAX_ATOMS {
        return Err(refuse(format!(
            "atom count {atoms} is outside 1..={MAX_ATOMS}"
        )));
    }
    if thresholds.thresholds.len() != atoms {
        return Err(refuse(format!(
            "{} threshold pairs for {atoms} atoms",
            thresholds.thresholds.len()
        )));
    }
    if rules.rules.is_empty() || rules.rules.len() > MAX_RULES {
        return Err(refuse(format!(
            "rule count {} is outside 1..={MAX_RULES}",
            rules.rules.len()
        )));
    }
    let mut ops = Vec::new();
    let mut total_clauses = 0usize;
    for (index, rule) in rules.rules.iter().enumerate() {
        let mut clauses = Vec::with_capacity(rule.clauses.len());
        for (clause, literals) in rule.clauses.iter().enumerate() {
            clauses.push(clause_ops(index, clause, literals, rules.atoms)?);
        }
        clauses.sort_by(|a, b| a.iter().map(WireOp::key).cmp(b.iter().map(WireOp::key)));
        clauses.dedup();
        if clauses.is_empty() || clauses.len() > MAX_CLAUSES_PER_RULE {
            return Err(refuse(format!(
                "rule {index} has {} clauses, outside 1..={MAX_CLAUSES_PER_RULE}",
                clauses.len()
            )));
        }
        total_clauses += clauses.len();
        for clause in clauses {
            ops.extend(clause);
            ops.push(WireOp {
                code: CODE_END_CLAUSE,
                word: 0,
                arg: 0,
                mask: 0,
            });
        }
        ops.push(WireOp {
            code: CODE_END_RULE,
            word: rule.polarity.word(),
            arg: u16::try_from(index).map_err(|_| refuse("rule id out of range"))?,
            mask: 0,
        });
    }
    if total_clauses > MAX_CLAUSES {
        return Err(refuse(format!(
            "{total_clauses} clauses, over {MAX_CLAUSES}"
        )));
    }
    if ops.len() > MAX_SCHEDULE_OPS {
        return Err(refuse(format!(
            "{} ops, over {MAX_SCHEDULE_OPS}",
            ops.len()
        )));
    }

    let mut out = Vec::with_capacity(16 + atoms * 8 + ops.len() * 12);
    out.extend_from_slice(ARTIFACT_MAGIC);
    out.extend_from_slice(&ARTIFACT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&rules.atoms.to_le_bytes());
    let rule_count = u16::try_from(rules.rules.len()).map_err(|_| refuse("rule count"))?;
    out.extend_from_slice(&rule_count.to_le_bytes());
    let op_count = u32::try_from(ops.len()).map_err(|_| refuse("op count"))?;
    out.extend_from_slice(&op_count.to_le_bytes());
    for (atom, pair) in thresholds.thresholds.iter().enumerate() {
        if pair.tau_neg > pair.tau_pos {
            return Err(refuse(format!(
                "atom {atom} has tau_neg {} above tau_pos {}",
                pair.tau_neg, pair.tau_pos
            )));
        }
        out.extend_from_slice(&pair.tau_neg.to_le_bytes());
        out.extend_from_slice(&pair.tau_pos.to_le_bytes());
    }
    for op in &ops {
        out.push(op.code);
        out.push(op.word);
        out.extend_from_slice(&op.arg.to_le_bytes());
        out.extend_from_slice(&op.mask.to_le_bytes());
    }
    verify(&out)?;
    Ok(out)
}

/// Decodes the artifact with the evaluator's own validator.
fn verify(bytes: &[u8]) -> Result<(), XtaskError> {
    static STORAGE: Mutex<ScheduleStorage> = Mutex::new(ScheduleStorage::empty());
    let mut storage = STORAGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    storage
        .decode(bytes)
        .and_then(|_| storage.schedule().map(|_| ()))
        .map_err(|error: DagError| refuse(format!("compiled artifact refused: {error:?}")))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, XtaskError> {
    let text = fs::read_to_string(path).map_err(|e| XtaskError::Io(display_path(path), e))?;
    serde_json::from_str(&text).map_err(|e| XtaskError::Json(display_path(path), e))
}

pub(crate) fn run(
    rules: &Path,
    thresholds: &Path,
    out: &Path,
    check: bool,
) -> Result<(), XtaskError> {
    let bytes = compile(&read_json(rules)?, &read_json(thresholds)?)?;
    if check {
        let existing = fs::read(out).map_err(|e| XtaskError::Io(display_path(out), e))?;
        if existing != bytes {
            return Err(XtaskError::Drift(format!(
                "{} differs from the compiled artifact",
                display_path(out)
            )));
        }
        println!("decision-model: {} is current", display_path(out));
        return Ok(());
    }
    fs::write(out, &bytes).map_err(|e| XtaskError::Io(display_path(out), e))?;
    println!(
        "decision-model: wrote {} ({} bytes)",
        display_path(out),
        bytes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = "crates/guards/chio-predicate-dag/tests/fixtures";

    fn parse_rules(json: &str) -> Result<RulesFile, XtaskError> {
        serde_json::from_str(json).map_err(|e| XtaskError::Json("rules".into(), e))
    }

    fn thresholds(n: usize) -> ThresholdsFile {
        ThresholdsFile {
            thresholds: (0..n)
                .map(|_| ThresholdSpec {
                    tau_neg: 0,
                    tau_pos: 1,
                })
                .collect(),
        }
    }

    fn refused(rules: &str, atoms: usize) -> bool {
        match parse_rules(rules) {
            Ok(rules) => matches!(
                compile(&rules, &thresholds(atoms)),
                Err(XtaskError::DecisionModel(_))
            ),
            Err(_) => true,
        }
    }

    #[test]
    fn the_reference_fixture_is_the_compiled_artifact() -> Result<(), XtaskError> {
        let root = super::super::workspace_root()?;
        let dir = root.join(FIXTURES);
        let bytes = compile(
            &read_json(&dir.join("reference-rules.json"))?,
            &read_json(&dir.join("reference-thresholds.json"))?,
        )?;
        let committed = fs::read(dir.join("reference-model.cdm"))
            .map_err(|e| XtaskError::Io("reference-model.cdm".into(), e))?;
        assert!(
            bytes == committed,
            "compiled bytes differ from reference-model.cdm"
        );
        Ok(())
    }

    #[test]
    fn literal_and_clause_order_and_duplicates_do_not_change_the_artifact() -> Result<(), XtaskError>
    {
        let a = parse_rules(
            r#"{"atoms": 70, "rules": [{"polarity": "deny", "clauses": [
                [{"atom": 65}, {"atom": 1, "negated": true}, {"atom": 3}, {"atom": 1, "negated": true}],
                [{"atom": 2}]]},
                {"polarity": "hold", "clauses": [[{"rule": 0, "negated": true}, {"atom": 0}]]}]}"#,
        )?;
        let b = parse_rules(
            r#"{"atoms": 70, "rules": [{"polarity": "deny", "clauses": [
                [{"atom": 2}], [{"atom": 3}, {"atom": 65}, {"atom": 1, "negated": true}],
                [{"atom": 2}]]},
                {"polarity": "hold", "clauses": [[{"atom": 0}, {"rule": 0, "negated": true}]]}]}"#,
        )?;
        assert_eq!(compile(&a, &thresholds(70))?, compile(&b, &thresholds(70))?);
        Ok(())
    }

    #[test]
    fn non_canonical_input_is_refused() {
        let one = r#"[{"atom": 0}]"#;
        assert!(refused(r#"{"atoms": 0, "rules": []}"#, 0));
        assert!(refused(r#"{"atoms": 1, "rules": []}"#, 1));
        assert!(refused(
            r#"{"atoms": 1, "rules": [{"polarity": "deny", "clauses": []}]}"#,
            1
        ));
        assert!(refused(
            r#"{"atoms": 1, "rules": [{"polarity": "deny", "clauses": [[]]}]}"#,
            1
        ));
        assert!(refused(
            r#"{"atoms": 1, "rules": [{"polarity": "deny", "clauses": [[{"atom": 1}]]}]}"#,
            1
        ));
        assert!(refused(
            r#"{"atoms": 1, "rules": [{"polarity": "deny", "clauses": [[{"rule": 0}]]}]}"#,
            1
        ));
        assert!(refused(
            r#"{"atoms": 1, "rules": [{"polarity": "deny", "clauses": [[{"atom": 0, "rule": 0}]]}]}"#,
            1
        ));
        assert!(refused(
            r#"{"atoms": 1, "rules": [{"polarity": "deny", "clauses": [[{}]]}]}"#,
            1
        ));
        assert!(refused(
            &format!(r#"{{"atoms": 1, "rules": [{{"polarity": "veto", "clauses": [{one}]}}]}}"#),
            1
        ));
        assert!(refused(
            &format!(
                r#"{{"atoms": 1, "extra": 1, "rules": [{{"polarity": "deny", "clauses": [{one}]}}]}}"#
            ),
            1
        ));
        let wide: Vec<String> = (0..17).map(|r| format!(r#"{{"rule": {r}}}"#)).collect();
        let mut many = vec![format!(r#"{{"polarity": "advisory", "clauses": [{one}]}}"#); 17];
        many.push(format!(
            r#"{{"polarity": "deny", "clauses": [[{}]]}}"#,
            wide.join(",")
        ));
        assert!(refused(
            &format!(r#"{{"atoms": 1, "rules": [{}]}}"#, many.join(",")),
            1
        ));
    }

    #[test]
    fn mismatched_or_inverted_thresholds_are_refused() -> Result<(), XtaskError> {
        let rules = parse_rules(
            r#"{"atoms": 2, "rules": [{"polarity": "deny", "clauses": [[{"atom": 0}]]}]}"#,
        )?;
        assert!(compile(&rules, &thresholds(1)).is_err());
        let inverted = ThresholdsFile {
            thresholds: vec![
                ThresholdSpec {
                    tau_neg: 0,
                    tau_pos: 0,
                },
                ThresholdSpec {
                    tau_neg: 2,
                    tau_pos: 1,
                },
            ],
        };
        assert!(compile(&rules, &inverted).is_err());
        Ok(())
    }
}
