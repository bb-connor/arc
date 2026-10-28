use chio_fixed::Q16_16;
use chio_kernel::GuardContext;
use chio_predicate_dag::{ATOM_WORDS, MAX_ATOMS};

use super::{ScoreError, ScoreSource, Scores};

/// JSON value kinds an argument predicate can test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonKind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

/// A deterministic predicate over the request. It reads names, presence and
/// JSON kinds only, never an argument value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtomPredicate {
    ToolName(String),
    ServerId(String),
    ArgumentPresent(String),
    ArgumentKind { key: String, kind: JsonKind },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExactPredicateSourceError {
    #[error("exact predicate source has {count} predicates; at most {max} atoms are addressable")]
    TooManyPredicates { count: usize, max: usize },
}

/// Scores atom `i` as `1.0` when predicate `i` holds and `0.0` otherwise.
/// Every score is attested.
#[derive(Clone, Debug)]
pub struct ExactPredicateSource {
    predicates: Vec<AtomPredicate>,
}

impl ExactPredicateSource {
    /// Refuses more than `MAX_ATOMS` predicates, so `provided_atoms` names
    /// exactly one atom per predicate.
    pub fn new(predicates: Vec<AtomPredicate>) -> Result<Self, ExactPredicateSourceError> {
        if predicates.len() > MAX_ATOMS {
            return Err(ExactPredicateSourceError::TooManyPredicates {
                count: predicates.len(),
                max: MAX_ATOMS,
            });
        }
        Ok(Self { predicates })
    }
}

impl ScoreSource for ExactPredicateSource {
    fn provided_atoms(&self) -> [u64; ATOM_WORDS] {
        let mut words = [0u64; ATOM_WORDS];
        for atom in 0..self.predicates.len() {
            if let Some(word) = words.get_mut(atom / 64) {
                *word |= 1u64 << (atom % 64);
            }
        }
        words
    }

    fn scores(&self, ctx: &GuardContext) -> Result<Scores, ScoreError> {
        let arguments = ctx.request.arguments.as_object();
        let scores = self
            .predicates
            .iter()
            .map(|predicate| {
                let holds = match predicate {
                    AtomPredicate::ToolName(name) => ctx.request.tool_name == *name,
                    AtomPredicate::ServerId(id) => ctx.server_id.as_str() == id,
                    AtomPredicate::ArgumentPresent(key) => {
                        arguments.is_some_and(|object| object.contains_key(key))
                    }
                    AtomPredicate::ArgumentKind { key, kind } => arguments
                        .and_then(|object| object.get(key))
                        .is_some_and(|value| json_kind(value) == *kind),
                };
                if holds {
                    Q16_16::from_int(1)
                } else {
                    Q16_16::from_int(0)
                }
            })
            .collect();
        Ok(Scores {
            scores,
            attested: self.provided_atoms(),
        })
    }
}

fn json_kind(value: &serde_json::Value) -> JsonKind {
    match value {
        serde_json::Value::Null => JsonKind::Null,
        serde_json::Value::Bool(_) => JsonKind::Bool,
        serde_json::Value::Number(_) => JsonKind::Number,
        serde_json::Value::String(_) => JsonKind::String,
        serde_json::Value::Array(_) => JsonKind::Array,
        serde_json::Value::Object(_) => JsonKind::Object,
    }
}
