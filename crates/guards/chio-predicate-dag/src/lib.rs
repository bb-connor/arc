#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::float_arithmetic
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
    )
)]
//! Alloc-free three-valued predicate rule DAG evaluator.
//!
//! Atom scores are classified against per-atom thresholds into strong Kleene
//! trits. A validated `chio.decision-model.v1` schedule evaluates rules, each
//! an AND of OR-clauses over possibly negated atoms and earlier rules, and
//! maps the rule trits to an outcome: any true Deny rule denies; otherwise any
//! unknown Deny or Hold rule, or any true Hold rule, holds; otherwise allow.
//!
//! Wire layout, all integers little-endian:
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `CDM1` |
//! | 4 | 2 | version, `1` |
//! | 6 | 2 | reserved, `0` |
//! | 8 | 2 | atom count, `1..=MAX_ATOMS` |
//! | 10 | 2 | rule count, `1..=MAX_RULES` |
//! | 12 | 4 | op count, `<= MAX_SCHEDULE_OPS` |
//! | 16 | 8 per atom | thresholds: `tau_neg` then `tau_pos`, Q16.16 bits as `i32` |
//! | then | 12 per op | opcode `u8`, word `u8`, argument `u16`, mask `u64` |
//!
//! Opcodes: `1` positive atom literals and `2` negated atom literals (word,
//! nonzero mask of atoms in that word, argument zero); `3` positive and `4`
//! negated rule literal (argument is an earlier rule id, word and mask zero);
//! `5` end of clause (all fields zero); `6` end of rule (argument is the rule
//! id, word is the polarity `0` Deny, `1` Hold, `2` Advisory, mask zero).
//!
//! Canonical form, enforced at decode: literal ops in a clause strictly
//! increase by (atoms before rules, word or rule id, positive before negated),
//! so each (word, polarity) appears once with its atoms merged into one mask;
//! a clause has 1 to `MAX_LITERALS_PER_CLAUSE` literals; clauses in a rule
//! strictly increase by their op sequence; a rule has 1 to
//! `MAX_CLAUSES_PER_RULE` clauses; rule ids are `0, 1, 2, ...` in order and a
//! rule literal names only an earlier rule. Complementary literals in one
//! clause are kept, since dropping them is unsound in Kleene logic.

mod artifact;
mod eval;
mod schedule;
mod thresholds;
mod trit;

#[cfg(kani)]
pub mod kani_public_harnesses;

pub use eval::{Evaluation, Outcome};
pub use schedule::{RulePolarity, Schedule, ScheduleStorage};
pub use thresholds::{classify, ScoreFrame, Thresholds};
pub use trit::{TriSet, Trit};

pub const MAX_ATOMS: usize = 1024;
pub const ATOM_WORDS: usize = 16;
pub const MAX_RULES: usize = 512;
pub const RULE_WORDS: usize = 8;
pub const MAX_CLAUSES: usize = 4096;
pub const MAX_CLAUSES_PER_RULE: usize = 16;
pub const MAX_LITERALS_PER_CLAUSE: usize = 16;
pub const MAX_SCHEDULE_OPS: usize = 65_536;
pub const ARTIFACT_MAGIC: &[u8; 4] = b"CDM1";
pub const ARTIFACT_VERSION: u16 = 1;

const _: () = assert!(ATOM_WORDS * 64 == MAX_ATOMS);
const _: () = assert!(RULE_WORDS * 64 == MAX_RULES);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DagError {
    BadMagic,
    BadLength,
    AtomOutOfRange,
    RuleOutOfRange,
    Cycle,
    TooManyOps,
    TooManyClauses,
    ClauseNotCanonical,
    DuplicateClause,
    PaddingNotZero,
    ThresholdOrder,
    PlaneOverlap,
    WorkExhausted,
    NotValidated,
}
