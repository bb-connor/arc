#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use chio_fixed::Q16_16;

use crate::artifact::decode_into;
use crate::schedule::{Op, Schedule};
use crate::trit::fill;
use crate::{classify, Outcome, ScoreFrame, Thresholds, TriSet, Trit, ATOM_WORDS};

fn header(atoms: u16, rules: u16, ops: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(b"CDM1");
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[8..10].copy_from_slice(&atoms.to_le_bytes());
    out[10..12].copy_from_slice(&rules.to_le_bytes());
    out[12..16].copy_from_slice(&ops.to_le_bytes());
    out
}

fn op(code: u8, word: u8, arg: u16, mask: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = code;
    out[1] = word;
    out[2..4].copy_from_slice(&arg.to_le_bytes());
    out[4..12].copy_from_slice(&mask.to_le_bytes());
    out
}

fn any_trit() -> Trit {
    match kani::any::<u8>() % 3 {
        0 => Trit::True,
        1 => Trit::False,
        _ => Trit::Unknown,
    }
}

fn atom_set(trits: [Trit; 4]) -> TriSet<ATOM_WORDS> {
    let mut pos = [0u64; ATOM_WORDS];
    let mut neg = [0u64; ATOM_WORDS];
    for (i, t) in trits.iter().enumerate() {
        match t {
            Trit::True => pos[0] |= 1 << i,
            Trit::False => neg[0] |= 1 << i,
            Trit::Unknown => {}
        }
    }
    match TriSet::new(pos, neg, 4) {
        Ok(set) => set,
        Err(_) => panic!("disjoint planes inside the live width are valid"),
    }
}

fn or(a: Trit, b: Trit) -> Trit {
    match (a, b) {
        (Trit::True, _) | (_, Trit::True) => Trit::True,
        (Trit::False, Trit::False) => Trit::False,
        _ => Trit::Unknown,
    }
}

fn and(a: Trit, b: Trit) -> Trit {
    match (a, b) {
        (Trit::False, _) | (_, Trit::False) => Trit::False,
        (Trit::True, Trit::True) => Trit::True,
        _ => Trit::Unknown,
    }
}

fn not(a: Trit) -> Trit {
    match a {
        Trit::True => Trit::False,
        Trit::False => Trit::True,
        Trit::Unknown => Trit::Unknown,
    }
}

#[kani::proof]
fn verify_fill_is_zero_or_all_ones() {
    let b: bool = kani::any();
    let filled = fill(b);
    assert!(filled == 0 || filled == u64::MAX);
    assert_eq!(filled == u64::MAX, b);
}

#[kani::proof]
fn verify_classify_respects_thresholds() {
    let bits: [i32; 2] = kani::any();
    let negs: [i32; 2] = kani::any();
    let poss: [i32; 2] = kani::any();
    kani::assume(negs[0] <= poss[0] && negs[1] <= poss[1]);
    let attested_bits: u64 = kani::any();
    let pairs = [
        (Q16_16::from_bits(negs[0]), Q16_16::from_bits(poss[0])),
        (Q16_16::from_bits(negs[1]), Q16_16::from_bits(poss[1])),
    ];
    let Ok(tau) = Thresholds::new(&pairs) else {
        panic!("ordered pairs are accepted");
    };
    let scores = [Q16_16::from_bits(bits[0]), Q16_16::from_bits(bits[1])];
    let mut attested = [0u64; ATOM_WORDS];
    attested[0] = attested_bits;
    let Ok(set) = classify(
        &ScoreFrame {
            scores: &scores,
            attested: &attested,
        },
        &tau,
    ) else {
        panic!("matching lengths classify");
    };
    for i in 0..2 {
        let expected = if attested_bits & (1 << i) == 0 {
            Trit::Unknown
        } else if bits[i] >= poss[i] {
            Trit::True
        } else if bits[i] < negs[i] {
            Trit::False
        } else {
            Trit::Unknown
        };
        assert_eq!(set.get(i), Some(expected));
    }
    assert_eq!(set.get(2), None);
}

/// Rule 0 (Deny): `(a0 OR NOT a1) AND a2`. Rule 1 (Hold): `NOT r0 OR a3`.
fn small_artifact() -> [u8; 16 + 4 * 8 + 10 * 12] {
    let mut out = [0u8; 16 + 4 * 8 + 10 * 12];
    out[..16].copy_from_slice(&header(4, 2, 10));
    let ops = [
        op(1, 0, 0, 0b0001),
        op(2, 0, 0, 0b0010),
        op(5, 0, 0, 0),
        op(1, 0, 0, 0b0100),
        op(5, 0, 0, 0),
        op(6, 0, 0, 0),
        op(1, 0, 0, 0b1000),
        op(4, 0, 0, 0),
        op(5, 0, 0, 0),
        op(6, 1, 1, 0),
    ];
    for (i, o) in ops.iter().enumerate() {
        let at = 48 + i * 12;
        out[at..at + 12].copy_from_slice(o);
    }
    out
}

#[kani::proof]
fn verify_eval_matches_reference_small() {
    let bytes = small_artifact();
    let mut ops = [Op::END_CLAUSE; 12];
    let Ok((meta, _)) = decode_into(&bytes, &mut ops) else {
        panic!("the fixed artifact is canonical");
    };
    let schedule = Schedule::new(&ops[..10], &meta);
    let trits = [any_trit(), any_trit(), any_trit(), any_trit()];
    let Ok(evaluation) = schedule.evaluate(&atom_set(trits), 10) else {
        panic!("a sufficient grant evaluates");
    };
    let r0 = and(or(trits[0], not(trits[1])), trits[2]);
    let r1 = or(not(r0), trits[3]);
    assert_eq!(evaluation.rules.get(0), Some(r0));
    assert_eq!(evaluation.rules.get(1), Some(r1));
    let expected = if r0 == Trit::True {
        Outcome::Deny
    } else if r0 == Trit::Unknown || r1 != Trit::False {
        Outcome::Hold
    } else {
        Outcome::Allow
    };
    assert_eq!(evaluation.outcome, expected);
    assert_eq!(evaluation.work_ops, 10);
}

#[kani::proof]
fn verify_widen_uncertainty_never_admits_single_rule() {
    let mut bytes = [0u8; 16 + 2 * 8 + 4 * 12];
    bytes[..16].copy_from_slice(&header(2, 1, 4));
    let polarity: u8 = if kani::any() { 0 } else { 1 };
    let ops = [
        op(1, 0, 0, 0b01),
        op(2, 0, 0, 0b10),
        op(5, 0, 0, 0),
        op(6, polarity, 0, 0),
    ];
    for (i, o) in ops.iter().enumerate() {
        let at = 32 + i * 12;
        bytes[at..at + 12].copy_from_slice(o);
    }
    let mut storage = [Op::END_CLAUSE; 4];
    let Ok((meta, _)) = decode_into(&bytes, &mut storage) else {
        panic!("the fixed artifact is canonical");
    };
    let schedule = Schedule::new(&storage, &meta);

    let scores_bits: [i32; 2] = kani::any();
    let negs: [i32; 2] = kani::any();
    let poss: [i32; 2] = kani::any();
    let lowered: [i32; 2] = kani::any();
    let raised: [i32; 2] = kani::any();
    let attested: u64 = kani::any::<u64>() & 0b11;
    let kept: u64 = kani::any::<u64>() & attested;
    for i in 0..2 {
        kani::assume(negs[i] <= poss[i]);
        kani::assume(lowered[i] <= negs[i] && raised[i] >= poss[i]);
    }
    let scores = scores_bits.map(Q16_16::from_bits);
    let outcome = |neg: [i32; 2], pos: [i32; 2], mask: u64| {
        let pairs = [
            (Q16_16::from_bits(neg[0]), Q16_16::from_bits(pos[0])),
            (Q16_16::from_bits(neg[1]), Q16_16::from_bits(pos[1])),
        ];
        let Ok(tau) = Thresholds::new(&pairs) else {
            panic!("ordered pairs are accepted");
        };
        let mut words = [0u64; ATOM_WORDS];
        words[0] = mask;
        let Ok(atoms) = classify(
            &ScoreFrame {
                scores: &scores,
                attested: &words,
            },
            &tau,
        ) else {
            panic!("matching lengths classify");
        };
        match schedule.evaluate(&atoms, 4) {
            Ok(evaluation) => evaluation.outcome,
            Err(_) => Outcome::Deny,
        }
    };
    let before = outcome(negs, poss, attested);
    let after = outcome(lowered, raised, kept);
    if before != Outcome::Allow {
        assert!(after != Outcome::Allow);
    }
}
