mod common;

use chio_fixed::Q16_16;
use chio_predicate_dag::{
    DagError, RulePolarity, ScheduleStorage, Thresholds, TriSet, Trit, ATOM_WORDS, MAX_SCHEDULE_OPS,
};
use common::{encode, q_pairs, storage, tri_set, Lit, Model, Raw, RawOp, Rule};

fn valid_ops() -> Vec<RawOp> {
    vec![
        RawOp::atoms(false, 0, 0b0011),
        RawOp::atoms(true, 0, 0b0100),
        RawOp::end_clause(),
        RawOp::atoms(false, 0, 0b1000),
        RawOp::end_clause(),
        RawOp::end_rule(0, RulePolarity::Deny),
        RawOp::rule(true, 0),
        RawOp::end_clause(),
        RawOp::end_rule(1, RulePolarity::Hold),
    ]
}

fn valid() -> Raw {
    Raw::new(vec![(-2, 3), (0, 0), (1, 1), (-5, 5)], 2, valid_ops())
}

fn decode(bytes: &[u8]) -> Result<Thresholds, DagError> {
    storage().decode(bytes)
}

fn refuses(raw: &Raw, expected: DagError) {
    assert_eq!(decode(&raw.bytes()).err(), Some(expected), "{raw:?}");
}

fn with_ops(ops: Vec<RawOp>) -> Raw {
    Raw { ops, ..valid() }
}

#[test]
fn a_valid_artifact_round_trips() -> Result<(), DagError> {
    let mut guard = storage();
    let thresholds = guard.decode(&valid().bytes())?;
    assert_eq!(
        thresholds,
        Thresholds::new(&q_pairs(&[(-2, 3), (0, 0), (1, 1), (-5, 5)]))?
    );
    assert_eq!(
        thresholds.get(0),
        Some((Q16_16::from_bits(-2), Q16_16::from_bits(3)))
    );
    assert_eq!(thresholds.get(4), None);
    let schedule = guard.schedule()?;
    assert_eq!(schedule.op_count(), 9);
    assert_eq!(schedule.atom_count(), 4);
    assert_eq!(schedule.rule_count(), 2);
    assert_eq!(schedule.referenced_atoms()[0], 0b1111);
    assert!(schedule.referenced_atoms()[1..].iter().all(|w| *w == 0));
    assert_eq!(schedule.rule_polarity(0), Some(RulePolarity::Deny));
    assert_eq!(schedule.rule_polarity(1), Some(RulePolarity::Hold));
    assert_eq!(schedule.rule_polarity(2), None);
    Ok(())
}

#[test]
fn the_encoder_emits_what_the_decoder_accepts() -> Result<(), DagError> {
    let model = Model {
        thresholds: vec![(0, 0); 70],
        rules: vec![
            Rule {
                polarity: RulePolarity::Advisory,
                clauses: vec![
                    vec![
                        Lit::Atom {
                            id: 69,
                            negated: false,
                        },
                        Lit::Atom {
                            id: 1,
                            negated: true,
                        },
                    ],
                    vec![
                        Lit::Atom {
                            id: 3,
                            negated: false,
                        },
                        Lit::Atom {
                            id: 2,
                            negated: false,
                        },
                    ],
                    vec![
                        Lit::Atom {
                            id: 2,
                            negated: false,
                        },
                        Lit::Atom {
                            id: 3,
                            negated: false,
                        },
                    ],
                ],
            },
            Rule {
                polarity: RulePolarity::Deny,
                clauses: vec![vec![
                    Lit::Rule {
                        id: 0,
                        negated: false,
                    },
                    Lit::Atom {
                        id: 64,
                        negated: true,
                    },
                ]],
            },
        ],
    };
    let mut guard = storage();
    guard.decode(&encode(&model))?;
    assert_eq!(guard.schedule()?.rule_count(), 2);
    Ok(())
}

#[test]
fn header_errors_are_refused() {
    refuses(
        &Raw {
            magic: *b"CDM0",
            ..valid()
        },
        DagError::BadMagic,
    );
    refuses(
        &Raw {
            version: 2,
            ..valid()
        },
        DagError::BadMagic,
    );
    refuses(
        &Raw {
            reserved: 1,
            ..valid()
        },
        DagError::PaddingNotZero,
    );
    refuses(
        &Raw {
            atom_count: 0,
            thresholds: vec![],
            ..valid()
        },
        DagError::AtomOutOfRange,
    );
    refuses(
        &Raw {
            atom_count: 1025,
            ..valid()
        },
        DagError::AtomOutOfRange,
    );
    refuses(
        &Raw {
            rule_count: 0,
            ..valid()
        },
        DagError::RuleOutOfRange,
    );
    refuses(
        &Raw {
            rule_count: 513,
            ..valid()
        },
        DagError::RuleOutOfRange,
    );
    let over = u32::try_from(MAX_SCHEDULE_OPS + 1).unwrap_or(u32::MAX);
    refuses(
        &Raw {
            op_count: Some(over),
            ..valid()
        },
        DagError::TooManyOps,
    );
}

#[test]
fn length_errors_are_refused() {
    assert_eq!(decode(&[]).err(), Some(DagError::BadLength));
    assert_eq!(decode(b"CDM1").err(), Some(DagError::BadLength));
    let bytes = valid().bytes();
    assert_eq!(
        decode(&bytes[..bytes.len() - 1]).err(),
        Some(DagError::BadLength)
    );
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(decode(&longer).err(), Some(DagError::BadLength));
    refuses(
        &Raw {
            op_count: Some(8),
            ..valid()
        },
        DagError::BadLength,
    );
    refuses(
        &Raw {
            atom_count: 5,
            ..valid()
        },
        DagError::BadLength,
    );
}

#[test]
fn threshold_order_is_refused() {
    refuses(
        &Raw {
            thresholds: vec![(-2, 3), (1, 0), (1, 1), (-5, 5)],
            ..valid()
        },
        DagError::ThresholdOrder,
    );
    assert_eq!(
        Thresholds::new(&q_pairs(&[(4, 3)])).err(),
        Some(DagError::ThresholdOrder)
    );
}

#[test]
fn atom_range_errors_are_refused() {
    let mut ops = valid_ops();
    ops[0] = RawOp::atoms(false, 0, 0b1_0001);
    refuses(&with_ops(ops), DagError::AtomOutOfRange);
    let mut ops = valid_ops();
    ops[0] = RawOp::atoms(false, 1, 0b1);
    refuses(&with_ops(ops), DagError::AtomOutOfRange);
    let mut ops = valid_ops();
    ops[0] = RawOp::atoms(false, 16, 0b1);
    refuses(&with_ops(ops), DagError::AtomOutOfRange);
}

#[test]
fn rule_range_and_cycle_errors_are_refused() {
    let mut ops = valid_ops();
    ops[6] = RawOp::rule(true, 2);
    refuses(&with_ops(ops), DagError::RuleOutOfRange);
    let mut ops = valid_ops();
    ops[6] = RawOp::rule(true, 1);
    refuses(&with_ops(ops), DagError::Cycle);
    let mut ops = valid_ops();
    ops[8] = RawOp::end_rule(2, RulePolarity::Hold);
    refuses(&with_ops(ops), DagError::RuleOutOfRange);
    let mut ops = valid_ops();
    ops.insert(0, RawOp::rule(false, 0));
    refuses(&with_ops(ops), DagError::Cycle);
}

#[test]
fn padding_errors_are_refused() {
    let mut ops = valid_ops();
    ops[0].arg = 1;
    refuses(&with_ops(ops), DagError::PaddingNotZero);
    let mut ops = valid_ops();
    ops[2].mask = 1;
    refuses(&with_ops(ops), DagError::PaddingNotZero);
    let mut ops = valid_ops();
    ops[6].word = 1;
    refuses(&with_ops(ops), DagError::PaddingNotZero);
    let mut ops = valid_ops();
    ops[6].mask = 1;
    refuses(&with_ops(ops), DagError::PaddingNotZero);
    let mut ops = valid_ops();
    ops[5].mask = 1;
    refuses(&with_ops(ops), DagError::PaddingNotZero);
}

#[test]
fn non_canonical_streams_are_refused() {
    let cases: Vec<Vec<RawOp>> = vec![
        {
            let mut ops = valid_ops();
            ops.swap(0, 1);
            ops
        },
        {
            let mut ops = valid_ops();
            ops[1] = RawOp::atoms(false, 0, 0b0100);
            ops
        },
        {
            let mut ops = valid_ops();
            ops[0].mask = 0;
            ops
        },
        {
            let mut ops = valid_ops();
            ops.insert(3, RawOp::end_clause());
            ops
        },
        {
            let mut ops = valid_ops();
            ops[3].code = 9;
            ops
        },
        {
            let mut ops = valid_ops();
            ops[5] = RawOp::end_rule(1, RulePolarity::Deny);
            ops
        },
        {
            let mut ops = valid_ops();
            ops[5].word = 3;
            ops
        },
        {
            let mut ops = valid_ops();
            ops.pop();
            ops
        },
        {
            let mut ops = valid_ops();
            ops.push(RawOp::atoms(false, 0, 1));
            ops.push(RawOp::end_clause());
            ops
        },
        {
            let mut ops = valid_ops();
            ops.remove(4);
            ops
        },
        {
            let mut ops = valid_ops();
            ops.insert(6, RawOp::end_rule(1, RulePolarity::Deny));
            ops
        },
        vec![
            RawOp::atoms(false, 0, 0b1000),
            RawOp::end_clause(),
            RawOp::atoms(false, 0, 0b0011),
            RawOp::atoms(true, 0, 0b0100),
            RawOp::end_clause(),
            RawOp::end_rule(0, RulePolarity::Deny),
            RawOp::rule(true, 0),
            RawOp::end_clause(),
            RawOp::end_rule(1, RulePolarity::Hold),
        ],
    ];
    for ops in cases {
        refuses(&with_ops(ops), DagError::ClauseNotCanonical);
    }
}

#[test]
fn a_clause_wider_than_sixteen_literals_is_refused() {
    let thresholds = vec![(0, 0); 17];
    let wide = Raw::new(
        thresholds.clone(),
        1,
        vec![
            RawOp::atoms(false, 0, (1 << 17) - 1),
            RawOp::end_clause(),
            RawOp::end_rule(0, RulePolarity::Deny),
        ],
    );
    refuses(&wide, DagError::ClauseNotCanonical);
    let sixteen = Raw::new(
        thresholds,
        1,
        vec![
            RawOp::atoms(false, 0, (1 << 16) - 1),
            RawOp::end_clause(),
            RawOp::end_rule(0, RulePolarity::Deny),
        ],
    );
    assert!(decode(&sixteen.bytes()).is_ok());
}

#[test]
fn duplicate_clauses_are_refused() {
    let raw = with_ops(vec![
        RawOp::atoms(false, 0, 0b1),
        RawOp::end_clause(),
        RawOp::atoms(false, 0, 0b1),
        RawOp::end_clause(),
        RawOp::end_rule(0, RulePolarity::Deny),
        RawOp::atoms(false, 0, 0b10),
        RawOp::end_clause(),
        RawOp::end_rule(1, RulePolarity::Deny),
    ]);
    refuses(&raw, DagError::DuplicateClause);
}

#[test]
fn too_many_clauses_are_refused() {
    let per_rule = |rule: u16, clauses: u64| {
        let mut ops: Vec<RawOp> = (0..clauses)
            .flat_map(|atom| [RawOp::atoms(false, 0, 1 << atom), RawOp::end_clause()])
            .collect();
        ops.push(RawOp::end_rule(rule, RulePolarity::Deny));
        ops
    };
    let thresholds = vec![(0, 0); 64];
    refuses(
        &Raw::new(thresholds.clone(), 1, per_rule(0, 17)),
        DagError::TooManyClauses,
    );
    assert!(decode(&Raw::new(thresholds.clone(), 1, per_rule(0, 16)).bytes()).is_ok());

    let mut ops = Vec::new();
    for rule in 0..257u16 {
        ops.extend(per_rule(rule, if rule == 256 { 1 } else { 16 }));
    }
    refuses(
        &Raw::new(thresholds.clone(), 257, ops),
        DagError::TooManyClauses,
    );
    let mut ops = Vec::new();
    for rule in 0..256u16 {
        ops.extend(per_rule(rule, 16));
    }
    assert!(decode(&Raw::new(thresholds, 256, ops).bytes()).is_ok());
}

#[test]
fn schedule_is_not_validated_before_or_after_a_failed_decode() -> Result<(), DagError> {
    static FRESH: ScheduleStorage = ScheduleStorage::empty();
    assert_eq!(FRESH.schedule().err(), Some(DagError::NotValidated));

    let mut guard = storage();
    guard.decode(&valid().bytes())?;
    assert!(guard.schedule().is_ok());
    assert_eq!(
        guard
            .decode(
                &Raw {
                    version: 2,
                    ..valid()
                }
                .bytes()
            )
            .err(),
        Some(DagError::BadMagic)
    );
    assert_eq!(guard.schedule().err(), Some(DagError::NotValidated));
    Ok(())
}

#[test]
fn work_below_the_op_count_is_refused() -> Result<(), DagError> {
    let mut guard = storage();
    guard.decode(&valid().bytes())?;
    let schedule = guard.schedule()?;
    let atoms = tri_set::<ATOM_WORDS>(&[Trit::True, Trit::False, Trit::True, Trit::Unknown]);
    let n = schedule.op_count();
    assert_eq!(
        schedule.evaluate(&atoms, n - 1).err(),
        Some(DagError::WorkExhausted)
    );
    assert_eq!(
        schedule.evaluate(&atoms, 0).err(),
        Some(DagError::WorkExhausted)
    );
    assert_eq!(schedule.evaluate(&atoms, n)?.work_ops, n);
    assert_eq!(schedule.evaluate(&atoms, n + 1)?.work_ops, n);
    Ok(())
}

#[test]
fn evaluate_refuses_an_atom_set_of_the_wrong_width() -> Result<(), DagError> {
    let mut guard = storage();
    guard.decode(&valid().bytes())?;
    let schedule = guard.schedule()?;
    let three = tri_set::<ATOM_WORDS>(&[Trit::True, Trit::True, Trit::True]);
    assert_eq!(
        schedule.evaluate(&three, 100).err(),
        Some(DagError::BadLength)
    );
    Ok(())
}

#[test]
fn unprovided_atoms_are_refused() -> Result<(), DagError> {
    let mut guard = storage();
    guard.decode(&valid().bytes())?;
    let schedule = guard.schedule()?;
    let mut provided = [0u64; ATOM_WORDS];
    provided[0] = 0b0111;
    assert_eq!(
        schedule.require_atoms(&provided).err(),
        Some(DagError::UnprovidedAtom)
    );
    provided[0] = 0b1111;
    assert_eq!(schedule.require_atoms(&provided), Ok(()));
    Ok(())
}

#[test]
fn tri_set_refuses_overlap_and_padding() {
    let mut pos = [0u64; 2];
    let mut neg = [0u64; 2];
    pos[0] = 0b1;
    neg[0] = 0b1;
    assert_eq!(
        TriSet::new(pos, neg, 10).err(),
        Some(DagError::PlaneOverlap)
    );
    neg[0] = 0;
    pos[0] = 1 << 10;
    assert_eq!(
        TriSet::new(pos, neg, 10).err(),
        Some(DagError::PaddingNotZero)
    );
    pos[0] = 0;
    neg[1] = 1;
    assert_eq!(
        TriSet::new(pos, neg, 64).err(),
        Some(DagError::PaddingNotZero)
    );
    assert_eq!(TriSet::new(pos, neg, 129).err(), Some(DagError::BadLength));
    assert!(TriSet::new(pos, neg, 65).is_ok());
}
