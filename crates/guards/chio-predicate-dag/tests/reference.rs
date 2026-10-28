mod common;

use chio_fixed::Q16_16;
use chio_predicate_dag::{
    classify, DagError, Outcome, RulePolarity, ScoreFrame, Thresholds, TriSet, Trit, ATOM_WORDS,
};
use common::{
    attested_words, encode, q_pairs, reference, single_atom_rule, storage, tri_set, trits, Lit,
    Model, Rule,
};
use proptest::prelude::*;

fn trit() -> impl Strategy<Value = Trit> {
    prop_oneof![Just(Trit::True), Just(Trit::False), Just(Trit::Unknown)]
}

fn polarity() -> impl Strategy<Value = RulePolarity> {
    prop_oneof![
        Just(RulePolarity::Deny),
        Just(RulePolarity::Hold),
        Just(RulePolarity::Advisory)
    ]
}

fn literal(atoms: u16, rule: u16) -> BoxedStrategy<Lit> {
    let atom = (0..atoms, any::<bool>()).prop_map(|(id, negated)| Lit::Atom { id, negated });
    if rule == 0 {
        atom.boxed()
    } else {
        prop_oneof![
            3 => atom,
            1 => (0..rule, any::<bool>()).prop_map(|(id, negated)| Lit::Rule { id, negated }),
        ]
        .boxed()
    }
}

fn rule(atoms: u16, index: u16) -> impl Strategy<Value = Rule> {
    (
        polarity(),
        proptest::collection::vec(proptest::collection::vec(literal(atoms, index), 1..5), 1..5),
    )
        .prop_map(|(polarity, clauses)| Rule { polarity, clauses })
}

fn model() -> impl Strategy<Value = Model> {
    (1u16..=64, 1u16..=32).prop_flat_map(|(atoms, rules)| {
        let rule_strategies: Vec<_> = (0..rules).map(|index| rule(atoms, index)).collect();
        let thresholds = proptest::collection::vec(
            (-4i32..4, 0i32..4).prop_map(|(neg, width)| (neg, neg + width)),
            usize::from(atoms),
        );
        (thresholds, rule_strategies).prop_map(|(thresholds, rules)| Model { thresholds, rules })
    })
}

fn model_and_trits() -> impl Strategy<Value = (Model, Vec<Trit>)> {
    model().prop_flat_map(|model| {
        let atoms = model.thresholds.len();
        (Just(model), proptest::collection::vec(trit(), atoms))
    })
}

fn evaluate(
    model: &Model,
    atoms: &TriSet<ATOM_WORDS>,
) -> Result<(Vec<Trit>, Outcome, u32, u32), DagError> {
    let mut guard = storage();
    guard.decode(&encode(model))?;
    let schedule = guard.schedule()?;
    let evaluation = schedule.evaluate(atoms, schedule.op_count())?;
    Ok((
        trits(&evaluation.rules),
        evaluation.outcome,
        evaluation.work_ops,
        schedule.op_count(),
    ))
}

fn outcome_for(
    model: &Model,
    scores: &[i32],
    tau: &[(i32, i32)],
    attested: &[bool],
) -> Result<Outcome, DagError> {
    let thresholds = Thresholds::new(&q_pairs(tau))?;
    let scores: Vec<Q16_16> = scores.iter().copied().map(Q16_16::from_bits).collect();
    let words = attested_words(attested);
    let atoms = classify(
        &ScoreFrame {
            scores: &scores,
            attested: &words,
        },
        &thresholds,
    )?;
    Ok(evaluate(model, &atoms)?.1)
}

fn fail(error: DagError) -> TestCaseError {
    TestCaseError::fail(format!("{error:?}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn evaluate_matches_the_reference((model, atom_trits) in model_and_trits()) {
        let atoms = tri_set::<ATOM_WORDS>(&atom_trits);
        let (rules, outcome, work_ops, op_count) = evaluate(&model, &atoms).map_err(fail)?;
        let (expected_rules, expected_outcome) = reference(&model, &atom_trits);
        prop_assert_eq!(rules, expected_rules);
        prop_assert_eq!(outcome, expected_outcome);
        prop_assert_eq!(work_ops, op_count);
    }

    #[test]
    fn widening_uncertainty_never_admits(
        (model, scores, raises, lowers, attested, keep) in model().prop_flat_map(|model| {
            let atoms = model.thresholds.len();
            (
                Just(model),
                proptest::collection::vec(-6i32..6, atoms),
                proptest::collection::vec(0i32..3, atoms),
                proptest::collection::vec(0i32..3, atoms),
                proptest::collection::vec(any::<bool>(), atoms),
                proptest::collection::vec(any::<bool>(), atoms),
            )
        })
    ) {
        let widened: Vec<(i32, i32)> = model
            .thresholds
            .iter()
            .zip(raises.iter().zip(&lowers))
            .map(|((neg, pos), (raise, lower))| (neg - lower, pos + raise))
            .collect();
        let narrowed_attestation: Vec<bool> =
            attested.iter().zip(&keep).map(|(a, k)| *a && *k).collect();
        let before = outcome_for(&model, &scores, &model.thresholds, &attested).map_err(fail)?;
        let after = outcome_for(&model, &scores, &widened, &narrowed_attestation).map_err(fail)?;
        if before != Outcome::Allow {
            prop_assert_ne!(after, Outcome::Allow);
        }
    }

    #[test]
    fn classify_matches_the_reference(
        cells in proptest::collection::vec((-8i32..8, -8i32..8, 0i32..8, any::<bool>()), 1..80)
    ) {
        let tau: Vec<(i32, i32)> = cells.iter().map(|(_, neg, width, _)| (*neg, neg + width)).collect();
        let thresholds = Thresholds::new(&q_pairs(&tau)).map_err(fail)?;
        let scores: Vec<Q16_16> = cells.iter().map(|(s, ..)| Q16_16::from_bits(*s)).collect();
        let attested: Vec<bool> = cells.iter().map(|(.., a)| *a).collect();
        let words = attested_words(&attested);
        let atoms = classify(&ScoreFrame { scores: &scores, attested: &words }, &thresholds).map_err(fail)?;
        for (i, (score, neg, width, attested)) in cells.iter().enumerate() {
            prop_assert_eq!(
                atoms.get(i),
                Some(common::classify_reference(*score, *neg, neg + width, *attested))
            );
        }
    }
}

#[test]
fn widening_can_relax_deny_to_hold() -> Result<(), DagError> {
    let model = Model {
        thresholds: vec![(0, 1)],
        rules: vec![single_atom_rule(RulePolarity::Deny, 0)],
    };
    assert_eq!(
        outcome_for(&model, &[1], &[(0, 1)], &[true])?,
        Outcome::Deny
    );
    assert_eq!(
        outcome_for(&model, &[1], &[(0, 2)], &[true])?,
        Outcome::Hold
    );
    Ok(())
}

#[test]
fn unattested_atom_is_unknown_and_holds_a_deny_rule() -> Result<(), DagError> {
    let model = Model {
        thresholds: vec![(0, 1)],
        rules: vec![single_atom_rule(RulePolarity::Deny, 0)],
    };
    assert_eq!(
        outcome_for(&model, &[5], &[(0, 1)], &[false])?,
        Outcome::Hold
    );
    assert_eq!(
        outcome_for(&model, &[-5], &[(0, 1)], &[true])?,
        Outcome::Allow
    );
    Ok(())
}

#[test]
fn complementary_literals_are_unknown_when_the_atom_is_unknown() -> Result<(), DagError> {
    let model = Model {
        thresholds: vec![(0, 0)],
        rules: vec![Rule {
            polarity: RulePolarity::Deny,
            clauses: vec![vec![
                Lit::Atom {
                    id: 0,
                    negated: false,
                },
                Lit::Atom {
                    id: 0,
                    negated: true,
                },
            ]],
        }],
    };
    let unknown = tri_set::<ATOM_WORDS>(&[Trit::Unknown]);
    let (rules, outcome, ..) = evaluate(&model, &unknown)?;
    assert_eq!(rules, vec![Trit::Unknown]);
    assert_eq!(outcome, Outcome::Hold);
    for known in [Trit::True, Trit::False] {
        let (rules, outcome, ..) = evaluate(&model, &tri_set::<ATOM_WORDS>(&[known]))?;
        assert_eq!(rules, vec![Trit::True]);
        assert_eq!(outcome, Outcome::Deny);
    }
    Ok(())
}

#[test]
fn polarity_maps_rule_trits_to_outcomes() -> Result<(), DagError> {
    let cases = [
        (RulePolarity::Deny, Trit::True, Outcome::Deny),
        (RulePolarity::Deny, Trit::Unknown, Outcome::Hold),
        (RulePolarity::Deny, Trit::False, Outcome::Allow),
        (RulePolarity::Hold, Trit::True, Outcome::Hold),
        (RulePolarity::Hold, Trit::Unknown, Outcome::Hold),
        (RulePolarity::Hold, Trit::False, Outcome::Allow),
        (RulePolarity::Advisory, Trit::True, Outcome::Allow),
        (RulePolarity::Advisory, Trit::Unknown, Outcome::Allow),
        (RulePolarity::Advisory, Trit::False, Outcome::Allow),
    ];
    for (polarity, atom, expected) in cases {
        let model = Model {
            thresholds: vec![(0, 0)],
            rules: vec![single_atom_rule(polarity, 0)],
        };
        let (rules, outcome, ..) = evaluate(&model, &tri_set::<ATOM_WORDS>(&[atom]))?;
        assert_eq!(rules, vec![atom]);
        assert_eq!(outcome, expected, "{polarity:?} {atom:?}");
    }
    Ok(())
}

#[test]
fn deny_wins_over_hold() -> Result<(), DagError> {
    let model = Model {
        thresholds: vec![(0, 0), (0, 0)],
        rules: vec![
            single_atom_rule(RulePolarity::Hold, 0),
            single_atom_rule(RulePolarity::Deny, 1),
        ],
    };
    let atoms = tri_set::<ATOM_WORDS>(&[Trit::True, Trit::True]);
    assert_eq!(evaluate(&model, &atoms)?.1, Outcome::Deny);
    Ok(())
}

#[test]
fn rule_literals_read_earlier_rules() -> Result<(), DagError> {
    let model = Model {
        thresholds: vec![(0, 0)],
        rules: vec![
            single_atom_rule(RulePolarity::Advisory, 0),
            Rule {
                polarity: RulePolarity::Deny,
                clauses: vec![vec![Lit::Rule {
                    id: 0,
                    negated: true,
                }]],
            },
        ],
    };
    let (rules, outcome, ..) = evaluate(&model, &tri_set::<ATOM_WORDS>(&[Trit::False]))?;
    assert_eq!(rules, vec![Trit::False, Trit::True]);
    assert_eq!(outcome, Outcome::Deny);
    let (rules, outcome, ..) = evaluate(&model, &tri_set::<ATOM_WORDS>(&[Trit::True]))?;
    assert_eq!(rules, vec![Trit::True, Trit::False]);
    assert_eq!(outcome, Outcome::Allow);
    Ok(())
}

#[test]
fn classify_rejects_a_length_mismatch() -> Result<(), DagError> {
    let thresholds = Thresholds::new(&q_pairs(&[(0, 0), (0, 0)]))?;
    let words = attested_words(&[true]);
    let scores = [Q16_16::ZERO];
    assert_eq!(
        classify(
            &ScoreFrame {
                scores: &scores,
                attested: &words
            },
            &thresholds
        )
        .err(),
        Some(DagError::BadLength)
    );
    Ok(())
}
