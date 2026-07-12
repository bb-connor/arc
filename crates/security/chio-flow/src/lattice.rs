use alloc::collections::{btree_map::Entry, BTreeSet};
use chio_security_types::{InformationLabel, LabelValidationError};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LatticeError {
    InvalidJoin(LabelValidationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressDenial {
    MissingClearance,
    TopSource,
    TopClearance,
    FlowViolation,
}

pub trait InformationFlowLattice {
    fn flows_to(&self, destination: &Self) -> bool;

    fn join(&self, other: &Self) -> Result<Self, LatticeError>
    where
        Self: Sized;
}

impl fmt::Display for LatticeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJoin(error) => write!(formatter, "invalid label join: {error}"),
        }
    }
}

impl core::error::Error for LatticeError {}

impl From<LabelValidationError> for LatticeError {
    fn from(error: LabelValidationError) -> Self {
        Self::InvalidJoin(error)
    }
}

impl fmt::Display for EgressDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MissingClearance => "egress clearance is missing",
            Self::TopSource => "top-labeled data cannot egress",
            Self::TopClearance => "top is not an operational egress clearance",
            Self::FlowViolation => "source label does not flow to destination clearance",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for EgressDenial {}

impl InformationFlowLattice for InformationLabel {
    fn flows_to(&self, destination: &Self) -> bool {
        match (self, destination) {
            (_, Self::Top) => true,
            (Self::Top, Self::Known { .. }) => false,
            (
                Self::Known {
                    owners: source_owners,
                    compartments: source_compartments,
                    ..
                },
                Self::Known {
                    owners: destination_owners,
                    compartments: destination_compartments,
                    ..
                },
            ) => {
                source_compartments.is_subset(destination_compartments)
                    && source_owners.iter().all(|(owner, source_readers)| {
                        destination_owners
                            .get(owner)
                            .is_some_and(|destination_readers| {
                                destination_readers.is_subset(source_readers)
                            })
                    })
            }
        }
    }

    fn join(&self, other: &Self) -> Result<Self, LatticeError> {
        let (
            Self::Known {
                owners: left_owners,
                compartments: left_compartments,
                ..
            },
            Self::Known {
                owners: right_owners,
                compartments: right_compartments,
                ..
            },
        ) = (self, other)
        else {
            return Ok(Self::Top);
        };

        let mut owners = left_owners.clone();
        for (owner, right_readers) in right_owners {
            match owners.entry(owner.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(right_readers.clone());
                }
                Entry::Occupied(mut entry) => {
                    let readers = entry
                        .get()
                        .intersection(right_readers)
                        .cloned()
                        .collect::<BTreeSet<_>>();
                    entry.insert(readers);
                }
            }
        }
        let compartments = left_compartments
            .union(right_compartments)
            .cloned()
            .collect();
        InformationLabel::try_known(owners, compartments).map_err(Into::into)
    }
}

pub fn authorize_egress(
    source: &InformationLabel,
    clearance: Option<&InformationLabel>,
) -> Result<(), EgressDenial> {
    if matches!(source, InformationLabel::Top) {
        return Err(EgressDenial::TopSource);
    }
    let clearance = clearance.ok_or(EgressDenial::MissingClearance)?;
    if matches!(clearance, InformationLabel::Top) {
        return Err(EgressDenial::TopClearance);
    }
    if !source.flows_to(clearance) {
        return Err(EgressDenial::FlowViolation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{authorize_egress, EgressDenial, InformationFlowLattice, LatticeError};
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::format;
    use chio_security_types::{Compartment, InformationLabel, PrincipalId};
    use proptest::collection::{btree_map, btree_set};
    use proptest::prelude::*;

    fn principal(value: u8) -> PrincipalId {
        PrincipalId::new(format!("p{value}")).unwrap_or_else(|error| panic!("id: {error}"))
    }

    fn compartment(value: u8) -> Compartment {
        Compartment::new(format!("c{value}")).unwrap_or_else(|error| panic!("id: {error}"))
    }

    fn known(policies: BTreeMap<u8, BTreeSet<u8>>, compartments: BTreeSet<u8>) -> InformationLabel {
        let owners = policies
            .into_iter()
            .map(|(owner, readers)| {
                let owner_id = principal(owner);
                let mut readers = readers.into_iter().map(principal).collect::<BTreeSet<_>>();
                readers.insert(owner_id.clone());
                (owner_id, readers)
            })
            .collect();
        let compartments = compartments.into_iter().map(compartment).collect();
        InformationLabel::try_known(owners, compartments)
            .unwrap_or_else(|error| panic!("generated label: {error}"))
    }

    fn label_strategy() -> impl Strategy<Value = InformationLabel> {
        prop_oneof![
            1 => Just(InformationLabel::Top),
            9 => (
                btree_map(0_u8..5, btree_set(0_u8..7, 0..7), 0..5),
                btree_set(0_u8..7, 0..7),
            )
                .prop_map(|(owners, compartments)| known(owners, compartments)),
        ]
    }

    proptest! {
        #[test]
        fn lattice_order_is_reflexive(label in label_strategy()) {
            prop_assert!(label.flows_to(&label));
        }

        #[test]
        fn lattice_order_is_antisymmetric(a in label_strategy(), b in label_strategy()) {
            if a.flows_to(&b) && b.flows_to(&a) {
                prop_assert_eq!(a, b);
            }
        }

        #[test]
        fn lattice_order_is_transitive(
            a in label_strategy(),
            b in label_strategy(),
            c in label_strategy(),
        ) {
            if a.flows_to(&b) && b.flows_to(&c) {
                prop_assert!(a.flows_to(&c));
            }
        }

        #[test]
        fn each_operand_flows_to_its_join(a in label_strategy(), b in label_strategy()) {
            let joined = a.join(&b).unwrap_or_else(|error| panic!("join: {error}"));
            prop_assert!(a.flows_to(&joined));
            prop_assert!(b.flows_to(&joined));
        }

        #[test]
        fn join_flows_to_every_generated_common_upper_bound(
            a in label_strategy(),
            b in label_strategy(),
            extra in label_strategy(),
        ) {
            let join = a.join(&b).unwrap_or_else(|error| panic!("join: {error}"));
            let upper_bound = join.join(&extra).unwrap_or_else(|error| panic!("upper bound: {error}"));
            prop_assert!(a.flows_to(&upper_bound));
            prop_assert!(b.flows_to(&upper_bound));
            prop_assert!(join.flows_to(&upper_bound));
        }

        #[test]
        fn join_is_commutative(a in label_strategy(), b in label_strategy()) {
            prop_assert_eq!(a.join(&b), b.join(&a));
        }

        #[test]
        fn join_is_associative(a in label_strategy(), b in label_strategy(), c in label_strategy()) {
            let left = a.join(&b).and_then(|joined| joined.join(&c));
            let right = b.join(&c).and_then(|joined| a.join(&joined));
            prop_assert_eq!(left, right);
        }

        #[test]
        fn join_is_idempotent(label in label_strategy()) {
            prop_assert_eq!(label.join(&label), Ok(label));
        }
    }

    #[test]
    fn redundant_same_owner_policies_cannot_create_unequal_equivalent_labels() {
        let alice = principal(1);
        let bob = principal(2);
        let canonical = InformationLabel::try_known(
            BTreeMap::from([(alice.clone(), BTreeSet::from([alice.clone(), bob]))]),
            BTreeSet::new(),
        )
        .unwrap_or_else(|error| panic!("label: {error}"));
        let encoded =
            r#"{"kind":"known","owners":{"p1":["p1","p2"],"p1":["p1"]},"compartments":[]}"#;
        assert!(serde_json::from_str::<InformationLabel>(encoded).is_err());
        assert_eq!(canonical.join(&canonical), Ok(canonical));
    }

    #[test]
    fn adding_an_owner_restriction_is_upward_in_the_order() {
        let bottom = InformationLabel::bottom();
        let alice = principal(1);
        let restricted = InformationLabel::try_known(
            BTreeMap::from([(alice.clone(), BTreeSet::from([alice]))]),
            BTreeSet::new(),
        )
        .unwrap_or_else(|error| panic!("label: {error}"));
        assert!(bottom.flows_to(&restricted));
        assert!(!restricted.flows_to(&bottom));
    }

    #[test]
    fn narrowing_readers_is_upward_in_the_order() {
        let alice = principal(1);
        let bob = principal(2);
        let broad = InformationLabel::try_known(
            BTreeMap::from([(alice.clone(), BTreeSet::from([alice.clone(), bob]))]),
            BTreeSet::new(),
        )
        .unwrap_or_else(|error| panic!("label: {error}"));
        let narrow = InformationLabel::try_known(
            BTreeMap::from([(alice.clone(), BTreeSet::from([alice]))]),
            BTreeSet::new(),
        )
        .unwrap_or_else(|error| panic!("label: {error}"));
        assert!(broad.flows_to(&narrow));
        assert!(!narrow.flows_to(&broad));
    }

    #[test]
    fn top_is_mathematical_top_but_operationally_denied_on_egress() {
        let bottom = InformationLabel::bottom();
        assert!(bottom.flows_to(&InformationLabel::Top));
        assert!(InformationLabel::Top.flows_to(&InformationLabel::Top));
        assert_eq!(
            authorize_egress(&InformationLabel::Top, Some(&InformationLabel::Top)),
            Err(EgressDenial::TopSource)
        );
        assert_eq!(
            authorize_egress(&bottom, Some(&InformationLabel::Top)),
            Err(EgressDenial::TopClearance)
        );
        assert_eq!(
            authorize_egress(&bottom, None),
            Err(EgressDenial::MissingClearance)
        );
    }

    #[test]
    fn join_cardinality_overflow_returns_a_validation_error() {
        let owners = |start: u8| {
            (start..start + 64)
                .map(|value| {
                    let owner = principal(value);
                    (owner.clone(), BTreeSet::from([owner]))
                })
                .collect::<BTreeMap<_, _>>()
        };
        let left = InformationLabel::try_known(owners(0), BTreeSet::new())
            .unwrap_or_else(|error| panic!("left label: {error}"));
        let right = InformationLabel::try_known(owners(64), BTreeSet::new())
            .unwrap_or_else(|error| panic!("right label: {error}"));
        assert!(matches!(
            left.join(&right),
            Err(LatticeError::InvalidJoin(_))
        ));
    }
}
