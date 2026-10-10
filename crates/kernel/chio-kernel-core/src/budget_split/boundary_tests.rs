use super::*;

#[test]
fn holder_exhaustion_refuses_a_lease_without_releasing_existing_share() {
    let mut split = BudgetSplit::new("parent".into(), 4_000);
    split.children.insert(
        "child".into(),
        ChildAdmission {
            share_bps: 4_000,
            holders: usize::MAX,
        },
    );
    assert_eq!(split.verify_child_admission("child".into(), 4_000), Ok(()));
    assert_eq!(
        split.try_admit_child("child".into(), 4_000),
        Err(BudgetSplitError::HolderCountOverflow {
            child_id: "child".into()
        })
    );
    assert_eq!(split.child_holders("child"), Some(usize::MAX));
    assert_eq!(split.release_child("child", 4_000), Ok(()));
    assert_eq!(split.child_holders("child"), Some(usize::MAX - 1));
    assert!(matches!(
        split.try_admit_child("sibling".into(), 1),
        Err(BudgetSplitError::OversubscribedSiblings {
            current_total_child_bps: 4_000,
            ..
        })
    ));
}

#[test]
fn forged_public_split_cannot_wrap_its_share_total_into_admission() {
    let mut split = BudgetSplit::new("parent".into(), MAX_BUDGET_SHARE_BPS);
    for index in 0..=u32::MAX / u32::from(u16::MAX) + 1 {
        split.children.insert(
            index.to_string(),
            ChildAdmission {
                share_bps: u16::MAX,
                holders: 1,
            },
        );
    }
    let expected = BudgetSplitError::ShareTotalOverflow {
        parent_token_id: "parent".into(),
    };
    let count = split.children.len();
    assert_eq!(split.current_total_child_bps(), Err(expected.clone()));
    assert_eq!(split.try_admit_child("new-child".into(), 1), Err(expected));
    assert_eq!(split.children.len(), count);
    assert_eq!(split.child_holders("new-child"), None);
}
