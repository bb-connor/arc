use super::*;
use alloc::format;
use alloc::string::ToString;

fn assert_counters_match_state(registry: &InMemoryBudgetRegistry) {
    let edges: usize = registry
        .parents
        .values()
        .map(|parent| parent.split.child_count())
        .sum();
    let bytes: usize = registry
        .parents
        .iter()
        .map(|(parent_token_id, parent)| {
            parent_token_id.len() * 2 + parent.split.children.keys().map(String::len).sum::<usize>()
        })
        .sum();
    assert_eq!(registry.child_edges, edges);
    assert_eq!(registry.retained_id_bytes, bytes);
}

fn exhausted(parent_token_id: &str) -> Result<(), BudgetSplitError> {
    Err(BudgetSplitError::RegistryCapacityExhausted {
        parent_token_id: parent_token_id.to_string(),
    })
}

fn fill_with_operator_parents(registry: &mut InMemoryBudgetRegistry, count: usize) {
    for index in 0..count {
        assert_eq!(
            registry.register_parent(format!("operator-{index}"), 0),
            Ok(())
        );
    }
}

#[test]
fn global_parent_capacity_refuses_fresh_parents_and_keeps_existing() {
    let mut registry = InMemoryBudgetRegistry::new();
    fill_with_operator_parents(&mut registry, MAX_BUDGET_PARENTS);
    assert_eq!(
        registry.register_parent("fresh".into(), 0),
        exhausted("fresh")
    );
    assert_eq!(registry.register_parent("operator-0".into(), 0), Ok(()));
    assert_eq!(registry.parents.len(), MAX_BUDGET_PARENTS);
    assert!(registry.split("fresh").is_none());
    assert_counters_match_state(&registry);
}

#[test]
fn many_zero_share_parents_reach_the_global_edge_capacity() {
    let mut registry = InMemoryBudgetRegistry::new();
    let edges_per_parent = MAX_REGISTRY_CHILD_EDGES / MAX_BUDGET_PARENTS;
    fill_with_operator_parents(&mut registry, MAX_BUDGET_PARENTS);
    for index in 0..MAX_BUDGET_PARENTS {
        let parent_token_id = format!("operator-{index}");
        for child in 0..edges_per_parent {
            assert_eq!(
                registry.verify_child_admission(&parent_token_id, format!("c{child}"), 0),
                Ok(())
            );
        }
    }
    assert_eq!(registry.child_edges, MAX_REGISTRY_CHILD_EDGES);
    assert_eq!(
        registry.verify_child_admission("operator-0", "one-more".into(), 0),
        exhausted("operator-0")
    );
    assert_eq!(
        registry.try_admit_child("operator-0", "c0".into(), 0),
        Ok(())
    );
    assert_eq!(
        registry
            .split("operator-0")
            .and_then(|split| split.child_holders("c0")),
        Some(1)
    );
    assert_counters_match_state(&registry);
}

#[test]
fn global_id_byte_capacity_counts_both_owned_parent_id_copies() {
    let mut registry = InMemoryBudgetRegistry::new();
    let parent_id_bytes = MAX_REGISTRY_RETAINED_ID_BYTES / 16;
    let parent = |index: usize| {
        let mut id = "0".repeat(parent_id_bytes);
        let prefix = index.to_string();
        id.replace_range(..prefix.len(), &prefix);
        id
    };
    for index in 0..8 {
        assert_eq!(registry.register_parent(parent(index), 0), Ok(()));
    }
    assert_eq!(registry.retained_id_bytes, MAX_REGISTRY_RETAINED_ID_BYTES);
    assert_eq!(
        registry.register_parent(parent(8), 0),
        exhausted(&parent(8))
    );
    assert_eq!(registry.parents.len(), 8);
    assert_counters_match_state(&registry);
}

#[test]
fn expired_zero_holder_parent_is_reclaimed_for_healthy_work() {
    let mut registry = InMemoryBudgetRegistry::new();
    assert_eq!(
        registry.register_expiring_parent("expiring".into(), 0, 100, 50),
        Ok(())
    );
    assert_eq!(
        registry.verify_child_admission("expiring", "verified-child".into(), 0),
        Ok(())
    );
    fill_with_operator_parents(&mut registry, MAX_BUDGET_PARENTS - 1);
    assert_eq!(
        registry.register_expiring_parent("healthy".into(), 0, 300, 150),
        Ok(())
    );
    assert!(registry.split("expiring").is_none());
    assert!(registry.split("healthy").is_some());
    assert_eq!(registry.parents.len(), MAX_BUDGET_PARENTS);
    assert_counters_match_state(&registry);
}

#[test]
fn any_live_lease_holder_keeps_an_expired_parent() {
    let mut registry = InMemoryBudgetRegistry::new();
    assert_eq!(
        registry.register_expiring_parent("expiring".into(), 0, 100, 50),
        Ok(())
    );
    assert_eq!(
        registry.verify_child_admission("expiring", "verified-child".into(), 0),
        Ok(())
    );
    assert_eq!(
        registry.try_admit_child("expiring", "leased-child".into(), 0),
        Ok(())
    );
    fill_with_operator_parents(&mut registry, MAX_BUDGET_PARENTS - 1);
    assert_eq!(
        registry.register_expiring_parent("healthy".into(), 0, 300, 150),
        exhausted("healthy")
    );
    assert!(registry.split("expiring").is_some());
    assert!(registry.split("healthy").is_none());
    assert_counters_match_state(&registry);
}

#[test]
fn stale_trusted_time_never_reclaims_an_unexpired_parent() {
    let mut registry = InMemoryBudgetRegistry::new();
    assert_eq!(
        registry.register_expiring_parent("expiring".into(), 0, 200, 150),
        Ok(())
    );
    fill_with_operator_parents(&mut registry, MAX_BUDGET_PARENTS - 1);
    assert_eq!(
        registry.register_parent("fresh".into(), 0),
        exhausted("fresh")
    );
    assert_eq!(
        registry.register_expiring_parent("healthy".into(), 0, 300, 120),
        exhausted("healthy")
    );
    assert_eq!(registry.latest_trusted_now_secs, Some(150));
    assert!(registry.split("expiring").is_some());
    assert_counters_match_state(&registry);
}

#[test]
fn already_expired_new_registration_is_refused_and_leaves_nothing() {
    let mut registry = InMemoryBudgetRegistry::new();
    assert_eq!(
        registry.register_expiring_parent("at-expiry".into(), 0, 150, 150),
        Err(BudgetSplitError::ExpiredParent {
            parent_token_id: "at-expiry".into()
        })
    );
    assert_eq!(registry.latest_trusted_now_secs, Some(150));
    assert_eq!(
        registry.register_expiring_parent("behind-watermark".into(), 0, 140, 120),
        Err(BudgetSplitError::ExpiredParent {
            parent_token_id: "behind-watermark".into()
        })
    );
    assert!(registry.parents.is_empty());
    assert_eq!(registry.retained_id_bytes, 0);
}

#[test]
fn expiry_or_share_conflict_keeps_the_original_registration() {
    let mut registry = InMemoryBudgetRegistry::new();
    assert_eq!(
        registry.register_expiring_parent("parent".into(), 5_000, 200, 10),
        Ok(())
    );
    assert_eq!(
        registry.try_admit_child("parent", "child".into(), 1_000),
        Ok(())
    );
    assert_eq!(
        registry.register_expiring_parent("parent".into(), 5_000, 300, 20),
        Err(BudgetSplitError::ParentExpiryConflict {
            parent_token_id: "parent".into()
        })
    );
    assert_eq!(
        registry.register_expiring_parent("parent".into(), 4_000, 200, 20),
        Err(BudgetSplitError::DuplicateChild {
            child_id: "parent".into()
        })
    );
    assert_eq!(
        registry.register_expiring_parent("parent".into(), 5_000, 200, 20),
        Ok(())
    );
    let parent = registry.parents.get("parent").expect("original kept");
    assert_eq!(parent.expires_at_secs, Some(200));
    assert_eq!(parent.split.parent_share_bps, 5_000);
    assert_eq!(parent.split.child_holders("child"), Some(1));
    assert_counters_match_state(&registry);
}

#[test]
fn operator_registered_parent_stays_non_expiring_under_lineage_registration() {
    let mut registry = InMemoryBudgetRegistry::new();
    assert_eq!(registry.register_parent("operator".into(), 5_000), Ok(()));
    assert_eq!(
        registry.register_expiring_parent("operator".into(), 5_000, 100, 10),
        Ok(())
    );
    assert_eq!(
        registry
            .parents
            .get("operator")
            .map(|parent| parent.expires_at_secs),
        Some(None)
    );
    fill_with_operator_parents(&mut registry, MAX_BUDGET_PARENTS - 1);
    assert_eq!(
        registry.register_expiring_parent("late".into(), 0, 1_000, 500),
        exhausted("late")
    );
    assert!(registry.split("operator").is_some());
}

#[test]
fn release_and_evict_return_exact_counters() {
    let mut registry = InMemoryBudgetRegistry::new();
    assert_eq!(registry.register_parent("parent".into(), 5_000), Ok(()));
    assert_eq!(
        registry.try_admit_child("parent", "a".into(), 1_000),
        Ok(())
    );
    assert_eq!(
        registry.try_admit_child("parent", "a".into(), 1_000),
        Ok(())
    );
    assert_eq!(
        registry.verify_child_admission("parent", "bb".into(), 0),
        Ok(())
    );
    assert_eq!(registry.child_edges, 2);
    assert_eq!(registry.release_child("parent", "a", 1_000), Ok(()));
    assert_eq!(registry.child_edges, 2);
    assert_eq!(registry.release_child("parent", "a", 1_000), Ok(()));
    assert_eq!(registry.child_edges, 1);
    assert_counters_match_state(&registry);
    registry.evict_parent("parent");
    assert_eq!(registry.child_edges, 0);
    assert_eq!(registry.retained_id_bytes, 0);
}
