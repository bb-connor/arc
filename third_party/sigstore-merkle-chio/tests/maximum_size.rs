use sigstore_merkle::{hash_children, hash_leaf, verify_inclusion_proof};

#[test]
fn maximum_size_rejects_an_incomplete_proof_without_panicking() {
    let hash = hash_leaf(b"maximum-size audit");
    assert!(verify_inclusion_proof(&hash, 0, u64::MAX, &[], &hash).is_err());
    let short_root = hash_children(&hash, &hash);
    assert!(verify_inclusion_proof(&hash, 0, u64::MAX, &[hash], &short_root).is_err());
}

#[test]
fn maximum_size_requires_the_complete_first_and_last_leaf_paths() {
    let leaf = hash_leaf(b"boundary leaf");
    let sibling = hash_leaf(b"boundary sibling");
    // The first leaf traverses 64 right siblings. The final leaf in this odd
    // tree is promoted once and traverses 63 left siblings.
    for (index, count, left_siblings) in [(0, 64, false), (u64::MAX - 1, 63, true)] {
        let proof = vec![sibling; count];
        let root = proof.iter().fold(leaf, |current, sibling| {
            if left_siblings {
                hash_children(sibling, &current)
            } else {
                hash_children(&current, sibling)
            }
        });
        assert!(verify_inclusion_proof(&leaf, index, u64::MAX, &proof, &root).is_ok());
        assert!(
            verify_inclusion_proof(&leaf, index, u64::MAX, &proof[..count - 1], &root).is_err()
        );
        let mut extra = proof.clone();
        extra.push(sibling);
        assert!(verify_inclusion_proof(&leaf, index, u64::MAX, &extra, &root).is_err());
        assert!(verify_inclusion_proof(&sibling, index, u64::MAX, &proof, &root).is_err());
    }
}
