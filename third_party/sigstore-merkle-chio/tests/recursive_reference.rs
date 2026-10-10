use sigstore_merkle::{hash_children, hash_leaf, verify_consistency_proof, verify_inclusion_proof};
use sigstore_types::Sha256Hash;

// Independent recursive definitions from RFC 6962 sections 2.1.1 and 2.1.2.
// The production verifier instead walks the proof using integer bit positions.
fn split(size: usize) -> usize {
    size.next_power_of_two() / 2
}

fn root(leaves: &[Sha256Hash]) -> Sha256Hash {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = split(leaves.len());
    hash_children(&root(&leaves[..k]), &root(&leaves[k..]))
}

fn inclusion(index: usize, leaves: &[Sha256Hash]) -> Vec<Sha256Hash> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let k = split(leaves.len());
    let (mut proof, sibling) = if index < k {
        (inclusion(index, &leaves[..k]), root(&leaves[k..]))
    } else {
        (inclusion(index - k, &leaves[k..]), root(&leaves[..k]))
    };
    proof.push(sibling);
    proof
}

fn consistency(old_size: usize, leaves: &[Sha256Hash], complete: bool) -> Vec<Sha256Hash> {
    if old_size == leaves.len() {
        return if complete {
            Vec::new()
        } else {
            vec![root(leaves)]
        };
    }
    let k = split(leaves.len());
    let (mut proof, sibling) = if old_size <= k {
        (
            consistency(old_size, &leaves[..k], complete),
            root(&leaves[k..]),
        )
    } else {
        (
            consistency(old_size - k, &leaves[k..], false),
            root(&leaves[..k]),
        )
    };
    proof.push(sibling);
    proof
}

#[test]
fn inclusion_matches_recursive_trees_and_rejects_substitutions() {
    let leaves: Vec<_> = (0u64..65).map(|i| hash_leaf(&i.to_be_bytes())).collect();
    let wrong = hash_leaf(b"unrelated leaf");
    for size in 1..=leaves.len() {
        let tree = &leaves[..size];
        let expected = root(tree);
        for (index, leaf) in tree.iter().enumerate() {
            let proof = inclusion(index, tree);
            assert!(
                verify_inclusion_proof(leaf, index as u64, size as u64, &proof, &expected).is_ok()
            );
            assert!(
                verify_inclusion_proof(&wrong, index as u64, size as u64, &proof, &expected)
                    .is_err()
            );
            assert!(
                verify_inclusion_proof(leaf, index as u64, size as u64, &proof, &wrong).is_err()
            );
            let mut extra = proof.clone();
            extra.push(wrong);
            assert!(
                verify_inclusion_proof(leaf, index as u64, size as u64, &extra, &expected).is_err()
            );
            if !proof.is_empty() {
                let mut substituted = proof.clone();
                substituted[0] = wrong;
                assert!(verify_inclusion_proof(
                    leaf,
                    index as u64,
                    size as u64,
                    &substituted,
                    &expected
                )
                .is_err());
                assert!(verify_inclusion_proof(
                    leaf,
                    index as u64,
                    size as u64,
                    &proof[1..],
                    &expected
                )
                .is_err());
            }
        }
    }
}

#[test]
fn consistency_matches_every_recursive_prefix_and_rejects_substitutions() {
    let leaves: Vec<_> = (0u64..65).map(|i| hash_leaf(&i.to_be_bytes())).collect();
    let wrong = hash_leaf(b"unrelated root");
    for size in 1..=leaves.len() {
        let tree = &leaves[..size];
        let new_root = root(tree);
        for old_size in 1..=size {
            let old_root = root(&tree[..old_size]);
            let proof = consistency(old_size, tree, true);
            assert!(verify_consistency_proof(
                old_size as u64,
                size as u64,
                &proof,
                &old_root,
                &new_root
            )
            .is_ok());
            assert!(verify_consistency_proof(
                old_size as u64,
                size as u64,
                &proof,
                &wrong,
                &new_root
            )
            .is_err());
            assert!(verify_consistency_proof(
                old_size as u64,
                size as u64,
                &proof,
                &old_root,
                &wrong
            )
            .is_err());
            let mut extra = proof.clone();
            extra.push(wrong);
            assert!(verify_consistency_proof(
                old_size as u64,
                size as u64,
                &extra,
                &old_root,
                &new_root
            )
            .is_err());
            if !proof.is_empty() {
                let mut substituted = proof.clone();
                substituted[0] = wrong;
                assert!(verify_consistency_proof(
                    old_size as u64,
                    size as u64,
                    &substituted,
                    &old_root,
                    &new_root
                )
                .is_err());
                assert!(verify_consistency_proof(
                    old_size as u64,
                    size as u64,
                    &proof[1..],
                    &old_root,
                    &new_root
                )
                .is_err());
            }
        }
    }
}
