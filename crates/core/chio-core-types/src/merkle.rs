//! RFC 6962-compatible Merkle tree (Certificate Transparency style).
//!
//! This tree is required for receipt log integrity proofs:
//! - `LeafHash(leaf_bytes) = SHA256(0x00 || leaf_bytes)`
//! - `NodeHash(left, right) = SHA256(0x01 || left || right)`
//!
//! This implementation does **not** "duplicate last" when a level has an odd
//! number of nodes; it carries the last node upward unchanged (left-balanced /
//! append-only semantics).

use alloc::vec::Vec;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::{Error, Result};
use crate::hashing::Hash;

/// Compute leaf hash per RFC 6962: `SHA256(0x00 || leaf_bytes)`.
#[must_use]
pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf_bytes);
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// Compute node hash per RFC 6962: `SHA256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// RFC 6962-compatible Merkle tree.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    ///
    /// Returns `Err(Error::EmptyTree)` if the slice is empty.
    pub fn from_leaves<T: AsRef<[u8]>>(leaves: &[T]) -> Result<Self> {
        if leaves.is_empty() {
            return Err(Error::EmptyTree);
        }

        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let mut current: Vec<Hash> = Vec::with_capacity(leaves.len());
        let mut li = 0;
        while li < leaves.len() {
            current.push(leaf_hash(leaves[li].as_ref()));
            li += 1;
        }
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next: Vec<Hash> = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(node_hash(&current[i], &current[i + 1]));
                } else {
                    // Carry last node upward unchanged.
                    next.push(current[i]);
                }
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels })
    }

    /// Build a Merkle tree from pre-hashed leaves.
    pub fn from_hashes(leaf_hashes: Vec<Hash>) -> Result<Self> {
        if leaf_hashes.is_empty() {
            return Err(Error::EmptyTree);
        }

        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let mut current = leaf_hashes;
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next: Vec<Hash> = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(node_hash(&current[i], &current[i + 1]));
                } else {
                    next.push(current[i]);
                }
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels })
    }

    /// Get the number of leaves.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        if self.levels.is_empty() {
            0
        } else {
            self.levels[0].len()
        }
    }

    /// Get the root hash.
    #[must_use]
    pub fn root(&self) -> Hash {
        if self.levels.is_empty() {
            Hash::zero()
        } else {
            let last = &self.levels[self.levels.len() - 1];
            if last.is_empty() {
                Hash::zero()
            } else {
                last[0]
            }
        }
    }

    /// Generate an inclusion proof for a leaf at the given index.
    pub fn inclusion_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        let tree_size = self.leaf_count();
        if leaf_index >= tree_size {
            return Err(Error::InvalidProofIndex {
                index: leaf_index,
                leaves: tree_size,
            });
        }

        let mut audit_path: Vec<Hash> = Vec::new();
        let mut idx = leaf_index;

        let mut level_idx = 0;
        while level_idx < self.levels.len() {
            let level_len = self.levels[level_idx].len();
            if level_len <= 1 {
                break;
            }

            if idx.is_multiple_of(2) {
                let sib = idx + 1;
                if sib < level_len {
                    audit_path.push(self.levels[level_idx][sib]);
                }
            } else {
                audit_path.push(self.levels[level_idx][idx - 1]);
            }

            idx /= 2;
            level_idx += 1;
        }

        Ok(MerkleProof {
            tree_size,
            leaf_index,
            audit_path,
        })
    }

    /// Generate the RFC 6962 consistency proof from `old_size` to this tree.
    ///
    /// The old tree is the prefix containing the first `old_size` leaves.
    /// A same-size proof is valid and has an empty audit path. Zero-sized and
    /// regressing proofs are rejected because this API has no RFC empty-tree
    /// root representation.
    pub fn consistency_proof(&self, old_size: usize) -> Result<MerkleConsistencyProof> {
        let new_size = self.leaf_count();
        if old_size == 0 || old_size > new_size {
            return Err(Error::MerkleProofFailed);
        }

        let mut audit_path = Vec::new();
        if old_size < new_size {
            consistency_subproof(old_size, &self.levels[0], true, &mut audit_path)?;
        }

        Ok(MerkleConsistencyProof {
            old_size,
            new_size,
            audit_path,
        })
    }
}

/// RFC 6962 consistency proof between two tree sizes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleConsistencyProof {
    /// Number of leaves committed by the older root.
    pub old_size: usize,
    /// Number of leaves committed by the newer root.
    pub new_size: usize,
    /// RFC 6962 consistency path ordered from the deepest node to the root.
    pub audit_path: Vec<Hash>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MerkleConsistencyProofWire {
    old_size: usize,
    new_size: usize,
    #[serde(deserialize_with = "deserialize_consistency_path")]
    audit_path: Vec<Hash>,
}

impl<'de> Deserialize<'de> for MerkleConsistencyProof {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = MerkleConsistencyProofWire::deserialize(deserializer)?;
        Ok(Self {
            old_size: wire.old_size,
            new_size: wire.new_size,
            audit_path: wire.audit_path,
        })
    }
}

fn deserialize_consistency_path<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<Hash>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ConsistencyPathVisitor;

    impl<'de> Visitor<'de> for ConsistencyPathVisitor {
        type Value = Vec<Hash>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a bounded RFC 6962 consistency path")
        }

        fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let maximum = usize::BITS as usize + 1;
            if sequence.size_hint().is_some_and(|size| size > maximum) {
                return Err(serde::de::Error::custom(
                    "consistency path exceeds platform tree depth",
                ));
            }
            let mut path = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(maximum));
            while let Some(hash) = sequence.next_element()? {
                if path.len() == maximum {
                    return Err(serde::de::Error::custom(
                        "consistency path exceeds platform tree depth",
                    ));
                }
                path.push(hash);
            }
            Ok(path)
        }
    }

    deserializer.deserialize_seq(ConsistencyPathVisitor)
}

impl MerkleConsistencyProof {
    /// Verify this proof against both advertised roots.
    ///
    /// Verification consumes the complete audit path and rejects malformed,
    /// truncated, extended, zero-sized, or regressing proofs.
    pub fn verify(&self, old_root: &Hash, new_root: &Hash) -> Result<()> {
        let maximum_path_length = usize::BITS as usize + 1;
        if self.audit_path.len() > maximum_path_length {
            return Err(Error::MerkleProofFailed);
        }

        if self.old_size == 0 || self.old_size > self.new_size {
            return Err(Error::MerkleProofFailed);
        }

        if self.old_size == self.new_size {
            if self.audit_path.is_empty() && old_root == new_root {
                return Ok(());
            }
            return Err(Error::MerkleProofFailed);
        }

        let mut old_node = self
            .old_size
            .checked_sub(1)
            .ok_or(Error::MerkleProofFailed)?;
        let mut new_node = self
            .new_size
            .checked_sub(1)
            .ok_or(Error::MerkleProofFailed)?;

        while old_node & 1 == 1 {
            old_node >>= 1;
            new_node >>= 1;
        }

        let (mut old_hash, mut new_hash, mut path_index) = if old_node == 0 {
            (*old_root, *old_root, 0usize)
        } else {
            let seed = *self.audit_path.first().ok_or(Error::MerkleProofFailed)?;
            (seed, seed, 1usize)
        };

        while path_index < self.audit_path.len() {
            if new_node == 0 {
                return Err(Error::MerkleProofFailed);
            }

            let sibling = &self.audit_path[path_index];
            path_index = path_index.checked_add(1).ok_or(Error::MerkleProofFailed)?;

            if old_node & 1 == 1 || old_node == new_node {
                old_hash = node_hash(sibling, &old_hash);
                new_hash = node_hash(sibling, &new_hash);

                while old_node != 0 && old_node & 1 == 0 {
                    old_node >>= 1;
                    new_node >>= 1;
                }
            } else {
                new_hash = node_hash(&new_hash, sibling);
            }

            old_node >>= 1;
            new_node >>= 1;
        }

        if new_node == 0 && old_hash == *old_root && new_hash == *new_root {
            Ok(())
        } else {
            Err(Error::MerkleProofFailed)
        }
    }
}

fn consistency_subproof(
    old_size: usize,
    leaves: &[Hash],
    old_root_known: bool,
    audit_path: &mut Vec<Hash>,
) -> Result<()> {
    if old_size == 0 || old_size > leaves.len() {
        return Err(Error::MerkleProofFailed);
    }

    if old_size == leaves.len() {
        if !old_root_known {
            audit_path.push(subtree_root(leaves)?);
        }
        return Ok(());
    }

    let split = largest_power_of_two_less_than(leaves.len())?;
    if old_size <= split {
        consistency_subproof(old_size, &leaves[..split], old_root_known, audit_path)?;
        audit_path.push(subtree_root(&leaves[split..])?);
    } else {
        let right_old_size = old_size
            .checked_sub(split)
            .ok_or(Error::MerkleProofFailed)?;
        consistency_subproof(right_old_size, &leaves[split..], false, audit_path)?;
        audit_path.push(subtree_root(&leaves[..split])?);
    }

    Ok(())
}

fn subtree_root(leaves: &[Hash]) -> Result<Hash> {
    match leaves {
        [] => Err(Error::EmptyTree),
        [leaf] => Ok(*leaf),
        _ => {
            let split = largest_power_of_two_less_than(leaves.len())?;
            let left = subtree_root(&leaves[..split])?;
            let right = subtree_root(&leaves[split..])?;
            Ok(node_hash(&left, &right))
        }
    }
}

fn largest_power_of_two_less_than(value: usize) -> Result<usize> {
    let below = value.checked_sub(1).ok_or(Error::MerkleProofFailed)?;
    if below == 0 {
        return Err(Error::MerkleProofFailed);
    }
    let exponent = usize::BITS
        .checked_sub(1)
        .and_then(|bits| bits.checked_sub(below.leading_zeros()))
        .ok_or(Error::MerkleProofFailed)?;
    1usize.checked_shl(exponent).ok_or(Error::MerkleProofFailed)
}

/// Merkle inclusion proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Total number of leaves in the tree.
    pub tree_size: usize,
    /// Index of the leaf being proved.
    pub leaf_index: usize,
    /// Audit path (sibling hashes from leaf to root).
    pub audit_path: Vec<Hash>,
}

impl MerkleProof {
    /// Compute the root from leaf bytes and the proof.
    pub fn compute_root(&self, leaf_bytes: &[u8]) -> Result<Hash> {
        self.compute_root_from_hash(leaf_hash(leaf_bytes))
    }

    /// Compute the root from a pre-hashed leaf and the proof.
    pub fn compute_root_from_hash(&self, lh: Hash) -> Result<Hash> {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return Err(Error::MerkleProofFailed);
        }

        let mut h = lh;
        let mut idx = self.leaf_index;
        let mut size = self.tree_size;
        let mut path_idx: usize = 0;

        while size > 1 {
            if idx.is_multiple_of(2) {
                if idx + 1 < size {
                    if path_idx >= self.audit_path.len() {
                        return Err(Error::MerkleProofFailed);
                    }
                    let sibling = &self.audit_path[path_idx];
                    path_idx += 1;
                    h = node_hash(&h, sibling);
                } // else: carried upward (no sibling at this level)
            } else {
                if path_idx >= self.audit_path.len() {
                    return Err(Error::MerkleProofFailed);
                }
                let sibling = &self.audit_path[path_idx];
                path_idx += 1;
                h = node_hash(sibling, &h);
            }

            idx /= 2;
            size = size.div_ceil(2);
        }

        if path_idx != self.audit_path.len() {
            return Err(Error::MerkleProofFailed);
        }

        Ok(h)
    }

    /// Verify the proof against an expected root.
    #[must_use]
    pub fn verify(&self, leaf_bytes: &[u8], expected_root: &Hash) -> bool {
        match self.compute_root(leaf_bytes) {
            Ok(root) => &root == expected_root,
            Err(_) => false,
        }
    }

    /// Verify the proof from a pre-hashed leaf.
    #[must_use]
    pub fn verify_hash(&self, lh: Hash, expected_root: &Hash) -> bool {
        match self.compute_root_from_hash(lh) {
            Ok(root) => &root == expected_root,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tree_hash_recursive(level0: &[Hash]) -> Hash {
        match level0.len() {
            0 => Hash::zero(),
            1 => level0[0],
            n => {
                let k = largest_power_of_two_less_than(n);
                let left = tree_hash_recursive(&level0[..k]);
                let right = tree_hash_recursive(&level0[k..]);
                node_hash(&left, &right)
            }
        }
    }

    fn largest_power_of_two_less_than(n: usize) -> usize {
        let mut p = 1usize;
        while (p << 1) < n {
            p <<= 1;
        }
        p
    }

    #[test]
    fn root_matches_recursive_reference() {
        for n in 1..32usize {
            let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect();
            let tree = MerkleTree::from_leaves(&leaves).unwrap();

            let leaf_hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
            let expected = tree_hash_recursive(&leaf_hashes);
            assert_eq!(tree.root(), expected, "n={n}");
        }
    }

    #[test]
    fn inclusion_proofs_roundtrip() {
        let leaves: Vec<Vec<u8>> = (0..25usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.inclusion_proof(idx).unwrap();
            assert!(proof.verify(leaf, &root), "idx={idx}");
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let leaves: Vec<Vec<u8>> = (0..10usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        let proof = tree.inclusion_proof(3).unwrap();
        assert!(!proof.verify(b"wrong", &root));
    }

    #[test]
    fn single_leaf_tree() {
        let tree = MerkleTree::from_leaves(&[b"single"]).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root(), leaf_hash(b"single"));

        let proof = tree.inclusion_proof(0).unwrap();
        assert!(proof.verify(b"single", &tree.root()));
        assert!(proof.audit_path.is_empty());
    }

    #[test]
    fn two_leaf_tree() {
        let leaves: Vec<&[u8]> = vec![b"left", b"right"];
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        assert_eq!(tree.leaf_count(), 2);

        let expected_root = node_hash(&leaf_hash(b"left"), &leaf_hash(b"right"));
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn empty_tree_fails() {
        let empty: Vec<&[u8]> = vec![];
        let result = MerkleTree::from_leaves(&empty);
        assert!(result.is_err());
    }

    #[test]
    fn proof_serialization_roundtrip() {
        let leaves: Vec<Vec<u8>> = (0..5usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let proof = tree.inclusion_proof(2).unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let restored: MerkleProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof.tree_size, restored.tree_size);
        assert_eq!(proof.leaf_index, restored.leaf_index);
        assert_eq!(proof.audit_path.len(), restored.audit_path.len());
        assert!(restored.verify(&leaves[2], &tree.root()));
    }

    #[test]
    fn from_hashes_matches_from_leaves() {
        let leaves: Vec<Vec<u8>> = (0..7usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree_from_leaves = MerkleTree::from_leaves(&leaves).unwrap();

        let hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
        let tree_from_hashes = MerkleTree::from_hashes(hashes).unwrap();

        assert_eq!(tree_from_leaves.root(), tree_from_hashes.root());
        assert_eq!(tree_from_leaves.leaf_count(), tree_from_hashes.leaf_count());
    }

    #[test]
    fn proof_out_of_bounds() {
        let tree = MerkleTree::from_leaves(&[b"single"]).unwrap();
        let result = tree.inclusion_proof(1);
        assert!(result.is_err());
    }

    #[test]
    fn verify_hash_works() {
        let leaves: Vec<Vec<u8>> = (0..4usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        let proof = tree.inclusion_proof(2).unwrap();
        let lh = leaf_hash(&leaves[2]);
        assert!(proof.verify_hash(lh, &root));
        assert!(!proof.verify_hash(Hash::zero(), &root));
    }

    fn rfc_example_leaves(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| format!("d{index}").into_bytes())
            .collect()
    }

    fn hashes_from_hex(values: &[&str]) -> Vec<Hash> {
        values
            .iter()
            .map(|value| Hash::from_hex(value).unwrap())
            .collect()
    }

    #[test]
    fn consistency_fixed_roots_match_rfc_6962_tree_hashing() {
        // Inputs follow the d0, d1, ... notation in RFC 6962 section 2.1.3.
        // Constants were independently generated from the RFC 6962 MTH
        // recurrence, rather than from MerkleTree's level representation.
        let expected = [
            "c67f9ffe68e0761021341dd516428f42fbdea633731cbdada03bea6b84c652f7",
            "46c78708413a23175f51faf1c22604bccb44482d553b45943b189130ea8221c8",
            "c64c5b9326951a2db82d5462565696286659d1c7a4a26a92703568f63462f7ba",
            "8df3870b33fae650e81938994f98eb4551b143b86c95d3dae4e6444e00715016",
            "2b650a5633502111de1a865b3581e012a91dc1f8b780ddf646a44873dec93163",
            "b65368cd1f024732c21e9db86bcde27d7de95dc2c40d728dd979ffcf943556e3",
            "73a590fb266b81557040b146b9d479e2a1b5849b125167642f5b64866f1d5c7d",
            "3b0c343929799440e33ea5b8376857850457f497736ca6ada6c320ee235b67a4",
            "68be87542fb826407adcdf28d49f0376082c7f3070e51523b21a8e75ddf90fcf",
            "9bfd185351345de98fdfed73047051035dbdc257fedac0fad5531585f20f6e41",
            "bb4b9330960c6cb3f6969214116c4a5b7b079915a3fabd8fc4eba5e46a18bbb8",
            "f7927246750d5116cfc53cfb5f8f3b94b22c4e370ccf4663800a4feaf6e9d3bb",
            "110d9590d50288d53f00eb0d9aabe113f707cc9b67596c347dfe85f750893ab2",
            "93713d9e0a3a1c1fc2f9720045ce7a6a0206dfb9a0c814a03e347f1f9703a02f",
            "21847fe1e39c8488b1c0704c4160d1ecc7c752e857a00777f7744d6540845da0",
            "9f24435f890045ade488df835da5496be8cb932b5b69ea2927abbca7a9687253",
        ];
        let leaves = rfc_example_leaves(expected.len());

        for (index, expected_root) in expected.iter().enumerate() {
            let tree = MerkleTree::from_leaves(&leaves[..=index]).unwrap();
            assert_eq!(
                tree.root().to_hex(),
                *expected_root,
                "tree size {}",
                index + 1
            );
        }
    }

    #[test]
    fn consistency_fixed_paths_match_rfc_6962_example_shape() {
        // RFC 6962 section 2.1.3 specifies PROOF(3, D[7]) = [c,d,g,l],
        // PROOF(4, D[7]) = [l], and PROOF(6, D[7]) = [i,j,k].
        let leaves = rfc_example_leaves(7);
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let vectors = [
            (
                3,
                &[
                    "f366df4718ef75064317794ff5300e0963e96dd93fe24203118055fa5a00be13",
                    "5e0c4e1130dfa84d27437ba073eb817e1896643d42ea100a0940f8752d496783",
                    "46c78708413a23175f51faf1c22604bccb44482d553b45943b189130ea8221c8",
                    "3cf05ff16d26c024828e93b3a14c5656e5abcbc5e6f0bce2cf8a169720599674",
                ][..],
            ),
            (
                4,
                &["3cf05ff16d26c024828e93b3a14c5656e5abcbc5e6f0bce2cf8a169720599674"][..],
            ),
            (
                6,
                &[
                    "a4f2a847cce0dce0519b1d6b83e4ca15166193dbb0c8f864e736665edbde1994",
                    "d750ca922fabc5422eec469d4370779b61d5488186cb871eeea299d8113d20bc",
                    "8df3870b33fae650e81938994f98eb4551b143b86c95d3dae4e6444e00715016",
                ][..],
            ),
        ];

        for (old_size, expected_path) in vectors {
            let proof = tree.consistency_proof(old_size).unwrap();
            assert_eq!(proof.audit_path, hashes_from_hex(expected_path));
        }
    }

    #[test]
    fn consistency_all_pairs_verify_through_sixteen_leaves() {
        let leaves = rfc_example_leaves(16);

        for new_size in 1..=leaves.len() {
            let new_tree = MerkleTree::from_leaves(&leaves[..new_size]).unwrap();
            for old_size in 1..=new_size {
                let old_tree = MerkleTree::from_leaves(&leaves[..old_size]).unwrap();
                let proof = new_tree.consistency_proof(old_size).unwrap();
                proof.verify(&old_tree.root(), &new_tree.root()).unwrap();
            }
        }
    }

    #[test]
    fn consistency_rejects_malformed_proofs_and_roots() {
        let leaves = rfc_example_leaves(7);
        let old_tree = MerkleTree::from_leaves(&leaves[..3]).unwrap();
        let new_tree = MerkleTree::from_leaves(&leaves).unwrap();
        let proof = new_tree.consistency_proof(3).unwrap();
        proof.verify(&old_tree.root(), &new_tree.root()).unwrap();

        assert!(proof.verify(&Hash::zero(), &new_tree.root()).is_err());
        assert!(proof.verify(&old_tree.root(), &Hash::zero()).is_err());

        let mut reordered = proof.clone();
        reordered.audit_path.swap(0, 1);
        assert!(reordered
            .verify(&old_tree.root(), &new_tree.root())
            .is_err());

        let mut truncated = proof.clone();
        truncated.audit_path.pop();
        assert!(truncated
            .verify(&old_tree.root(), &new_tree.root())
            .is_err());

        let mut extended = proof.clone();
        extended.audit_path.push(Hash::zero());
        assert!(extended.verify(&old_tree.root(), &new_tree.root()).is_err());

        let zero = MerkleConsistencyProof {
            old_size: 0,
            new_size: 7,
            audit_path: Vec::new(),
        };
        assert!(zero.verify(&old_tree.root(), &new_tree.root()).is_err());

        let regressed = MerkleConsistencyProof {
            old_size: 8,
            new_size: 7,
            audit_path: Vec::new(),
        };
        assert!(regressed
            .verify(&old_tree.root(), &new_tree.root())
            .is_err());

        let overflow_boundary = MerkleConsistencyProof {
            old_size: usize::MAX - 1,
            new_size: usize::MAX,
            audit_path: Vec::new(),
        };
        assert!(overflow_boundary
            .verify(&old_tree.root(), &new_tree.root())
            .is_err());

        let overlong = MerkleConsistencyProof {
            old_size: 3,
            new_size: 7,
            audit_path: vec![Hash::zero(); usize::BITS as usize + 2],
        };
        assert!(overlong.verify(&old_tree.root(), &new_tree.root()).is_err());
    }

    #[test]
    fn consistency_deserialization_rejects_overlong_paths_before_growth() {
        let hashes = vec![Hash::zero(); usize::BITS as usize + 2];
        let json = serde_json::json!({
            "old_size": 1,
            "new_size": 2,
            "audit_path": hashes,
        });
        assert!(serde_json::from_value::<MerkleConsistencyProof>(json).is_err());
    }

    #[test]
    fn consistency_generation_rejects_zero_and_oversized_old_tree() {
        let leaves = rfc_example_leaves(4);
        let tree = MerkleTree::from_leaves(&leaves).unwrap();

        assert!(tree.consistency_proof(0).is_err());
        assert!(tree.consistency_proof(5).is_err());
    }
}
