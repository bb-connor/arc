//! Immutable representation of the imported scope index: bounds, the leaf and
//! member commitments, the expected tree and the single protected root record.
use super::*;
use chio_core::hashing::Hash;
use chio_core::merkle::{MerkleProof, MerkleTree};
use chio_security_types::recovery::SafeInteger;

use crate::admission_operation_store::security_participant_migration::MAX_TOTAL_ROWS;

/// Every relevant source row joins at most two scopes.
pub(super) const MAX_SCOPE_LEAVES: u64 = 2 * MAX_TOTAL_ROWS;
/// A scope cannot hold more rows than the retained inventory of the store.
pub(super) const MAX_SCOPE_MEMBERS: u64 = MAX_TOTAL_ROWS;
/// Mirrors the migration row index bound.
pub(super) const MAX_MEMBER_ROW_INDEX: u32 = 16_383;
/// Mirrors the migration row byte bound.
pub(super) const MAX_SOURCE_ROW_BYTES: i64 = 16 * 1024 * 1024;
/// A tree of at most 131072 leaves needs at most 17 audit hashes.
pub(super) const MAX_PROOF_DEPTH: usize = 17;
/// Seventeen prefixed hashes plus the proof framing stay below this bound.
pub(super) const MAX_PROOF_BYTES: usize = 2_048;
/// The longest canonical reference is `[8,16383],`.
const MEMBER_REFERENCE_BYTES: u64 = 10;
const MEMBER_DIGEST_DOMAIN: &[u8] = b"chio.imported-influence-scope-index.member-digest.v1\0";

/// Exact byte ceiling of a canonical member list with this many references.
pub(super) fn max_member_bytes(member_count: u64) -> u64 {
    member_count.saturating_mul(MEMBER_REFERENCE_BYTES) + 2
}

/// One member: relevant-table ordinal and row index within that table.
pub(super) type MemberReference = (u16, u32);

pub(super) fn encode_members(
    members: &[MemberReference],
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(&members).map_err(invalid)
}

/// Decode a member list whose byte length the caller already bounded in SQL.
/// The list must be canonical, exactly `member_count` long, strictly ordered
/// and made only of valid relevant-table ordinals and row indices.
pub(super) fn decode_members(
    bytes: &[u8],
    member_count: u64,
) -> Result<Vec<MemberReference>, AdmissionOperationStoreError> {
    if u64::try_from(bytes.len()).map_err(invalid)? > max_member_bytes(member_count) {
        return Err(invalid("imported scope membership exceeds bounds"));
    }
    let members: Vec<MemberReference> = serde_json::from_slice(bytes).map_err(invalid)?;
    if u64::try_from(members.len()).map_err(invalid)? != member_count
        || encode_members(&members)? != bytes
    {
        return Err(invalid(
            "imported scope membership differs from its leaf count",
        ));
    }
    let mut previous: Option<MemberReference> = None;
    for member in &members {
        let (ordinal, row_index) = *member;
        if usize::from(ordinal) >= RELEVANT_TABLES.len() || row_index > MAX_MEMBER_ROW_INDEX {
            return Err(invalid("imported scope member reference is out of bounds"));
        }
        if previous.is_some_and(|prior| prior >= *member) {
            return Err(invalid("imported scope membership is not strictly ordered"));
        }
        previous = Some(*member);
    }
    Ok(members)
}

/// The leaf bytes committed into the tree.
pub(super) fn leaf_payload(
    scope_key: &str,
    member_count: u64,
    member_digest: &str,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(&(scope_key, member_count, member_digest)).map_err(invalid)
}

/// Digest over one scope's complete ordered member list. Each entry commits
/// the relevant source table, the row index and the SHA-256 of the canonical
/// source bytes of that row.
pub(super) fn member_digest(
    scope_key: &str,
    members: &[(&'static str, u32, String)],
) -> Result<String, AdmissionOperationStoreError> {
    let mut bytes = MEMBER_DIGEST_DOMAIN.to_vec();
    bytes.extend(canonical_json_bytes(&(scope_key, members)).map_err(invalid)?);
    Ok(sha256_hex(&bytes))
}

/// One expected leaf, rebuilt identically by hydration and the cold verifier.
pub(super) struct ScopeLeaf {
    pub(super) scope_key: String,
    pub(super) member_count: u64,
    pub(super) member_digest: String,
    pub(super) members: Vec<u8>,
}

/// The complete expected index. A leaf's position is its leaf index. Proofs are
/// derived on demand from the tree so no copy of them is held in memory.
pub(super) struct ExpectedScopeIndex {
    leaves: Vec<ScopeLeaf>,
    tree: Option<MerkleTree>,
}

impl ExpectedScopeIndex {
    /// `leaves` must already be sorted by unique scope key.
    pub(super) fn from_leaves(
        leaves: Vec<ScopeLeaf>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if u64::try_from(leaves.len()).map_err(invalid)? > MAX_SCOPE_LEAVES {
            return Err(invalid("imported scope index exceeds its leaf bound"));
        }
        let tree = if leaves.is_empty() {
            None
        } else {
            let payloads = leaves
                .iter()
                .map(|leaf| leaf_payload(&leaf.scope_key, leaf.member_count, &leaf.member_digest))
                .collect::<Result<Vec<_>, _>>()?;
            Some(MerkleTree::from_leaves(&payloads).map_err(invalid)?)
        };
        Ok(Self { leaves, tree })
    }

    pub(super) fn leaves(&self) -> &[ScopeLeaf] {
        &self.leaves
    }

    pub(super) fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// An empty import still has an authenticated root: the zero hash, bound to
    /// its exact source by the protected record.
    pub(super) fn root(&self) -> Hash {
        self.tree.as_ref().map_or_else(Hash::zero, MerkleTree::root)
    }

    pub(super) fn proof_bytes(
        &self,
        leaf_index: usize,
    ) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let tree = self
            .tree
            .as_ref()
            .ok_or_else(|| invalid("empty imported scope index has no leaf proof"))?;
        let proof = tree.inclusion_proof(leaf_index).map_err(invalid)?;
        let bytes = canonical_json_bytes(&proof).map_err(invalid)?;
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(invalid("imported scope proof exceeds bounds"));
        }
        Ok(bytes)
    }
}

/// Decode a stored proof, already byte-bounded in SQL, and verify it places
/// exactly this leaf at exactly this index of the authenticated tree.
pub(super) fn verify_leaf_proof(
    root: &IndexRoot,
    leaf_index: u64,
    payload: &[u8],
    proof_bytes: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    if proof_bytes.is_empty() || proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(invalid("imported scope proof exceeds bounds"));
    }
    let proof: MerkleProof = serde_json::from_slice(proof_bytes).map_err(invalid)?;
    if proof.tree_size != usize::try_from(root.leaf_count()).map_err(invalid)?
        || proof.leaf_index != usize::try_from(leaf_index).map_err(invalid)?
        || proof.audit_path.len() > MAX_PROOF_DEPTH
        || !proof.verify(payload, root.root())
    {
        return Err(invalid("imported scope proof does not reach its root"));
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum IndexRootSchema {
    #[serde(rename = "chio.imported-influence-scope-index.root.v1")]
    V1,
}

/// The single protected root per initialized authority. It binds the native
/// authority (and so the store and the current initialization), the sealed
/// source identity and the complete scope tree.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct IndexRoot {
    schema: IndexRootSchema,
    native_authority: NativeSecurityAuthorityBindingV1,
    expectation_id: String,
    fingerprint: String,
    root: Hash,
    leaf_count: SafeInteger,
}

impl IndexRoot {
    pub(super) fn bind(
        binding: &NativeSecurityAuthorityBindingV1,
        initialization: &SecurityParticipantStateInitialization,
        root: Hash,
        leaf_count: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            schema: IndexRootSchema::V1,
            native_authority: binding.clone(),
            expectation_id: initialization.expectation_id().as_str().to_owned(),
            fingerprint: initialization.fingerprint.clone(),
            root,
            leaf_count: SafeInteger::new(leaf_count).map_err(invalid)?,
        })
    }

    /// Whether this decoded record is bound to exactly this initialization and
    /// is internally consistent.
    pub(super) fn is_bound_to(
        &self,
        binding: &NativeSecurityAuthorityBindingV1,
        initialization: &SecurityParticipantStateInitialization,
    ) -> bool {
        self.schema == IndexRootSchema::V1
            && self.native_authority == *binding
            && self.expectation_id == initialization.expectation_id().as_str()
            && self.fingerprint == initialization.fingerprint
            && self.leaf_count() <= MAX_SCOPE_LEAVES
            && (self.leaf_count() != 0 || self.root == Hash::zero())
    }

    pub(super) fn root(&self) -> &Hash {
        &self.root
    }

    pub(super) fn leaf_count(&self) -> u64 {
        self.leaf_count.get()
    }
}
