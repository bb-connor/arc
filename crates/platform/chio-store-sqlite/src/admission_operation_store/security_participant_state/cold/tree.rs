//! Persistent leaf-compressed radix map. Reads authenticate every fetched node.

use super::encoding::Payload;
use super::{Digest, Error, Result};
use sha2::{Digest as _, Sha256};

const KEY_BITS: usize = 256;
const LEAF_DOMAIN: &[u8] = b"chio.native-cold.leaf.v1\0";
const BRANCH_DOMAIN: &[u8] = b"chio.native-cold.branch.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Node {
    Leaf { key: Digest, payload: Vec<u8> },
    Branch { left: Digest, right: Digest },
}

impl Node {
    pub(super) fn digest(&self) -> Result<Digest> {
        let mut hash = Sha256::new();
        match self {
            Self::Leaf { key, payload } => {
                Payload::decode(payload)?;
                hash.update(LEAF_DOMAIN);
                hash.update(key);
                hash.update(Sha256::digest(payload));
            }
            Self::Branch { left, right } => {
                hash.update(BRANCH_DOMAIN);
                hash.update(left);
                hash.update(right);
            }
        }
        Ok(hash.finalize().into())
    }
}

pub(super) trait NodeSource {
    fn load(&mut self, digest: Digest) -> Result<Option<Node>>;
}

pub(super) trait NodeSink: NodeSource {
    fn store(&mut self, digest: Digest, node: Node) -> Result<()>;
}

pub(super) fn empty_digest() -> Digest {
    Sha256::digest(b"chio.native-cold.empty.v1\0").into()
}

pub(super) fn lookup(
    source: &mut impl NodeSource,
    root: Digest,
    key: Digest,
) -> Result<Option<Payload>> {
    let empty = empty_digest();
    let mut node = root;
    let mut depth = 0;
    let mut must_be_branch = false;
    loop {
        if node == empty {
            return Ok(None);
        }
        match checked_node(source, node, depth, must_be_branch)? {
            Node::Leaf {
                key: found,
                payload,
            } => {
                if !prefix_matches(&found, &key, depth) {
                    return Err(Error::Placement);
                }
                return if found == key {
                    Ok(Some(Payload::decode(&payload)?))
                } else {
                    Ok(None)
                };
            }
            Node::Branch { left, right } => {
                let (selected, sibling) = if bit(&key, depth) {
                    (right, left)
                } else {
                    (left, right)
                };
                if selected == empty {
                    // An EMPTY child is canonical only beside a branch. This
                    // early-return fetch keeps valid absence within 256 reads.
                    checked_node(source, sibling, depth + 1, true)?;
                    return Ok(None);
                }
                node = selected;
                depth += 1;
                must_be_branch = sibling == empty;
            }
        }
    }
}

pub(super) fn batch_update(
    store: &mut impl NodeSink,
    root: Digest,
    updates: &[(Digest, Payload)],
) -> Result<Digest> {
    if updates.is_empty() {
        if root != empty_digest() {
            checked_node(store, root, 0, false)?;
        }
        return Ok(root);
    }
    let mut encoded = updates
        .iter()
        .map(|(key, payload)| Ok((*key, payload.encode()?)))
        .collect::<Result<Vec<_>>>()?;
    encoded.sort_by_key(|entry| entry.0);
    if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::DuplicateKey);
    }
    merge(store, root, 0, &encoded, false)
}

fn checked_node(
    source: &mut impl NodeSource,
    digest: Digest,
    depth: usize,
    must_be_branch: bool,
) -> Result<Node> {
    let node = source.load(digest)?.ok_or(Error::MissingNode)?;
    if node.digest()? != digest {
        return Err(Error::NodeDigest);
    }
    match &node {
        Node::Leaf { .. } if depth > KEY_BITS => return Err(Error::Depth),
        Node::Leaf { .. } if must_be_branch => return Err(Error::Shape),
        Node::Branch { .. } if depth >= KEY_BITS => return Err(Error::Depth),
        Node::Branch { left, right } => {
            let empty = empty_digest();
            if (*left == empty && *right == empty)
                || (depth == KEY_BITS - 1 && (*left == empty || *right == empty))
            {
                return Err(Error::Shape);
            }
        }
        _ => {}
    }
    Ok(node)
}

fn merge(
    store: &mut impl NodeSink,
    root: Digest,
    depth: usize,
    updates: &[(Digest, Vec<u8>)],
    must_be_branch: bool,
) -> Result<Digest> {
    let empty = empty_digest();
    if root == empty {
        if must_be_branch {
            return Err(Error::Shape);
        }
        return build(store, depth, updates);
    }
    if updates.is_empty() {
        if must_be_branch {
            checked_node(store, root, depth, true)?;
        }
        return Ok(root);
    }
    match checked_node(store, root, depth, must_be_branch)? {
        Node::Leaf { key, payload } => {
            if !prefix_matches(&key, &updates[0].0, depth) {
                return Err(Error::Placement);
            }
            let mut combined = updates.to_vec();
            if !combined.iter().any(|entry| entry.0 == key) {
                combined.push((key, payload));
            }
            combined.sort_by_key(|entry| entry.0);
            build(store, depth, &combined)
        }
        Node::Branch { left, right } => {
            let split = updates.partition_point(|entry| !bit(&entry.0, depth));
            let right_must_be_branch = left == empty;
            let left = merge(store, left, depth + 1, &updates[..split], right == empty)?;
            let right = merge(
                store,
                right,
                depth + 1,
                &updates[split..],
                right_must_be_branch,
            )?;
            combine(store, depth, left, right)
        }
    }
}

fn build(store: &mut impl NodeSink, depth: usize, entries: &[(Digest, Vec<u8>)]) -> Result<Digest> {
    match entries {
        [] => Ok(empty_digest()),
        [(key, payload)] if depth <= KEY_BITS => persist(
            store,
            Node::Leaf {
                key: *key,
                payload: payload.clone(),
            },
        ),
        _ if depth >= KEY_BITS => Err(Error::Depth),
        _ => {
            let split = entries.partition_point(|entry| !bit(&entry.0, depth));
            let left = build(store, depth + 1, &entries[..split])?;
            let right = build(store, depth + 1, &entries[split..])?;
            combine(store, depth, left, right)
        }
    }
}

fn combine(store: &mut impl NodeSink, depth: usize, left: Digest, right: Digest) -> Result<Digest> {
    let empty = empty_digest();
    if left == empty && right == empty {
        return Ok(empty);
    }
    if left == empty || right == empty {
        let nonempty = if left == empty { right } else { left };
        if matches!(
            checked_node(store, nonempty, depth + 1, false)?,
            Node::Leaf { .. }
        ) {
            return Ok(nonempty);
        }
    }
    persist(store, Node::Branch { left, right })
}

fn persist(store: &mut impl NodeSink, node: Node) -> Result<Digest> {
    let digest = node.digest()?;
    if digest == empty_digest() {
        return Err(Error::Conflict);
    }
    if let Some(prior) = store.load(digest)? {
        if prior.digest()? != digest || prior != node {
            return Err(Error::Conflict);
        }
    } else {
        store.store(digest, node)?;
    }
    Ok(digest)
}

// Callers check branch depth before selecting its bit.
fn bit(key: &Digest, depth: usize) -> bool {
    key[depth / 8] & (1 << (7 - depth % 8)) != 0
}

fn prefix_matches(first: &Digest, second: &Digest, depth: usize) -> bool {
    if depth > KEY_BITS {
        return false;
    }
    let bytes = depth / 8;
    if first[..bytes] != second[..bytes] {
        return false;
    }
    let rest = depth % 8;
    rest == 0 || first[bytes] & (u8::MAX << (8 - rest)) == second[bytes] & (u8::MAX << (8 - rest))
}
