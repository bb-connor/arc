//! Differential anchored-root tuple harness for M04 Phase 6.
//!
//! This Cargo-recognized integration test emits the Rust-side
//! `(receipt_id, leaf_hash, inclusion_proof, root)` tuple shape for the
//! replay fixture corpus. The TypeScript conformance runner emits the same
//! shape from `sdks/typescript/packages/conformance/src/replay.ts`.

use std::fs;
use std::path::{Path, PathBuf};

use chio_core::canonical::canonical_json_bytes;
use chio_core::merkle::{leaf_hash, MerkleTree};
use serde_json::{json, Value};

const EXPECTED_FIXTURE_COUNT: usize = 50;
const FIXED_CLOCK_EPOCH_MS: u64 = 1_767_225_600_000;
const CANARY_RECEIPT_ID: &str = "allow_simple/01_basic_capability";
const CANARY_LEAF_HASH: &str = "0xe4b0ab524d5ed0a97dec2d92d0dceba4d1b8abb551acacfafff9df69a16436bb";

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnchoredRootTuple {
    receipt_id: String,
    leaf_hash: String,
    inclusion_proof: InclusionProofTuple,
    root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InclusionProofTuple {
    tree_size: usize,
    leaf_index: usize,
    audit_path: Vec<String>,
}

#[test]
fn rust_anchored_root_tuples_emit_in_deterministic_order() -> Result<(), String> {
    let tuples = emit_anchored_root_tuples()?;

    assert_eq!(
        tuples.len(),
        EXPECTED_FIXTURE_COUNT,
        "tuple count must match the replay fixture corpus"
    );

    for pair in tuples.windows(2) {
        assert!(
            pair[0].receipt_id < pair[1].receipt_id,
            "tuple receipt IDs must be byte-sorted: {} then {}",
            pair[0].receipt_id,
            pair[1].receipt_id,
        );
    }

    for tuple in &tuples {
        assert_eq!(
            tuple.leaf_hash, tuple.root,
            "single-receipt scenario root must equal leaf hash for {}",
            tuple.receipt_id,
        );
        assert_eq!(
            tuple.inclusion_proof.tree_size, 1,
            "single-receipt proof tree_size must be one for {}",
            tuple.receipt_id,
        );
        assert_eq!(
            tuple.inclusion_proof.leaf_index, 0,
            "single-receipt proof leaf_index must be zero for {}",
            tuple.receipt_id,
        );
        assert!(
            tuple.inclusion_proof.audit_path.is_empty(),
            "single-receipt proof audit_path must be empty for {}",
            tuple.receipt_id,
        );
    }

    let canary = tuples
        .iter()
        .find(|tuple| tuple.receipt_id == CANARY_RECEIPT_ID)
        .ok_or_else(|| format!("missing canary tuple {CANARY_RECEIPT_ID}"))?;
    assert_eq!(canary.leaf_hash, CANARY_LEAF_HASH);
    assert_eq!(canary.root, CANARY_LEAF_HASH);

    Ok(())
}

#[test]
fn rust_anchored_root_tuples_fail_closed_on_invalid_fixture_root() {
    let result = emit_anchored_root_tuples_from(&workspace_root().join("tests/replay/missing"));
    assert!(
        result.is_err(),
        "missing replay fixture root must fail closed"
    );
}

fn emit_anchored_root_tuples() -> Result<Vec<AnchoredRootTuple>, String> {
    emit_anchored_root_tuples_from(&workspace_root().join("tests/replay/fixtures"))
}

fn emit_anchored_root_tuples_from(root: &Path) -> Result<Vec<AnchoredRootTuple>, String> {
    let manifests = enumerate_manifests(root)?;
    if manifests.len() != EXPECTED_FIXTURE_COUNT {
        return Err(format!(
            "expected {EXPECTED_FIXTURE_COUNT} replay manifests under {}, found {}",
            root.display(),
            manifests.len(),
        ));
    }

    manifests
        .iter()
        .map(|path| {
            let manifest = load_manifest(path)?;
            build_tuple_from_manifest(&manifest)
        })
        .collect()
}

fn build_tuple_from_manifest(manifest: &Value) -> Result<AnchoredRootTuple, String> {
    let receipt_id = string_field(manifest, "name")?.to_string();
    let receipt = json!({
        "scenario": receipt_id,
        "verdict": string_field(manifest, "expected_verdict")?,
        "nonce": nonce_hex_for_seed_index(u64_field(manifest, "fixed_nonce_seed_index")?),
    });
    let receipt_bytes = canonical_json_bytes(&receipt)
        .map_err(|error| format!("canonicalize receipt for {receipt_id}: {error}"))?;
    let leaves = vec![receipt_bytes.clone()];
    let tree = MerkleTree::from_leaves(&leaves)
        .map_err(|error| format!("build Merkle tree for {receipt_id}: {error}"))?;
    let proof = tree
        .inclusion_proof(0)
        .map_err(|error| format!("build inclusion proof for {receipt_id}: {error}"))?;
    let computed_leaf_hash = leaf_hash(&receipt_bytes);
    let root = tree.root();

    if !proof.verify(&receipt_bytes, &root) {
        return Err(format!("inclusion proof failed to verify for {receipt_id}"));
    }
    if computed_leaf_hash != root {
        return Err(format!(
            "single-receipt root does not match leaf hash for {receipt_id}"
        ));
    }

    Ok(AnchoredRootTuple {
        receipt_id,
        leaf_hash: computed_leaf_hash.to_hex_prefixed(),
        inclusion_proof: InclusionProofTuple {
            tree_size: proof.tree_size,
            leaf_index: proof.leaf_index,
            audit_path: proof
                .audit_path
                .iter()
                .map(chio_core::hashing::Hash::to_hex_prefixed)
                .collect(),
        },
        root: root.to_hex_prefixed(),
    })
}

fn enumerate_manifests(root: &Path) -> Result<Vec<PathBuf>, String> {
    let root_meta = fs::metadata(root)
        .map_err(|error| format!("stat replay fixture root {}: {error}", root.display()))?;
    if !root_meta.is_dir() {
        return Err(format!(
            "replay fixture root is not a directory: {}",
            root.display(),
        ));
    }

    let mut out = Vec::new();
    walk_json_files(root, &mut out)?;
    out.sort_by(|left, right| path_bytes(root, left).cmp(&path_bytes(root, right)));
    Ok(out)
}

fn walk_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(dir)
        .map_err(|error| format!("read replay fixture directory {}: {error}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "read replay fixture directory entry {}: {error}",
                dir.display()
            )
        })?;
    entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));

    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("stat replay fixture entry {}: {error}", path.display()))?;
        if file_type.is_dir() {
            walk_json_files(&path, out)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            out.push(path);
        } else if file_type.is_symlink() {
            return Err(format!(
                "symlink in replay fixture tree: {}",
                path.display()
            ));
        }
    }

    Ok(())
}

fn load_manifest(path: &Path) -> Result<Value, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("read replay manifest {}: {error}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("parse replay manifest {}: {error}", path.display()))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| format!("manifest missing non-empty string field {key}"))
}

fn u64_field(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("manifest missing non-negative integer field {key}"))
}

fn nonce_hex_for_seed_index(seed_index: u64) -> String {
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&FIXED_CLOCK_EPOCH_MS.to_be_bytes());
    nonce[8..].copy_from_slice(&seed_index.to_be_bytes());
    hex_lower(&nonce)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn path_bytes(root: &Path, path: &Path) -> Vec<u8> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
        .into_bytes()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
