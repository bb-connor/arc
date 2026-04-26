//! Golden writer for the M04 deterministic-replay gate.
//!
//! Each replay-gate scenario produces three on-disk artifacts under
//! `tests/replay/goldens/<family>/<name>/`:
//!
//! - `receipts.ndjson`: one canonical-JSON object per line, newline
//!   (`0x0a`) terminated, including the final line. NDJSON keeps the
//!   M10 tee streams byte-compatible with the goldens.
//! - `checkpoint.json`: a single canonical-JSON object describing the
//!   scenario's anchor checkpoint. No leading or trailing whitespace.
//! - `root.hex`: the 32-byte Merkle root encoded as exactly 64
//!   lowercase hex characters with no trailing newline. Raw hex makes
//!   diffs human-readable while keeping byte-stable behaviour.
//!
//! The output of this writer is the ground-truth golden bytes for the
//! replay gate, so determinism is the load-bearing guarantee. Every
//! JSON object that flows through [`GoldenSet::append_receipt`] or
//! [`GoldenSet::set_checkpoint`] is reshaped through
//! [`canonicalize`] (recursively sorts object keys, preserves array
//! order) before serialization. `serde_json::to_string` is then used
//! with its default (no insignificant whitespace) settings, and the
//! resulting bytes are what the gate diffs against.
//!
//! Writes are staged into `<file>.tmp` siblings and renamed into place
//! on commit so a partially-written goldens directory is never
//! observable to a follow-on reader.
//!
//! T3 lands the writer only. T4 will add the byte-comparison reader
//! that consumes these files as raw `Vec<u8>` (no serde round-trip),
//! and T5/T6 wire the writer into actual fixture execution.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;
use thiserror::Error;

/// Length, in bytes, of a Merkle root hash produced by the kernel.
const ROOT_LEN: usize = 32;

/// Length, in characters, of a 32-byte root encoded as lowercase hex.
const ROOT_HEX_LEN: usize = ROOT_LEN * 2;

/// Filename for the per-scenario NDJSON receipt stream.
const RECEIPTS_FILENAME: &str = "receipts.ndjson";

/// Filename for the per-scenario canonical-JSON checkpoint.
const CHECKPOINT_FILENAME: &str = "checkpoint.json";

/// Filename for the per-scenario raw-hex Merkle root.
const ROOT_FILENAME: &str = "root.hex";

/// Suffix for staged temporary writes (renamed into place on commit).
const TMP_SUFFIX: &str = ".tmp";

/// Errors produced while staging or committing a [`GoldenSet`].
#[derive(Debug, Error)]
pub enum GoldenWriterError {
    /// `serde_json` failed to serialize a canonicalized value. In
    /// practice this only fires for non-string object keys, which the
    /// recursive [`canonicalize`] helper does not produce, but we keep
    /// the variant so any future regression surfaces fail-closed.
    #[error("canonical-JSON serialization failed: {0}")]
    CanonicalJson(#[from] serde_json::Error),

    /// `commit` was called without a prior `set_checkpoint`.
    #[error("cannot commit goldens: checkpoint was not set")]
    MissingCheckpoint,

    /// `commit` was called without a prior `set_root`.
    #[error("cannot commit goldens: root was not set")]
    MissingRoot,

    /// `commit` was called with no receipts appended. A scenario with
    /// zero receipts is a usage bug, not a valid empty corpus.
    #[error("cannot commit goldens: no receipts were appended")]
    EmptyReceipts,

    /// An I/O operation against a goldens path failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path that was being operated on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Per-file byte sizes recorded after a successful commit. Useful for
/// CI logs and for sanity-checking that a refactor did not change the
/// goldens out from under the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenSetByteSizes {
    /// Byte length of `receipts.ndjson`.
    pub receipts: u64,
    /// Byte length of `checkpoint.json`.
    pub checkpoint: u64,
    /// Byte length of `root.hex`.
    pub root: u64,
}

/// Summary returned from a successful [`GoldenSet::commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenSetSummary {
    /// Directory the goldens were written into.
    pub dir: PathBuf,
    /// Number of receipts written to `receipts.ndjson`.
    pub receipt_count: usize,
    /// Lowercase hex of the Merkle root that was written to
    /// `root.hex` (without a trailing newline).
    pub root_hex: String,
    /// Per-file byte sizes of the three goldens.
    pub byte_sizes: GoldenSetByteSizes,
}

/// In-memory accumulator for one scenario's golden artifacts.
///
/// Construct with [`GoldenSet::new`], stage inputs via
/// [`append_receipt`](Self::append_receipt),
/// [`set_checkpoint`](Self::set_checkpoint), and
/// [`set_root`](Self::set_root), then call [`commit`](Self::commit) to
/// flush the staged bytes to disk atomically.
///
/// Buffers are kept as raw `Vec<u8>` (already canonical-JSON encoded)
/// so the writer never re-serializes between staging and commit, which
/// is what makes the byte-equivalence gate possible.
#[derive(Debug)]
pub struct GoldenSet {
    dir: PathBuf,
    receipts_buf: Vec<u8>,
    receipt_count: usize,
    checkpoint: Option<Vec<u8>>,
    root: Option<[u8; ROOT_LEN]>,
}

impl GoldenSet {
    /// Initialize a new `GoldenSet` for the given per-scenario goldens
    /// directory. The directory is not touched until
    /// [`commit`](Self::commit) is called; create-on-commit keeps the
    /// staging surface side-effect free.
    pub fn new(scenario_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: scenario_dir.as_ref().to_path_buf(),
            receipts_buf: Vec::new(),
            receipt_count: 0,
            checkpoint: None,
            root: None,
        }
    }

    /// Append a single receipt to the staged NDJSON buffer.
    ///
    /// The receipt is canonicalized (object keys sorted recursively),
    /// serialized via `serde_json::to_string` (no insignificant
    /// whitespace), and terminated with a single `\n`.
    pub fn append_receipt(&mut self, receipt: &Value) -> Result<(), GoldenWriterError> {
        let canonical = canonicalize(receipt);
        let line = serde_json::to_string(&canonical)?;
        self.receipts_buf.extend_from_slice(line.as_bytes());
        self.receipts_buf.push(b'\n');
        self.receipt_count = self.receipt_count.saturating_add(1);
        Ok(())
    }

    /// Stage the canonical-JSON encoding of `checkpoint` for later
    /// commit. Replaces any previously staged checkpoint (the last
    /// caller wins, matching the natural "rebuild and overwrite"
    /// flow the gate uses on `--bless`).
    pub fn set_checkpoint(&mut self, checkpoint: &Value) -> Result<(), GoldenWriterError> {
        let canonical = canonicalize(checkpoint);
        let bytes = serde_json::to_vec(&canonical)?;
        self.checkpoint = Some(bytes);
        Ok(())
    }

    /// Stage the 32-byte Merkle root for later commit. Replaces any
    /// previously staged root.
    pub fn set_root(&mut self, root: [u8; ROOT_LEN]) {
        self.root = Some(root);
    }

    /// Flush the staged goldens to disk atomically.
    ///
    /// Behaviour:
    ///
    /// 1. Validates that at least one receipt has been appended and
    ///    that both a checkpoint and a root have been staged. Missing
    ///    pieces produce [`GoldenWriterError::EmptyReceipts`],
    ///    [`GoldenWriterError::MissingCheckpoint`], and
    ///    [`GoldenWriterError::MissingRoot`] respectively.
    /// 2. Creates the goldens directory (`mkdir -p` semantics).
    /// 3. Writes each artifact to a `<file>.tmp` sibling, then renames
    ///    it into place. A failure midway through leaves stale `.tmp`
    ///    files but never half-written goldens.
    /// 4. Returns a [`GoldenSetSummary`] describing what was written.
    pub fn commit(self) -> Result<GoldenSetSummary, GoldenWriterError> {
        if self.receipt_count == 0 {
            return Err(GoldenWriterError::EmptyReceipts);
        }
        let checkpoint_bytes = match self.checkpoint {
            Some(bytes) => bytes,
            None => return Err(GoldenWriterError::MissingCheckpoint),
        };
        let root_bytes = match self.root {
            Some(bytes) => bytes,
            None => return Err(GoldenWriterError::MissingRoot),
        };

        // mkdir -p the per-scenario goldens directory.
        if let Err(source) = fs::create_dir_all(&self.dir) {
            return Err(GoldenWriterError::Io {
                path: self.dir.clone(),
                source,
            });
        }

        let receipts_path = self.dir.join(RECEIPTS_FILENAME);
        let checkpoint_path = self.dir.join(CHECKPOINT_FILENAME);
        let root_path = self.dir.join(ROOT_FILENAME);

        let root_hex = hex::encode(root_bytes);
        // Defensive: the encoder is documented to produce 2*N lowercase
        // hex chars, but the gate's ground-truth invariant is "exactly
        // 64 lowercase hex chars, no trailing newline". Reject up front
        // if that ever drifts.
        if root_hex.len() != ROOT_HEX_LEN {
            return Err(GoldenWriterError::Io {
                path: root_path.clone(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "hex-encoded root has wrong length: expected {ROOT_HEX_LEN}, got {}",
                        root_hex.len()
                    ),
                ),
            });
        }

        atomic_write(&receipts_path, &self.receipts_buf)?;
        atomic_write(&checkpoint_path, &checkpoint_bytes)?;
        atomic_write(&root_path, root_hex.as_bytes())?;

        let receipts_size = file_size(&receipts_path)?;
        let checkpoint_size = file_size(&checkpoint_path)?;
        let root_size = file_size(&root_path)?;

        Ok(GoldenSetSummary {
            dir: self.dir,
            receipt_count: self.receipt_count,
            root_hex,
            byte_sizes: GoldenSetByteSizes {
                receipts: receipts_size,
                checkpoint: checkpoint_size,
                root: root_size,
            },
        })
    }
}

/// Recursively reshape a [`serde_json::Value`] into canonical form.
///
/// Object keys are sorted lexicographically (via [`BTreeMap`]). Array
/// element order is preserved. Strings, numbers, booleans, and null
/// pass through unchanged. The output is structurally identical to
/// the input, so `serde_json` round-tripping it is value-equal but
/// byte-stable across `serde_json` versions that may otherwise emit a
/// different key order.
///
/// This function is the load-bearing determinism primitive for the
/// replay-gate goldens: every byte the writer emits flows through it.
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (key, val) in map.iter() {
                sorted.insert(key.clone(), canonicalize(val));
            }
            // BTreeMap iteration order is the canonical sorted order.
            // serde_json preserves insertion order when not built with
            // the `preserve_order` feature, so we feed the sorted
            // pairs into a fresh Map to lock the byte order in.
            let mut out = serde_json::Map::with_capacity(sorted.len());
            for (key, val) in sorted.into_iter() {
                out.insert(key, val);
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items.iter() {
                out.push(canonicalize(item));
            }
            Value::Array(out)
        }
        // Primitives are byte-stable already.
        other => other.clone(),
    }
}

/// Atomically write `bytes` to `final_path` by staging into
/// `final_path.tmp` and renaming. Wraps any I/O error with the path
/// that was being operated on so callers can distinguish "writing
/// receipts.ndjson failed" from "writing root.hex failed".
fn atomic_write(final_path: &Path, bytes: &[u8]) -> Result<(), GoldenWriterError> {
    let mut staging = final_path.as_os_str().to_owned();
    staging.push(TMP_SUFFIX);
    let staging = PathBuf::from(staging);

    if let Err(source) = fs::write(&staging, bytes) {
        return Err(GoldenWriterError::Io {
            path: staging,
            source,
        });
    }
    if let Err(source) = fs::rename(&staging, final_path) {
        return Err(GoldenWriterError::Io {
            path: final_path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Returns the byte length of `path`, mapping I/O errors into
/// [`GoldenWriterError::Io`].
fn file_size(path: &Path) -> Result<u64, GoldenWriterError> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.len()),
        Err(source) => Err(GoldenWriterError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the golden writer. These drive the canonicalizer
    //! directly and exercise the on-disk write/commit dance through a
    //! temporary directory. The byte-stable invariants asserted here
    //! (key order, NDJSON terminator, root.hex shape) are exactly the
    //! invariants the M04 replay gate diffs against, so a regression
    //! in any one of them surfaces here before the gate ever runs.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn make_dir() -> TempDir {
        TempDir::new().expect("tempdir must succeed in tests")
    }

    fn read_bytes(path: &Path) -> Vec<u8> {
        fs::read(path).expect("read of just-committed goldens must succeed")
    }

    fn read_string(path: &Path) -> String {
        fs::read_to_string(path).expect("read of just-committed goldens must succeed")
    }

    #[test]
    fn canonicalize_sorts_object_keys() {
        let input = json!({"b": 1, "a": 2});
        let out = canonicalize(&input);
        let serialized = serde_json::to_string(&out).expect("re-serialize must succeed");
        assert_eq!(serialized, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn canonicalize_recurses_into_nested() {
        let input = json!({"x": {"b": 1, "a": 2}});
        let out = canonicalize(&input);
        let serialized = serde_json::to_string(&out).expect("re-serialize must succeed");
        assert_eq!(serialized, r#"{"x":{"a":2,"b":1}}"#);
    }

    #[test]
    fn canonicalize_preserves_array_order() {
        let input = json!([3, 1, 2]);
        let out = canonicalize(&input);
        let serialized = serde_json::to_string(&out).expect("re-serialize must succeed");
        assert_eq!(serialized, "[3,1,2]");
    }

    #[test]
    fn canonicalize_handles_primitives() {
        // Numbers, strings, booleans, null pass through structurally.
        for value in [
            json!(null),
            json!(true),
            json!(false),
            json!(0),
            json!(-7),
            json!(2.5),
            json!("hello"),
        ] {
            let out = canonicalize(&value);
            assert_eq!(out, value, "primitive must round-trip unchanged");
        }
    }

    #[test]
    fn canonicalize_sorts_array_of_objects_per_element() {
        let input = json!([
            {"b": 1, "a": 2},
            {"d": 3, "c": 4},
        ]);
        let out = canonicalize(&input);
        let serialized = serde_json::to_string(&out).expect("re-serialize must succeed");
        assert_eq!(serialized, r#"[{"a":2,"b":1},{"c":4,"d":3}]"#);
    }

    #[test]
    fn append_receipt_then_commit_writes_ndjson() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_a");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"b": 1, "a": 2}))
            .expect("append must succeed");
        set.append_receipt(&json!({"id": 42, "kind": "allow"}))
            .expect("append must succeed");
        set.append_receipt(&json!({"nested": {"z": 1, "y": 2}}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "deadbeef", "height": 1}))
            .expect("set_checkpoint must succeed");
        set.set_root([0u8; 32]);

        let summary = set.commit().expect("commit must succeed");
        assert_eq!(summary.receipt_count, 3);
        assert_eq!(summary.dir, dir);

        let receipts_path = dir.join(RECEIPTS_FILENAME);
        let body = read_string(&receipts_path);
        let lines: Vec<&str> = body.split_terminator('\n').collect();
        assert_eq!(lines.len(), 3, "exactly three receipts must be written");
        assert_eq!(lines[0], r#"{"a":2,"b":1}"#);
        assert_eq!(lines[1], r#"{"id":42,"kind":"allow"}"#);
        assert_eq!(lines[2], r#"{"nested":{"y":2,"z":1}}"#);
    }

    #[test]
    fn commit_without_root_fails() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_no_root");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"k": "v"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");

        let err = set.commit().expect_err("commit must fail without root");
        assert!(matches!(err, GoldenWriterError::MissingRoot));
        // The directory should not have been created either, since the
        // mkdir step runs after validation.
        assert!(
            !dir.exists(),
            "no goldens directory must be created on failure"
        );
    }

    #[test]
    fn commit_without_checkpoint_fails() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_no_checkpoint");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"k": "v"}))
            .expect("append must succeed");
        set.set_root([1u8; 32]);

        let err = set
            .commit()
            .expect_err("commit must fail without checkpoint");
        assert!(matches!(err, GoldenWriterError::MissingCheckpoint));
        assert!(
            !dir.exists(),
            "no goldens directory must be created on failure"
        );
    }

    #[test]
    fn commit_with_empty_receipts_fails() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_empty");

        let mut set = GoldenSet::new(&dir);
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");
        set.set_root([2u8; 32]);

        let err = set.commit().expect_err("commit must fail with no receipts");
        assert!(matches!(err, GoldenWriterError::EmptyReceipts));
        assert!(
            !dir.exists(),
            "no goldens directory must be created on failure"
        );
    }

    #[test]
    fn root_hex_is_lowercase_64_chars_no_trailing_newline() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_root_shape");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"only": "one"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "ab", "height": 7}))
            .expect("set_checkpoint must succeed");
        // Use a non-trivial root so we can spot-check encoding.
        let mut root = [0u8; 32];
        for (i, byte) in root.iter_mut().enumerate() {
            *byte = i as u8;
        }
        set.set_root(root);

        let summary = set.commit().expect("commit must succeed");
        assert_eq!(summary.root_hex.len(), 64);
        assert_eq!(
            summary.root_hex,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );

        let root_path = dir.join(ROOT_FILENAME);
        let bytes = read_bytes(&root_path);
        assert_eq!(bytes.len(), 64, "root.hex must be exactly 64 bytes on disk");
        let s = String::from_utf8(bytes).expect("root.hex must be valid UTF-8");
        assert_eq!(s.len(), 64, "root.hex must be exactly 64 chars on disk");
        assert!(
            !s.ends_with('\n'),
            "root.hex must not have a trailing newline"
        );
        assert!(
            s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "root.hex must be lowercase hex only"
        );
    }

    #[test]
    fn ndjson_terminator_is_lf_only() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_ndjson_terminator");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"i": 0}))
            .expect("append must succeed");
        set.append_receipt(&json!({"i": 1}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");
        set.set_root([0u8; 32]);

        set.commit().expect("commit must succeed");

        let receipts_path = dir.join(RECEIPTS_FILENAME);
        let bytes = read_bytes(&receipts_path);
        assert!(!bytes.is_empty(), "receipts.ndjson must not be empty");
        assert_eq!(
            *bytes.last().unwrap_or(&0),
            b'\n',
            "receipts.ndjson must end with a single LF after the last line"
        );
        // No CR anywhere.
        for (i, b) in bytes.iter().enumerate() {
            assert_ne!(
                *b, b'\r',
                "receipts.ndjson byte {i} is CR; LF-only required"
            );
        }
        // Exactly two LFs (one per receipt).
        let lf_count = bytes.iter().filter(|b| **b == b'\n').count();
        assert_eq!(lf_count, 2, "expected one LF per receipt for two receipts");
    }

    #[test]
    fn checkpoint_json_is_canonical_with_no_extra_whitespace() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_checkpoint_canonical");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"x": 1}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"height": 9, "root": "00", "anchored_at": "2026"}))
            .expect("set_checkpoint must succeed");
        set.set_root([3u8; 32]);

        set.commit().expect("commit must succeed");

        let checkpoint_path = dir.join(CHECKPOINT_FILENAME);
        let body = read_string(&checkpoint_path);
        // Keys must be sorted, no spaces, no trailing newline.
        assert_eq!(
            body, r#"{"anchored_at":"2026","height":9,"root":"00"}"#,
            "checkpoint.json must be canonical JSON with sorted keys and no whitespace"
        );
    }

    #[test]
    fn commit_creates_directory_and_reports_byte_sizes() {
        let tmp = make_dir();
        // Use a nested path to verify mkdir -p semantics.
        let dir = tmp.path().join("nested").join("scenario_sizes");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"k": "v"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");
        set.set_root([0u8; 32]);

        let summary = set.commit().expect("commit must succeed");
        assert!(dir.is_dir(), "commit must create nested goldens directory");

        let receipts_size = fs::metadata(dir.join(RECEIPTS_FILENAME))
            .expect("receipts metadata")
            .len();
        let checkpoint_size = fs::metadata(dir.join(CHECKPOINT_FILENAME))
            .expect("checkpoint metadata")
            .len();
        let root_size = fs::metadata(dir.join(ROOT_FILENAME))
            .expect("root metadata")
            .len();

        assert_eq!(summary.byte_sizes.receipts, receipts_size);
        assert_eq!(summary.byte_sizes.checkpoint, checkpoint_size);
        assert_eq!(summary.byte_sizes.root, root_size);
        assert_eq!(summary.byte_sizes.root, 64);
    }

    #[test]
    fn no_tmp_files_remain_after_successful_commit() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_no_tmp");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"k": "v"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");
        set.set_root([0u8; 32]);

        set.commit().expect("commit must succeed");

        let entries: Vec<PathBuf> = fs::read_dir(&dir)
            .expect("readdir must succeed")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .collect();
        for entry in &entries {
            let name = entry
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            assert!(
                !name.ends_with(TMP_SUFFIX),
                "no .tmp staging files must remain after commit (found {name})"
            );
        }
    }
}
