//! Pins every built-in signed-artifact catalog row: the schema id, its
//! registry metadata, and its position in the catalog.

use sha2::{Digest, Sha256};

const CATALOG_ROWS: usize = 443;

/// SHA-256 of the catalog serialized as one `schema\tartifact_kind\tintroduced_by\n`
/// line per row, in catalog order, with empty metadata fields for a row that
/// has no registry entry.
const CATALOG_SHA256: &str = "8e63665459dd1b8ccfcb14f014aa97bc68c5576be7f078168685158bf1e78837";

#[test]
fn built_in_catalog_matches_pinned_rows_in_order() {
    let mut registry = chio_core_types::built_in_signed_artifact_registry()
        .into_iter()
        .peekable();
    let mut serialized = String::new();
    for schema in chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS {
        let (artifact_kind, introduced_by) = registry
            .next_if(|entry| entry.schema == *schema)
            .map(|entry| (entry.artifact_kind, entry.introduced_by))
            .unwrap_or_default();
        for field in [*schema, artifact_kind.as_str(), introduced_by.as_str()] {
            serialized.push_str(field);
            serialized.push('\t');
        }
        serialized.pop();
        serialized.push('\n');
    }

    assert!(
        registry.next().is_none(),
        "registry entries must follow the accepted schema order"
    );
    assert_eq!(
        chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS.len(),
        CATALOG_ROWS,
        "catalog row count changed"
    );
    assert_eq!(
        hex::encode(Sha256::digest(serialized.as_bytes())),
        CATALOG_SHA256,
        "catalog rows, metadata or order changed:\n{serialized}"
    );
}
