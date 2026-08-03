pub(crate) fn manual_receipt_policy_hash(label: &str) -> String {
    chio_core_types::sha256_hex(label.as_bytes())
}
