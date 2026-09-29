//! Exact collection counts for wire and accounting fields.

#[cfg(not(any(
    target_pointer_width = "16",
    target_pointer_width = "32",
    target_pointer_width = "64"
)))]
compile_error!("control plane requires collection lengths representable by u64");

#[allow(
    clippy::as_conversions,
    reason = "The compile-time target-width gate proves usize fits in u64."
)]
pub(crate) const fn count(value: usize) -> u64 {
    value as u64
}
