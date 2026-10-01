//! libFuzzer entry points for the store's byte-level decoders.
//!
//! Gated behind the `fuzz` Cargo feature so these symbols only compile into
//! the standalone `chio-fuzz` workspace at `../../../fuzz`. Production builds
//! never expose them.
//!
//! # Rollback anchor slots
//!
//! The serving owner's rollback anchor is a fixed-size file of two committed
//! slots, each a marker, a payload length, a payload checksum, a canonical
//! JSON record and zero padding. The anchor is installed with one positioned
//! write, so a crash can leave a slot holding the prior record, the new
//! record, or bytes that must be rejected, and the decoder is the only thing
//! standing between a torn write and a forged rollback proof. This target
//! drives the decoder over arbitrary images and checks that a rejected image
//! never panics and that every accepted slot validates and re-encodes to the
//! bytes it was read from.

/// Decode an arbitrary rollback anchor image; see the module documentation.
pub fn rollback_anchor_slots(data: &[u8]) {
    crate::serving_owner::exercise_slot_image(data);
}
