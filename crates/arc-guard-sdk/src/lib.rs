//! Guest-side SDK for writing ARC WASM guards.
//!
//! Guard authors import this crate to get typed Rust structs that deserialize
//! identically to the host's JSON schema, and an allocator the host runtime
//! can call to place request data in guest linear memory.
