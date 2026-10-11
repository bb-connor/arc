//! Audited descriptor ACL inspection for file custody.
//!
//! Inspection does not grant custody. Callers separately validate ownership,
//! permissions, file type and the expected descriptor identity.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(target_vendor = "apple", test))]
mod darwin_acl;

#[cfg(target_vendor = "apple")]
pub use darwin_acl::darwin_descriptor_grants_extended_acl_authority;
