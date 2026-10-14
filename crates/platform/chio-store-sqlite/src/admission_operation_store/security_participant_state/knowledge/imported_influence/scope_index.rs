//! One authenticated Merkle root over the imported source's per-scope membership.
//!
//! Hydration builds a sorted unique set of scope leaves from the verified
//! sealed source rows. A leaf commits its scope key, member count and the
//! digest over its complete ordered member list. The RFC 6962 root over all
//! leaves is held by one protected record bound to the initialization; each
//! leaf's inclusion proof sits in an immutable index row that is untrusted until
//! proven against that root. The warm reader proves each requested scope
//! present or absent against the root and still fetches and rehashes the actual
//! current sealed source bytes of every member. Cold verification rebuilds the
//! complete expected index from the sealed source and compares it exactly.
use super::*;

mod build;
mod install;
mod model;
mod read;
mod root;
mod startup;

pub(in crate::admission_operation_store) use install::{
    install_imported_scope_index, verify_imported_scope_index, verify_imported_scope_index_coverage,
};
pub(in crate::admission_operation_store) use read::{read_scope_members, ROOT_WORK};
pub(in crate::admission_operation_store) use root::{
    authenticate_root, VerifiedImportedInfluenceRoot,
};
pub(in crate::admission_operation_store) use startup::historical_root_pending;
pub(crate) use startup::publish_imported_influence_roots_at_startup;
