//! Receipt query snapshot tests.
#[path = "tests/build.rs"]
mod build;
#[path = "tests/capacity.rs"]
mod capacity;
#[path = "tests/count_parity_sequence.rs"]
mod count_parity_sequence;
#[path = "tests/late_lineage.rs"]
mod late_lineage;
#[path = "tests/lineage.rs"]
mod lineage;
#[path = "tests/memory.rs"]
mod memory;
#[cfg(target_os = "linux")]
#[path = "tests/placement.rs"]
mod placement;
#[path = "tests/publication.rs"]
mod publication;
#[path = "tests/query.rs"]
mod query;
#[path = "tests/service.rs"]
mod service;
#[path = "tests/support.rs"]
mod support;

#[path = "tests/recovery.rs"]
mod recovery;
