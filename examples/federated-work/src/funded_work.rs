//! Experimental, receiver-owned funding admission. Local development chain only.

mod agreement;
#[cfg(unix)]
mod child;
#[cfg(unix)]
mod child_process;
mod evidence;
#[cfg(unix)]
pub use child_process::{collect_worker as child_collector, parent_worker, run as child};
mod capture_resolution;
mod lifecycle;
#[cfg(unix)]
mod resolution_process;
mod settlement;
mod settlement_observer;
mod verification;
mod waiver_terms;
pub use lifecycle::run as lifecycle;
#[cfg(unix)]
pub use resolution_process::{run as resolution, worker as resolution_worker};
mod allocation;
mod journal;
mod local_chain;
mod native;
mod observer;
mod rail;
mod smoke;
mod tool;
pub use smoke::run as smoke;
#[cfg(unix)]
mod lifecycle_process;
#[cfg(unix)]
mod process;
#[cfg(unix)]
pub use lifecycle_process::{admission_loss, run as lifecycle_fault, worker as lifecycle_worker};
#[cfg(unix)]
pub use process::{run_fault as smoke_fault, worker};

type Checkpoint = std::sync::Arc<dyn Fn(&'static str) -> crate::common::Result<()> + Send + Sync>;

fn now_ms() -> crate::common::Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

#[cfg(test)]
mod tests;
