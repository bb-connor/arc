//! Experimental, receiver-owned funding admission. Local development chain only.

mod agreement;
mod evidence;
mod lifecycle;
mod settlement;
mod settlement_observer;
mod verification;
pub use lifecycle::run as lifecycle;
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
