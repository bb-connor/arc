//! Supervision of one service process under systemd.
//!
//! The supervisor receives the service's secrets from the credentials
//! directory instead of an environment file, reports readiness over the
//! notify socket once the service answers, forwards stop signals so the
//! service drains, and ends with the service's own exit status so the
//! manager sees exactly how the service stopped.

pub mod credentials;
#[cfg(unix)]
pub mod notify;
#[cfg(unix)]
pub mod readiness;
#[cfg(unix)]
pub mod run;

pub use credentials::{load_bindings, CredentialBinding};
#[cfg(unix)]
pub use notify::Notifier;
#[cfg(unix)]
pub use readiness::Readiness;
#[cfg(unix)]
pub use run::{exec_with_credentials, supervise, Exit, Supervision};
