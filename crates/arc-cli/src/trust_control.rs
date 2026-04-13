#![allow(clippy::result_large_err)]

#[path = "trust_control/health.rs"]
mod trust_control_health;

include!("trust_control/service_types.rs");
include!("trust_control/config_and_public.rs");
include!("trust_control/service_runtime.rs");
include!("trust_control/http_handlers_a.rs");
include!("trust_control/http_handlers_b.rs");
include!("trust_control/cluster_and_reports.rs");
include!("trust_control/capital_and_liability.rs");
include!("trust_control/credit_and_loss.rs");
include!("trust_control/underwriting_and_support.rs");
