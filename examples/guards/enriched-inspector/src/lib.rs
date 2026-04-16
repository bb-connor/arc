//! Example guard: enriched field inspection + host functions.
//!
//! Demonstrates GEXM-02 (reading action_type and extracted_path)
//! and GEXM-03 (calling arc::log and arc::get_config host functions).
//!
//! Policy: blocks file_write actions to /etc (or a configurable
//! blocked_path from guard config). Allows everything else.

use arc_guard_sdk::prelude::*;
use arc_guard_sdk_macros::arc_guard;

#[arc_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    // GEXM-03: Use host functions
    log(log_level::INFO, "enriched inspector evaluating request");

    let blocked_path = get_config("blocked_path");

    // GEXM-02: Read enriched fields
    if let Some(ref action) = req.action_type {
        if action == "file_write" {
            if let Some(ref path) = req.extracted_path {
                log(log_level::WARN, "file write detected");

                // Check against configured blocked path
                if let Some(ref bp) = blocked_path {
                    if path.starts_with(bp.as_str()) {
                        return GuardVerdict::deny("write to protected path blocked by policy");
                    }
                }

                // Default: block writes to /etc
                if path.starts_with("/etc") {
                    return GuardVerdict::deny("write to /etc blocked");
                }
            }
        }
    }

    GuardVerdict::allow()
}
