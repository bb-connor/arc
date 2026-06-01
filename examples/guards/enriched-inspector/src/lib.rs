//! Example guard: enriched field inspection + host functions.
//!
//! Demonstrates GEXM-02 (reading action_type and extracted_path)
//! and GEXM-03 (calling chio::log and chio::get_config host functions).
//!
//! Policy: blocks file_write actions to /etc (or a configurable
//! blocked_path from guard config). Allows everything else.

use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

#[chio_guard]
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
                    if path_is_under(path, bp) {
                        return GuardVerdict::deny("write to protected path blocked by policy");
                    }
                }

                // Default: block writes to /etc
                if path_is_under(path, "/etc") {
                    return GuardVerdict::deny("write to /etc blocked");
                }
            }
        }
    }

    GuardVerdict::allow()
}

fn path_is_under(path: &str, root: &str) -> bool {
    if root == "/" {
        return path.starts_with('/');
    }
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::path_is_under;

    #[test]
    fn path_is_under_respects_segment_boundaries() {
        assert!(path_is_under("/etc", "/etc"));
        assert!(path_is_under("/etc/passwd", "/etc"));
        assert!(!path_is_under("/etcetera/passwd", "/etc"));
    }
}
