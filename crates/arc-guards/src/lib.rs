//! Security guards for the ARC runtime kernel.
//!
//! This crate provides policy-driven security guards adapted from
//! [ClawdStrike](https://github.com/backbay-labs/clawdstrike).  Each guard
//! implements `arc_kernel::Guard` and can be registered on the kernel via
//! `kernel.add_guard(...)` or composed into a [`GuardPipeline`].
//!
//! # Implemented guards
//!
//! | Guard | Status | Description |
//! |-------|--------|-------------|
//! | [`ForbiddenPathGuard`] | **Full** | Blocks access to sensitive filesystem paths |
//! | [`ShellCommandGuard`] | **Full** | Blocks dangerous shell commands |
//! | [`EgressAllowlistGuard`] | **Full** | Controls network egress by domain |
//! | [`PathAllowlistGuard`] | **Full** | Allowlist-based path access control |
//! | [`McpToolGuard`] | **Full** | Restricts MCP tool invocations |
//! | [`SecretLeakGuard`] | **Full** | Detects secrets in file writes |
//! | [`PatchIntegrityGuard`] | **Full** | Validates patch safety |
//!
//! # Guard pipeline
//!
//! The [`GuardPipeline`] runs guards in sequence, fail-closed.  If any guard
//! denies, the pipeline denies.  Register it on the kernel:
//!
//! ```ignore
//! use arc_guards::GuardPipeline;
//!
//! let pipeline = GuardPipeline::default_pipeline();
//! kernel.add_guard(Box::new(pipeline));
//! ```

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod action;
mod path_normalization;

mod egress_allowlist;
mod forbidden_path;
pub mod mcp_tool;
pub mod patch_integrity;
pub mod path_allowlist;
mod pipeline;
pub mod secret_leak;
mod shell_command;
pub mod velocity;

pub use egress_allowlist::EgressAllowlistGuard;
pub use forbidden_path::ForbiddenPathGuard;
pub use mcp_tool::McpToolGuard;
pub use patch_integrity::PatchIntegrityGuard;
pub use path_allowlist::PathAllowlistGuard;
pub use pipeline::GuardPipeline;
pub use secret_leak::SecretLeakGuard;
pub use shell_command::ShellCommandGuard;
pub use velocity::VelocityGuard;

pub use action::{extract_action, ToolAction};
