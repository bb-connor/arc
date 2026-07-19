//! `ChioKernel` construction and configuration surface.
//!
//! Holds the kernel constructor, session/store accessors, and the
//! `set_*` / `with_*` / `register_*` configuration setters, including
//! federation, emergency-stop, DPoP, and execution-nonce wiring.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chio_log_redact::redacted;
use dashmap::DashMap;

use super::*;

include!("construction.part1.inc");
include!("construction.part2.inc");
