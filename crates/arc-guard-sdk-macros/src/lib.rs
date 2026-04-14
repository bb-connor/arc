//! Proc-macro crate for the ARC WASM guard SDK.
//!
//! Provides the `#[arc_guard]` attribute macro that transforms a plain
//! `fn evaluate(req: GuardRequest) -> GuardVerdict` into a complete WASM
//! guard binary with all ABI exports:
//!
//! - `evaluate` -- `#[no_mangle] extern "C"` entry point that deserializes the
//!   request, calls the user function, and encodes the verdict
//! - `arc_alloc` / `arc_free` -- allocator re-exports
//! - `arc_deny_reason` -- structured deny reason re-export
//!
//! # Usage
//!
//! ```rust,ignore
//! use arc_guard_sdk::prelude::*;
//! use arc_guard_sdk_macros::arc_guard;
//!
//! #[arc_guard]
//! fn evaluate(req: GuardRequest) -> GuardVerdict {
//!     if req.tool_name == "dangerous_tool" {
//!         GuardVerdict::deny("tool is blocked by policy")
//!     } else {
//!         GuardVerdict::allow()
//!     }
//! }
//! ```

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn};

/// Attribute macro that generates the full ABI surface for an ARC WASM guard.
///
/// Annotate a function `fn evaluate(req: GuardRequest) -> GuardVerdict` with
/// `#[arc_guard]` to produce:
///
/// 1. Re-exports of `arc_alloc`, `arc_free`, and `arc_deny_reason`
/// 2. The user function renamed to an internal name
/// 3. A `#[no_mangle] pub extern "C" fn evaluate(ptr: i32, len: i32) -> i32`
///    that deserializes the request, calls the user function, and encodes the
///    verdict
///
/// The macro does **not** depend on `arc-guard-sdk` at compile time. It
/// generates code that references `arc_guard_sdk::*` paths, resolved at the
/// call site.
#[proc_macro_attribute]
pub fn arc_guard(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_block = &input_fn.block;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_attrs = &input_fn.attrs;
    let fn_vis = &input_fn.vis;

    let internal_name = format_ident!("__arc_guard_user_{}", fn_name);

    let expanded = quote! {
        // Re-export allocator functions so the WASM binary has arc_alloc and
        // arc_free as top-level exports.
        pub use arc_guard_sdk::alloc::{arc_alloc, arc_free};

        // Re-export the deny-reason glue so the host can retrieve structured
        // deny reasons.
        pub use arc_guard_sdk::glue::arc_deny_reason;

        // The user's original function, renamed to avoid collision with the
        // generated extern "C" evaluate entry point.
        #(#fn_attrs)*
        #fn_vis fn #internal_name(#fn_inputs) #fn_output
            #fn_block

        // Generated ABI entry point.
        #[no_mangle]
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        pub extern "C" fn evaluate(ptr: i32, len: i32) -> i32 {
            let request = match unsafe { arc_guard_sdk::read_request(ptr, len) } {
                Ok(r) => r,
                Err(_) => return arc_guard_sdk::VERDICT_DENY,
            };
            let verdict = #internal_name(request);
            arc_guard_sdk::encode_verdict(verdict)
        }
    };

    TokenStream::from(expanded)
}
