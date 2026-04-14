//! WASM guard runtime and kernel integration.
//!
//! This module provides `WasmGuard` which implements `arc_kernel::Guard` and
//! `WasmGuardRuntime` which manages a collection of loaded WASM guards.

use std::sync::Mutex;

use arc_kernel::{Guard, GuardContext, KernelError, Verdict};
use tracing::{debug, warn};

use crate::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use crate::config::WasmGuardConfig;
use crate::error::WasmGuardError;

// ---------------------------------------------------------------------------
// WasmGuard -- single WASM guard implementing arc_kernel::Guard
// ---------------------------------------------------------------------------

/// A single WASM guard module loaded into the runtime.
///
/// Wraps a `WasmGuardAbi` backend and adapts it to the kernel's `Guard` trait.
/// On any error (fuel exhaustion, traps, serialization failures) the guard
/// fails closed and returns `Verdict::Deny`.
pub struct WasmGuard {
    /// Guard name (from config).
    name: String,
    /// The loaded WASM backend, behind a Mutex for interior mutability.
    backend: Mutex<Box<dyn WasmGuardAbi>>,
    /// Whether this guard is advisory-only (non-blocking).
    advisory: bool,
}

impl WasmGuard {
    /// Create a new WASM guard from a loaded backend.
    pub fn new(name: String, backend: Box<dyn WasmGuardAbi>, advisory: bool) -> Self {
        Self {
            name,
            backend: Mutex::new(backend),
            advisory,
        }
    }

    /// Returns `true` if this guard is advisory-only.
    #[must_use]
    pub fn is_advisory(&self) -> bool {
        self.advisory
    }

    fn build_request(ctx: &GuardContext<'_>) -> GuardRequest {
        let scopes = ctx
            .scope
            .grants
            .iter()
            .map(|g| format!("{}:{}", g.server_id, g.tool_name))
            .collect();

        GuardRequest {
            tool_name: ctx.request.tool_name.clone(),
            server_id: ctx.server_id.clone(),
            agent_id: ctx.agent_id.clone(),
            arguments: ctx.request.arguments.clone(),
            scopes,
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        }
    }
}

impl std::fmt::Debug for WasmGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmGuard")
            .field("name", &self.name)
            .field("advisory", &self.advisory)
            .finish()
    }
}

impl Guard for WasmGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let request = Self::build_request(ctx);

        let mut backend = self
            .backend
            .lock()
            .map_err(|e| KernelError::Internal(format!("WASM guard mutex poisoned: {e}")))?;

        match backend.evaluate(&request) {
            Ok(GuardVerdict::Allow) => {
                debug!(guard = %self.name, "WASM guard allowed request");
                Ok(Verdict::Allow)
            }
            Ok(GuardVerdict::Deny { reason }) => {
                let reason_str = reason.as_deref().unwrap_or("denied by WASM guard");
                if self.advisory {
                    debug!(
                        guard = %self.name,
                        reason = %reason_str,
                        "WASM advisory guard denied (non-blocking)"
                    );
                    Ok(Verdict::Allow)
                } else {
                    warn!(
                        guard = %self.name,
                        reason = %reason_str,
                        "WASM guard denied request"
                    );
                    Ok(Verdict::Deny)
                }
            }
            Err(e) => {
                // Fail closed: any error during WASM execution denies.
                warn!(
                    guard = %self.name,
                    error = %e,
                    "WASM guard error -- failing closed"
                );
                if self.advisory {
                    Ok(Verdict::Allow)
                } else {
                    Ok(Verdict::Deny)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WasmGuardRuntime -- manages multiple WASM guards
// ---------------------------------------------------------------------------

/// Runtime that manages a collection of loaded WASM guard modules.
///
/// Guards are sorted by priority (lower = earlier) before evaluation.
pub struct WasmGuardRuntime {
    guards: Vec<WasmGuard>,
}

impl WasmGuardRuntime {
    /// Create a new empty runtime.
    pub fn new() -> Self {
        Self { guards: Vec::new() }
    }

    /// Register a pre-loaded WASM guard.
    pub fn add_guard(&mut self, guard: WasmGuard) {
        self.guards.push(guard);
    }

    /// Load a WASM guard from a configuration entry and a backend factory.
    ///
    /// The `factory` closure receives the raw WASM bytes and fuel limit,
    /// and must return a loaded `WasmGuardAbi` implementation.
    pub fn load_guard<F>(
        &mut self,
        config: &WasmGuardConfig,
        factory: F,
    ) -> Result<(), WasmGuardError>
    where
        F: FnOnce(&[u8], u64) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError>,
    {
        let wasm_bytes = std::fs::read(&config.path).map_err(|e| WasmGuardError::ModuleLoad {
            path: config.path.clone(),
            reason: e.to_string(),
        })?;

        // WGSEC-03: Pre-check module size before passing to the factory
        if wasm_bytes.len() > config.max_module_size {
            return Err(WasmGuardError::ModuleTooLarge {
                size: wasm_bytes.len(),
                limit: config.max_module_size,
            });
        }

        let backend = factory(&wasm_bytes, config.fuel_limit)?;

        self.guards.push(WasmGuard::new(
            config.name.clone(),
            backend,
            config.advisory,
        ));

        Ok(())
    }

    /// Return the number of loaded guards.
    #[must_use]
    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    /// Return an iterator over the loaded guards as `&dyn Guard`.
    pub fn guards(&self) -> impl Iterator<Item = &WasmGuard> {
        self.guards.iter()
    }

    /// Convert this runtime into a vector of boxed `Guard` trait objects
    /// suitable for registering on the kernel.
    pub fn into_guards(self) -> Vec<Box<dyn Guard>> {
        self.guards
            .into_iter()
            .map(|g| Box::new(g) as Box<dyn Guard>)
            .collect()
    }
}

impl Default for WasmGuardRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Mock backend for testing
// ---------------------------------------------------------------------------

/// A mock WASM guard backend for testing.
///
/// Returns a fixed verdict for every invocation.
pub struct MockWasmBackend {
    verdict: GuardVerdict,
    loaded: bool,
}

impl MockWasmBackend {
    /// Create a mock backend that always allows.
    pub fn allowing() -> Self {
        Self {
            verdict: GuardVerdict::Allow,
            loaded: false,
        }
    }

    /// Create a mock backend that always denies with the given reason.
    pub fn denying(reason: &str) -> Self {
        Self {
            verdict: GuardVerdict::Deny {
                reason: Some(reason.to_string()),
            },
            loaded: false,
        }
    }
}

impl WasmGuardAbi for MockWasmBackend {
    fn load_module(&mut self, _wasm_bytes: &[u8], _fuel_limit: u64) -> Result<(), WasmGuardError> {
        self.loaded = true;
        Ok(())
    }

    fn evaluate(&mut self, _request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        if !self.loaded {
            return Err(WasmGuardError::BackendUnavailable);
        }
        Ok(self.verdict.clone())
    }

    fn backend_name(&self) -> &str {
        "mock"
    }
}

// ---------------------------------------------------------------------------
// Wasmtime backend (behind feature flag)
// ---------------------------------------------------------------------------

#[cfg(feature = "wasmtime-runtime")]
pub mod wasmtime_backend {
    //! Wasmtime-based WASM guard backend.
    //!
    //! Requires the `wasmtime-runtime` feature.

    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;
    use crate::host::{create_shared_engine, register_host_functions, WasmHostState};
    use wasmtime::{Engine, Linker, Memory, Module, Store};

    use crate::host::MAX_MEMORY_BYTES;

    /// Default maximum module size in bytes (10 MiB).
    const DEFAULT_MAX_MODULE_SIZE: usize = 10 * 1024 * 1024;

    /// WASM guard backend powered by Wasmtime.
    ///
    /// Uses a shared [`Arc<Engine>`] and creates a fresh
    /// [`Store<WasmHostState>`] per `evaluate()` call. Host functions
    /// (`arc.log`, `arc.get_config`, `arc.get_time_unix_secs`) are registered
    /// on the Linker before module instantiation.
    pub struct WasmtimeBackend {
        engine: Arc<Engine>,
        module: Option<Module>,
        fuel_limit: u64,
        config: HashMap<String, String>,
        max_memory_bytes: usize,
        max_module_size: usize,
    }

    impl WasmtimeBackend {
        /// Create a new Wasmtime backend with its own shared engine.
        ///
        /// For backward compatibility; callers that want to share an engine
        /// across multiple guards should use [`with_engine`] instead.
        pub fn new() -> Result<Self, WasmGuardError> {
            let engine = create_shared_engine()?;
            Ok(Self {
                engine,
                module: None,
                fuel_limit: 0,
                config: HashMap::new(),
                max_memory_bytes: MAX_MEMORY_BYTES,
                max_module_size: DEFAULT_MAX_MODULE_SIZE,
            })
        }

        /// Create a Wasmtime backend with a pre-existing shared engine.
        ///
        /// This is the recommended constructor when loading multiple guards:
        /// create one `Arc<Engine>` via [`create_shared_engine()`] and pass it
        /// to each backend.
        pub fn with_engine(engine: Arc<Engine>) -> Self {
            Self {
                engine,
                module: None,
                fuel_limit: 0,
                config: HashMap::new(),
                max_memory_bytes: MAX_MEMORY_BYTES,
                max_module_size: DEFAULT_MAX_MODULE_SIZE,
            }
        }

        /// Create a Wasmtime backend with a shared engine and guard-specific
        /// config that will be accessible to guests via `arc.get_config`.
        pub fn with_engine_and_config(
            engine: Arc<Engine>,
            config: HashMap<String, String>,
        ) -> Self {
            Self {
                engine,
                module: None,
                fuel_limit: 0,
                config,
                max_memory_bytes: MAX_MEMORY_BYTES,
                max_module_size: DEFAULT_MAX_MODULE_SIZE,
            }
        }

        /// Set custom resource limits for module size and memory.
        ///
        /// Builder-style method for configuring security boundaries.
        #[must_use]
        pub fn with_limits(mut self, max_memory_bytes: usize, max_module_size: usize) -> Self {
            self.max_memory_bytes = max_memory_bytes;
            self.max_module_size = max_module_size;
            self
        }
    }

    impl Default for WasmtimeBackend {
        fn default() -> Self {
            match Self::new() {
                Ok(b) => b,
                Err(_) => Self {
                    engine: Arc::new(Engine::default()),
                    module: None,
                    fuel_limit: 0,
                    config: HashMap::new(),
                    max_memory_bytes: MAX_MEMORY_BYTES,
                    max_module_size: DEFAULT_MAX_MODULE_SIZE,
                },
            }
        }
    }

    impl WasmGuardAbi for WasmtimeBackend {
        fn load_module(
            &mut self,
            wasm_bytes: &[u8],
            fuel_limit: u64,
        ) -> Result<(), WasmGuardError> {
            // WGSEC-03: Reject oversized modules before compilation
            if wasm_bytes.len() > self.max_module_size {
                return Err(WasmGuardError::ModuleTooLarge {
                    size: wasm_bytes.len(),
                    limit: self.max_module_size,
                });
            }

            let module = Module::new(&self.engine, wasm_bytes)
                .map_err(|e| WasmGuardError::Compilation(e.to_string()))?;

            // WGSEC-02: Validate that all imports come from the "arc" namespace
            for import in module.imports() {
                if import.module() != "arc" {
                    return Err(WasmGuardError::ImportViolation {
                        module: import.module().to_string(),
                        name: import.name().to_string(),
                    });
                }
            }

            self.module = Some(module);
            self.fuel_limit = fuel_limit;
            Ok(())
        }

        fn evaluate(&mut self, request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
            let module = self
                .module
                .as_ref()
                .ok_or(WasmGuardError::BackendUnavailable)?;

            // WGSEC-01: Create a fresh Store with configurable memory limit
            let host_state = WasmHostState::with_memory_limit(
                self.config.clone(),
                self.max_memory_bytes,
            );
            let mut store = Store::new(&self.engine, host_state);
            store.limiter(|state| &mut state.limits);
            store
                .set_fuel(self.fuel_limit)
                .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

            // Create a Linker with host functions registered
            let mut linker: Linker<WasmHostState> = Linker::new(&self.engine);
            register_host_functions(&mut linker)?;

            let instance = linker
                .instantiate(&mut store, module)
                .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

            // Serialize request to JSON
            let request_json = serde_json::to_vec(request)
                .map_err(|e| WasmGuardError::Serialization(e.to_string()))?;

            // Get guest memory
            let memory = instance
                .get_memory(&mut store, "memory")
                .ok_or_else(|| WasmGuardError::MissingExport("memory".to_string()))?;

            // Probe for optional arc_alloc guest export
            let arc_alloc_fn = instance
                .get_typed_func::<i32, i32>(&mut store, "arc_alloc")
                .ok();

            let request_len: i32 = request_json.len() as i32;

            let request_ptr: i32 = if let Some(ref alloc_fn) = arc_alloc_fn {
                match alloc_fn.call(&mut store, request_len) {
                    Ok(ptr) => {
                        // Validate returned pointer is in bounds
                        let mem_size = memory.data_size(&store);
                        if ptr >= 0
                            && (ptr as usize).saturating_add(request_len as usize) <= mem_size
                        {
                            ptr
                        } else {
                            // Out-of-bounds pointer -- fall back to offset 0
                            tracing::warn!(
                                ptr = ptr,
                                request_len = request_len,
                                mem_size = mem_size,
                                "arc_alloc returned out-of-bounds pointer, falling back to offset 0"
                            );
                            0
                        }
                    }
                    Err(e) => {
                        // arc_alloc call failed -- fall back to offset 0
                        tracing::warn!(
                            error = %e,
                            "arc_alloc call failed, falling back to offset 0"
                        );
                        0
                    }
                }
            } else {
                // No arc_alloc export -- use legacy offset-0 protocol
                0
            };

            // Write request into guest memory at the resolved offset
            memory
                .write(&mut store, request_ptr as usize, &request_json)
                .map_err(|e| WasmGuardError::Memory(e.to_string()))?;

            // Call the evaluate function
            let evaluate_fn = instance
                .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
                .map_err(|e| WasmGuardError::MissingExport(format!("evaluate: {e}")))?;

            let result = evaluate_fn
                .call(&mut store, (request_ptr, request_len))
                .map_err(|e| {
                    // Check if this was a fuel exhaustion
                    let msg = e.to_string();
                    if msg.contains("fuel") {
                        let consumed = self
                            .fuel_limit
                            .saturating_sub(store.get_fuel().unwrap_or(0));
                        WasmGuardError::FuelExhausted {
                            consumed,
                            limit: self.fuel_limit,
                        }
                    } else {
                        WasmGuardError::Trap(msg)
                    }
                })?;

            let verdict = match result {
                crate::abi::VERDICT_ALLOW => Ok(GuardVerdict::Allow),
                crate::abi::VERDICT_DENY => {
                    // Probe for structured arc_deny_reason export
                    let deny_reason_fn = instance
                        .get_typed_func::<(i32, i32), i32>(&mut store, "arc_deny_reason")
                        .ok();

                    let reason = if let Some(ref reason_fn) = deny_reason_fn {
                        read_structured_deny_reason(reason_fn, &memory, &mut store)
                    } else {
                        // Fallback to legacy offset-64K NUL-terminated string
                        read_deny_reason(&memory, &store)
                    };

                    Ok(GuardVerdict::Deny { reason })
                }
                _ => {
                    // Unexpected return value -- fail closed
                    Err(WasmGuardError::Trap(format!(
                        "unexpected return value from evaluate: {result}"
                    )))
                }
            };

            // Drain the log buffer and emit via tracing for host-side visibility
            for (level, msg) in &store.data().logs {
                match level {
                    0 => tracing::trace!(target: "wasm_guard", "{msg}"),
                    1 => tracing::debug!(target: "wasm_guard", "{msg}"),
                    2 => tracing::info!(target: "wasm_guard", "{msg}"),
                    3 => tracing::warn!(target: "wasm_guard", "{msg}"),
                    4 => tracing::error!(target: "wasm_guard", "{msg}"),
                    _ => {}
                }
            }

            verdict
        }

        fn backend_name(&self) -> &str {
            "wasmtime"
        }
    }

    /// Read a structured deny reason from the guest via the `arc_deny_reason`
    /// export. The host calls `arc_deny_reason(buf_ptr, buf_len)` with a
    /// buffer region in guest memory. The guest writes a JSON-encoded
    /// [`GuestDenyResponse`](crate::abi::GuestDenyResponse) into the buffer
    /// and returns the number of bytes written (or a negative/zero value on
    /// error).
    ///
    /// All error paths return `None` (fail closed with no reason rather than
    /// crashing).
    fn read_structured_deny_reason(
        reason_fn: &wasmtime::TypedFunc<(i32, i32), i32>,
        memory: &Memory,
        store: &mut Store<WasmHostState>,
    ) -> Option<String> {
        const DENY_BUF_OFFSET: i32 = 65536;
        const DENY_BUF_LEN: i32 = 4096;

        // Call the guest's arc_deny_reason function
        let bytes_written = match reason_fn.call(&mut *store, (DENY_BUF_OFFSET, DENY_BUF_LEN)) {
            Ok(n) if n > 0 && n <= DENY_BUF_LEN => n,
            Ok(_) => return None,  // 0 or negative or too large
            Err(_) => return None, // call failed -- no reason
        };

        // Read the response from guest memory
        let mut buf = vec![0u8; bytes_written as usize];
        if memory.read(store, DENY_BUF_OFFSET as usize, &mut buf).is_err() {
            return None;
        }

        // Try to parse as JSON GuestDenyResponse
        match serde_json::from_slice::<crate::abi::GuestDenyResponse>(&buf) {
            Ok(resp) => Some(resp.reason),
            Err(_) => {
                // Not valid JSON -- try as plain UTF-8 string
                std::str::from_utf8(&buf)
                    .ok()
                    .map(|s| s.trim_end_matches('\0').to_string())
                    .filter(|s| !s.is_empty())
            }
        }
    }

    /// Try to read a deny reason string from the guest memory region after
    /// the request data. The guest may write a NUL-terminated UTF-8 string
    /// starting at a well-known offset (64 KiB).
    fn read_deny_reason(memory: &Memory, store: &Store<WasmHostState>) -> Option<String> {
        const DENY_REASON_OFFSET: usize = 65536;
        const MAX_REASON_LEN: usize = 4096;

        let data = memory.data(store);
        if data.len() <= DENY_REASON_OFFSET {
            return None;
        }

        let region = &data[DENY_REASON_OFFSET..];
        let end = region
            .iter()
            .take(MAX_REASON_LEN)
            .position(|&b| b == 0)
            .unwrap_or(region.len().min(MAX_REASON_LEN));

        if end == 0 {
            return None;
        }

        std::str::from_utf8(&region[..end]).ok().map(String::from)
    }

    // -----------------------------------------------------------------------
    // Tests for wasmtime_backend
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::abi::GuardRequest;

        fn make_guard_request() -> GuardRequest {
            GuardRequest {
                tool_name: "test_tool".to_string(),
                server_id: "test_server".to_string(),
                agent_id: "agent-1".to_string(),
                arguments: serde_json::json!({"key": "value"}),
                scopes: vec!["test_server:test_tool".to_string()],
                action_type: None,
                extracted_path: None,
                extracted_target: None,
                filesystem_roots: Vec::new(),
                matched_grant_index: None,
            }
        }

        // -------------------------------------------------------------------
        // arc_alloc tests
        // -------------------------------------------------------------------

        #[test]
        fn arc_alloc_used_when_exported() {
            // WAT module with arc_alloc that returns 1024.
            // evaluate checks that ptr == 1024 and returns ALLOW only if so.
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    (func (export "arc_alloc") (param $size i32) (result i32)
                        ;; Always allocate at offset 1024
                        (i32.const 1024)
                    )
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Return ALLOW (0) only if ptr == 1024, else DENY (1)
                        (if (result i32) (i32.eq (local.get $ptr) (i32.const 1024))
                            (then (i32.const 0))
                            (else (i32.const 1))
                        )
                    )
                )
            "#;

            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req).unwrap();
            assert!(
                result.is_allow(),
                "expected ALLOW (arc_alloc should have been used), got: {result:?}"
            );
        }

        #[test]
        fn no_arc_alloc_uses_offset_zero() {
            // WAT module WITHOUT arc_alloc.
            // evaluate checks that ptr == 0 and returns ALLOW only if so.
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Return ALLOW (0) only if ptr == 0, else DENY (1)
                        (if (result i32) (i32.eqz (local.get $ptr))
                            (then (i32.const 0))
                            (else (i32.const 1))
                        )
                    )
                )
            "#;

            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req).unwrap();
            assert!(
                result.is_allow(),
                "expected ALLOW (offset 0 fallback should be used without arc_alloc), got: {result:?}"
            );
        }

        #[test]
        fn arc_alloc_oob_falls_back() {
            // WAT module with arc_alloc that returns 999_999_999 (out-of-bounds).
            // evaluate checks that ptr == 0 (proving fallback occurred).
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    (func (export "arc_alloc") (param $size i32) (result i32)
                        ;; Return absurdly large pointer
                        (i32.const 999999999)
                    )
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Return ALLOW (0) only if ptr == 0 (fallback), else DENY (1)
                        (if (result i32) (i32.eqz (local.get $ptr))
                            (then (i32.const 0))
                            (else (i32.const 1))
                        )
                    )
                )
            "#;

            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req).unwrap();
            assert!(
                result.is_allow(),
                "expected ALLOW (OOB arc_alloc should fall back to offset 0), got: {result:?}"
            );
        }

        #[test]
        fn arc_alloc_negative_falls_back() {
            // WAT module with arc_alloc that returns -1 (negative pointer).
            // evaluate checks that ptr == 0 (proving fallback occurred).
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    (func (export "arc_alloc") (param $size i32) (result i32)
                        ;; Return negative pointer
                        (i32.const -1)
                    )
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Return ALLOW (0) only if ptr == 0 (fallback), else DENY (1)
                        (if (result i32) (i32.eqz (local.get $ptr))
                            (then (i32.const 0))
                            (else (i32.const 1))
                        )
                    )
                )
            "#;

            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req).unwrap();
            assert!(
                result.is_allow(),
                "expected ALLOW (negative arc_alloc should fall back to offset 0), got: {result:?}"
            );
        }

        // -------------------------------------------------------------------
        // arc_deny_reason tests
        // -------------------------------------------------------------------

        #[test]
        fn arc_deny_reason_structured() {
            // WAT module with arc_deny_reason that writes a JSON GuestDenyResponse
            // into the provided buffer and returns the byte count.
            //
            // The JSON {"reason":"blocked by policy"} is stored using escaped
            // quotes in the WAT data segment at offset 512.
            // arc_deny_reason copies it to buf_ptr using memory.copy.
            let json_bytes = br#"{"reason":"blocked by policy"}"#;
            let json_len = json_bytes.len(); // 30

            // Build WAT data segment using \xx hex escapes to avoid quote issues
            let hex_data: String = json_bytes
                .iter()
                .map(|b| format!("\\{b:02x}"))
                .collect();

            let wat = format!(
                r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    ;; Store the JSON response at offset 512 using hex escapes
                    (data (i32.const 512) "{hex_data}")
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Return DENY (1)
                        (i32.const 1)
                    )
                    (func (export "arc_deny_reason") (param $buf_ptr i32) (param $buf_len i32) (result i32)
                        ;; Copy JSON from offset 512 to buf_ptr using memory.copy
                        (memory.copy
                            (local.get $buf_ptr)  ;; dest
                            (i32.const 512)       ;; src
                            (i32.const {json_len})  ;; len
                        )
                        ;; Return number of bytes written
                        (i32.const {json_len})
                    )
                )
            "#
            );

            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req).unwrap();
            match &result {
                GuardVerdict::Deny { reason } => {
                    assert_eq!(
                        reason.as_deref(),
                        Some("blocked by policy"),
                        "expected structured deny reason from arc_deny_reason"
                    );
                }
                _ => panic!("expected Deny verdict, got: {result:?}"),
            }
        }

        #[test]
        fn arc_deny_reason_fallback_legacy() {
            // WAT module WITHOUT arc_deny_reason export.
            // Has a NUL-terminated string at offset 65536 ("legacy reason\0").
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    (data (i32.const 65536) "legacy reason\00")
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Return DENY (1)
                        (i32.const 1)
                    )
                )
            "#;

            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req).unwrap();
            match &result {
                GuardVerdict::Deny { reason } => {
                    assert_eq!(
                        reason.as_deref(),
                        Some("legacy reason"),
                        "expected legacy deny reason from offset 64K"
                    );
                }
                _ => panic!("expected Deny verdict, got: {result:?}"),
            }
        }

        #[test]
        fn arc_deny_reason_invalid_returns_none() {
            // WAT module with arc_deny_reason that returns -1 (error).
            // The host should fall back to None reason.
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Return DENY (1)
                        (i32.const 1)
                    )
                    (func (export "arc_deny_reason") (param $buf_ptr i32) (param $buf_len i32) (result i32)
                        ;; Return -1 (error)
                        (i32.const -1)
                    )
                )
            "#;

            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req).unwrap();
            match &result {
                GuardVerdict::Deny { reason } => {
                    assert_eq!(
                        reason, &None,
                        "expected None reason when arc_deny_reason returns -1"
                    );
                }
                _ => panic!("expected Deny verdict, got: {result:?}"),
            }
        }

        // -------------------------------------------------------------------
        // Security enforcement tests (WGSEC-01, WGSEC-02, WGSEC-03)
        // -------------------------------------------------------------------

        #[test]
        fn module_too_large_rejected() {
            // Set a very small max_module_size and provide bytes exceeding it
            let mut backend = WasmtimeBackend::new().unwrap()
                .with_limits(16 * 1024 * 1024, 100);
            let big_bytes = vec![0u8; 200];
            let result = backend.load_module(&big_bytes, 1_000_000);
            match result {
                Err(WasmGuardError::ModuleTooLarge { size, limit }) => {
                    assert_eq!(size, 200);
                    assert_eq!(limit, 100);
                }
                other => panic!("expected ModuleTooLarge, got: {other:?}"),
            }
        }

        #[test]
        fn module_within_size_accepted() {
            // Use a small valid WAT module with default limits (10 MiB)
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 1)
                    (func (export "evaluate") (param i32 i32) (result i32)
                        (i32.const 0)
                    )
                )
            "#;
            let mut backend = WasmtimeBackend::new().unwrap();
            let result = backend.load_module(wat.as_bytes(), 1_000_000);
            assert!(result.is_ok(), "expected Ok, got: {result:?}");
        }

        #[test]
        fn import_validation_rejects_wasi() {
            // WAT module that imports from wasi_snapshot_preview1 (forbidden)
            let wat = r#"
                (module
                    (import "wasi_snapshot_preview1" "fd_write"
                        (func $fd_write (param i32 i32 i32 i32) (result i32)))
                    (memory (export "memory") 1)
                    (func (export "evaluate") (param i32 i32) (result i32)
                        (i32.const 0)
                    )
                )
            "#;
            let mut backend = WasmtimeBackend::new().unwrap();
            let result = backend.load_module(wat.as_bytes(), 1_000_000);
            match result {
                Err(WasmGuardError::ImportViolation { module, name }) => {
                    assert_eq!(module, "wasi_snapshot_preview1");
                    assert_eq!(name, "fd_write");
                }
                other => panic!("expected ImportViolation, got: {other:?}"),
            }
        }

        #[test]
        fn import_validation_accepts_arc_only() {
            // WAT module that imports only from "arc" namespace
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 1)
                    (func (export "evaluate") (param i32 i32) (result i32)
                        (i32.const 0)
                    )
                )
            "#;
            let mut backend = WasmtimeBackend::new().unwrap();
            let result = backend.load_module(wat.as_bytes(), 1_000_000);
            assert!(result.is_ok(), "expected Ok for arc-only imports, got: {result:?}");
        }

        #[test]
        fn memory_growth_beyond_limit_traps() {
            // WAT module that tries to grow memory by 1000 pages (64 MB)
            // with a very small limit (2 pages = 128 KiB)
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 1)
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Try to grow memory by 1000 pages -- should trap
                        (drop (memory.grow (i32.const 1000)))
                        (i32.const 0)
                    )
                )
            "#;
            let mut backend = WasmtimeBackend::new().unwrap()
                .with_limits(2 * 64 * 1024, 10 * 1024 * 1024);
            backend.load_module(wat.as_bytes(), 10_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req);
            assert!(
                result.is_err(),
                "expected error (trap) when memory.grow exceeds limit, got: {result:?}"
            );
        }

        #[test]
        fn memory_growth_within_limit_works() {
            // WAT module that grows memory by 1 page with default 16 MiB limit
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 1)
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Grow memory by 1 page (64 KiB) -- should succeed
                        (drop (memory.grow (i32.const 1)))
                        (i32.const 0)
                    )
                )
            "#;
            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 10_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req);
            assert!(
                result.is_ok(),
                "expected Ok when memory.grow is within limit, got: {result:?}"
            );
        }

        #[test]
        fn deny_no_reason_at_all() {
            // WAT module without arc_deny_reason and no string at offset 64K.
            // Memory is zeroed so read_deny_reason will find a NUL at position 0.
            let wat = r#"
                (module
                    (import "arc" "log" (func $log (param i32 i32 i32)))
                    (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                    (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
                    (memory (export "memory") 2)
                    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                        ;; Return DENY (1)
                        (i32.const 1)
                    )
                )
            "#;

            let mut backend = WasmtimeBackend::new().unwrap();
            backend.load_module(wat.as_bytes(), 1_000_000).unwrap();

            let req = make_guard_request();
            let result = backend.evaluate(&req).unwrap();
            match &result {
                GuardVerdict::Deny { reason } => {
                    assert_eq!(
                        reason, &None,
                        "expected None reason when no deny reason mechanism is available"
                    );
                }
                _ => panic!("expected Deny verdict, got: {result:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::capability::ArcScope;
    use arc_kernel::{GuardContext, ToolCallRequest};

    fn make_test_request() -> ToolCallRequest {
        ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: arc_core::capability::CapabilityToken::sign(
                arc_core::capability::CapabilityTokenBody {
                    id: "cap-1".to_string(),
                    issuer: arc_core::crypto::Keypair::generate().public_key(),
                    subject: arc_core::crypto::Keypair::generate().public_key(),
                    scope: ArcScope::default(),
                    issued_at: 0,
                    expires_at: u64::MAX,
                    delegation_chain: vec![],
                },
                &arc_core::crypto::Keypair::generate(),
            )
            .unwrap(),
            tool_name: "test_tool".to_string(),
            server_id: "test_server".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({"key": "value"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        }
    }

    #[test]
    fn mock_allow_backend() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-allow".to_string(), Box::new(backend), false);

        let request = make_test_request();
        let scope = ArcScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx);
        assert!(matches!(result, Ok(Verdict::Allow)));
    }

    #[test]
    fn mock_deny_backend() {
        let mut backend = MockWasmBackend::denying("blocked by test");
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-deny".to_string(), Box::new(backend), false);

        let request = make_test_request();
        let scope = ArcScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx);
        assert!(matches!(result, Ok(Verdict::Deny)));
    }

    #[test]
    fn advisory_guard_allows_on_deny() {
        let mut backend = MockWasmBackend::denying("advisory denial");
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-advisory".to_string(), Box::new(backend), true);
        assert!(guard.is_advisory());

        let request = make_test_request();
        let scope = ArcScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        // Advisory guards should allow even when the backend denies
        let result = guard.evaluate(&ctx);
        assert!(matches!(result, Ok(Verdict::Allow)));
    }

    #[test]
    fn runtime_manages_multiple_guards() {
        let mut runtime = WasmGuardRuntime::new();
        assert_eq!(runtime.guard_count(), 0);

        let mut b1 = MockWasmBackend::allowing();
        b1.load_module(b"fake", 1000).unwrap();
        runtime.add_guard(WasmGuard::new("g1".to_string(), Box::new(b1), false));

        let mut b2 = MockWasmBackend::denying("no");
        b2.load_module(b"fake", 1000).unwrap();
        runtime.add_guard(WasmGuard::new("g2".to_string(), Box::new(b2), false));

        assert_eq!(runtime.guard_count(), 2);

        let boxed = runtime.into_guards();
        assert_eq!(boxed.len(), 2);
    }

    #[test]
    fn guard_request_serialization() {
        let req = GuardRequest {
            tool_name: "read_file".to_string(),
            server_id: "fs-server".to_string(),
            agent_id: "agent-42".to_string(),
            arguments: serde_json::json!({"path": "/etc/passwd"}),
            scopes: vec!["fs-server:read_file".to_string()],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: GuardRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.tool_name, "read_file");
        assert_eq!(deserialized.scopes.len(), 1);
    }

    #[test]
    fn guard_verdict_helpers() {
        let allow = GuardVerdict::Allow;
        assert!(allow.is_allow());
        assert!(!allow.is_deny());

        let deny = GuardVerdict::Deny {
            reason: Some("bad".to_string()),
        };
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
    }

    #[test]
    fn unloaded_mock_fails() {
        let mut backend = MockWasmBackend::allowing();
        // Do NOT call load_module
        let req = GuardRequest {
            tool_name: "t".to_string(),
            server_id: "s".to_string(),
            agent_id: "a".to_string(),
            arguments: serde_json::Value::Null,
            scopes: vec![],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };
        let result = backend.evaluate(&req);
        assert!(result.is_err());
    }
}
