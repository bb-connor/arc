//! Host state and host function registration for WASM guards.
//!
//! Provides [`WasmHostState`] which carries per-guard configuration and a
//! bounded log buffer, plus three host functions importable by WASM guests:
//!
//! - `chio.log(level, ptr, len)` -- structured logging to the host
//! - `chio.get_config(key_ptr, key_len, val_out_ptr, val_out_len) -> i32` -- read config values
//! - `chio.get_time_unix_secs() -> i64` -- wall-clock time

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use wasmtime::{Caller, Engine, Linker, StoreLimits, StoreLimitsBuilder};

use crate::error::WasmGuardError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of log entries buffered per guard invocation.
pub const MAX_LOG_ENTRIES: usize = 256;

/// Maximum guest memory size in bytes (16 MiB).
pub const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;

/// Maximum length of a single log message in bytes.
pub const MAX_LOG_MESSAGE_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// WasmHostState
// ---------------------------------------------------------------------------

/// Per-invocation host state stored in the wasmtime `Store`.
///
/// Each `evaluate()` call creates a fresh `WasmHostState` with the guard's
/// config map and an empty log buffer. Host functions access this state via
/// `Caller::data()` / `Caller::data_mut()`.
pub struct WasmHostState {
    /// Guard-specific configuration key-value pairs from the manifest.
    pub config: HashMap<String, String>,
    /// Captured log entries from `chio.log` calls: `(level, message)`.
    pub logs: Vec<(i32, String)>,
    /// Maximum log entries per invocation (bounded at [`MAX_LOG_ENTRIES`]).
    pub max_log_entries: usize,
    /// Resource limits for memory and table growth.
    pub limits: StoreLimits,
}

impl WasmHostState {
    /// Create a new host state with the given config and default limits.
    pub fn new(config: HashMap<String, String>) -> Self {
        Self::with_memory_limit(config, MAX_MEMORY_BYTES)
    }

    /// Create a new host state with a custom memory limit.
    ///
    /// `trap_on_grow_failure(true)` is set so that any `memory.grow` beyond
    /// the configured cap causes a trap (fail-closed) instead of returning -1.
    pub fn with_memory_limit(config: HashMap<String, String>, max_memory: usize) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(max_memory)
            .trap_on_grow_failure(true)
            .build();
        Self {
            config,
            logs: Vec::new(),
            max_log_entries: MAX_LOG_ENTRIES,
            limits,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared Engine constructor
// ---------------------------------------------------------------------------

/// Create a shared wasmtime [`Engine`] with fuel consumption enabled.
///
/// Returns `Arc<Engine>` suitable for sharing across multiple
/// `WasmtimeBackend` instances. Maps construction errors to
/// `WasmGuardError::Compilation`.
pub fn create_shared_engine() -> Result<Arc<Engine>, WasmGuardError> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    config.wasm_component_model(true);
    let engine = Engine::new(&config).map_err(|e| WasmGuardError::Compilation(e.to_string()))?;
    Ok(Arc::new(engine))
}

// ---------------------------------------------------------------------------
// Host function registration
// ---------------------------------------------------------------------------

/// Register the `chio.*` host functions on the given [`Linker`].
///
/// Registers:
/// - `chio.log(level: i32, ptr: i32, len: i32)` -- guest logging
/// - `chio.get_config(key_ptr: i32, key_len: i32, val_out_ptr: i32, val_out_len: i32) -> i32`
/// - `chio.get_time_unix_secs() -> i64`
///
/// All host function closures are safe: they never panic, never call
/// `unwrap()` or `expect()`, and return graceful sentinel values on error.
pub fn register_host_functions(linker: &mut Linker<WasmHostState>) -> Result<(), WasmGuardError> {
    // -----------------------------------------------------------------------
    // chio.log(level: i32, ptr: i32, len: i32)
    // -----------------------------------------------------------------------
    linker
        .func_wrap(
            "chio",
            "log",
            |mut caller: Caller<'_, WasmHostState>, level: i32, ptr: i32, len: i32| {
                // Validate level range (0=trace, 1=debug, 2=info, 3=warn, 4=error)
                if !(0..=4).contains(&level) {
                    return;
                }
                // Validate length is non-negative and within bounds
                if len < 0 || len as usize > MAX_LOG_MESSAGE_LEN {
                    return;
                }
                let len_usize = len as usize;

                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return,
                };

                let mut buf = vec![0u8; len_usize];
                if memory.read(&caller, ptr as usize, &mut buf).is_err() {
                    return;
                }

                let msg = String::from_utf8_lossy(&buf).to_string();

                // Emit via tracing at the appropriate level
                match level {
                    0 => tracing::trace!(target: "wasm_guard", "{msg}"),
                    1 => tracing::debug!(target: "wasm_guard", "{msg}"),
                    2 => tracing::info!(target: "wasm_guard", "{msg}"),
                    3 => tracing::warn!(target: "wasm_guard", "{msg}"),
                    4 => tracing::error!(target: "wasm_guard", "{msg}"),
                    _ => {} // unreachable due to range check above
                }

                // Buffer in host state (bounded)
                let state = caller.data_mut();
                if state.logs.len() < state.max_log_entries {
                    state.logs.push((level, msg));
                }
            },
        )
        .map_err(|e| WasmGuardError::HostFunction(e.to_string()))?;

    // -----------------------------------------------------------------------
    // chio.get_config(key_ptr: i32, key_len: i32, val_out_ptr: i32, val_out_len: i32) -> i32
    // -----------------------------------------------------------------------
    linker
        .func_wrap(
            "chio",
            "get_config",
            |mut caller: Caller<'_, WasmHostState>,
             key_ptr: i32,
             key_len: i32,
             val_out_ptr: i32,
             val_out_len: i32|
             -> i32 {
                // Validate key length
                if key_len < 0 || key_len as usize > 1024 {
                    return -1;
                }
                let key_len_usize = key_len as usize;

                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return -1,
                };

                // Read the key from guest memory
                let mut key_buf = vec![0u8; key_len_usize];
                if memory
                    .read(&caller, key_ptr as usize, &mut key_buf)
                    .is_err()
                {
                    return -1;
                }

                let key = match std::str::from_utf8(&key_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return -1,
                };

                // Split borrow: get memory data and store state simultaneously
                let (mem_data, state) = memory.data_and_store_mut(&mut caller);
                let value = match state.config.get(&key) {
                    Some(v) => v.clone(),
                    None => return -1,
                };

                let value_bytes = value.as_bytes();
                let actual_len = value_bytes.len();
                let out_len = val_out_len as usize;
                let out_ptr = val_out_ptr as usize;

                // Write as much as fits into the output buffer
                let copy_len = actual_len.min(out_len);
                if out_ptr.saturating_add(copy_len) <= mem_data.len() {
                    mem_data[out_ptr..out_ptr + copy_len].copy_from_slice(&value_bytes[..copy_len]);
                }

                // Return actual value length so guest can detect truncation
                actual_len as i32
            },
        )
        .map_err(|e| WasmGuardError::HostFunction(e.to_string()))?;

    // -----------------------------------------------------------------------
    // chio.get_time_unix_secs() -> i64
    // -----------------------------------------------------------------------
    linker
        .func_wrap(
            "chio",
            "get_time_unix_secs",
            |_caller: Caller<'_, WasmHostState>| -> i64 {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            },
        )
        .map_err(|e| WasmGuardError::HostFunction(e.to_string()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::{Module, Store};

    /// Helper: create a shared engine, linker with host functions, and store
    /// with the given config. Returns (store, linker, engine) for test use.
    fn setup_test_env(
        config: HashMap<String, String>,
    ) -> (Store<WasmHostState>, Linker<WasmHostState>, Arc<Engine>) {
        let engine = create_shared_engine().expect("create engine");
        let mut linker = Linker::new(&engine);
        register_host_functions(&mut linker).expect("register host functions");
        let host_state = WasmHostState::new(config);
        let mut store = Store::new(&engine, host_state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(1_000_000).expect("set fuel");
        (store, linker, engine)
    }

    // -----------------------------------------------------------------------
    // WasmHostState unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn host_state_new_creates_empty_logs_with_config() {
        let mut config = HashMap::new();
        config.insert("key".to_string(), "value".to_string());
        let state = WasmHostState::new(config.clone());
        assert!(state.logs.is_empty());
        assert_eq!(state.max_log_entries, MAX_LOG_ENTRIES);
        assert_eq!(state.config.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn host_state_with_memory_limit_uses_custom_limit() {
        let config = HashMap::new();
        let custom_limit = 4 * 1024 * 1024; // 4 MiB
        let state = WasmHostState::with_memory_limit(config, custom_limit);
        assert!(state.logs.is_empty());
        assert_eq!(state.max_log_entries, MAX_LOG_ENTRIES);
        // We verify the state was created with the custom limit by checking
        // it is usable (the actual enforcement is tested in runtime.rs)
    }

    #[test]
    fn host_state_new_uses_default_max_memory() {
        // WasmHostState::new() should use MAX_MEMORY_BYTES (16 MiB)
        let state = WasmHostState::new(HashMap::new());
        assert!(state.logs.is_empty());
        // The default limit is MAX_MEMORY_BYTES; we confirm construction works.
        // Actual enforcement tested via the wasmtime runtime integration tests.
    }

    // -----------------------------------------------------------------------
    // Shared engine tests
    // -----------------------------------------------------------------------

    #[test]
    fn host_create_shared_engine_returns_arc() {
        let engine = create_shared_engine();
        assert!(engine.is_ok());
        let engine = engine.unwrap();
        // Verify it is clonable (Arc)
        let _clone = engine.clone();
    }

    // -----------------------------------------------------------------------
    // chio.log tests
    // -----------------------------------------------------------------------

    #[test]
    fn host_log_captures_message() {
        let (mut store, linker, engine) = setup_test_env(HashMap::new());

        // WAT module that stores "hello" in memory and calls chio.log(2, 0, 5)
        let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "hello")
                (func (export "evaluate") (param i32 i32) (result i32)
                    (call $log (i32.const 2) (i32.const 0) (i32.const 5))
                    (i32.const 0)
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("compile WAT");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");

        let evaluate = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .expect("get evaluate");
        let _result = evaluate.call(&mut store, (0, 0)).expect("call evaluate");

        assert_eq!(store.data().logs, vec![(2, "hello".to_string())]);
    }

    #[test]
    fn host_log_buffer_respects_max_entries() {
        let (mut store, linker, engine) = setup_test_env(HashMap::new());

        // WAT module that calls chio.log 257 times in a loop
        // We use a local counter and br_if to loop
        let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "x")
                (func (export "evaluate") (param i32 i32) (result i32)
                    (local $i i32)
                    (local.set $i (i32.const 0))
                    (block $break
                        (loop $loop
                            (br_if $break (i32.ge_u (local.get $i) (i32.const 257)))
                            (call $log (i32.const 2) (i32.const 0) (i32.const 1))
                            (local.set $i (i32.add (local.get $i) (i32.const 1)))
                            (br $loop)
                        )
                    )
                    (i32.const 0)
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("compile WAT");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");

        let evaluate = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .expect("get evaluate");
        let _result = evaluate.call(&mut store, (0, 0)).expect("call evaluate");

        assert_eq!(store.data().logs.len(), MAX_LOG_ENTRIES);
    }

    #[test]
    fn host_log_invalid_level_is_silently_ignored() {
        let (mut store, linker, engine) = setup_test_env(HashMap::new());

        // WAT module that calls chio.log with level=99
        let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "bad")
                (func (export "evaluate") (param i32 i32) (result i32)
                    (call $log (i32.const 99) (i32.const 0) (i32.const 3))
                    (i32.const 0)
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("compile WAT");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");

        let evaluate = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .expect("get evaluate");
        let _result = evaluate.call(&mut store, (0, 0)).expect("call evaluate");

        assert!(store.data().logs.is_empty());
    }

    #[test]
    fn host_log_oversized_message_is_silently_ignored() {
        let (mut store, linker, engine) = setup_test_env(HashMap::new());

        // WAT module that calls chio.log with len > 4096
        let wat = r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (memory (export "memory") 1)
                (func (export "evaluate") (param i32 i32) (result i32)
                    (call $log (i32.const 2) (i32.const 0) (i32.const 4097))
                    (i32.const 0)
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("compile WAT");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");

        let evaluate = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .expect("get evaluate");
        let _result = evaluate.call(&mut store, (0, 0)).expect("call evaluate");

        assert!(store.data().logs.is_empty());
    }

    // -----------------------------------------------------------------------
    // chio.get_config tests
    // -----------------------------------------------------------------------

    #[test]
    fn host_get_config_reads_value() {
        let mut config = HashMap::new();
        config.insert("timeout".to_string(), "30".to_string());
        let (mut store, linker, engine) = setup_test_env(config);

        // WAT module that:
        // 1. Stores key "timeout" at offset 0 in memory
        // 2. Calls chio.get_config(0, 7, 100, 64) to read value into offset 100
        // 3. Stores the return value (actual length) at offset 200
        let wat = r#"
            (module
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "timeout")
                (func (export "evaluate") (param i32 i32) (result i32)
                    (i32.store
                        (i32.const 200)
                        (call $get_config
                            (i32.const 0)   ;; key_ptr
                            (i32.const 7)   ;; key_len ("timeout" = 7 bytes)
                            (i32.const 100) ;; val_out_ptr
                            (i32.const 64)  ;; val_out_len
                        )
                    )
                    (i32.const 0)
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("compile WAT");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");

        let evaluate = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .expect("get evaluate");
        let _result = evaluate.call(&mut store, (0, 0)).expect("call evaluate");

        // Read the return value from offset 200
        let memory = instance
            .get_memory(&mut store, "memory")
            .expect("get memory");
        let mut ret_buf = [0u8; 4];
        memory.read(&store, 200, &mut ret_buf).expect("read ret");
        let ret_val = i32::from_le_bytes(ret_buf);
        assert_eq!(ret_val, 2); // "30" has length 2

        // Read the value from offset 100
        let mut val_buf = [0u8; 2];
        memory.read(&store, 100, &mut val_buf).expect("read val");
        assert_eq!(&val_buf, b"30");
    }

    #[test]
    fn host_get_config_missing_key_returns_negative_one() {
        let (mut store, linker, engine) = setup_test_env(HashMap::new());

        // WAT module that looks up a nonexistent key and stores result
        let wat = r#"
            (module
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "missing")
                (func (export "evaluate") (param i32 i32) (result i32)
                    (i32.store
                        (i32.const 200)
                        (call $get_config
                            (i32.const 0)   ;; key_ptr
                            (i32.const 7)   ;; key_len ("missing" = 7 bytes)
                            (i32.const 100) ;; val_out_ptr
                            (i32.const 64)  ;; val_out_len
                        )
                    )
                    (i32.const 0)
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("compile WAT");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");

        let evaluate = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .expect("get evaluate");
        let _result = evaluate.call(&mut store, (0, 0)).expect("call evaluate");

        // Read the return value -- should be -1
        let memory = instance
            .get_memory(&mut store, "memory")
            .expect("get memory");
        let mut ret_buf = [0u8; 4];
        memory.read(&store, 200, &mut ret_buf).expect("read ret");
        let ret_val = i32::from_le_bytes(ret_buf);
        assert_eq!(ret_val, -1);
    }

    // -----------------------------------------------------------------------
    // chio.get_time_unix_secs tests
    // -----------------------------------------------------------------------

    #[test]
    fn host_get_time_returns_positive_value() {
        let (mut store, linker, engine) = setup_test_env(HashMap::new());

        // WAT module that calls chio.get_time_unix_secs and stores result as i64 at offset 0
        let wat = r#"
            (module
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 1)
                (func (export "evaluate") (param i32 i32) (result i32)
                    (i64.store
                        (i32.const 0)
                        (call $get_time)
                    )
                    (i32.const 0)
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("compile WAT");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");

        let evaluate = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .expect("get evaluate");
        let _result = evaluate.call(&mut store, (0, 0)).expect("call evaluate");

        // Read the i64 stored at offset 0
        let memory = instance
            .get_memory(&mut store, "memory")
            .expect("get memory");
        let mut time_buf = [0u8; 8];
        memory.read(&store, 0, &mut time_buf).expect("read time");
        let time_val = i64::from_le_bytes(time_buf);
        assert!(time_val > 0, "expected positive timestamp, got {time_val}");
    }
}
