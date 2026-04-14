//! Error types for the WASM guard runtime.

/// Errors that can occur during WASM guard loading and execution.
#[derive(Debug, thiserror::Error)]
pub enum WasmGuardError {
    /// The `.wasm` module could not be read from disk.
    #[error("failed to read WASM module at {path}: {reason}")]
    ModuleLoad { path: String, reason: String },

    /// The module failed compilation or validation.
    #[error("WASM module compilation failed: {0}")]
    Compilation(String),

    /// The module does not export the required ABI functions.
    #[error("missing required export: {0}")]
    MissingExport(String),

    /// The module's exported function has the wrong signature.
    #[error("invalid export signature for {name}: {reason}")]
    InvalidSignature { name: String, reason: String },

    /// The guest ran out of fuel (CPU budget exhausted).
    #[error("fuel exhausted after {consumed} units (limit: {limit})")]
    FuelExhausted { consumed: u64, limit: u64 },

    /// The guest's memory could not be accessed.
    #[error("guest memory error: {0}")]
    Memory(String),

    /// Serialization or deserialization of the guard request/response failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A runtime trap or unexpected guest abort.
    #[error("WASM trap: {0}")]
    Trap(String),

    /// A host function call failed.
    #[error("host function error: {0}")]
    HostFunction(String),

    /// The runtime backend is not available (feature not enabled).
    #[error("WASM runtime backend not available -- enable the 'wasmtime-runtime' feature")]
    BackendUnavailable,
}
