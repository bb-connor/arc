use chio_kernel::Guard;

use crate::abi::WasmGuardAbi;
use crate::config::WasmGuardConfig;
use crate::error::WasmGuardError;

use super::guard::WasmGuard;

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
        let wasm_bytes =
            crate::input::read_file(std::path::Path::new(&config.path), config.max_module_size)
                .map_err(|source| WasmGuardError::InputFile {
                    path: config.path.clone().into(),
                    source,
                })?;

        let backend = factory(&wasm_bytes, config.fuel_limit)?;

        self.guards.push(WasmGuard::new(
            config.name.clone(),
            backend,
            config.advisory,
            None, // manifest_sha256 is only available on manifest-backed loaders
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
