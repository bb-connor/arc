use std::{env, ffi::OsString};

pub(super) struct EnvVarOverride {
    name: &'static str,
    previous: Option<OsString>,
}

impl EnvVarOverride {
    pub(super) fn remove(name: &'static str) -> Self {
        let previous = env::var_os(name);
        env::remove_var(name);
        Self { name, previous }
    }

    pub(super) fn set(name: &'static str, value: &'static str) -> Self {
        let previous = env::var_os(name);
        env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvVarOverride {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => env::set_var(self.name, value),
            None => env::remove_var(self.name),
        }
    }
}
