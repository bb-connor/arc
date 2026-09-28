use super::*;

pub(super) fn accounting_error() -> KernelError {
    KernelError::Dpop(super::DpopError::Accounting)
}

#[cfg(test)]
#[path = "accounting_tests.rs"]
mod tests;

impl DpopNonceState {
    pub(super) fn ensure_accounting(&self) -> Result<(), KernelError> {
        if self.accounting_failed {
            return Err(accounting_error());
        }
        Ok(())
    }

    /// Validate the whole release before deleting any replay marker. Pruning
    /// several expired entries and rolling back one owned reservation share
    /// the same accounting rule.
    pub(super) fn release_accounted_entries(
        &mut self,
        entries: &[((String, String), usize)],
    ) -> Result<(), KernelError> {
        self.ensure_accounting()?;
        let plan = (|| {
            let mut bytes = self.identity_bytes;
            let mut counts = HashMap::new();
            for (key, released_bytes) in entries {
                if self.cache.peek(key).is_none() {
                    return Err(accounting_error());
                }
                bytes = bytes
                    .checked_sub(*released_bytes)
                    .ok_or_else(accounting_error)?;
                let remaining = counts
                    .entry(key.1.clone())
                    .or_insert_with(|| self.capability_counts.get(&key.1).copied().unwrap_or(0));
                *remaining = remaining.checked_sub(1).ok_or_else(accounting_error)?;
            }
            Ok((bytes, counts))
        })();
        let (bytes, counts) = match plan {
            Ok(plan) => plan,
            Err(error) => {
                self.accounting_failed = true;
                return Err(error);
            }
        };
        for (key, _) in entries {
            self.cache.pop(key);
        }
        self.identity_bytes = bytes;
        for (capability, remaining) in counts {
            if remaining == 0 {
                self.capability_counts.remove(&capability);
            } else {
                self.capability_counts.insert(capability, remaining);
            }
        }
        Ok(())
    }
}
