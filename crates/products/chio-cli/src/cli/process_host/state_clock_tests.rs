//! Exercise the actual host composition without relying on the machine epoch.
use super::state::kernel_with_clock;
use chio_control_plane::policy;
use chio_core_types::Keypair;
use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct HostTestClock {
    fixed: FixedClock,
    unavailable: AtomicBool,
}
impl Clock for HostTestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(ClockError::Unavailable)
        } else {
            self.fixed.read()
        }
    }
}

#[test]
fn host_authority_uses_injected_epoch_and_refuses_clock_outage(
) -> Result<(), Box<dyn std::error::Error>> {
    for epoch in [3_600_000, 4_000_000_000_000] {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let policy_path = directory.path().join("policy.yaml");
        std::fs::write(
            &policy_path,
            r#"kernel:
  max_capability_ttl: 3600
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: reports
        tool: read
        operations: [invoke]
        ttl: 60
"#,
        )?;
        let loaded = policy::load_policy(&policy_path)?;
        let scope = loaded.default_capabilities[0].scope.clone();
        let clock = Arc::new(HostTestClock {
            fixed: FixedClock::from_millis(epoch),
            unavailable: AtomicBool::new(false),
        });
        let host = kernel_with_clock(directory.path(), loaded, true, false, None, clock.clone())?;
        let subject = Keypair::generate().public_key();
        let token = host.kernel.issue_capability(&subject, scope.clone(), 60)?;
        assert_eq!(token.issued_at, epoch / 1000);
        assert_eq!(token.expires_at, epoch / 1000 + 60);
        assert!(token.verify_signature()?);
        clock.unavailable.store(true, Ordering::SeqCst);
        assert!(host.kernel.issue_capability(&subject, scope, 60).is_err());
        assert!(host.kernel.revoke_capability(&token.id).is_err());
    }
    Ok(())
}
