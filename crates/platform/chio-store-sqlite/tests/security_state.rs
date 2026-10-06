include!("security_state_parts/part_01.rs");
include!("security_state_parts/part_02.rs");

#[path = "support/security_state_clock.rs"]
mod clock;
#[cfg(unix)]
#[path = "security_state_parts/open_path.rs"]
mod open_path;
use clock::FixedSecurityStateClock;
