use chio_core_types::rng::{Rng, RngError};

use super::generate_random_session_id;
use crate::KernelError;

struct FailingRng;

impl Rng for FailingRng {
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), RngError> {
        Err(RngError("source offline"))
    }
}

struct PatternRng;

impl Rng for PatternRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        dest.fill(0x5a);
        Ok(())
    }
}

#[test]
fn session_id_entropy_failure_refuses() {
    match generate_random_session_id(&FailingRng) {
        Err(KernelError::Internal(reason)) => {
            assert!(reason.contains("entropy source failed: source offline"));
        }
        other => panic!("entropy failure must refuse, got {other:?}"),
    }
}

#[test]
fn session_id_encodes_drawn_entropy() {
    let session_id = match generate_random_session_id(&PatternRng) {
        Ok(session_id) => session_id,
        Err(error) => panic!("pattern rng must mint a session id: {error}"),
    };
    assert_eq!(session_id.as_str(), "sess-WlpaWlpaWlpaWlpaWlpaWg");
}
