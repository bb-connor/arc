//! Fuzz target for the decision-model artifact decoder: arbitrary bytes
//! must decode or be refused without panicking, a refused artifact leaves no
//! schedule, and a validated schedule evaluates within its op count.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chio_fuzz::entries::decision_model_artifact(data);
});
