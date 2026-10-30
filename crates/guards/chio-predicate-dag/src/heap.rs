use alloc::boxed::Box;
use alloc::vec;

use crate::schedule::{decode_storage, storage_schedule, Meta, Op, Schedule};
use crate::thresholds::Thresholds;
use crate::{DagError, MAX_SCHEDULE_OPS};

/// Heap-backed storage for one validated schedule, for hosts with an
/// allocator. The op buffer is allocated directly on the heap, so no
/// `MAX_SCHEDULE_OPS`-sized value is ever staged on a thread stack. Decode
/// and schedule share `ScheduleStorage`'s implementation.
#[derive(Debug)]
pub struct HeapScheduleStorage {
    ops: Box<[Op]>,
    meta: Meta,
    validated: bool,
}

impl HeapScheduleStorage {
    pub fn new() -> Self {
        Self {
            ops: vec![Op::END_CLAUSE; MAX_SCHEDULE_OPS].into_boxed_slice(),
            meta: Meta::EMPTY,
            validated: false,
        }
    }

    /// Decodes and validates `chio.decision-model.v1` bytes. Fail closed.
    pub fn decode(&mut self, bytes: &[u8]) -> Result<Thresholds, DagError> {
        decode_storage(bytes, &mut self.ops, &mut self.meta, &mut self.validated)
    }

    /// A view of the validated schedule, borrowed for one evaluation.
    pub fn schedule(&self) -> Result<Schedule<'_>, DagError> {
        storage_schedule(&self.ops, &self.meta, self.validated)
    }
}

impl Default for HeapScheduleStorage {
    fn default() -> Self {
        Self::new()
    }
}
