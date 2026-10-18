//! Pure program composition and bounded description checking.

mod compiler;
mod types;

pub use compiler::{compile_program, validate_compiled_program};
pub use types::*;

use crate::computer::{decode, DescriptionError, MAX_DESCRIPTION_BYTES};

pub const COMPILED_DESCRIPTION_SCHEMA: &str = "chio.computer.compiled-description.v1";
pub const MAX_EXPRESSION_NODES: usize = 2047;
pub const MAX_EXPRESSION_DEPTH: usize = 32;
pub const MAX_PROGRAM_LEAVES: usize = 1024;
pub const MAX_DEPENDENCY_EDGES: usize = 4096;
pub const MAX_COMPILED_BYTES: usize = 8 * 1024 * 1024;

impl ProgramExpr {
    pub fn from_json(bytes: &[u8]) -> Result<Self, DescriptionError> {
        let expression = decode(bytes, MAX_DESCRIPTION_BYTES)?;
        compiler::preflight(&expression)?;
        Ok(expression)
    }

    #[must_use]
    pub fn pipe(self, next: Self) -> Self {
        Self::Sequence {
            items: vec![self, next],
        }
    }
}

impl std::ops::BitAnd for ProgramExpr {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Self::Parallel {
            items: vec![self, other],
        }
    }
}

impl std::ops::BitOr for ProgramExpr {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.pipe(other)
    }
}

impl CompiledDescription {
    pub fn from_json(bytes: &[u8]) -> Result<Self, DescriptionError> {
        decode(bytes, MAX_COMPILED_BYTES)
    }
}
