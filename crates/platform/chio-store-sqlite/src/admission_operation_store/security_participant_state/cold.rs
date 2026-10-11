//! Preparatory authenticated map component. No live native reader uses it.

mod encoding;
mod tree;
mod tree_tests;

type Digest = [u8; 32];
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum Error {
    #[error("native cold encoding is invalid")]
    Encoding,
    #[error("native cold node source is unavailable")]
    Source,
    #[error("native cold content address conflicts")]
    Conflict,
    #[error("native cold proof node is missing")]
    MissingNode,
    #[error("native cold proof node digest differs")]
    NodeDigest,
    #[error("native cold tree shape is invalid")]
    Shape,
    #[error("native cold tree exceeds its key depth")]
    Depth,
    #[error("native cold leaf is outside its authenticated path")]
    Placement,
    #[error("native cold batch repeats a key")]
    DuplicateKey,
    #[error("native cold value belongs to another key")]
    Binding,
}
