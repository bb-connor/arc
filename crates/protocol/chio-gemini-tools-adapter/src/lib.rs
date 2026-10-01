//! Provider-native Google Gemini tool adapter.

#![forbid(unsafe_code)]

pub mod loaded_weights;
pub mod native;
pub mod streaming;
pub mod transport;

mod adapter;
mod response;

pub use adapter::*;
