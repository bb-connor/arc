#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod flow;
pub mod ports;

pub use flow::{
    Compartment, InformationLabel, LabelLimits, LabelValidationError, PrincipalId,
    DEFAULT_LABEL_LIMITS,
};
