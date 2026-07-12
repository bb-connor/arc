#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod lattice;

pub use lattice::{authorize_egress, EgressDenial, InformationFlowLattice, LatticeError};
