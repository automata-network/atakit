//! Canonical CVM identifier and policy encodings.
//!
//! Public functions use fixed byte arrays and vectors. Alloy provides the
//! internal Solidity ABI implementation but does not appear in this API.

mod identity;
pub mod pcr_comparison;

pub use identity::*;
