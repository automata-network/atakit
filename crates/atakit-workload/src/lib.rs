#[cfg(feature = "cli")]
pub mod cli;
mod error;
mod scaffold;

pub use error::WorkloadError;
pub use scaffold::create_workload;
