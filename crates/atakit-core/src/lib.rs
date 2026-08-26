mod env;
mod progress;
mod refs;
pub mod tee_attributes;

pub use env::{restrict_to_owner, Env, LegacyImageStore};
pub use progress::{NullReporter, ProgressHandle, ProgressReporter};
pub use refs::{is_canonical_id, is_valid_ref_name, is_valid_ref_version};

/// Archive compression format for `.atawl` and `.atabi` files.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveCompression {
    /// Zstandard (default). Faster compression and decompression than gzip.
    #[default]
    Zstd,
    /// Gzip. Legacy format for backwards compatibility.
    Gz,
}
