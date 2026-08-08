mod env;
mod progress;
mod refs;
pub mod tee_attributes;

pub use env::{Env, LegacyImageStore};
pub use progress::{NullReporter, ProgressHandle, ProgressReporter};
pub use refs::encode_ref_path_segment;

/// Archive compression format for `.atawl` and `.atabi` files.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveCompression {
    /// Zstandard (default). Faster compression and decompression than gzip.
    #[default]
    Zstd,
    /// Gzip. Legacy format for backwards compatibility.
    Gz,
}
