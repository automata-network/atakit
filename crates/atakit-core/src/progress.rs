/// A handle to an active progress bar/gauge.
///
/// Implementations update the visual progress indicator. The handle is
/// dropped when the operation completes.
pub trait ProgressHandle: Send + Sync {
    /// Advance the progress by `n` bytes (or units).
    fn inc(&self, n: u64);

    /// Mark the progress as finished.
    fn finish(&self);
}

/// Factory for creating progress handles.
///
/// CLI can implement this with indicatif, TUI with ratatui gauges, etc.
/// Library code accepts `&dyn ProgressReporter` to stay UI-agnostic.
pub trait ProgressReporter: Send + Sync {
    /// Create a new progress bar for an operation.
    ///
    /// - `message`: label for the operation (e.g. filename)
    /// - `total`: total size in bytes (0 if unknown)
    fn create(&self, message: &str, total: u64) -> Box<dyn ProgressHandle>;
}

/// No-op reporter that discards all progress updates.
pub struct NullReporter;

impl ProgressReporter for NullReporter {
    fn create(&self, _message: &str, _total: u64) -> Box<dyn ProgressHandle> {
        Box::new(NullHandle)
    }
}

struct NullHandle;

impl ProgressHandle for NullHandle {
    fn inc(&self, _n: u64) {}
    fn finish(&self) {}
}
