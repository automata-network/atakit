use atakit_core::{ProgressHandle, ProgressReporter};
use indicatif::{ProgressBar, ProgressStyle};

/// Progress reporter backed by indicatif progress bars.
pub struct IndicatifReporter;

impl ProgressReporter for IndicatifReporter {
    fn create(&self, message: &str, total: u64) -> Box<dyn ProgressHandle> {
        if total == 0 {
            // Unknown duration: use a spinner instead of a stuck 0/0 bar.
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{msg}\n  {spinner:.cyan} {elapsed_precise}")
                    .expect("valid template"),
            );
            pb.set_message(message.to_string());
            pb.enable_steady_tick(std::time::Duration::from_millis(120));
            Box::new(IndicatifHandle(pb))
        } else {
            let pb = ProgressBar::new(total);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "{msg}\n  [{bar:40.cyan/dim}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
                    )
                    .expect("valid template")
                    .progress_chars("=> "),
            );
            pb.set_message(message.to_string());
            Box::new(IndicatifHandle(pb))
        }
    }
}

struct IndicatifHandle(ProgressBar);

impl ProgressHandle for IndicatifHandle {
    fn inc(&self, n: u64) {
        self.0.inc(n);
    }

    fn finish(&self) {
        self.0.finish_and_clear();
    }
}
