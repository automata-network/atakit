//! Display only public disk operation fields. Never print an entire response.
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::Value;
use std::{
    io::IsTerminal,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct Display {
    spinner: Option<ProgressBar>,
    previous: String,
    last_print: Option<Instant>,
}
impl Display {
    pub fn update(&mut self, status: &Value) {
        let message = summary(status);
        if message.is_empty() {
            self.clear();
            self.previous.clear();
            return;
        }
        if std::io::stderr().is_terminal() {
            let spinner = self.spinner.get_or_insert_with(|| {
                let spinner = ProgressBar::new_spinner();
                spinner.set_style(ProgressStyle::with_template("{spinner} {msg}").unwrap());
                spinner.enable_steady_tick(Duration::from_millis(100));
                spinner
            });
            spinner.set_message(message.clone());
        } else if self
            .last_print
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(10))
            || phase_summary(status) != self.previous
        {
            eprintln!("{message}");
            self.last_print = Some(Instant::now());
        }
        self.previous = phase_summary(status);
    }
    fn clear(&mut self) {
        if let Some(spinner) = self.spinner.take() {
            spinner.finish_and_clear();
        }
    }
}
impl Drop for Display {
    fn drop(&mut self) {
        self.clear();
    }
}

fn phase_summary(status: &Value) -> String {
    rows(status, false).join("; ")
}
pub(super) fn summary(status: &Value) -> String {
    rows(status, true).join("; ")
}
fn rows(status: &Value, elapsed: bool) -> Vec<String> {
    status["disks"]
        .as_object()
        .into_iter()
        .flat_map(|disks| disks.iter())
        .filter_map(|(name, disk)| {
            let operation = match disk["operation"].as_str()? {
                "resolving_device" => "resolving device",
                "checking_disk" => "checking disk",
                "setting_up_encryption" => "setting up encryption",
                "formatting_filesystem" => "formatting filesystem",
                "unlocking" => "unlocking",
                "mounting" => "mounting",
                "waiting_for_supervisor" => "waiting for supervisor",
                // Do not run a spinner over a passphrase prompt.
                _ => return None,
            };
            let name: String = name
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
                .take(128)
                .collect();
            let suffix = if elapsed {
                format!(" ({}s)", disk["elapsed_seconds"].as_u64().unwrap_or(0))
            } else {
                String::new()
            };
            Some(format!("Disk {name}: {operation}{suffix}"))
        })
        .collect()
}

pub(crate) struct Monitor(tokio::task::JoinHandle<()>);
impl Drop for Monitor {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) fn start(client: &reqwest::Client, host: &str, port: u16) -> Monitor {
    let client = client.clone();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let base = format!("https://{host}:{port}");
    Monitor(tokio::spawn(async move { monitor(&client, &base).await }))
}

pub(super) async fn monitor(client: &reqwest::Client, base: &str) {
    let mut display = Display::default();
    loop {
        let status = super::disk::poll_status(client, &format!("{base}/status")).await;
        display.update(&status);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renders_only_known_public_progress() {
        let status = serde_json::json!({"disks": {
            "data\u{1b}": {"state":"pending", "operation":"formatting_filesystem", "elapsed_seconds":42, "passphrase":"SECRET"},
            "other": {"operation":"SECRET"}
        }});
        assert_eq!(summary(&status), "Disk data: formatting filesystem (42s)");
        assert_eq!(
            summary(&serde_json::json!({"disks":{"data":{"state":"mounted"}}})),
            ""
        );
    }
}
