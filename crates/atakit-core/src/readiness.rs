//! Measured startup checks shared by the workload builder and portal.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawReadiness")]
pub struct Readiness {
    pub command: Vec<String>,
    #[serde(rename = "interval-seconds")]
    pub interval_seconds: u64,
    #[serde(rename = "attempt-timeout-seconds")]
    pub attempt_timeout_seconds: u64,
    #[serde(rename = "deadline-seconds")]
    pub deadline_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReadiness {
    command: Vec<String>,
    #[serde(rename = "interval-seconds")]
    interval_seconds: u64,
    #[serde(rename = "attempt-timeout-seconds")]
    attempt_timeout_seconds: u64,
    #[serde(rename = "deadline-seconds")]
    deadline_seconds: u64,
}
impl TryFrom<RawReadiness> for Readiness {
    type Error = String;
    fn try_from(raw: RawReadiness) -> Result<Self, Self::Error> {
        let check = Self {
            command: raw.command,
            interval_seconds: raw.interval_seconds,
            attempt_timeout_seconds: raw.attempt_timeout_seconds,
            deadline_seconds: raw.deadline_seconds,
        };
        check.validate()?;
        Ok(check)
    }
}
impl Readiness {
    pub fn validate(&self) -> Result<(), String> {
        if self.command.is_empty()
            || self.command.len() > 128
            || self.command[0].is_empty()
            || self.command[0].starts_with('-')
            || self.command.iter().any(|s| s.contains('\0'))
            || self.command.iter().map(String::len).sum::<usize>() > 16384
        {
            return Err("readiness.command must be a nonempty executable and argument array (at most 128 arguments and 16384 bytes, no NUL)".into());
        }
        if !(1..=86400).contains(&self.deadline_seconds)
            || self.interval_seconds == 0
            || self.interval_seconds > self.deadline_seconds
            || self.attempt_timeout_seconds == 0
            || self.attempt_timeout_seconds > self.deadline_seconds
        {
            return Err("readiness durations must be positive; deadline-seconds must be at most 86400, and interval-seconds and attempt-timeout-seconds must not exceed it".into());
        }
        Ok(())
    }
}
