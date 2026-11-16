//! Signed CPU controls shared by the workload builder and Portal.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CPU_POLICY_FORMAT: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CpuIdlePolicy {
    /// Exact Linux CPUIdle driver, or "auto" to use the guest's active driver.
    /// State names must exist on that driver on every online CPU.
    pub driver: String,
    #[serde(default)]
    pub governor: Option<String>,
    #[serde(default)]
    pub disabled_states: Vec<String>,
    #[serde(default = "required_default")]
    pub required: bool,
}
fn required_default() -> bool {
    true
}
impl CpuIdlePolicy {
    pub fn validate(&self) -> Result<(), String> {
        fn name(s: &str) -> bool {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        }
        if !name(&self.driver) || self.governor.as_deref().is_some_and(|s| !name(s)) {
            return Err("cpu-idle driver/governor must be nonempty names containing letters, digits, underscores or hyphens".into());
        }
        if self.governor.is_none() && self.disabled_states.is_empty() {
            return Err("cpu-idle must request a governor or disabled-states".into());
        }
        let mut seen = BTreeSet::new();
        for state in &self.disabled_states {
            if !name(state) || !seen.insert(state) {
                return Err("cpu-idle disabled-states must contain unique state names".into());
            }
        }
        Ok(())
    }
}

/// VM-wide CPU frequency governor, distinct from the CPU idle governor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CpuFrequencyPolicy {
    pub governor: String,
    #[serde(default = "required_default")]
    pub required: bool,
}
impl CpuFrequencyPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.governor.is_empty()
            || self.governor.len() > 64
            || !self
                .governor
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err("cpu-frequency governor must be a nonempty name containing letters, digits, underscores or hyphens".into());
        }
        Ok(())
    }
}

/// Parse a bounded Linux CPU list. Reject empty sets, descending ranges and
/// nonnumeric input rather than passing unvalidated text to the runtime.
pub fn parse_cpuset(value: &str) -> Result<BTreeSet<u32>, String> {
    let invalid =
        || format!("invalid cpuset {value:?}; use CPU numbers or ranges, for example 0-3,6");
    // The longest canonical list is 8192 seven-digit IDs plus 8191 commas.
    // Accept our own output even when the source used a short range.
    if value.is_empty() || value.len() > 65535 {
        return Err(invalid());
    }
    let mut cpus = BTreeSet::new();
    for part in value.split(',') {
        let mut range = part.split('-');
        let number = |s: &str| -> Result<u32, String> {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            s.parse().map_err(|_| invalid())
        };
        let first = number(range.next().ok_or_else(invalid)?)?;
        let last = range.next().map(number).transpose()?.unwrap_or(first);
        if range.next().is_some() || first > last || last > 1_048_575 || last - first >= 8192 {
            return Err(invalid());
        }
        cpus.extend(first..=last);
        if cpus.len() > 8192 {
            return Err(invalid());
        }
    }
    Ok(cpus)
}
pub fn canonical_cpuset(value: &str) -> Result<String, String> {
    Ok(parse_cpuset(value)?
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(","))
}
/// An omitted baby request inherits its signed slot allowance. Explicit baby
/// CPU selection requires a signed allowance and must remain inside it.
pub fn baby_cpuset(request: Option<&str>, allowed: Option<&str>) -> Result<Option<String>, String> {
    match (request, allowed) {
        (None, None) => Ok(None),
        (None, Some(set)) => canonical_cpuset(set).map(Some),
        (Some(_), None) => {
            Err("baby cpuset selection requires a signed slot cpuset allowance".into())
        }
        (Some(request), Some(allowed)) => {
            if !parse_cpuset(request)?.is_subset(&parse_cpuset(allowed)?) {
                return Err("baby cpuset exceeds the signed slot cpuset allowance".into());
            }
            canonical_cpuset(request).map(Some)
        }
    }
}
pub fn validate_cpu_policy<'a>(
    format: u32,
    idle: Option<&CpuIdlePolicy>,
    frequency: Option<&CpuFrequencyPolicy>,
    sets: impl Iterator<Item = &'a str>,
) -> Result<(), String> {
    let sets: Vec<_> = sets.collect();
    if (idle.is_some() || frequency.is_some() || !sets.is_empty()) && format < CPU_POLICY_FORMAT {
        return Err(
            "cpu-idle, cpu-frequency and cpuset require format = 16 and a v0.3.6 or newer image"
                .into(),
        );
    }
    if let Some(idle) = idle {
        idle.validate()?;
    }
    if let Some(frequency) = frequency {
        frequency.validate()?;
    }
    for set in sets {
        parse_cpuset(set)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frequency_policy_requires_format_16_and_valid_name() {
        let mut p = CpuFrequencyPolicy {
            governor: "performance".into(),
            required: true,
        };
        assert!(validate_cpu_policy(15, None, Some(&p), std::iter::empty()).is_err());
        assert!(validate_cpu_policy(16, None, Some(&p), std::iter::empty()).is_ok());
        for name in ["", "performance\n", "../powersave", "performance powersave"] {
            p.governor = name.into();
            assert!(p.validate().is_err());
        }
    }
    #[test]
    fn cpuset_bounds_and_baby_permissions() {
        assert_eq!(canonical_cpuset("2-4,2,0").unwrap(), "0,2,3,4");
        for invalid in ["", "-1", "4-2", "1,", "1-2-3", " 1", "0-4294967295"] {
            assert!(parse_cpuset(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            baby_cpuset(None, Some("2-3")).unwrap().as_deref(),
            Some("2,3")
        );
        assert!(baby_cpuset(Some("0"), Some("2-3")).is_err());
        assert!(baby_cpuset(Some("0"), None).is_err());
        assert_eq!(
            baby_cpuset(Some("3"), Some("2-3")).unwrap().as_deref(),
            Some("3")
        );
        assert!(validate_cpu_policy(15, None, None, ["0"].into_iter()).is_err());
    }

    #[test]
    fn largest_canonical_cpuset_can_be_parsed_again() {
        let canonical = canonical_cpuset("1040384-1048575").unwrap();
        assert_eq!(canonical.len(), 65535);
        assert_eq!(parse_cpuset(&canonical).unwrap().len(), 8192);
        assert_eq!(canonical_cpuset(&canonical).unwrap(), canonical);
        assert!(parse_cpuset("1040383-1048575").is_err());
        assert!(parse_cpuset(&format!("{canonical},0")).is_err());
    }
}
