//! Signed publisher permissions and separate, untrusted operator choices.
//! Resolving a choice never modifies the measured manifest.
use crate::cpu::{canonical_cpuset, parse_cpuset, CpuFrequencyPolicy, CpuIdlePolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn required_default() -> bool {
    true
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn names(values: Option<&Vec<String>>, wildcard: bool) -> Result<(), String> {
    if let Some(values) = values {
        if values.len() > 128 || values.iter().any(|v| !(name(v) || wildcard && v == "*")) {
            return Err("CPU allowance contains an invalid name".into());
        }
    }
    Ok(())
}
fn allowed(values: Option<&Vec<String>>, value: &str, wildcard: bool) -> bool {
    values.is_some_and(|values| values.iter().any(|v| v == value || wildcard && v == "*"))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct IdleSelection {
    pub governor: Option<String>,
    pub disabled_states: Option<Vec<String>>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct FrequencySelection {
    pub governor: Option<String>,
}

/// Complete desired operator request. Missing fields mean no operator choice;
/// layered CLI inputs are merged before this object is sent to Portal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuntimeCpuConfig {
    pub cpu_idle: Option<IdleSelection>,
    pub cpu_frequency: Option<FrequencySelection>,
    pub cpuset: Option<String>,
    pub dependencies: BTreeMap<String, String>,
    pub baby_containers: BTreeMap<String, String>,
}
impl RuntimeCpuConfig {
    /// Higher-priority values replace lower-priority values, including [] lists.
    pub fn overlay(&mut self, higher: &Self) {
        if let Some(h) = &higher.cpu_idle {
            let v = self.cpu_idle.get_or_insert_with(Default::default);
            if h.governor.is_some() {
                v.governor.clone_from(&h.governor);
            }
            if h.disabled_states.is_some() {
                v.disabled_states.clone_from(&h.disabled_states);
            }
        }
        if let Some(h) = &higher.cpu_frequency {
            if h.governor.is_some() {
                self.cpu_frequency = Some(h.clone());
            }
        }
        if higher.cpuset.is_some() {
            self.cpuset.clone_from(&higher.cpuset);
        }
        self.dependencies.extend(higher.dependencies.clone());
        self.baby_containers.extend(higher.baby_containers.clone());
    }
    pub fn normalize(&mut self) -> Result<(), String> {
        if let Some(idle) = &mut self.cpu_idle {
            if idle.governor.as_deref().is_some_and(|v| !name(v)) {
                return Err("invalid idle governor".into());
            }
            names(idle.disabled_states.as_ref(), false)?;
            if let Some(states) = &mut idle.disabled_states {
                states.sort();
                states.dedup();
            }
        }
        if self
            .cpu_frequency
            .as_ref()
            .and_then(|p| p.governor.as_deref())
            .is_some_and(|v| !name(v))
        {
            return Err("invalid frequency governor".into());
        }
        for set in self
            .cpuset
            .iter_mut()
            .chain(self.dependencies.values_mut())
            .chain(self.baby_containers.values_mut())
        {
            *set = canonical_cpuset(set)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CpuIdleRules {
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub governor: Option<String>,
    #[serde(default)]
    pub disabled_states: Vec<String>,
    #[serde(default = "required_default")]
    pub required: bool,
    #[serde(default)]
    pub allow_operator: Option<bool>,
    #[serde(default)]
    pub allowed_governors: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_disabled_states: Option<Vec<String>>,
}
impl CpuIdleRules {
    pub fn fixed(&self) -> bool {
        self.governor.is_some() || !self.disabled_states.is_empty()
    }
    pub fn validate(&self) -> Result<(), String> {
        names(self.allowed_governors.as_ref(), false)?;
        names(self.allowed_disabled_states.as_ref(), true)?;
        if self.fixed() {
            CpuIdlePolicy {
                driver: self.driver.clone().ok_or("cpu-idle requires driver")?,
                governor: self.governor.clone(),
                disabled_states: self.disabled_states.clone(),
                required: self.required,
            }
            .validate()?;
        } else if self.allow_operator == Some(true) {
            if !self.driver.as_deref().is_some_and(name) {
                return Err("delegated cpu-idle requires a driver".into());
            }
            if self.allowed_governors.as_ref().is_none_or(Vec::is_empty) {
                return Err("delegated cpu-idle requires allowed-governors".into());
            }
        } else if self.allow_operator != Some(false) {
            return Err("cpu-idle needs fixed settings or explicit operator permission".into());
        }
        Ok(())
    }
    pub fn resolve(
        &self,
        request: Option<&IdleSelection>,
    ) -> Result<Option<CpuIdlePolicy>, String> {
        self.validate()?;
        if self.fixed() {
            if request.is_some() {
                return Err("operator cannot override publisher-fixed cpu-idle".into());
            }
            return Ok(Some(CpuIdlePolicy {
                driver: self.driver.clone().unwrap(),
                governor: self.governor.clone(),
                disabled_states: self.disabled_states.clone(),
                required: self.required,
            }));
        }
        if self.allow_operator != Some(true) {
            if request.is_some() {
                return Err("publisher forbids operator cpu-idle tuning".into());
            }
            return Ok(None);
        }
        let Some(request) = request else {
            return if self.required {
                Err("publisher requires an operator cpu-idle selection".into())
            } else {
                Ok(None)
            };
        };
        let governor = request
            .governor
            .as_ref()
            .ok_or("operator must select an explicit idle governor")?;
        if !allowed(self.allowed_governors.as_ref(), governor, false) {
            return Err("idle governor is outside publisher allowance".into());
        }
        let states = request.disabled_states.clone().unwrap_or_default();
        if states
            .iter()
            .any(|s| !allowed(self.allowed_disabled_states.as_ref(), s, true))
        {
            return Err("idle state is outside publisher allowance".into());
        }
        let policy = CpuIdlePolicy {
            driver: self.driver.clone().unwrap(),
            governor: Some(governor.clone()),
            disabled_states: states,
            required: self.required,
        };
        policy.validate()?;
        Ok(Some(policy))
    }
    pub fn normalize(&mut self) {
        self.disabled_states.sort();
        self.disabled_states.dedup();
        for list in [
            &mut self.allowed_governors,
            &mut self.allowed_disabled_states,
        ]
        .into_iter()
        .flatten()
        {
            list.sort();
            list.dedup();
        }
        if self
            .allowed_disabled_states
            .as_ref()
            .is_some_and(|v| v.iter().any(|s| s == "*"))
        {
            self.allowed_disabled_states = Some(vec!["*".into()]);
        }
    }
}
impl From<CpuIdlePolicy> for CpuIdleRules {
    fn from(p: CpuIdlePolicy) -> Self {
        Self {
            driver: Some(p.driver),
            governor: p.governor,
            disabled_states: p.disabled_states,
            required: p.required,
            allow_operator: None,
            allowed_governors: None,
            allowed_disabled_states: None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CpuFrequencyRules {
    #[serde(default)]
    pub governor: Option<String>,
    #[serde(default = "required_default")]
    pub required: bool,
    #[serde(default)]
    pub allow_operator: Option<bool>,
    #[serde(default)]
    pub allowed_governors: Option<Vec<String>>,
}
impl CpuFrequencyRules {
    pub fn validate(&self) -> Result<(), String> {
        names(self.allowed_governors.as_ref(), false)?;
        if let Some(governor) = &self.governor {
            CpuFrequencyPolicy {
                governor: governor.clone(),
                required: self.required,
            }
            .validate()?;
        } else if self.allow_operator == Some(true) {
            if self.allowed_governors.as_ref().is_none_or(Vec::is_empty) {
                return Err("delegated cpu-frequency requires allowed-governors".into());
            }
        } else if self.allow_operator != Some(false) {
            return Err("cpu-frequency needs a governor or explicit operator permission".into());
        }
        Ok(())
    }
    pub fn resolve(
        &self,
        request: Option<&FrequencySelection>,
    ) -> Result<Option<CpuFrequencyPolicy>, String> {
        self.validate()?;
        if let Some(governor) = &self.governor {
            if request.is_some() {
                return Err("operator cannot override publisher-fixed cpu-frequency".into());
            }
            return Ok(Some(CpuFrequencyPolicy {
                governor: governor.clone(),
                required: self.required,
            }));
        }
        if self.allow_operator != Some(true) {
            if request.is_some() {
                return Err("publisher forbids operator cpu-frequency tuning".into());
            }
            return Ok(None);
        }
        let Some(request) = request else {
            return if self.required {
                Err("publisher requires an operator cpu-frequency selection".into())
            } else {
                Ok(None)
            };
        };
        let governor = request
            .governor
            .as_ref()
            .ok_or("operator must select a frequency governor")?;
        if !allowed(self.allowed_governors.as_ref(), governor, false) {
            return Err("frequency governor is outside publisher allowance".into());
        }
        Ok(Some(CpuFrequencyPolicy {
            governor: governor.clone(),
            required: self.required,
        }))
    }
}
impl From<CpuFrequencyPolicy> for CpuFrequencyRules {
    fn from(p: CpuFrequencyPolicy) -> Self {
        Self {
            governor: Some(p.governor),
            required: p.required,
            allow_operator: None,
            allowed_governors: None,
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct CpusetRules {
    pub allow_operator: Option<bool>,
    /// Explicit guest CPU list, or "online" to permit any exposed guest CPUs.
    pub allowed_cpus: Option<String>,
    #[serde(default = "required_default")]
    pub required: bool,
}
impl CpusetRules {
    pub fn validate(&self) -> Result<(), String> {
        if self.allow_operator == Some(true) && self.allowed_cpus.is_none() {
            return Err("delegated cpuset requires allowed-cpus".into());
        }
        if let Some(cpus) = &self.allowed_cpus {
            if cpus != "online" {
                parse_cpuset(cpus)?;
            }
        }
        Ok(())
    }
    pub fn normalize(&mut self) -> Result<(), String> {
        self.validate()?;
        if let Some(set) = &mut self.allowed_cpus {
            if set != "online" {
                *set = canonical_cpuset(set)?;
            }
        }
        Ok(())
    }
}
pub fn resolve_cpuset(
    fixed: Option<&str>,
    rule: Option<&CpusetRules>,
    request: Option<&str>,
) -> Result<Option<String>, String> {
    if let Some(rule) = rule {
        rule.validate()?;
    }
    if let Some(fixed) = fixed {
        if request.is_some() {
            return Err("operator cannot override publisher-fixed cpuset".into());
        }
        return canonical_cpuset(fixed).map(Some);
    }
    let Some(request) = request else {
        if rule.is_some_and(|r| r.allow_operator == Some(true) && r.required) {
            return Err("publisher requires an operator cpuset selection".into());
        }
        return Ok(None);
    };
    let rule = rule
        .filter(|r| r.allow_operator == Some(true))
        .ok_or("publisher did not allow operator cpuset tuning")?;
    let set = parse_cpuset(request)?;
    let allowance = rule.allowed_cpus.as_deref().ok_or("missing allowed-cpus")?;
    if allowance != "online" && !set.is_subset(&parse_cpuset(allowance)?) {
        return Err("cpuset is outside publisher allowance".into());
    }
    canonical_cpuset(request).map(Some)
}
pub fn resolve_idle(
    rule: Option<&CpuIdleRules>,
    request: Option<&IdleSelection>,
) -> Result<Option<CpuIdlePolicy>, String> {
    match rule {
        Some(rule) => rule.resolve(request),
        None if request.is_some() => Err("publisher did not allow operator cpu-idle tuning".into()),
        None => Ok(None),
    }
}
pub fn resolve_frequency(
    rule: Option<&CpuFrequencyRules>,
    request: Option<&FrequencySelection>,
) -> Result<Option<CpuFrequencyPolicy>, String> {
    match rule {
        Some(rule) => rule.resolve(request),
        None if request.is_some() => {
            Err("publisher did not allow operator cpu-frequency tuning".into())
        }
        None => Ok(None),
    }
}
pub fn request_digest(tls: &str, challenge: &str, body: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let body_hash = Sha256::digest(body);
    let mut h = Sha256::new();
    for part in [
        b"ATAKIT_RUNTIME_CPU_V1".as_slice(),
        tls.as_bytes(),
        challenge.as_bytes(),
        body_hash.as_slice(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

pub fn validate_rules<'a>(
    format: u32,
    idle: Option<&CpuIdleRules>,
    frequency: Option<&CpuFrequencyRules>,
    sets: impl Iterator<Item = &'a str>,
) -> Result<(), String> {
    crate::cpu::validate_cpu_policy(format, None, None, sets)?;
    if format < 16 && (idle.is_some() || frequency.is_some()) {
        return Err("CPU controls require format 16".into());
    }
    if let Some(p) = idle {
        p.validate()?;
    }
    if let Some(p) = frequency {
        p.validate()?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeCpuSelection {
    pub config: RuntimeCpuConfig,
    /// Display only; never used for authorization.
    pub sources: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn idle() -> CpuIdleRules {
        serde_json::from_value(serde_json::json!({"driver":"intel_idle","allow-operator":true,"required":false,"allowed-governors":["menu","teo"],"allowed-disabled-states":["*"]})).unwrap()
    }
    #[test]
    fn deny_by_default_fixed_always_wins_and_required_is_signed() {
        let request = IdleSelection {
            governor: Some("teo".into()),
            disabled_states: Some(vec!["C6".into()]),
        };
        assert!(resolve_idle(None, Some(&request)).is_err());
        let mut rule = idle();
        assert!(rule.resolve(None).unwrap().is_none());
        assert!(!rule.resolve(Some(&request)).unwrap().unwrap().required);
        rule.required = true;
        assert!(rule.resolve(None).is_err());
        assert!(rule.resolve(Some(&request)).unwrap().unwrap().required);
        rule.allow_operator = None;
        assert!(rule.resolve(Some(&request)).is_err());
        rule.allow_operator = Some(false);
        assert!(rule.resolve(None).unwrap().is_none());
        assert!(rule.resolve(Some(&request)).is_err());
        rule.governor = Some("menu".into());
        assert_eq!(
            rule.resolve(None).unwrap().unwrap().governor.as_deref(),
            Some("menu")
        );
        assert!(rule.resolve(Some(&request)).is_err());
    }
    #[test]
    fn allowance_limits_and_no_operator_requirements() {
        let mut rule = idle();
        let mut request = IdleSelection {
            governor: Some("ladder".into()),
            disabled_states: None,
        };
        assert!(rule.resolve(Some(&request)).is_err());
        request.governor = Some("teo".into());
        request.disabled_states = Some(vec!["C99".into()]);
        assert!(rule.resolve(Some(&request)).is_ok()); // runtime checks exposed subset
        rule.allowed_disabled_states = Some(vec!["C6".into()]);
        assert!(rule.resolve(Some(&request)).is_err());
        request.governor = None;
        assert!(rule.resolve(Some(&request)).is_err());
        for key in ["required", "allow-operator", "driver"] {
            let value = format!(r#"{{"cpu-idle":{{"{key}":false}}}}"#);
            assert!(serde_json::from_str::<RuntimeCpuConfig>(&value).is_err());
        }
    }
    #[test]
    fn cpu_placement_requires_explicit_signed_bounds() {
        assert!(resolve_cpuset(None, None, Some("0")).is_err());
        let rule: CpusetRules =
            serde_json::from_value(serde_json::json!({"allow-operator":true,"allowed-cpus":"0-3"}))
                .unwrap();
        assert!(rule.required);
        assert!(resolve_cpuset(None, Some(&rule), None).is_err());
        assert_eq!(
            resolve_cpuset(None, Some(&rule), Some("3,0-2"))
                .unwrap()
                .as_deref(),
            Some("0,1,2,3")
        );
        assert!(resolve_cpuset(None, Some(&rule), Some("4")).is_err());
        assert!(resolve_cpuset(Some("0"), Some(&rule), Some("1")).is_err());
        let invalid = CpusetRules {
            allow_operator: Some(true),
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn merge_is_per_field_and_empty_lists_override() {
        let mut a = RuntimeCpuConfig {
            cpu_idle: Some(IdleSelection {
                governor: Some("menu".into()),
                disabled_states: Some(vec!["C6".into()]),
            }),
            cpuset: Some("3,0-2".into()),
            ..Default::default()
        };
        let b = RuntimeCpuConfig {
            cpu_idle: Some(IdleSelection {
                governor: None,
                disabled_states: Some(vec![]),
            }),
            ..Default::default()
        };
        a.overlay(&b);
        a.normalize().unwrap();
        assert_eq!(
            a.cpu_idle.unwrap(),
            IdleSelection {
                governor: Some("menu".into()),
                disabled_states: Some(vec![])
            }
        );
        assert_eq!(a.cpuset.as_deref(), Some("0,1,2,3"));
    }
    #[test]
    fn signatures_bind_tls_nonce_and_body_including_check() {
        let original = request_digest("tls", "nonce", b"config");
        for (tls, nonce, body) in [
            ("other", "nonce", b"config".as_slice()),
            ("tls", "other", b"config"),
            ("tls", "nonce", b"changed"),
        ] {
            assert_ne!(original, request_digest(tls, nonce, body));
        }
    }
}
