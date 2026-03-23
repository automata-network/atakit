pub mod deploy;
pub mod destroy;
pub mod list;
pub mod serial;
pub mod ssh;
pub mod status;

use anyhow::{Result, bail};
use atakit_cloud::{CloudConfig, CloudTarget, PersistedAgentEnv};

use crate::config::PublishConfig;

/// Resolve agent env fields with precedence: CLI > target > [cloud] > [publish].
pub struct AgentEnvBuilder<'a> {
	pub cli_rpc_url: Option<&'a str>,
	pub cli_session_registry: Option<&'a str>,
	pub cli_owner_key: Option<&'a str>,
	pub cli_relay_key: Option<&'a str>,
	pub target: &'a CloudTarget,
	pub cloud: &'a CloudConfig,
	pub publish: &'a PublishConfig,
}

impl<'a> AgentEnvBuilder<'a> {
	pub fn rpc_url(&self) -> Option<String> {
		self.cli_rpc_url
			.map(String::from)
			.or_else(|| self.target.rpc_url.clone())
			.or_else(|| self.cloud.rpc_url.clone())
			.or_else(|| self.publish.rpc_url.clone())
	}

	pub fn session_registry(&self) -> Option<String> {
		self.cli_session_registry
			.map(String::from)
			.or_else(|| self.target.session_registry.clone())
			.or_else(|| self.cloud.session_registry.clone())
			.or_else(|| self.publish.session_registry.clone())
	}

	pub fn owner_key_file(&self) -> Option<String> {
		self.cli_owner_key
			.map(String::from)
			.or_else(|| self.target.owner_key_file.clone())
			.or_else(|| self.cloud.owner_key_file.clone())
			.or_else(|| self.publish.owner_key_file.clone())
	}

	pub fn relay_key_file(&self) -> Option<String> {
		self.cli_relay_key
			.map(String::from)
			.or_else(|| self.target.relay_key_file.clone())
			.or_else(|| self.cloud.relay_key_file.clone())
			.or_else(|| self.publish.relay_key_file.clone())
	}

	pub fn expire_offset(&self) -> Option<u64> {
		self.cloud.expire_offset
	}

	pub fn build(&self) -> PersistedAgentEnv {
		PersistedAgentEnv {
			rpc_url: self.rpc_url(),
			session_registry: self.session_registry(),
			owner_key_file: self.owner_key_file(),
			relay_key_file: self.relay_key_file(),
			expire_offset: self.expire_offset(),
		}
	}
}

/// Parse instance reference: "target/instance" or just "instance".
pub fn parse_instance_ref(s: &str) -> (Option<&str>, &str) {
	if let Some((target, instance)) = s.split_once('/') {
		(Some(target), instance)
	} else {
		(None, s)
	}
}

/// Resolve an instance reference to (target_name, instance_name) using the state store.
pub fn resolve_instance(
	data_dir: &std::path::Path,
	instance: &str,
	target_filter: Option<&str>,
) -> Result<(String, String)> {
	let (embedded_target, instance_name) = parse_instance_ref(instance);
	let target = target_filter.or(embedded_target);
	atakit_cloud::state::find_instance(data_dir, instance_name, target)
		.map_err(|e| anyhow::anyhow!("{e}"))
}

/// Parse metadata key=value strings into a map.
pub fn parse_metadata(items: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
	let mut map = std::collections::BTreeMap::new();
	for item in items {
		let (key, value) = item.split_once('=').ok_or_else(|| {
			anyhow::anyhow!("invalid metadata format: expected KEY=VALUE, got '{item}'")
		})?;
		if key.is_empty() {
			bail!("metadata key cannot be empty in '{item}'");
		}
		map.insert(key.to_string(), value.to_string());
	}
	Ok(map)
}
