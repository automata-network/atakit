use anyhow::{Result, bail};
use compose_spec::service::build::Context;
use compose_spec::service::volumes::mount::Mount;
use compose_spec::service::volumes::{ShortVolume, Source};
use compose_spec::{Compose, Resource, Service, ShortOrLong};
use indexmap::IndexMap;

use crate::types::*;

pub fn convert(compose: &Compose) -> Result<WorkloadCompose> {
    let mut errors: Vec<String> = Vec::new();

    check_top_level(compose, &mut errors);

    let volumes = convert_top_level_volumes(compose, &mut errors);

    let mut services = IndexMap::new();
    for (name, service) in &compose.services {
        match convert_service(name.as_str(), service, &mut errors) {
            Some(s) => {
                services.insert(name.to_string(), s);
            }
            None => {}
        }
    }

    if !errors.is_empty() {
        let count = errors.len();
        let detail = errors
            .iter()
            .enumerate()
            .map(|(i, e)| format!("  {}. {}", i + 1, e))
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "Unsupported docker-compose features detected ({count} issue{}):\n{detail}",
            if count == 1 { "" } else { "s" }
        );
    }

    Ok(WorkloadCompose { services, volumes })
}

fn check_top_level(compose: &Compose, errors: &mut Vec<String>) {
    if !compose.networks.is_empty() {
        errors.push(
            "Unsupported: top-level 'networks' are not supported by workload-compose".into(),
        );
    }
    if !compose.configs.is_empty() {
        errors.push(
            "Unsupported: top-level 'configs' are not supported by workload-compose".into(),
        );
    }
    if !compose.secrets.is_empty() {
        errors.push(
            "Unsupported: top-level 'secrets' are not supported by workload-compose".into(),
        );
    }
    if !compose.include.is_empty() {
        errors.push(
            "Unsupported: top-level 'include' is not supported by workload-compose".into(),
        );
    }
}

fn convert_top_level_volumes(
    compose: &Compose,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let mut volumes = Vec::new();
    for (name, resource) in &compose.volumes {
        match resource {
            Some(Resource::External { .. }) => {
                errors.push(format!(
                    "Unsupported: top-level volume '{name}' uses 'external' which is not supported by workload-compose"
                ));
                continue;
            }
            Some(Resource::Compose(vol)) => {
                if vol.driver.is_some() {
                    errors.push(format!(
                        "Unsupported: top-level volume '{name}' uses 'driver' which is not supported by workload-compose"
                    ));
                    continue;
                }
                if !vol.driver_opts.is_empty() {
                    errors.push(format!(
                        "Unsupported: top-level volume '{name}' uses 'driver_opts' which is not supported by workload-compose"
                    ));
                    continue;
                }
            }
            None => {
                // Simple declaration with no config — allowed
            }
        }
        volumes.push(name.to_string());
    }
    volumes
}

fn convert_service(
    name: &str,
    service: &Service,
    errors: &mut Vec<String>,
) -> Option<WorkloadService> {
    check_unsupported_service_fields(name, service, errors);

    let image = service.image.as_ref().map(|i| i.to_string());
    let build = convert_build(name, &service.build, errors);
    let command = service.command.as_ref().map(convert_command);
    let entrypoint = service.entrypoint.as_ref().map(convert_command);
    let environment = convert_environment(&service.environment);
    let env_file = convert_env_file(&service.env_file);
    let ports = convert_ports(name, &service.ports, errors);
    let volumes = convert_service_volumes(name, &service.volumes, errors);
    let restart = service.restart.as_ref().map(convert_restart);
    let depends_on = convert_depends_on(&service.depends_on);

    Some(WorkloadService {
        image,
        build,
        command,
        entrypoint,
        environment,
        env_file,
        ports,
        volumes,
        restart,
        depends_on,
    })
}

fn check_unsupported_service_fields(
    name: &str,
    service: &Service,
    errors: &mut Vec<String>,
) {
    macro_rules! reject_bool {
        ($field:ident) => {
            if service.$field {
                errors.push(format!(
                    "Unsupported: service '{}' uses '{}' which is not supported by workload-compose",
                    name,
                    stringify!($field)
                ));
            }
        };
    }

    macro_rules! reject_option {
        ($field:ident) => {
            if service.$field.is_some() {
                errors.push(format!(
                    "Unsupported: service '{}' uses '{}' which is not supported by workload-compose",
                    name,
                    stringify!($field)
                ));
            }
        };
    }

    macro_rules! reject_option_display {
        ($field:ident, $display:expr) => {
            if service.$field.is_some() {
                errors.push(format!(
                    "Unsupported: service '{}' uses '{}' which is not supported by workload-compose",
                    name, $display
                ));
            }
        };
    }

    macro_rules! reject_not_empty {
        ($field:ident) => {
            if !service.$field.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{}' uses '{}' which is not supported by workload-compose",
                    name,
                    stringify!($field)
                ));
            }
        };
    }

    // container identity
    reject_option!(container_name);

    // process & execution
    reject_option!(user);
    reject_option!(working_dir);
    reject_bool!(init);
    reject_bool!(stdin_open);
    reject_bool!(tty);

    // labels & annotations
    if !service.labels.is_empty() {
        errors.push(format!(
            "Unsupported: service '{name}' uses 'labels' which is not supported by workload-compose"
        ));
    }
    if !service.annotations.is_empty() {
        errors.push(format!(
            "Unsupported: service '{name}' uses 'annotations' which is not supported by workload-compose"
        ));
    }

    // networking
    reject_option_display!(network_config, "network_config");
    reject_option!(hostname);
    reject_option!(domain_name);
    reject_option!(dns);
    reject_not_empty!(dns_opt);
    reject_option!(dns_search);
    reject_option!(mac_address);
    reject_not_empty!(links);
    reject_not_empty!(external_links);
    reject_not_empty!(extra_hosts);
    reject_not_empty!(expose);

    // storage extras
    reject_not_empty!(volumes_from);
    reject_option!(tmpfs);

    // CPU & memory
    reject_option!(cpu_count);
    reject_option!(cpu_percent);
    reject_option!(cpu_shares);
    reject_option!(cpu_period);
    reject_option!(cpu_quota);
    reject_option!(cpu_rt_runtime);
    reject_option!(cpu_rt_period);
    reject_option!(cpus);
    reject_not_empty!(cpuset);
    reject_option!(mem_limit);
    reject_option!(mem_reservation);
    reject_option!(mem_swappiness);
    reject_option!(memswap_limit);
    reject_option!(pids_limit);

    // security & isolation
    reject_bool!(privileged);
    reject_not_empty!(cap_add);
    reject_not_empty!(cap_drop);
    reject_not_empty!(security_opt);
    reject_bool!(read_only);
    reject_option!(ipc);
    reject_option!(pid);
    reject_option!(uts);
    reject_option!(cgroup);
    reject_option!(cgroup_parent);
    reject_option!(userns_mode);
    reject_option!(credential_spec);

    // health & lifecycle
    reject_option!(healthcheck);
    reject_option!(stop_grace_period);
    reject_option!(stop_signal);
    reject_bool!(oom_kill_disable);
    reject_option!(oom_score_adj);

    // deployment & platform
    reject_option!(platform);
    reject_option!(pull_policy);
    reject_option!(deploy);
    reject_option!(develop);
    reject_option!(extends);
    reject_option!(scale);
    reject_option!(runtime);
    reject_not_empty!(profiles);
    if !service.attach {
        // attach defaults to true, so only flag if explicitly set to false
        // Actually, we can't distinguish default from explicit. Skip this check.
    }

    // device & resource management
    reject_not_empty!(devices);
    reject_not_empty!(device_cgroup_rules);
    if !service.ulimits.is_empty() {
        errors.push(format!(
            "Unsupported: service '{name}' uses 'ulimits' which is not supported by workload-compose"
        ));
    }
    reject_option!(blkio_config);
    reject_option!(shm_size);
    if !service.storage_opt.is_empty() {
        errors.push(format!(
            "Unsupported: service '{name}' uses 'storage_opt' which is not supported by workload-compose"
        ));
    }
    if !service.sysctls.is_empty() {
        errors.push(format!(
            "Unsupported: service '{name}' uses 'sysctls' which is not supported by workload-compose"
        ));
    }
    reject_option!(isolation);

    // configs & secrets
    reject_not_empty!(configs);
    reject_not_empty!(secrets);
    reject_not_empty!(group_add);

    // logging
    reject_option!(logging);
}

fn convert_build(
    name: &str,
    build: &Option<ShortOrLong<Context, compose_spec::service::build::Build>>,
    errors: &mut Vec<String>,
) -> Option<WorkloadBuild> {
    let build = build.as_ref()?;

    match build {
        ShortOrLong::Short(context) => Some(WorkloadBuild {
            context: context.to_string(),
            dockerfile: None,
            args: Vec::new(),
        }),
        ShortOrLong::Long(b) => {
            // Check unsupported build fields
            if !b.ssh.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'ssh' which is not supported by workload-compose"
                ));
            }
            if !b.cache_from.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'cache_from' which is not supported by workload-compose"
                ));
            }
            if !b.cache_to.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'cache_to' which is not supported by workload-compose"
                ));
            }
            if !b.additional_contexts.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'additional_contexts' which is not supported by workload-compose"
                ));
            }
            if !b.entitlements.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'entitlements' which is not supported by workload-compose"
                ));
            }
            if !b.extra_hosts.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'extra_hosts' which is not supported by workload-compose"
                ));
            }
            if b.isolation.is_some() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'isolation' which is not supported by workload-compose"
                ));
            }
            if b.privileged {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'privileged' which is not supported by workload-compose"
                ));
            }
            if !b.labels.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'labels' which is not supported by workload-compose"
                ));
            }
            if b.no_cache {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'no_cache' which is not supported by workload-compose"
                ));
            }
            if b.pull {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'pull' which is not supported by workload-compose"
                ));
            }
            if b.network.is_some() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'network' which is not supported by workload-compose"
                ));
            }
            if b.shm_size.is_some() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'shm_size' which is not supported by workload-compose"
                ));
            }
            if b.target.is_some() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'target' which is not supported by workload-compose"
                ));
            }
            if !b.secrets.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'secrets' which is not supported by workload-compose"
                ));
            }
            if !b.tags.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'tags' which is not supported by workload-compose"
                ));
            }
            if !b.ulimits.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'ulimits' which is not supported by workload-compose"
                ));
            }
            if !b.platforms.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' build uses 'platforms' which is not supported by workload-compose"
                ));
            }

            let context = b
                .context
                .as_ref()
                .map(|c| c.to_string())
                .unwrap_or_else(|| ".".into());
            let dockerfile = b.dockerfile.as_ref().map(|d| match d {
                compose_spec::service::build::Dockerfile::File(path) => {
                    path.to_string_lossy().to_string()
                }
                compose_spec::service::build::Dockerfile::Inline(s) => s.clone(),
            });
            let args = convert_list_or_map(&b.args);

            Some(WorkloadBuild {
                context,
                dockerfile,
                args,
            })
        }
    }
}

fn convert_command(command: &compose_spec::service::Command) -> WorkloadCommand {
    match command {
        compose_spec::service::Command::String(s) => WorkloadCommand::Shell(s.clone()),
        compose_spec::service::Command::List(v) => WorkloadCommand::Exec(v.clone()),
    }
}

fn convert_environment(env: &compose_spec::ListOrMap) -> Vec<EnvVar> {
    convert_list_or_map(env)
}

fn convert_list_or_map(list_or_map: &compose_spec::ListOrMap) -> Vec<EnvVar> {
    match list_or_map {
        compose_spec::ListOrMap::List(list) => list
            .iter()
            .map(|entry| {
                if let Some((k, v)) = entry.split_once('=') {
                    EnvVar {
                        key: k.to_string(),
                        value: Some(v.to_string()),
                    }
                } else {
                    EnvVar {
                        key: entry.clone(),
                        value: None,
                    }
                }
            })
            .collect(),
        compose_spec::ListOrMap::Map(map) => map
            .iter()
            .map(|(k, v)| EnvVar {
                key: k.to_string(),
                value: v.as_ref().map(|v| v.to_string()),
            })
            .collect(),
    }
}

fn convert_env_file(env_file: &Option<compose_spec::service::EnvFile>) -> Vec<String> {
    match env_file {
        None => Vec::new(),
        Some(compose_spec::service::EnvFile::Single(path)) => {
            vec![path.to_string_lossy().to_string()]
        }
        Some(compose_spec::service::EnvFile::List(list)) => list
            .iter()
            .map(|entry| match entry {
                ShortOrLong::Short(path) => path.to_string_lossy().to_string(),
                ShortOrLong::Long(config) => config.path.to_string_lossy().to_string(),
            })
            .collect(),
    }
}

fn convert_ports(
    name: &str,
    ports: &compose_spec::service::Ports,
    errors: &mut Vec<String>,
) -> Vec<WorkloadPort> {
    let mut result = Vec::new();

    for port_entry in ports {
        match port_entry {
            ShortOrLong::Short(short) => {
                let container_range = short.ranges.container();
                if container_range.size() > 1 {
                    errors.push(format!(
                        "Unsupported: service '{name}' uses port ranges which are not supported by workload-compose"
                    ));
                    continue;
                }

                let host_port = short.ranges.host().map(|r| {
                    if r.size() > 1 {
                        errors.push(format!(
                            "Unsupported: service '{name}' uses host port ranges which are not supported by workload-compose"
                        ));
                    }
                    r.start()
                });

                let protocol = short
                    .protocol
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "tcp".into());

                result.push(WorkloadPort {
                    host_ip: short.host_ip.map(|ip| ip.to_string()),
                    host_port,
                    container_port: container_range.start(),
                    protocol,
                });
            }
            ShortOrLong::Long(port) => {
                if let Some(ref published) = port.published {
                    if published.size() > 1 {
                        errors.push(format!(
                            "Unsupported: service '{name}' uses port ranges which are not supported by workload-compose"
                        ));
                        continue;
                    }
                }

                let protocol = port
                    .protocol
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "tcp".into());

                result.push(WorkloadPort {
                    host_ip: port.host_ip.map(|ip| ip.to_string()),
                    host_port: port.published.as_ref().map(|r| r.start()),
                    container_port: port.target,
                    protocol,
                });
            }
        }
    }

    result
}

fn convert_service_volumes(
    name: &str,
    volumes: &compose_spec::service::Volumes,
    errors: &mut Vec<String>,
) -> Vec<WorkloadVolumeMount> {
    let mut result = Vec::new();

    for volume_entry in volumes {
        match volume_entry {
            ShortOrLong::Short(short) => {
                result.extend(convert_short_volume(name, short, errors));
            }
            ShortOrLong::Long(mount) => {
                result.extend(convert_mount(name, mount, errors));
            }
        }
    }

    result
}

fn convert_short_volume(
    name: &str,
    short: &ShortVolume,
    errors: &mut Vec<String>,
) -> Option<WorkloadVolumeMount> {
    let container_path = short.container_path.as_path().to_string_lossy().to_string();

    match &short.options {
        None => {
            // Anonymous volume — not supported since they need a name.
            errors.push(format!(
                "Unsupported: service '{name}' uses an anonymous volume which is not supported by workload-compose"
            ));
            None
        }
        Some(opts) => {
            let read_only = opts.read_only;
            match &opts.source {
                Source::Volume(identifier) => Some(WorkloadVolumeMount::Named {
                    name: identifier.to_string(),
                    container_path,
                    read_only,
                }),
                Source::HostPath(host_path) => Some(WorkloadVolumeMount::Bind {
                    host_path: host_path.as_path().to_string_lossy().to_string(),
                    container_path,
                    read_only,
                }),
            }
        }
    }
}

fn convert_mount(
    name: &str,
    mount: &Mount,
    errors: &mut Vec<String>,
) -> Option<WorkloadVolumeMount> {
    match mount {
        Mount::Volume(vol) => {
            let vol_name = vol
                .source
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default();
            if vol_name.is_empty() {
                errors.push(format!(
                    "Unsupported: service '{name}' uses an anonymous volume which is not supported by workload-compose"
                ));
                return None;
            }
            Some(WorkloadVolumeMount::Named {
                name: vol_name,
                container_path: vol.common.target.as_path().to_string_lossy().to_string(),
                read_only: vol.common.read_only,
            })
        }
        Mount::Bind(bind) => Some(WorkloadVolumeMount::Bind {
            host_path: bind.source.as_path().to_string_lossy().to_string(),
            container_path: bind.common.target.as_path().to_string_lossy().to_string(),
            read_only: bind.common.read_only,
        }),
        Mount::Tmpfs(_) => {
            errors.push(format!(
                "Unsupported: service '{name}' uses tmpfs volume mount which is not supported by workload-compose"
            ));
            None
        }
        Mount::NamedPipe(_) => {
            errors.push(format!(
                "Unsupported: service '{name}' uses named pipe volume mount which is not supported by workload-compose"
            ));
            None
        }
        Mount::Cluster(_) => {
            errors.push(format!(
                "Unsupported: service '{name}' uses cluster volume mount which is not supported by workload-compose"
            ));
            None
        }
    }
}

fn convert_restart(restart: &compose_spec::service::Restart) -> WorkloadRestart {
    match restart {
        compose_spec::service::Restart::No => WorkloadRestart::No,
        compose_spec::service::Restart::Always => WorkloadRestart::Always,
        compose_spec::service::Restart::OnFailure => WorkloadRestart::OnFailure,
        compose_spec::service::Restart::UnlessStopped => WorkloadRestart::UnlessStopped,
    }
}

fn convert_depends_on(
    depends_on: &compose_spec::service::DependsOn,
) -> IndexMap<String, WorkloadDependency> {
    let mut result = IndexMap::new();

    match depends_on {
        ShortOrLong::Short(set) => {
            for name in set {
                result.insert(
                    name.to_string(),
                    WorkloadDependency { condition: None },
                );
            }
        }
        ShortOrLong::Long(map) => {
            for (name, dep) in map {
                result.insert(
                    name.to_string(),
                    WorkloadDependency {
                        condition: Some(format!("{:?}", dep.condition)),
                    },
                );
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_convert(yaml: &str) -> Result<WorkloadCompose> {
        let compose = Compose::options()
            .apply_merge(true)
            .from_yaml_str(yaml)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        convert(&compose)
    }

    #[test]
    fn test_basic_service() {
        let yaml = r#"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    restart: always
"#;
        let wc = parse_and_convert(yaml).unwrap();
        assert_eq!(wc.services.len(), 1);
        let web = &wc.services["web"];
        assert_eq!(web.image.as_deref(), Some("nginx:latest"));
        assert_eq!(web.ports.len(), 1);
        assert_eq!(web.ports[0].host_port, Some(8080));
        assert_eq!(web.ports[0].container_port, 80);
        assert_eq!(web.ports[0].protocol, "tcp");
        assert_eq!(web.restart, Some(WorkloadRestart::Always));
    }

    #[test]
    fn test_secure_signer_example() {
        let yaml = r#"
services:
  secure-signer:
    image: secure-signer:latest
    build:
      context: ..
      dockerfile: container/Dockerfile
    ports:
      - "3000:3000"
    restart: unless-stopped
    volumes:
      - secure-signer-data:/data
      - secure-signer-data2:/data2
volumes:
  secure-signer-data:
  secure-signer-data2:
"#;
        let wc = parse_and_convert(yaml).unwrap();
        assert_eq!(wc.services.len(), 1);
        assert_eq!(wc.volumes.len(), 2);
        assert!(wc.volumes.contains(&"secure-signer-data".to_string()));
        assert!(wc.volumes.contains(&"secure-signer-data2".to_string()));

        let svc = &wc.services["secure-signer"];
        assert_eq!(svc.image.as_deref(), Some("secure-signer:latest"));

        let build = svc.build.as_ref().unwrap();
        assert_eq!(build.context, "..");
        assert_eq!(build.dockerfile.as_deref(), Some("container/Dockerfile"));

        assert_eq!(svc.ports.len(), 1);
        assert_eq!(svc.ports[0].host_port, Some(3000));
        assert_eq!(svc.ports[0].container_port, 3000);

        assert_eq!(svc.restart, Some(WorkloadRestart::UnlessStopped));

        assert_eq!(svc.volumes.len(), 2);
        match &svc.volumes[0] {
            WorkloadVolumeMount::Named {
                name,
                container_path,
                read_only,
            } => {
                assert_eq!(name, "secure-signer-data");
                assert_eq!(container_path, "/data");
                assert!(!read_only);
            }
            _ => panic!("Expected Named volume"),
        }
    }

    #[test]
    fn test_bind_mount() {
        let yaml = r#"
services:
  app:
    image: app:latest
    volumes:
      - ./config:/app/config
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        assert_eq!(svc.volumes.len(), 1);
        match &svc.volumes[0] {
            WorkloadVolumeMount::Bind {
                host_path,
                container_path,
                read_only,
            } => {
                assert_eq!(host_path, "./config");
                assert_eq!(container_path, "/app/config");
                assert!(!read_only);
            }
            _ => panic!("Expected Bind volume"),
        }
    }

    #[test]
    fn test_environment_vars() {
        let yaml = r#"
services:
  app:
    image: app:latest
    environment:
      - FOO=bar
      - BAZ
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        assert_eq!(svc.environment.len(), 2);
        assert_eq!(svc.environment[0].key, "FOO");
        assert_eq!(svc.environment[0].value.as_deref(), Some("bar"));
        assert_eq!(svc.environment[1].key, "BAZ");
        assert_eq!(svc.environment[1].value, None);
    }

    #[test]
    fn test_environment_map_form() {
        let yaml = r#"
services:
  app:
    image: app:latest
    environment:
      FOO: bar
      BAZ: "123"
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        assert_eq!(svc.environment.len(), 2);
    }

    #[test]
    fn test_depends_on_short() {
        let yaml = r#"
services:
  web:
    image: web:latest
    depends_on:
      - db
      - redis
  db:
    image: postgres:latest
  redis:
    image: redis:latest
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let web = &wc.services["web"];
        assert_eq!(web.depends_on.len(), 2);
        assert!(web.depends_on.contains_key("db"));
        assert!(web.depends_on.contains_key("redis"));
        assert!(web.depends_on["db"].condition.is_none());
    }

    #[test]
    fn test_rejects_unsupported_features() {
        let yaml = r#"
services:
  web:
    image: nginx:latest
    privileged: true
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3
networks:
  frontend:
"#;
        let err = parse_and_convert(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("privileged"), "Should mention privileged: {msg}");
        assert!(
            msg.contains("healthcheck"),
            "Should mention healthcheck: {msg}"
        );
        assert!(msg.contains("networks"), "Should mention networks: {msg}");
        assert!(msg.contains("3 issue"), "Should report 3 issues: {msg}");
    }

    #[test]
    fn test_rejects_external_volume() {
        let yaml = r#"
services:
  app:
    image: app:latest
volumes:
  data:
    external: true
"#;
        let err = parse_and_convert(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("external"), "Should mention external: {msg}");
    }

    #[test]
    fn test_command_shell_form() {
        let yaml = r#"
services:
  app:
    image: app:latest
    command: "echo hello world"
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        match svc.command.as_ref().unwrap() {
            WorkloadCommand::Shell(s) => assert_eq!(s, "echo hello world"),
            _ => panic!("Expected Shell command"),
        }
    }

    #[test]
    fn test_command_exec_form() {
        let yaml = r#"
services:
  app:
    image: app:latest
    command: ["echo", "hello", "world"]
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        match svc.command.as_ref().unwrap() {
            WorkloadCommand::Exec(v) => {
                assert_eq!(v, &["echo", "hello", "world"]);
            }
            _ => panic!("Expected Exec command"),
        }
    }

    #[test]
    fn test_env_file() {
        let yaml = r#"
services:
  app:
    image: app:latest
    env_file:
      - .env
      - .env.local
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        assert_eq!(svc.env_file, vec![".env", ".env.local"]);
    }

    #[test]
    fn test_build_short_syntax() {
        let yaml = r#"
services:
  app:
    build: ./app
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        let build = svc.build.as_ref().unwrap();
        assert_eq!(build.context, "./app");
        assert!(build.dockerfile.is_none());
        assert!(build.args.is_empty());
    }

    #[test]
    fn test_build_with_args() {
        let yaml = r#"
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.dev
      args:
        - VARIANT=alpine
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        let build = svc.build.as_ref().unwrap();
        assert_eq!(build.context, ".");
        assert_eq!(build.dockerfile.as_deref(), Some("Dockerfile.dev"));
        assert_eq!(build.args.len(), 1);
        assert_eq!(build.args[0].key, "VARIANT");
        assert_eq!(build.args[0].value.as_deref(), Some("alpine"));
    }

    #[test]
    fn test_multiple_errors_collected() {
        let yaml = r#"
services:
  web:
    image: nginx:latest
    privileged: true
    read_only: true
    cap_add:
      - NET_ADMIN
secrets:
  my_secret:
    file: ./secret.txt
"#;
        let err = parse_and_convert(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("privileged"));
        assert!(msg.contains("read_only"));
        assert!(msg.contains("cap_add"));
        assert!(msg.contains("secrets"));
        assert!(msg.contains("4 issues"));
    }

    #[test]
    fn test_port_without_host() {
        let yaml = r#"
services:
  app:
    image: app:latest
    ports:
      - "80"
"#;
        let wc = parse_and_convert(yaml).unwrap();
        let svc = &wc.services["app"];
        assert_eq!(svc.ports.len(), 1);
        assert_eq!(svc.ports[0].container_port, 80);
        assert_eq!(svc.ports[0].host_port, None);
    }
}
