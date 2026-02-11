//! YAML serialization for WorkloadCompose types.
//!
//! Generates normalized docker-compose YAML directly from WorkloadCompose,
//! providing type safety without round-trip serde structs.

use indexmap::IndexMap;
use serde::Serialize;

use crate::types::{
    EnvVar, WorkloadCommand, WorkloadCompose, WorkloadPort, WorkloadRestart, WorkloadService,
    WorkloadVolumeMount,
};

/// Serialize a WorkloadCompose to YAML string.
pub fn to_yaml(compose: &WorkloadCompose) -> anyhow::Result<String> {
    // Create a serializable representation
    let output = SerializableCompose::from_compose(compose);
    serde_yaml::to_string(&output).map_err(|e| anyhow::anyhow!("Failed to serialize compose: {e}"))
}

/// Generate an isolated docker-compose YAML for a single service.
///
/// The output is normalized:
/// - `build` is removed (images are pre-built)
/// - `image` is resolved to fully qualified form
/// - `depends_on` is excluded (references services not in isolated compose)
pub fn service_to_yaml(
    service_name: &str,
    service: &WorkloadService,
    needed_volumes: &[String],
) -> anyhow::Result<String> {
    let mut services = IndexMap::new();
    services.insert(
        service_name.to_string(),
        SerializableService::from_service(service),
    );

    // Only include volumes that are actually used by this service
    let volumes: IndexMap<String, serde_yaml::Value> = needed_volumes
        .iter()
        .map(|v| (v.clone(), serde_yaml::Value::Null))
        .collect();

    let output = SerializableCompose {
        services,
        volumes: if volumes.is_empty() {
            None
        } else {
            Some(volumes)
        },
    };

    serde_yaml::to_string(&output)
        .map_err(|e| anyhow::anyhow!("Failed to serialize service compose: {e}"))
}

/// Resolve short Docker image names to fully qualified form.
///
/// - `nginx` -> `docker.io/library/nginx`
/// - `user/image` -> `docker.io/user/image`
/// - `ghcr.io/user/image` -> unchanged
pub fn resolve_image_short_name(image: &str) -> String {
    if image.is_empty() {
        return image.to_string();
    }

    match image.find('/') {
        None => {
            // No `/` -- official library image (e.g. `nginx`, `nginx:latest`).
            format!("docker.io/library/{}", image)
        }
        Some(slash_pos) => {
            let first = &image[..slash_pos];
            if first.contains('.') || first.contains(':') || first == "localhost" {
                // First component looks like a registry hostname.
                image.to_string()
            } else {
                // Namespace without registry (e.g. `user/image:tag`).
                format!("docker.io/{}", image)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal serializable types for YAML output
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SerializableCompose {
    services: IndexMap<String, SerializableService>,
    #[serde(skip_serializing_if = "Option::is_none")]
    volumes: Option<IndexMap<String, serde_yaml::Value>>,
}

impl SerializableCompose {
    fn from_compose(compose: &WorkloadCompose) -> Self {
        let services = compose
            .services
            .iter()
            .map(|(name, svc)| (name.clone(), SerializableService::from_service(svc)))
            .collect();

        let volumes: IndexMap<String, serde_yaml::Value> = compose
            .volumes
            .iter()
            .map(|v| (v.clone(), serde_yaml::Value::Null))
            .collect();

        Self {
            services,
            volumes: if volumes.is_empty() {
                None
            } else {
                Some(volumes)
            },
        }
    }
}

#[derive(Serialize)]
struct SerializableService {
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<SerializableCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entrypoint: Option<SerializableCommand>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    environment: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    env_file: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    volumes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart: Option<String>,
}

impl SerializableService {
    fn from_service(svc: &WorkloadService) -> Self {
        // Resolve image to fully qualified form
        let image = svc.image.as_ref().map(|i| resolve_image_short_name(i));

        // Convert command
        let command = svc.command.as_ref().map(SerializableCommand::from_command);
        let entrypoint = svc
            .entrypoint
            .as_ref()
            .map(SerializableCommand::from_command);

        // Convert environment to list of KEY=value strings
        let environment = svc
            .environment
            .iter()
            .map(|e| env_var_to_string(e))
            .collect();

        // Convert ports to strings
        let ports = svc.ports.iter().map(port_to_string).collect();

        // Convert volumes to strings
        let volumes = svc.volumes.iter().map(volume_mount_to_string).collect();

        // Convert restart policy
        let restart = svc.restart.as_ref().map(restart_to_string);

        Self {
            image,
            command,
            entrypoint,
            environment,
            env_file: svc.env_file.clone(),
            ports,
            volumes,
            restart,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum SerializableCommand {
    Shell(String),
    Exec(Vec<String>),
}

impl SerializableCommand {
    fn from_command(cmd: &WorkloadCommand) -> Self {
        match cmd {
            WorkloadCommand::Shell(s) => Self::Shell(s.clone()),
            WorkloadCommand::Exec(v) => Self::Exec(v.clone()),
        }
    }
}

fn env_var_to_string(env: &EnvVar) -> String {
    match &env.value {
        Some(v) => format!("{}={}", env.key, v),
        None => env.key.clone(),
    }
}

fn port_to_string(port: &WorkloadPort) -> String {
    let mut result = String::new();

    if let Some(ref ip) = port.host_ip {
        result.push_str(ip);
        result.push(':');
    }

    if let Some(hp) = port.host_port {
        result.push_str(&hp.to_string());
        result.push(':');
    }

    result.push_str(&port.container_port.to_string());

    if port.protocol != "tcp" {
        result.push('/');
        result.push_str(&port.protocol);
    }

    result
}

fn volume_mount_to_string(vol: &WorkloadVolumeMount) -> String {
    match vol {
        WorkloadVolumeMount::Named {
            name,
            container_path,
            read_only,
        } => {
            if *read_only {
                format!("{}:{}:ro", name, container_path)
            } else {
                format!("{}:{}", name, container_path)
            }
        }
        WorkloadVolumeMount::Bind {
            host_path,
            container_path,
            read_only,
        } => {
            if *read_only {
                format!("{}:{}:ro", host_path, container_path)
            } else {
                format!("{}:{}", host_path, container_path)
            }
        }
    }
}

fn restart_to_string(restart: &WorkloadRestart) -> String {
    match restart {
        WorkloadRestart::No => "no".to_string(),
        WorkloadRestart::Always => "always".to_string(),
        WorkloadRestart::OnFailure => "on-failure".to_string(),
        WorkloadRestart::UnlessStopped => "unless-stopped".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::from_yaml_str;

    #[test]
    fn test_resolve_image_short_name() {
        assert_eq!(
            resolve_image_short_name("nginx"),
            "docker.io/library/nginx"
        );
        assert_eq!(
            resolve_image_short_name("nginx:latest"),
            "docker.io/library/nginx:latest"
        );
        assert_eq!(
            resolve_image_short_name("user/image"),
            "docker.io/user/image"
        );
        assert_eq!(
            resolve_image_short_name("user/image:tag"),
            "docker.io/user/image:tag"
        );
        assert_eq!(
            resolve_image_short_name("ghcr.io/user/image"),
            "ghcr.io/user/image"
        );
        assert_eq!(
            resolve_image_short_name("localhost/myimage"),
            "localhost/myimage"
        );
        assert_eq!(
            resolve_image_short_name("registry:5000/image"),
            "registry:5000/image"
        );
        assert_eq!(resolve_image_short_name(""), "");
    }

    #[test]
    fn test_to_yaml_basic() {
        let yaml = r#"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    restart: always
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let output = to_yaml(&compose).unwrap();

        assert!(output.contains("services:"));
        assert!(output.contains("web:"));
        assert!(output.contains("docker.io/library/nginx:latest"));
        assert!(output.contains("8080:80"));
        assert!(output.contains("restart: always"));
    }

    #[test]
    fn test_to_yaml_with_volumes() {
        let yaml = r#"
services:
  app:
    image: app:latest
    volumes:
      - ./config:/app/config:ro
      - app-data:/data
volumes:
  app-data:
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let output = to_yaml(&compose).unwrap();

        assert!(output.contains("./config:/app/config:ro"));
        assert!(output.contains("app-data:/data"));
        assert!(output.contains("volumes:"));
        assert!(output.contains("app-data:"));
    }

    #[test]
    fn test_to_yaml_excludes_build() {
        let yaml = r#"
services:
  app:
    image: myapp:v1
    build: .
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let output = to_yaml(&compose).unwrap();

        // build should be excluded
        assert!(!output.contains("build:"));
        // image should be present and resolved
        assert!(output.contains("docker.io/library/myapp:v1"));
    }

    #[test]
    fn test_to_yaml_excludes_depends_on() {
        let yaml = r#"
services:
  web:
    image: web:latest
    depends_on:
      - db
  db:
    image: postgres:latest
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let output = to_yaml(&compose).unwrap();

        // depends_on should be excluded
        assert!(!output.contains("depends_on:"));
    }

    #[test]
    fn test_service_to_yaml() {
        let yaml = r#"
services:
  app:
    image: app:latest
    volumes:
      - app-data:/data
volumes:
  app-data:
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let service = compose.services.get("app").unwrap();

        let output = service_to_yaml("app", service, &["app-data".to_string()]).unwrap();

        assert!(output.contains("services:"));
        assert!(output.contains("app:"));
        assert!(output.contains("volumes:"));
        assert!(output.contains("app-data:"));
    }

    #[test]
    fn test_port_to_string() {
        // Basic port mapping
        let port = WorkloadPort {
            host_ip: None,
            host_port: Some(8080),
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        assert_eq!(port_to_string(&port), "8080:80");

        // With UDP protocol
        let port = WorkloadPort {
            host_ip: None,
            host_port: Some(53),
            container_port: 53,
            protocol: "udp".to_string(),
        };
        assert_eq!(port_to_string(&port), "53:53/udp");

        // With host IP
        let port = WorkloadPort {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: Some(8080),
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        assert_eq!(port_to_string(&port), "127.0.0.1:8080:80");

        // Container port only
        let port = WorkloadPort {
            host_ip: None,
            host_port: None,
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        assert_eq!(port_to_string(&port), "80");
    }

    #[test]
    fn test_volume_mount_to_string() {
        // Named volume
        let vol = WorkloadVolumeMount::Named {
            name: "data".to_string(),
            container_path: "/data".to_string(),
            read_only: false,
        };
        assert_eq!(volume_mount_to_string(&vol), "data:/data");

        // Named volume read-only
        let vol = WorkloadVolumeMount::Named {
            name: "config".to_string(),
            container_path: "/config".to_string(),
            read_only: true,
        };
        assert_eq!(volume_mount_to_string(&vol), "config:/config:ro");

        // Bind mount
        let vol = WorkloadVolumeMount::Bind {
            host_path: "./src".to_string(),
            container_path: "/app/src".to_string(),
            read_only: false,
        };
        assert_eq!(volume_mount_to_string(&vol), "./src:/app/src");

        // Bind mount read-only
        let vol = WorkloadVolumeMount::Bind {
            host_path: "./config".to_string(),
            container_path: "/app/config".to_string(),
            read_only: true,
        };
        assert_eq!(volume_mount_to_string(&vol), "./config:/app/config:ro");
    }

    #[test]
    fn test_env_var_to_string() {
        let env = EnvVar {
            key: "FOO".to_string(),
            value: Some("bar".to_string()),
        };
        assert_eq!(env_var_to_string(&env), "FOO=bar");

        let env = EnvVar {
            key: "BAZ".to_string(),
            value: None,
        };
        assert_eq!(env_var_to_string(&env), "BAZ");
    }
}
