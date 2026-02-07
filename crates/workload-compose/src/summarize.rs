use crate::types::*;

impl WorkloadCompose {
    /// Produce a flat, cross-service summary of the compose file.
    ///
    /// Extracts referenced files (env_file paths, bind-mount host paths),
    /// deduplicated named volumes, port mappings, and image classifications
    /// without applying any project-specific transforms.
    pub fn summarize(&self) -> ComposeSummary {
        let mut referenced_files = Vec::new();
        let mut named_volumes = Vec::new();
        let mut ports = Vec::new();
        let mut images = Vec::new();

        for (name, svc) in &self.services {
            // env_file paths
            for path in &svc.env_file {
                referenced_files.push(ReferencedFile {
                    service: name.clone(),
                    path: path.clone(),
                    kind: FileRefKind::EnvFile,
                });
            }

            // volumes
            for vol in &svc.volumes {
                match vol {
                    WorkloadVolumeMount::Bind {
                        host_path,
                        container_path,
                        read_only,
                    } => {
                        referenced_files.push(ReferencedFile {
                            service: name.clone(),
                            path: host_path.clone(),
                            kind: FileRefKind::BindMount {
                                container_path: container_path.clone(),
                                read_only: *read_only,
                            },
                        });
                    }
                    WorkloadVolumeMount::Named { name: vol_name, .. } => {
                        if !named_volumes.contains(vol_name) {
                            named_volumes.push(vol_name.clone());
                        }
                    }
                }
            }

            // ports
            for port in &svc.ports {
                ports.push(ServicePort {
                    service: name.clone(),
                    port: port.clone(),
                });
            }

            // image classification
            match (&svc.build, &svc.image) {
                (Some(_), Some(tag)) => images.push(ServiceImage {
                    service: name.clone(),
                    kind: ImageKind::Build { tag: tag.clone() },
                }),
                (Some(_), None) => images.push(ServiceImage {
                    service: name.clone(),
                    kind: ImageKind::BuildUntagged,
                }),
                (None, Some(tag)) => images.push(ServiceImage {
                    service: name.clone(),
                    kind: ImageKind::Pull { tag: tag.clone() },
                }),
                (None, None) => {} // utility service, skip
            }
        }

        ComposeSummary {
            referenced_files,
            named_volumes,
            ports,
            images,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::from_yaml_str;

    use super::*;

    #[test]
    fn summarize_basic() {
        let yaml = r#"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
  db:
    image: postgres:16
    volumes:
      - db-data:/var/lib/postgresql/data
volumes:
  db-data:
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let summary = compose.summarize();

        assert_eq!(summary.images.len(), 2);
        assert!(summary.images.iter().any(|i| i.service == "web"
            && matches!(&i.kind, ImageKind::Pull { tag } if tag == "nginx:latest")));
        assert!(summary.images.iter().any(|i| i.service == "db"
            && matches!(&i.kind, ImageKind::Pull { tag } if tag == "postgres:16")));

        assert_eq!(summary.ports.len(), 1);
        assert_eq!(summary.ports[0].service, "web");
        assert_eq!(summary.ports[0].port.host_port, Some(8080));
        assert_eq!(summary.ports[0].port.container_port, 80);

        assert_eq!(summary.named_volumes, vec!["db-data"]);
        assert!(summary.referenced_files.is_empty());
    }

    #[test]
    fn summarize_referenced_files() {
        let yaml = r#"
services:
  app:
    image: app:latest
    env_file:
      - .env
      - .env.local
    volumes:
      - ./config:/app/config:ro
      - app-data:/data
volumes:
  app-data:
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let summary = compose.summarize();

        assert_eq!(summary.referenced_files.len(), 3);

        let env_files: Vec<_> = summary
            .referenced_files
            .iter()
            .filter(|r| matches!(r.kind, FileRefKind::EnvFile))
            .collect();
        assert_eq!(env_files.len(), 2);
        assert_eq!(env_files[0].path, ".env");
        assert_eq!(env_files[1].path, ".env.local");

        let bind_mounts: Vec<_> = summary
            .referenced_files
            .iter()
            .filter(|r| matches!(r.kind, FileRefKind::BindMount { .. }))
            .collect();
        assert_eq!(bind_mounts.len(), 1);
        assert_eq!(bind_mounts[0].path, "./config");
        match &bind_mounts[0].kind {
            FileRefKind::BindMount {
                container_path,
                read_only,
            } => {
                assert_eq!(container_path, "/app/config");
                assert!(read_only);
            }
            _ => unreachable!(),
        }

        assert_eq!(summary.named_volumes, vec!["app-data"]);
    }

    #[test]
    fn summarize_image_classification() {
        let yaml = r#"
services:
  built-tagged:
    image: myapp:v1
    build: .
  built-untagged:
    build: ./svc
  pulled:
    image: redis:7
  utility:
    entrypoint: ["sleep", "infinity"]
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let summary = compose.summarize();

        assert_eq!(summary.images.len(), 3);

        let built_tagged = summary
            .images
            .iter()
            .find(|i| i.service == "built-tagged")
            .unwrap();
        assert!(matches!(&built_tagged.kind, ImageKind::Build { tag } if tag == "myapp:v1"));

        let built_untagged = summary
            .images
            .iter()
            .find(|i| i.service == "built-untagged")
            .unwrap();
        assert!(matches!(&built_untagged.kind, ImageKind::BuildUntagged));

        let pulled = summary
            .images
            .iter()
            .find(|i| i.service == "pulled")
            .unwrap();
        assert!(matches!(&pulled.kind, ImageKind::Pull { tag } if tag == "redis:7"));

        // utility service should be absent
        assert!(summary.images.iter().all(|i| i.service != "utility"));
    }

    #[test]
    fn summarize_deduplicates_named_volumes() {
        let yaml = r#"
services:
  a:
    image: a:latest
    volumes:
      - shared:/data
  b:
    image: b:latest
    volumes:
      - shared:/data
volumes:
  shared:
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let summary = compose.summarize();

        assert_eq!(summary.named_volumes, vec!["shared"]);
    }

    #[test]
    fn summarize_classifies_additional_data() {
        let yaml = r#"
services:
  app:
    image: app:latest
    env_file:
      - .env
      - additional-data/secrets.env
    volumes:
      - ./config:/app/config
      - ./additional-data/certs:/app/certs:ro
"#;
        let compose = from_yaml_str(yaml).unwrap();
        let summary = compose.summarize();

        assert_eq!(summary.referenced_files.len(), 4);

        let measured = summary.measured_files();
        assert_eq!(measured.len(), 2);
        assert!(measured.iter().any(|f| f.path == ".env"));
        assert!(measured.iter().any(|f| f.path == "./config"));

        let additional = summary.additional_data_files();
        assert_eq!(additional.len(), 2);
        assert!(additional.iter().any(|f| f.path == "additional-data/secrets.env"));
        assert!(additional.iter().any(|f| f.path == "./additional-data/certs"));
    }
}
