use indexmap::IndexMap;

/// A normalized representation of a Docker Compose file,
/// containing only the features supported by workload-compose.
#[derive(Debug, Clone)]
pub struct WorkloadCompose {
    pub services: IndexMap<String, WorkloadService>,
    pub volumes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WorkloadService {
    pub image: Option<String>,
    pub build: Option<WorkloadBuild>,
    pub command: Option<WorkloadCommand>,
    pub entrypoint: Option<WorkloadCommand>,
    pub environment: Vec<EnvVar>,
    pub env_file: Vec<String>,
    pub ports: Vec<WorkloadPort>,
    pub volumes: Vec<WorkloadVolumeMount>,
    pub restart: Option<WorkloadRestart>,
    pub depends_on: IndexMap<String, WorkloadDependency>,
}

#[derive(Debug, Clone)]
pub struct WorkloadBuild {
    pub context: String,
    pub dockerfile: Option<String>,
    pub args: Vec<EnvVar>,
}

#[derive(Debug, Clone)]
pub enum WorkloadCommand {
    Shell(String),
    Exec(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct EnvVar {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WorkloadPort {
    pub host_ip: Option<String>,
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub enum WorkloadVolumeMount {
    Named {
        name: String,
        container_path: String,
        read_only: bool,
    },
    Bind {
        host_path: String,
        container_path: String,
        read_only: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadRestart {
    No,
    Always,
    OnFailure,
    UnlessStopped,
}

#[derive(Debug, Clone)]
pub struct WorkloadDependency {
    pub condition: Option<String>,
}

// --- Compose summary types ---

/// Cross-service summary of a compose file.
#[derive(Debug, Clone)]
pub struct ComposeSummary {
    /// All file paths referenced by bind mounts and env_files.
    pub referenced_files: Vec<ReferencedFile>,
    /// Named volumes used by services: (service_name, volume_name).
    /// Each volume must be used by exactly one service.
    pub named_volumes: Vec<(String, String)>,
    /// Port mappings with service names attached.
    pub ports: Vec<ServicePort>,
    /// Image specs per service.
    pub images: Vec<ServiceImage>,
}

impl ComposeSummary {
    /// Returns files that should be measured (not under additional-data/).
    pub fn measured_files(&self) -> Vec<&ReferencedFile> {
        self.referenced_files
            .iter()
            .filter(|f| !f.is_additional_data())
            .collect()
    }

    /// Returns files that are operator-provided additional data.
    pub fn additional_data_files(&self) -> Vec<&ReferencedFile> {
        self.referenced_files
            .iter()
            .filter(|f| f.is_additional_data())
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ReferencedFile {
    pub service: String,
    pub path: String,
    pub kind: FileRefKind,
}

impl ReferencedFile {
    /// Returns true if this file is under an `additional-data/` directory.
    ///
    /// Additional data files are operator-provided and excluded from measurement.
    pub fn is_additional_data(&self) -> bool {
        self.path.contains("additional-data/") || self.path.starts_with("additional-data")
    }
}

#[derive(Debug, Clone)]
pub enum FileRefKind {
    EnvFile,
    BindMount {
        container_path: String,
        read_only: bool,
    },
}

#[derive(Debug, Clone)]
pub struct ServicePort {
    pub service: String,
    pub port: WorkloadPort,
}

#[derive(Debug, Clone)]
pub struct ServiceImage {
    pub service: String,
    pub kind: ImageKind,
}

#[derive(Debug, Clone)]
pub enum ImageKind {
    /// Has `build:` + explicit `image:` tag.
    Build { tag: String },
    /// Has `build:` but no `image:` tag — caller must generate one.
    BuildUntagged,
    /// Pre-published image (no `build:`).
    Pull { tag: String },
}
