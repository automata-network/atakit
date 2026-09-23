use std::{
    collections::BTreeMap,
    ffi::OsStr,
    io::{IsTerminal, Write},
};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::process::Command;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Builder {
    name: String,
    #[serde(default)]
    driver: String,
    #[serde(default)]
    current: bool,
    nodes: Option<Vec<Node>>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Node {
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    status: String,
    platforms: Option<Vec<String>>,
}

impl Builder {
    fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().flatten()
    }
}

async fn list(docker: &OsStr) -> Result<BTreeMap<String, Builder>> {
    let output = Command::new(docker)
        .args(["buildx", "ls", "--format", "{{json .}}"])
        .output()
        .await
        .context("cannot run docker buildx; install Docker Buildx")?;
    if !output.status.success() {
        bail!("cannot list builders; a Buildx version supporting `buildx ls --format` is required: {}", String::from_utf8_lossy(&output.stderr));
    }
    let mut builders = BTreeMap::new();
    for line in output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        let builder: Builder =
            serde_json::from_slice(line).context("unsupported buildx builder metadata")?;
        builders.insert(builder.name.clone(), builder);
    }
    Ok(builders)
}

async fn verify(docker: &OsStr, mut builder: Builder) -> Result<Builder> {
    if !builder.nodes().any(|node| node.status == "running") {
        let output = Command::new(docker)
            .args(["buildx", "inspect", "--bootstrap", &builder.name])
            .output()
            .await?;
        if !output.status.success() {
            bail!(
                "cannot start builder {}: {}",
                builder.name,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        builder = list(docker)
            .await?
            .remove(&builder.name)
            .context("builder disappeared after bootstrap")?;
    }
    if !builder.nodes().any(|node| {
        node.status == "running"
            && node.platforms.as_ref().is_some_and(|platforms| {
                platforms
                    .iter()
                    .any(|platform| platform.trim_end_matches('*') == "linux/amd64")
            })
    }) {
        bail!(
            "builder {} does not report a running node supporting linux/amd64",
            builder.name
        );
    }
    // Exercise the exporter instead of inferring support from the driver name.
    let probe = tempfile::tempdir()?;
    std::fs::write(
        probe.path().join("Dockerfile"),
        "FROM scratch\nCOPY payload /payload\n",
    )?;
    std::fs::write(
        probe.path().join("payload"),
        "atakit builder capability probe\n",
    )?;
    let archive = probe.path().join("probe.tar");
    let output = Command::new(docker)
        .args([
            "buildx",
            "build",
            "--builder",
            &builder.name,
            "--provenance=false",
            "--output",
        ])
        .arg(format!(
            "type=docker,name=atakit-builder-probe:local,dest={},rewrite-timestamp=true",
            archive.display()
        ))
        .args(["--build-arg", "SOURCE_DATE_EPOCH=0"])
        .env("SOURCE_DATE_EPOCH", "0")
        .arg(probe.path())
        .output()
        .await?;
    if !output.status.success() || !archive.is_file() {
        bail!(
            "builder {} cannot export the required Docker archive: {}",
            builder.name,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(builder)
}

fn report(builder: Builder) -> String {
    let platforms: std::collections::BTreeSet<_> = builder
        .nodes()
        .filter_map(|node| node.platforms.as_ref())
        .flatten()
        .cloned()
        .collect();
    eprintln!(
        "Using Docker builder {} ({}); platforms: {}",
        builder.name,
        builder.driver,
        platforms.into_iter().collect::<Vec<_>>().join(", ")
    );
    builder.name
}

async fn prepare(
    docker: &OsStr,
    explicit: Option<&str>,
    verbose: bool,
    ask: impl Fn(&str) -> Result<String>,
) -> Result<String> {
    let builders = list(docker).await?;
    if let Some(name) = explicit {
        let builder = builders.get(name).with_context(|| {
            format!("BUILDX_BUILDER={name}: builder not found; run `docker buildx ls`")
        })?;
        return Ok(report(verify(docker, builder.clone()).await.with_context(
            || format!("BUILDX_BUILDER={name} is incompatible; select another builder explicitly"),
        )?));
    }
    let mut failures = Vec::new();
    let current = builders.values().find(|builder| builder.current);
    if let Some(current) = current {
        match verify(docker, current.clone()).await {
            Ok(builder) => return Ok(report(builder)),
            Err(error) => {
                let message = format!("Current Docker builder is incompatible: {error:#}");
                if verbose {
                    eprintln!("{message}");
                }
                failures.push(message);
            }
        }
    }
    let mut compatible = Vec::new();
    for builder in builders.values().filter(|builder| !builder.current) {
        // Do not automatically send the workload to a different Docker endpoint.
        if current.is_some_and(|current| {
            !builder.nodes().any(|node| {
                current
                    .nodes()
                    .any(|active| !node.endpoint.is_empty() && active.endpoint == node.endpoint)
            })
        }) {
            continue;
        }
        match verify(docker, builder.clone()).await {
            Ok(builder) => compatible.push(builder),
            Err(error) => {
                let message = format!("Skipping builder {}: {error:#}", builder.name);
                if verbose {
                    eprintln!("{message}");
                }
                failures.push(message);
            }
        }
    }
    if compatible.len() == 1 {
        return Ok(report(compatible.remove(0)));
    }
    if !compatible.is_empty() {
        let choices = compatible
            .iter()
            .enumerate()
            .map(|(i, b)| format!("  {}. {} ({})", i + 1, b.name, b.driver))
            .collect::<Vec<_>>()
            .join("\n");
        let input = ask(&format!("Compatible Docker builders:\n{choices}\nSelect [1-{}] (or set BUILDX_BUILDER to a listed name): ", compatible.len()))?;
        let pick: usize = input
            .trim()
            .parse()
            .context("builder selection cancelled or invalid")?;
        if pick == 0 || pick > compatible.len() {
            bail!("builder selection out of range");
        }
        return Ok(report(compatible.remove(pick - 1)));
    }
    if !verbose {
        for message in failures {
            eprintln!("{message}");
        }
    }
    let mut name = "atakit-workload".to_string();
    let mut suffix = 2;
    while builders.contains_key(&name) {
        name = format!("atakit-workload-{suffix}");
        suffix += 1;
    }
    let create =
        format!("docker buildx create --name {name} --driver docker-container --bootstrap");
    let answer = ask(&format!("No compatible Docker builder supporting linux/amd64 and archive export was found.\nCreate {name}? This starts a BuildKit container and retains its cache; it may download the BuildKit image.\nCommand: {create}\nGlobal builder selection will not change. Create builder? [y/N]: "))?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("builder creation cancelled; create one with `{create}`, then set BUILDX_BUILDER={name}");
    }
    let output = Command::new(docker)
        .args([
            "buildx",
            "create",
            "--name",
            &name,
            "--driver",
            "docker-container",
            "--bootstrap",
        ])
        .output()
        .await?;
    if !output.status.success() {
        bail!(
            "builder creation failed: {}; inspect with `docker buildx inspect {name}`",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let builder = list(docker)
        .await?
        .remove(&name)
        .context("created builder is absent from buildx ls")?;
    Ok(report(verify(docker, builder).await.with_context(|| format!("created builder {name} is not compatible; inspect it with `docker buildx inspect {name}`"))?))
}

/// Selects an export-capable Docker builder, asking before creating one.
pub(super) async fn select(verbose: bool) -> Result<String> {
    let explicit = std::env::var("BUILDX_BUILDER")
        .ok()
        .filter(|value| !value.is_empty());
    prepare(OsStr::new("docker"), explicit.as_deref(), verbose, |prompt| {
        if !std::io::stdin().is_terminal() {
            bail!("{prompt}\nCannot prompt in a noninteractive session. Create/select a compatible builder and set BUILDX_BUILDER before retrying.");
        }
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        Ok(answer)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(builders: &str, after_create: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("builders"), builders).unwrap();
        std::fs::write(root.path().join("created-builders"), after_create).unwrap();
        let docker = root.path().join("docker");
        std::fs::write(&docker, r#"#!/bin/sh
root=${0%/*}
printf '%s\n' "$*" >> "$root/calls"
case "$1 $2" in
  'buildx ls') /bin/cat "$root/builders" ;;
  'buildx create') /bin/cp "$root/created-builders" "$root/builders" ;;
  'buildx inspect') exit 0 ;;
  'buildx build')
    case "$*" in *'--builder desktop-linux'*) echo 'Docker exporter is not supported' >&2; exit 1;; esac
    for arg in "$@"; do
      case "$arg" in type=docker,*) dest=${arg#*dest=}; dest=${dest%%,*}; printf 'archive' > "$dest";; esac
    done ;;
  *) exit 99 ;;
esac
"#).unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
        (root, docker)
    }
    const DEFAULT: &str = r#"{"Name":"desktop-linux","Driver":"docker","Current":true,"Nodes":[{"Endpoint":"desktop-linux","Status":"running","Platforms":["linux/amd64","linux/arm64"]}]}"#;
    const GOOD: &str = r#"{"Name":"working","Driver":"docker-container","Nodes":[{"Endpoint":"desktop-linux","Status":"running","Platforms":["linux/amd64","linux/arm64"]}]}"#;
    const CREATED: &str = r#"{"Name":"atakit-workload","Driver":"docker-container","Nodes":[{"Endpoint":"desktop-linux","Status":"running","Platforms":["linux/amd64","linux/arm64"]}]}"#;

    #[tokio::test]
    async fn reuses_compatible_builder_without_changing_global_selection() {
        let (root, docker) = fixture(&format!("{DEFAULT}\n{GOOD}\n{GOOD}"), "");
        let name = prepare(docker.as_os_str(), None, false, |_| {
            panic!("unexpected prompt")
        })
        .await
        .unwrap();
        assert_eq!(name, "working");
        let calls = std::fs::read_to_string(root.path().join("calls")).unwrap();
        assert!(!calls.contains("buildx create"));
        assert!(!calls.contains("--use"));
        assert!(!calls.contains("--platform"));
        assert!(calls.contains("rewrite-timestamp=true"));
    }

    #[tokio::test]
    async fn explicit_incompatible_builder_is_not_silently_replaced() {
        let (_root, docker) = fixture(&format!("{DEFAULT}\n{GOOD}"), "");
        let err = prepare(docker.as_os_str(), Some("desktop-linux"), false, |_| {
            panic!("unexpected prompt")
        })
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("BUILDX_BUILDER"));
    }

    #[tokio::test]
    async fn creates_only_after_confirmation_and_verifies_detected_platforms() {
        let (root, docker) = fixture(DEFAULT, CREATED);
        let name = prepare(docker.as_os_str(), None, false, |prompt| {
            assert!(prompt.contains("[y/N]"));
            Ok("yes".into())
        })
        .await
        .unwrap();
        assert_eq!(name, "atakit-workload");
        let calls = std::fs::read_to_string(root.path().join("calls")).unwrap();
        assert!(calls.contains(
            "buildx create --name atakit-workload --driver docker-container --bootstrap"
        ));
        assert!(!calls.contains("--platform"));
        assert!(!calls.contains("--use"));
    }

    #[tokio::test]
    async fn refusal_or_noninteractive_input_never_creates_builder() {
        for answer in [Some("no"), None] {
            let (root, docker) = fixture(DEFAULT, CREATED);
            assert!(prepare(docker.as_os_str(), None, false, |_| match answer {
                Some(text) => Ok(text.into()),
                None => anyhow::bail!("noninteractive"),
            })
            .await
            .is_err());
            assert!(!std::fs::read_to_string(root.path().join("calls"))
                .unwrap()
                .contains("buildx create"));
        }
    }

    #[tokio::test]
    async fn missing_amd64_is_rejected_and_multiple_candidates_require_selection() {
        let arm_only = GOOD.replace("\"linux/amd64\",", "");
        let (_root, docker) = fixture(&arm_only, "");
        let err = prepare(docker.as_os_str(), Some("working"), false, |_| {
            panic!("unexpected prompt")
        })
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("linux/amd64"));
        let other = GOOD.replace("working", "working2");
        let (_root, docker) = fixture(&format!("{DEFAULT}\n{GOOD}\n{other}"), "");
        assert_eq!(
            prepare(docker.as_os_str(), None, false, |prompt| {
                assert!(prompt.contains("working2"));
                Ok("2".into())
            })
            .await
            .unwrap(),
            "working2"
        );
    }
    #[tokio::test]
    async fn docker_driver_is_accepted_when_actual_export_succeeds() {
        let metadata = GOOD
            .replace("docker-container", "docker")
            .replace("\"Driver\"", "\"Current\":true,\"Driver\"");
        let (root, docker) = fixture(&metadata, "");
        assert_eq!(
            prepare(docker.as_os_str(), None, false, |_| panic!(
                "unexpected prompt"
            ))
            .await
            .unwrap(),
            "working"
        );
        assert!(!std::fs::read_to_string(root.path().join("calls"))
            .unwrap()
            .contains("create"));
    }

    #[tokio::test]
    async fn incompatible_created_builder_fails_and_existing_names_are_preserved() {
        let arm_only = CREATED.replace("\"linux/amd64\",", "");
        let (_root, docker) = fixture(DEFAULT, &arm_only);
        let error = prepare(docker.as_os_str(), None, false, |_| Ok("y".into()))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("linux/amd64"));
        let (root, docker) = fixture(
            &format!("{DEFAULT}\n{arm_only}"),
            &CREATED.replace("atakit-workload", "atakit-workload-2"),
        );
        assert_eq!(
            prepare(docker.as_os_str(), None, false, |_| Ok("y".into()))
                .await
                .unwrap(),
            "atakit-workload-2"
        );
        let calls = std::fs::read_to_string(root.path().join("calls")).unwrap();
        assert!(calls.contains("create --name atakit-workload-2 "));
        assert!(!calls.contains("create --name atakit-workload "));
    }
}
