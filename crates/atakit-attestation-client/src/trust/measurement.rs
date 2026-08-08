//! Base-image measurement policy loading and TLS attestation report output.

use std::path::{Path, PathBuf};

use atakit_attestation::{verify_measurement_pack, MeasurementPolicy, VerificationReport};
use automata_tee_workload_measurement::base_image_registry::BaseImageRegistry;
use automata_tee_workload_measurement::types::AppRef;

use crate::error::PortalVerificationError;
use crate::trust::files::parse_measurement_publisher_keys;

pub fn cloud_tls_attestation_report_path(
    data_dir: &Path,
    target_name: &str,
    instance_name: &str,
) -> PathBuf {
    data_dir
        .join("cloud")
        .join("deployments")
        .join(target_name)
        .join(format!("{instance_name}.tls-attestation-report.json"))
}

pub fn workload_tls_attestation_report_path(
    cache_dir: &Path,
    host: &str,
    status_port: u16,
) -> PathBuf {
    cache_dir.join("tls-attestation").join(format!(
        "{}-{status_port}.tls-attestation-report.json",
        sanitize_report_name(host)
    ))
}

fn sanitize_report_name(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "portal".to_string()
    } else {
        out
    }
}

pub fn write_tls_attestation_report(
    report: &VerificationReport,
    path: &Path,
) -> Result<(), PortalVerificationError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| PortalVerificationError::IoPath {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let bytes = serde_json::to_vec_pretty(report)?;
    std::fs::write(path, bytes).map_err(|source| PortalVerificationError::IoPath {
        path: path.to_path_buf(),
        source,
    })
}

/// Load an offline measurement policy for TLS attestation.
///
/// Accept either a measurement-pack JSON file or a directory containing
/// `measurement-pack.json` and `measurement-pack.sig`. If no explicit path is
/// supplied, a `--base-image name:version` lookup searches the local atakit
/// data directory under `baseimage/measurements/<name>/<version>/`.
pub fn load_measurement_policy(
    measurements: Option<&Path>,
    base_image: Option<&str>,
    measurement_publisher_keys: &[String],
    data_dir: Option<&Path>,
) -> Result<Option<MeasurementPolicy>, PortalVerificationError> {
    let base_image_ref = base_image.map(parse_base_image_ref).transpose()?;
    let base_image_ref = base_image_ref.as_ref();
    let (json_path, sig_path, source) = if let Some(path) = measurements {
        let (json_path, sig_path) = measurement_pack_paths(path);
        let source = json_path.display().to_string();
        (json_path, sig_path, source)
    } else if let Some(app_ref) = base_image_ref {
        let Some(data_dir) = data_dir else {
            return Err(PortalVerificationError::Config {
                message: "--base-image local measurement lookup requires a data directory"
                    .to_string(),
            });
        };
        let path = select_local_measurement_pack_dir(data_dir, app_ref)?.path;
        let (json_path, sig_path) = measurement_pack_dir_paths(&path);
        (json_path, sig_path, format!("local:{}", path.display()))
    } else {
        return Ok(None);
    };

    let json = std::fs::read(&json_path).map_err(|source| PortalVerificationError::IoPath {
        path: json_path.clone(),
        source,
    })?;
    let sig = std::fs::read(&sig_path).map_err(|source| PortalVerificationError::IoPath {
        path: sig_path.clone(),
        source,
    })?;
    if sig.is_empty() {
        return Err(PortalVerificationError::Config {
            message: format!(
                "measurement pack signature is empty: {}",
                sig_path.display()
            ),
        });
    }

    let trusted_keys = parse_measurement_publisher_keys(measurement_publisher_keys)?;
    let pack = verify_measurement_pack(&json, &sig, &trusted_keys).map_err(|e| {
        PortalVerificationError::Config {
            message: e.to_string(),
        }
    })?;
    if let Some(app_ref) = base_image_ref {
        if pack.subject.name != app_ref.name || pack.subject.version != app_ref.version {
            return Err(PortalVerificationError::Config {
                message: format!(
                    "measurement pack is for {}:{}, not {}:{}",
                    pack.subject.name, pack.subject.version, app_ref.name, app_ref.version
                ),
            });
        }
    }

    Ok(Some(MeasurementPolicy { source, pack }))
}

/// Return whether either file for the automatic local pack lookup exists.
///
/// Callers use this only to choose local-versus-chain precedence. Once a local
/// pack artifact exists, loading or signature errors must fail closed instead
/// of falling back to a different policy source.
pub fn local_measurement_pack_exists(
    data_dir: &Path,
    base_image: &str,
) -> Result<bool, PortalVerificationError> {
    let app_ref = parse_base_image_ref(base_image)?;
    Ok(select_local_measurement_pack_dir(data_dir, &app_ref)?.detected)
}

/// Parse a canonical `<publisher>/<name>:<version>` base-image reference.
fn parse_base_image_ref(value: &str) -> Result<AppRef, PortalVerificationError> {
    value
        .parse::<AppRef>()
        .map_err(|error| PortalVerificationError::Config {
            message: format!("invalid --base-image {value:?}: {error}"),
        })
}

fn measurement_pack_paths(path: &Path) -> (PathBuf, PathBuf) {
    if path.is_dir() {
        return measurement_pack_dir_paths(path);
    }
    let sig_path = if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        path.with_extension("sig")
    } else {
        PathBuf::from(format!("{}.sig", path.display()))
    };
    (path.to_path_buf(), sig_path)
}

fn measurement_pack_dir_paths(path: &Path) -> (PathBuf, PathBuf) {
    (
        path.join("measurement-pack.json"),
        path.join("measurement-pack.sig"),
    )
}

/// Where a locally cached measurement pack for a base image lives.
///
/// Keyed by base-image identifier rather than by name and version. The
/// identifier is `0x` plus 64 lowercase hexadecimal characters, so it is
/// path-safe by construction — nothing to escape — and it is
/// publisher-qualified, so two publishers holding the same name and version get
/// separate directories instead of overwriting each other.
fn local_measurement_pack_dir(data_dir: &Path, app_ref: &AppRef) -> PathBuf {
    let base_image_id = BaseImageRegistry::get_image_id(app_ref);
    data_dir
        .join("baseimage")
        .join("measurements")
        .join(format!("{base_image_id:#x}"))
}

struct LocalMeasurementPackSelection {
    path: PathBuf,
    detected: bool,
}

fn select_local_measurement_pack_dir(
    data_dir: &Path,
    app_ref: &AppRef,
) -> Result<LocalMeasurementPackSelection, PortalVerificationError> {
    let path = local_measurement_pack_dir(data_dir, app_ref);
    let detected = measurement_pack_artifact_exists(&path)?;
    Ok(LocalMeasurementPackSelection { path, detected })
}

fn measurement_pack_artifact_exists(dir: &Path) -> Result<bool, PortalVerificationError> {
    let (json, signature) = measurement_pack_dir_paths(dir);
    Ok(path_exists(&json)? || path_exists(&signature)?)
}

fn path_exists(path: &Path) -> Result<bool, PortalVerificationError> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(PortalVerificationError::IoPath {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLISHER: &str = "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f";

    /// A canonical reference for a test base image.
    fn reference(name: &str, version: &str) -> String {
        format!("{PUBLISHER}/{name}:{version}")
    }

    /// The directory a pack for that reference lives in.
    fn pack_dir(data_dir: &Path, name: &str, version: &str) -> PathBuf {
        let app_ref: AppRef = reference(name, version)
            .parse()
            .expect("canonical reference");
        local_measurement_pack_dir(data_dir, &app_ref)
    }
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};

    fn measurement_pack_json(name: &str, version: &str) -> String {
        format!(
            // Canonical key order, because the signature covers these exact bytes.
            r#"{{"measurements":{{"profiles":[]}},"published_at":1786000000,"revision":1,"schema":"atakit.base_image_measurement_pack.v4","subject":{{"id":"0x{}","name":"{name}","publisher":"0x{}","version":"{version}"}}}}"#,
            "00".repeat(32),
            "aa".repeat(32)
        )
    }

    fn signed_measurement_pack(json: &str) -> (Vec<u8>, Vec<String>) {
        let signing_key = K256SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let signature: K256Signature = signing_key.sign(json.as_bytes());
        let publisher_key = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        (signature.to_bytes().to_vec(), vec![publisher_key])
    }

    #[test]
    fn load_measurement_policy_accepts_json_and_signature() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("base-v1.measurements.json");
        let sig_path = dir.path().join("base-v1.measurements.sig");
        let json = measurement_pack_json("base", "v1");
        let (sig, publisher_keys) = signed_measurement_pack(&json);
        std::fs::write(&json_path, json).unwrap();
        std::fs::write(&sig_path, sig).unwrap();

        let policy = load_measurement_policy(
            Some(&json_path),
            Some(&reference("base", "v1")),
            &publisher_keys,
            None,
        )
        .unwrap()
        .expect("policy");

        assert_eq!(policy.pack.subject.name, "base");
        assert_eq!(policy.pack.subject.version, "v1");
        assert_eq!(policy.source, json_path.display().to_string());
    }

    #[test]
    fn load_measurement_policy_rejects_base_image_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let json = measurement_pack_json("base", "v1");
        let (sig, publisher_keys) = signed_measurement_pack(&json);
        std::fs::write(dir.path().join("measurement-pack.json"), json).unwrap();
        std::fs::write(dir.path().join("measurement-pack.sig"), sig).unwrap();

        let err = load_measurement_policy(
            Some(dir.path()),
            Some(&reference("base", "v2")),
            &publisher_keys,
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("measurement pack is for base:v1"),
            "got: {err}"
        );
    }

    #[test]
    fn load_measurement_policy_finds_local_baseimage_pack() {
        let dir = tempfile::tempdir().unwrap();
        let json = measurement_pack_json("base/image", "v1");
        let (sig, publisher_keys) = signed_measurement_pack(&json);
        let pack_dir = pack_dir(dir.path(), "base/image", "v1");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.json"), json).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.sig"), sig).unwrap();

        let policy = load_measurement_policy(
            None,
            Some(&reference("base/image", "v1")),
            &publisher_keys,
            Some(dir.path()),
        )
        .unwrap()
        .expect("policy");

        assert_eq!(policy.pack.subject.name, "base/image");
        assert_eq!(policy.source, format!("local:{}", pack_dir.display()));
    }

    #[test]
    fn load_measurement_policy_reports_missing_local_baseimage_pack() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            load_measurement_policy(None, Some(&reference("base", "v1")), &[], Some(dir.path()))
                .unwrap_err();
        assert!(
            err.to_string().contains("measurement-pack.json")
                && err
                    .to_string()
                    .contains(&pack_dir(dir.path(), "base", "v1").display().to_string()),
            "got: {err}"
        );
    }

    #[test]
    fn local_measurement_pack_exists_when_either_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let pack_dir = pack_dir(dir.path(), "base", "v1");
        std::fs::create_dir_all(&pack_dir).unwrap();
        assert!(!local_measurement_pack_exists(dir.path(), &reference("base", "v1")).unwrap());

        std::fs::write(pack_dir.join("measurement-pack.json"), b"{}").unwrap();
        assert!(local_measurement_pack_exists(dir.path(), &reference("base", "v1")).unwrap());

        std::fs::remove_file(pack_dir.join("measurement-pack.json")).unwrap();
        std::fs::write(pack_dir.join("measurement-pack.sig"), b"signature").unwrap();
        assert!(local_measurement_pack_exists(dir.path(), &reference("base", "v1")).unwrap());

        std::fs::write(pack_dir.join("measurement-pack.json"), b"{}").unwrap();
        assert!(local_measurement_pack_exists(dir.path(), &reference("base", "v1")).unwrap());
    }

    /// Distinct references get distinct directories, including references that
    /// differ only by publisher — the collision the identifier removes.
    #[test]
    fn distinct_references_do_not_collapse() {
        let dir = tempfile::tempdir().unwrap();
        assert_ne!(
            pack_dir(dir.path(), "foo@bar", "v1"),
            pack_dir(dir.path(), "foo_bar", "v1")
        );

        let other: AppRef = format!("{}/base:v1", "0x".to_string() + &"ab".repeat(32))
            .parse()
            .unwrap();
        assert_ne!(
            pack_dir(dir.path(), "base", "v1"),
            local_measurement_pack_dir(dir.path(), &other)
        );
    }

    #[test]
    fn incomplete_pack_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let new_path = pack_dir(dir.path(), "base", "v1");
        std::fs::create_dir_all(&new_path).unwrap();
        std::fs::write(
            new_path.join("measurement-pack.json"),
            measurement_pack_json("base", "v1"),
        )
        .unwrap();
        let error =
            load_measurement_policy(None, Some(&reference("base", "v1")), &[], Some(dir.path()))
                .unwrap_err();
        assert!(
            error.to_string().contains("measurement-pack.sig"),
            "got: {error}"
        );
    }

    #[test]
    fn no_local_pack_artifacts_remain_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!local_measurement_pack_exists(dir.path(), &reference("base", "v1")).unwrap());
    }

    #[test]
    fn load_measurement_policy_rejects_missing_publisher_key() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("base-v1.measurements.json");
        let sig_path = dir.path().join("base-v1.measurements.sig");
        let json = measurement_pack_json("base", "v1");
        let (sig, _) = signed_measurement_pack(&json);
        std::fs::write(&json_path, json).unwrap();
        std::fs::write(&sig_path, sig).unwrap();

        let err =
            load_measurement_policy(Some(&json_path), Some(&reference("base", "v1")), &[], None)
                .unwrap_err();

        assert!(
            err.to_string()
                .contains("no trusted measurement publisher keys"),
            "got: {err}"
        );
    }
}
