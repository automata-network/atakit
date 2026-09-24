use atakit_emulator::{
    compose,
    endpoints::{EndpointInfo, WorkloadEndpoint},
};
use serde_json::json;
use std::collections::BTreeMap;
#[test]
fn compose_scopes_service_environment_and_file_mounts() {
    let tmp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let dir = tmp.path();
    std::fs::create_dir(dir.join("measured-data")).unwrap();
    std::fs::write(dir.join("measured-data/main"), "secret").unwrap();
    std::fs::write(dir.join("measured-data/side"), "public").unwrap();
    let snapshot = dir.join("snapshot/atakit-portal/measured-data");
    std::fs::create_dir_all(&snapshot).unwrap();
    std::fs::write(snapshot.join("main"), "frozen-main").unwrap();
    std::fs::write(snapshot.join("side"), "frozen-side").unwrap();
    let config = dir.join("atakit-workload.toml");
    std::fs::write(&config,"format=7\n[workload]\nname='app'\nversion='1'\nbase-image-mode='whitelist'\nimage={build='.'}\natakit-portal=true\nmeasured-data=['/main']\n[workload.environment]\nMAIN_SECRET='only-main'\nPORTAL_SOCKET='/run/atakit-portal.sock'\nRPC_URL='http://business-chain:8545'\nDATA_DIR='/custom-data'\nMEASURED_DATA_DIR='/custom-measured'\nUNMEASURED_DATA_DIR='/custom-unmeasured'\nSHARED='main'\nLITERAL='a${NOT_AN_ENV}b$tail'\n[dependencies.side]\nimage='example:2'\nmeasured-data=['/side']\n[dependencies.side.environment]\nSHARED='side'\n").unwrap();
    let e = EndpointInfo {
        environment_id: "test".into(),
        upstream_rpc_url: "http://localhost:8545".into(),
        anchor_number: 0,
        anchor_hash: "0x00".into(),
        rpc_url: "http://127.0.0.1:8546".into(),
        chain_id: 31337,
        session_registry: "".into(),
        workload_registry: "".into(),
        base_image_registry: "".into(),
        state: "ready".into(),
        workloads: BTreeMap::from([(
            "app".into(),
            WorkloadEndpoint {
                version: Some("1".into()),
                config_file: config.clone(),
                workload_dir: dir.into(),
                portal_socket: dir.join("portal.sock"),
                owner_fingerprint: None,
                publisher_fingerprint: "".into(),
                workload_id: None,
                session_id: None,
                state: "ready".into(),
                error: None,
                env: BTreeMap::from([
                    (
                        "EMULATOR_ROOTFS".into(),
                        dir.join("snapshot").display().to_string(),
                    ),
                    ("MAIN_SECRET".into(), "only-main".into()),
                    ("SHARED".into(), "main".into()),
                ]),
            },
        )]),
    };
    let native = compose::project_with_transport;
    let no_ports = serde_json::Map::new();
    assert!(native(
        &e,
        &["app".into()],
        &no_ports,
        dir,
        atakit_emulator::cli::PortalTransport::Native
    )
    .is_err());
    let socket = dir.join("portal.sock");
    std::fs::write(&socket, "not a socket").unwrap();
    assert!(native(
        &e,
        &["app".into()],
        &no_ports,
        dir,
        atakit_emulator::cli::PortalTransport::Native
    )
    .unwrap_err()
    .to_string()
    .contains("not a Unix socket"));
    std::fs::remove_file(&socket).unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let direct = native(
        &e,
        &["app".into()],
        &no_ports,
        dir,
        atakit_emulator::cli::PortalTransport::Native,
    )
    .unwrap();
    assert!(direct["services"].get("app-portal-bridge").is_none());
    assert!(!dir.join("bridges").exists());
    assert!(direct["volumes"].as_object().unwrap().is_empty());
    let mount = direct["services"]["app"]["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mount| mount["target"] == "/run/atakit-portal.sock")
        .unwrap();
    assert_eq!(
        mount,
        &json!({"type":"bind","source":socket,"target":"/run/atakit-portal.sock","read_only":true})
    );
    assert!(mount.get("bind").is_none());
    assert!(!direct["services"]["app-side"]["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|mount| mount["target"] == "/run/atakit-portal.sock"));
    let mut two = e.clone();
    two.workloads
        .insert("api".into(), e.workloads["app"].clone());
    let api = native(
        &two,
        &["api".into()],
        &no_ports,
        dir,
        atakit_emulator::cli::PortalTransport::Native,
    )
    .unwrap();
    let together = native(
        &two,
        &["app".into(), "api".into()],
        &no_ports,
        dir,
        atakit_emulator::cli::PortalTransport::Native,
    )
    .unwrap();
    let reversed = native(
        &two,
        &["api".into(), "app".into()],
        &no_ports,
        dir,
        atakit_emulator::cli::PortalTransport::Native,
    )
    .unwrap();
    assert_ne!(direct["name"], api["name"]);
    assert_ne!(direct["name"], together["name"]);
    assert_eq!(together["name"], reversed["name"]);

    let ports =
        serde_json::from_value(json!({"app":{"portal_port":9999,"token":"test-token"}})).unwrap();
    let doc = compose::project(&e, &["app".into()], &ports, dir).unwrap();
    assert!(doc["services"]["app"]["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|mount| mount["source"].as_str() == Some(snapshot.join("main").to_str().unwrap())));
    let main_env = &doc["services"]["app"]["environment"];
    assert!(main_env.get("EMULATOR_ROOTFS").is_none());
    let expected_rpc = if cfg!(target_os = "linux") {
        "http://127.0.0.1:8546/"
    } else {
        "http://host.docker.internal:8546/"
    };
    assert_eq!(main_env["EMULATOR_RPC_URL"], expected_rpc);
    assert_eq!(
        doc["services"]["app-side"]["environment"]["EMULATOR_RPC_URL"],
        expected_rpc
    );
    assert_eq!(
        direct["services"]["app"]["environment"]["EMULATOR_RPC_URL"],
        expected_rpc
    );

    assert_eq!(main_env["PORTAL_SOCKET"], "/run/atakit-portal.sock");
    assert_eq!(main_env["RPC_URL"], "http://business-chain:8545");
    assert_eq!(main_env["DATA_DIR"], "/custom-data");
    assert_eq!(main_env["MEASURED_DATA_DIR"], "/custom-measured");
    assert_eq!(main_env["UNMEASURED_DATA_DIR"], "/custom-unmeasured");
    for key in [
        "RPC_URL",
        "DATA_DIR",
        "MEASURED_DATA_DIR",
        "UNMEASURED_DATA_DIR",
        "PORTAL_SOCKET",
    ] {
        assert!(doc["services"]["app-side"]["environment"]
            .get(key)
            .is_none());
    }
    assert_eq!(main_env["LITERAL"], "a$${NOT_AN_ENV}b$$tail");
    let socket_mount = doc["services"]["app"]["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mount| mount["target"] == "/run/atakit-portal.sock")
        .expect("Portal socket at canonical path");
    assert_eq!(socket_mount["volume"]["subpath"], "atakit-portal.sock");
    assert_eq!(socket_mount["read_only"], true);
    let implicit = compose::project(&e, &[], &ports, dir).unwrap();
    assert_eq!(implicit, doc);
    let mut multiple = e.clone();
    multiple
        .workloads
        .insert("another".into(), e.workloads["app"].clone());
    assert!(compose::project(&multiple, &[], &ports, dir)
        .unwrap_err()
        .to_string()
        .contains("--workload is required"));
    let script = std::fs::read_to_string(dir.join("bridges/app-connect.sh")).unwrap();
    assert!(script.contains("exec socat -u STDIN STDOUT"));
    assert!(!script.contains("ignoreeof"));
    assert_eq!(doc["services"]["app"]["group_add"], json!(["65530"]));
    assert!(doc["services"]["app-portal-bridge"]["command"][0]
        .as_str()
        .unwrap()
        .contains("mode=0660,group=65530"));
    assert_eq!(doc["services"]["app-side"]["environment"]["SHARED"], "side");
    assert!(doc["services"]["app-side"]["environment"]
        .get("MAIN_SECRET")
        .is_none());
    let mounts = doc["services"]["app-side"]["volumes"].as_array().unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0]["target"], "/atakit-portal/measured-data/side");
    assert!(!doc["services"]["app-side"]
        .to_string()
        .contains("test-token"));
    assert!(doc["services"]["app-side"]["environment"]
        .get("PORTAL_SOCKET")
        .is_none());
    let original = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        original.replace(
            "SHARED='main'",
            "SHARED='main'\nEMULATOR_RPC_URL='http://wrong-chain'",
        ),
    )
    .unwrap();
    assert!(compose::project(&e, &["app".into()], &ports, dir)
        .unwrap_err()
        .to_string()
        .contains("reserved environment variable EMULATOR_RPC_URL"));
    std::fs::write(&config, &original).unwrap();

    std::fs::write(
        &config,
        original.replace("atakit-portal=true", "atakit-portal=false"),
    )
    .unwrap();
    let no_portal = compose::project(&e, &[], &serde_json::Map::new(), dir).unwrap();
    assert!(no_portal["services"].get("app-portal-bridge").is_none());
    assert_eq!(
        no_portal["services"]["app"]["environment"]["PORTAL_SOCKET"],
        "/run/atakit-portal.sock"
    );
    assert!(!no_portal["services"]["app"]["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|mount| mount["target"] == "/run/atakit-portal.sock"));
    for changed in [
        original.replace("atakit-portal=true", "atakit-portal=true\nip-env=true"),
        original.replace("[dependencies.side]", "[dependencies.side]\nip-env=true"),
    ] {
        std::fs::write(&config, changed).unwrap();
        assert!(compose::project(&e, &[], &ports, dir)
            .unwrap_err()
            .to_string()
            .contains("ip-env"));
    }
    std::fs::write(&config, &original).unwrap();
    // Unsupported requirements must fail before a misleading Compose file is emitted.
    let base = std::fs::read_to_string(&config).unwrap();
    for (declaration, field) in [
        ("[baby-container]\nenabled=true\n", "baby-container"),
        (
            "[baby-container.slots.job]\nparent-service='app'\n",
            "baby-container",
        ),
    ] {
        std::fs::write(&config, format!("{base}\n{declaration}")).unwrap();
        let error = compose::project(&e, &["app".into()], &ports, dir).unwrap_err();
        assert!(error.to_string().contains(field), "{error:#}");
    }
    std::fs::write(&config, format!("{base}\n[baby-container]\nenabled=false\n[disks.data]\nsize='1GB'\nencryption={{unlock_method=[],bind=[]}}\n")).unwrap();
    compose::project(&e, &["app".into()], &ports, dir).unwrap();
    for policy in [
        "unlock_method=['tpm'],bind=['platform','baseimage','workload']",
        "unlock_method=[],bind=['workload']",
    ] {
        let source = format!("{base}\n[workload.storage.data]\ndisk='data'\nbase-path='/shared'\nmount-path='/data'\nread-only=true\n[dependencies.side.storage.data]\ndisk='data'\nbase-path='/shared'\nmount-path='/side-data'\nread-only=false\n[disks.data]\nsize='1GB'\nencryption={{{policy}}}\n");
        std::fs::write(&config, &source).unwrap();
        let data = dir.join("data/app/data/shared");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("retained"), "existing data").unwrap();
        let projected = compose::project(&e, &["app".into()], &ports, dir).unwrap();
        for (service, target, read_only) in
            [("app", "/data", true), ("app-side", "/side-data", false)]
        {
            let mount = projected["services"][service]["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|mount| mount["target"] == target)
                .unwrap();
            assert_eq!(mount["type"], "bind");
            assert_eq!(mount["source"], data.display().to_string());
            assert_eq!(mount["read_only"], read_only);
        }
        assert_eq!(
            std::fs::read_to_string(data.join("retained")).unwrap(),
            "existing data"
        );
        assert_eq!(std::fs::read_to_string(&config).unwrap(), source);
    }
}
#[tokio::test]
async fn bridge_requires_credential_before_reaching_private_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UnixListener};
    let tmp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let path = tmp.path().join("private.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (port, token, task) = compose::start_bridge(path).await.unwrap();
    let mut denied = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    denied.write_all(&[b'x'; 65]).await.unwrap();
    let mut byte = [0];
    assert_eq!(denied.read(&mut byte).await.unwrap(), 0);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    let mut allowed = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    allowed
        .write_all(format!("{token}\nhello").as_bytes())
        .await
        .unwrap();
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut body = [0; 5];
    socket.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"hello");
    // HTTP clients await a response while keeping their request stream open.
    socket.write_all(b"response").await.unwrap();
    let mut response = [0; 8];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        allowed.read_exact(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&response, b"response");
    task.abort();
}

#[test]
fn compose_file_is_yaml_and_preserves_string_values_and_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("compose.yaml");
    let document = json!({"services":{"app":{
        "image":"example:1",
        "environment":{"BOOLEAN":"true","NUMBER":"123","EMPTY":"", "NULL":"null", "LITERAL":"a$${NOT_AN_ENV}", "MULTILINE":"first\nsecond"},
        "ports":["3000:3000"],
        "command":["/bin/sh","-c","printf '%s\\n' \"hello: world\""]
    }}});
    compose::write_compose(&path, &document).unwrap();
    let yaml = std::fs::read_to_string(&path).unwrap();
    assert!(yaml.contains("services:\n"));
    assert!(!yaml.trim_start().starts_with('{'));
    assert_eq!(
        serde_yaml::from_str::<serde_json::Value>(&yaml).unwrap(),
        document
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    compose::write_compose(&path, &document).unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn compose_paths_are_scoped_and_group_order_is_irrelevant() {
    let dir = tempfile::tempdir().unwrap();
    let a = vec!["app".to_string()];
    let b = vec!["api".to_string()];
    let ab = vec!["app".to_string(), "api".to_string()];
    let ba = vec!["api".to_string(), "app".to_string()];
    let path = |names: &[String]| compose::default_output(dir.path(), names).unwrap();
    assert_eq!(path(&a), dir.path().join("app/compose.yaml"));
    assert_ne!(path(&a), path(&b));
    assert_ne!(path(&a), path(&ab));
    assert_eq!(path(&ab), path(&ba));
    for invalid in [
        vec![],
        vec!["../escape".into()],
        vec!["app".into(), "app".into()],
        vec!["compose".into()],
    ] {
        assert!(compose::default_output(dir.path(), &invalid).is_err());
    }
}
