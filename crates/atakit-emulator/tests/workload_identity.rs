use atakit_emulator::inputs;
#[test]
fn development_measurement_covers_nested_inputs_and_ignores_toml_formatting() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    std::fs::create_dir_all(root.join("measured-data/nested")).unwrap();
    std::fs::write(root.join("measured-data/nested/a"), "a").unwrap();
    let path = root.join("atakit-workload.toml");
    let config="format=7\n[package]\nmeasured-data=['/nested']\n[workload]\nname='sample'\nversion='1'\nbase-image-mode='whitelist'\nimage='example:1'\n";
    std::fs::write(&path, config).unwrap();
    let original = inputs::measurement(&path, root).unwrap();
    std::fs::write(&path, format!("# formatting only\n{config}")).unwrap();
    assert_eq!(original, inputs::measurement(&path, root).unwrap());
    std::fs::write(root.join("measured-data/nested/a"), "b").unwrap();
    assert_ne!(original, inputs::measurement(&path, root).unwrap());
    assert!(inputs::measured_files(&root.join("measured-data"), &["../outside".into()]).is_err());
}
