use super::*;

#[test]
fn default_config_file() {
    let cf = PayloadConfigFile::default();
    assert_eq!(cf.max_per_category, 0);
    assert!(cf.deduplicate);
    assert_eq!(cf.marker_prefix, "SLN");
    assert_eq!(cf.marker_position, "prefix");
    assert!(cf.grammar_dirs.is_empty());
}

#[test]
fn parse_minimal_toml() {
    let cf = PayloadConfigFile::from_toml("", "<test>".into()).unwrap();
    assert!(cf.deduplicate);
}

#[test]
fn parse_full_toml() {
    let cf = PayloadConfigFile::from_toml(
        r#"
max_per_category = 500
deduplicate = false
marker_prefix = "TAINT"
marker_position = "suffix"
target_runtime = ["php"]
exclude_categories = ["xxe"]
include_categories = ["sqli", "xss"]
grammar_dirs = ["./grammars", "/opt/payloads"]
"#,
        "<test>".into(),
    )
    .unwrap();

    assert_eq!(cf.max_per_category, 500);
    assert!(!cf.deduplicate);
    assert_eq!(cf.marker_prefix, "TAINT");
    assert_eq!(cf.target_runtime, Some(vec!["php".into()]));
    assert_eq!(cf.exclude_categories, vec!["xxe"]);
    assert_eq!(cf.grammar_dirs, vec!["./grammars", "/opt/payloads"]);
}

#[test]
fn into_config_converts() {
    let cf = PayloadConfigFile {
        marker_position: "replace:{M}".into(),
        max_per_category: 42,
        ..Default::default()
    };
    let config = cf.into_config().unwrap();
    assert_eq!(config.max_per_category, 42);
    assert_eq!(
        config.marker_position,
        MarkerPosition::Replace("{M}".into())
    );
}

#[test]
fn marker_position_parsing() {
    assert_eq!(
        parse_marker_position("prefix").unwrap(),
        MarkerPosition::Prefix
    );
    assert_eq!(
        parse_marker_position("suffix").unwrap(),
        MarkerPosition::Suffix
    );
    assert_eq!(
        parse_marker_position("inline").unwrap(),
        MarkerPosition::Inline
    );
    assert_eq!(
        parse_marker_position("replace:{MARKER}").unwrap(),
        MarkerPosition::Replace("{MARKER}".into())
    );
    assert!(parse_marker_position("unknown").is_err());
}

#[test]
fn load_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
max_per_category = 100
grammar_dirs = ["./g"]
"#,
    )
    .unwrap();

    let cf = PayloadConfigFile::load(&path).unwrap();
    assert_eq!(cf.max_per_category, 100);
    assert_eq!(cf.grammar_dirs, vec!["./g"]);
}

#[test]
fn load_nonexistent_file_errors() {
    assert!(PayloadConfigFile::load("/nonexistent/config.toml").is_err());
}

#[test]
fn invalid_toml_errors() {
    assert!(PayloadConfigFile::from_toml("{{invalid", "<test>".into()).is_err());
}
