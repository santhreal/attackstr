use attackstr::{MarkerPosition, PayloadConfig, PayloadDb, PayloadError};

#[test]
fn load_toml_string() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "test"
sink_category = "test-cat"

[[contexts]]
name = "default"
prefix = ""
suffix = ""

[[techniques]]
name = "basic"
template = "hello"

[[encodings]]
name = "raw"
transform = "identity"
"#,
    )
    .unwrap();

    let payloads = db.payloads("test-cat");
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].text, "hello");
    assert_eq!(payloads[0].technique, "basic");
    assert_eq!(payloads[0].context, "default");
    assert!((payloads[0].confidence - 1.0).abs() < f64::EPSILON);
    assert!(payloads[0].expected_pattern.is_none());
}

#[test]
fn multiple_grammars_same_category() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "a"
sink_category = "cat"
[[techniques]]
name = "t1"
template = "payload-a"
"#,
    )
    .unwrap();
    db.load_toml(
        r#"
[grammar]
name = "b"
sink_category = "cat"
[[techniques]]
name = "t2"
template = "payload-b"
"#,
    )
    .unwrap();

    let payloads = db.payloads("cat");
    assert_eq!(payloads.len(), 2);
    let texts: Vec<&str> = payloads.iter().map(|p| p.text.as_str()).collect();
    assert!(texts.contains(&"payload-a"));
    assert!(texts.contains(&"payload-b"));
}

#[test]
fn deduplication() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        deduplicate: true,
        ..PayloadConfig::default()
    });
    // Two grammars producing same payload.
    for _ in 0..2 {
        db.load_toml(
            r#"
[grammar]
name = "dup"
sink_category = "dup-cat"
[[techniques]]
name = "t"
template = "same"
"#,
        )
        .unwrap();
    }

    let payloads = db.payloads("dup-cat");
    assert_eq!(payloads.len(), 1);
}

#[test]
fn max_per_category() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        max_per_category: 2,
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "big"
sink_category = "big-cat"

[[techniques]]
name = "t1"
template = "{var}"

[[vars]]
value = "a"
[[vars]]
value = "b"
[[vars]]
value = "c"
[[vars]]
value = "d"
[[vars]]
value = "e"
"#,
    )
    .unwrap();

    let payloads = db.payloads("big-cat");
    assert_eq!(payloads.len(), 2); // Truncated to 2.
}

#[test]
fn exclude_categories() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        exclude_categories: vec!["blocked".into()],
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "blocked"
sink_category = "blocked"
[[techniques]]
name = "t"
template = "evil"
"#,
    )
    .unwrap();

    assert!(db.payloads("blocked").is_empty());
    assert_eq!(db.grammar_count(), 0);
}

#[test]
fn include_categories() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        include_categories: vec!["allowed".into()],
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "good"
sink_category = "allowed"
[[techniques]]
name = "t"
template = "ok"
"#,
    )
    .unwrap();
    db.load_toml(
        r#"
[grammar]
name = "bad"
sink_category = "not-allowed"
[[techniques]]
name = "t"
template = "nope"
"#,
    )
    .unwrap();

    assert_eq!(db.payloads("allowed").len(), 1);
    assert!(db.payloads("not-allowed").is_empty());
}

#[test]
fn runtime_filter_includes_matching_grammar() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        target_runtime: Some(vec!["php".into()]),
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "php-only"
sink_category = "runtime-cat"
target_runtime = ["php", "node"]

[[techniques]]
name = "t"
template = "payload"
"#,
    )
    .unwrap();

    assert_eq!(db.payloads("runtime-cat").len(), 1);
}

#[test]
fn runtime_filter_excludes_non_matching_grammar() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        target_runtime: Some(vec!["ruby".into()]),
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "php-only"
sink_category = "runtime-cat"
target_runtime = ["php", "node"]

[[techniques]]
name = "t"
template = "payload"
"#,
    )
    .unwrap();

    assert!(db.payloads("runtime-cat").is_empty());
    assert_eq!(db.grammar_count(), 0);
}

#[test]
fn runtime_filter_allows_unspecified_grammar_runtime() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        target_runtime: Some(vec!["node".into()]),
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "generic"
sink_category = "runtime-generic"

[[techniques]]
name = "t"
template = "payload"
"#,
    )
    .unwrap();

    assert_eq!(db.payloads("runtime-generic").len(), 1);
}

#[test]
fn marker_injection() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "m"
sink_category = "mark"
[[techniques]]
name = "t"
template = "alert(1)"
"#,
    )
    .unwrap();

    let marked = db.payloads_with_marker("mark", "SLN_42_");
    assert_eq!(marked.len(), 1);
    assert_eq!(marked[0].text, "SLN_42_alert(1)");
}

#[test]
fn marker_injection_suffix() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        marker_position: MarkerPosition::Suffix,
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "m"
sink_category = "mark-suffix"
[[techniques]]
name = "t"
template = "alert(1)"
"#,
    )
    .unwrap();

    let marked = db.payloads_with_marker("mark-suffix", "SLN_42_");
    assert_eq!(marked[0].text, "alert(1)SLN_42_");
}

#[test]
fn iter_categories_returns_sorted_names() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "zeta"
sink_category = "zeta"
[[techniques]]
name = "t"
template = "a"
"#,
    )
    .unwrap();
    db.load_toml(
        r#"
[grammar]
name = "alpha"
sink_category = "alpha"
[[techniques]]
name = "t"
template = "b"
"#,
    )
    .unwrap();

    let categories: Vec<_> = db.iter_categories().collect();
    assert_eq!(categories, vec!["alpha", "zeta"]);
}

#[test]
fn config_file_round_trip_loads_grammar_dir_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let grammar_dir = dir.path().join("grammars");
    std::fs::create_dir(&grammar_dir).unwrap();

    std::fs::write(
        grammar_dir.join("xss.toml"),
        r#"
[grammar]
name = "example-xss"
sink_category = "xss"

[[contexts]]
name = "quoted"
prefix = "'"
suffix = "'"

[[techniques]]
name = "alert"
template = "{prefix}<script>{payload}</script>{suffix}"

[[payloads]]
value = "alert(1)"

[[encodings]]
name = "raw"
transform = "identity"
"#,
    )
    .unwrap();

    std::fs::write(
        dir.path().join("attackstr.toml"),
        r#"
max_per_category = 5
deduplicate = true
marker_prefix = "TRACE"
marker_position = "replace:{MARKER}"
grammar_dirs = ["./grammars"]
"#,
    )
    .unwrap();

    let (mut db, errors) =
        PayloadDb::load_config_and_grammars(dir.path().join("attackstr.toml")).unwrap();
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");

    let payloads = db.payloads("xss");
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].text, "'<script>alert(1)</script>'");
}

#[test]
fn marker_injection_inline() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        marker_position: MarkerPosition::Inline,
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "m"
sink_category = "mark-inline"
[[techniques]]
name = "t"
template = "alert(1)"
"#,
    )
    .unwrap();

    let marked = db.payloads_with_marker("mark-inline", "SLN_42_");
    assert_eq!(marked[0].text, "{SLN_42_}alert(1)");
}

#[test]
fn marker_injection_replace_placeholder() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        marker_position: MarkerPosition::Replace("{MARKER}".into()),
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "m"
sink_category = "mark-replace"
[[techniques]]
name = "t"
template = "<!-- {MARKER} -->alert(1)"
"#,
    )
    .unwrap();

    let marked = db.payloads_with_marker("mark-replace", "SLN_42_");
    assert_eq!(marked[0].text, "<!-- SLN_42_ -->alert(1)");
}

#[test]
fn custom_encoding() {
    fn reverse(s: &str) -> String {
        s.chars().rev().collect()
    }

    let mut db = PayloadDb::new();
    db.register_encoding("reverse", reverse);
    db.load_toml(
        r#"
[grammar]
name = "enc"
sink_category = "enc-cat"
[[techniques]]
name = "t"
template = "hello"
[[encodings]]
name = "rev"
transform = "reverse"
"#,
    )
    .unwrap();

    let payloads = db.payloads("enc-cat");
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].text, "olleh");
}

#[test]
fn payload_strings_convenience() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "s"
sink_category = "strings"
[[techniques]]
name = "t"
template = "abc"
"#,
    )
    .unwrap();

    let strings = db.payload_strings("strings");
    assert_eq!(strings, vec!["abc"]);
}

#[test]
fn categories_list() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "a"
sink_category = "alpha"
[[techniques]]
name = "t"
template = "x"
"#,
    )
    .unwrap();
    db.load_toml(
        r#"
[grammar]
name = "b"
sink_category = "beta"
[[techniques]]
name = "t"
template = "y"
"#,
    )
    .unwrap();

    let mut cats = db.categories();
    cats.sort_unstable();
    assert_eq!(cats, vec!["alpha", "beta"]);
}

#[test]
fn clear_resets() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "c"
sink_category = "cleared"
[[techniques]]
name = "t"
template = "x"
"#,
    )
    .unwrap();

    assert_eq!(db.grammar_count(), 1);
    db.clear();
    assert_eq!(db.grammar_count(), 0);
    assert!(db.payloads("cleared").is_empty());
}

#[test]
fn missing_category_returns_empty() {
    let mut db = PayloadDb::new();
    assert!(db.payloads("nonexistent").is_empty());
}

#[test]
fn load_dir_with_tempdir() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("test.toml"),
        r#"
[grammar]
name = "dir-test"
sink_category = "dir-cat"
[[techniques]]
name = "t"
template = "from-dir"
"#,
    )
    .unwrap();

    // Non-TOML file should be skipped.
    std::fs::write(dir.path().join("readme.txt"), "not a grammar").unwrap();

    let mut db = PayloadDb::new();
    let errors = db.load_dir(dir.path()).unwrap();
    assert!(errors.is_empty());

    assert_eq!(db.payloads("dir-cat").len(), 1);
    assert_eq!(db.payloads("dir-cat")[0].text, "from-dir");
}

#[test]
fn load_dir_not_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file.txt");
    std::fs::write(&file, "not a dir").unwrap();

    let mut db = PayloadDb::new();
    assert!(db.load_dir(&file).is_err());
}

#[test]
fn invalid_toml_error() {
    let mut db = PayloadDb::new();
    let result = db.load_toml("this is not valid {{{ toml");
    assert!(result.is_err());
}

#[test]
fn load_dir_collects_errors_and_continues() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("good.toml"),
        r#"
[grammar]
name = "good"
sink_category = "dir-cat"
[[techniques]]
name = "t"
template = "ok"
"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("bad.toml"), "not valid toml {{{").unwrap();

    let mut db = PayloadDb::new();
    let errors = db.load_dir(dir.path()).unwrap();

    assert_eq!(errors.len(), 1);
    assert_eq!(db.payloads("dir-cat").len(), 1);
    assert_eq!(db.payloads("dir-cat")[0].text, "ok");
}

#[test]
fn load_dir_lenient_collects_template_errors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("bad-template.toml"),
        r#"
[grammar]
name = "bad-template"
sink_category = "dir-cat"
[[techniques]]
name = "t"
template = "{broken"
"#,
    )
    .unwrap();

    let mut db = PayloadDb::new();
    let errors = db.load_dir_lenient(dir.path()).unwrap();

    assert_eq!(errors.len(), 1);
    assert!(matches!(errors[0], PayloadError::GrammarValidation { .. }));
    assert!(db.payloads("dir-cat").is_empty());
}

#[test]
fn load_toml_rejects_empty_technique_templates() {
    let mut db = PayloadDb::new();
    let error = db
        .load_toml(
            r#"
[grammar]
name = "invalid"
sink_category = "dir-cat"

[[techniques]]
name = "blank"
template = "   "
"#,
        )
        .unwrap_err();

    match error {
        PayloadError::GrammarValidation { issues, .. } => {
            assert!(issues
                .iter()
                .any(|issue| issue.message.contains("empty template")));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_dir_reports_concurrent_loads_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let db = PayloadDb::new();
    let _guard = db.begin_load_session().unwrap();

    let mut db = db;
    let error = db.load_dir_lenient(dir.path()).unwrap_err();
    assert!(matches!(error, PayloadError::ConcurrentLoad));
}

#[test]
fn variable_expansion_with_encodings() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "ve"
sink_category = "ve-cat"

[[contexts]]
name = "c"
prefix = "'"
suffix = ""

[[techniques]]
name = "t"
template = "{prefix}OR {tautology}"

[[tautologies]]
value = "1=1"

[[encodings]]
name = "raw"
transform = "identity"

[[encodings]]
name = "url"
transform = "url_encode"
"#,
    )
    .unwrap();

    let payloads = db.payloads("ve-cat");
    assert_eq!(payloads.len(), 2); // 1 var × 1 technique × 2 encodings
    let texts: Vec<&str> = payloads.iter().map(|p| p.text.as_str()).collect();
    assert!(texts.contains(&"'OR 1=1"));
    assert!(texts.contains(&"%27OR%201%3D1"));
}

#[test]
fn payload_metadata_propagates() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "meta"
sink_category = "meta-cat"
severity = "high"
cwe = "CWE-89"

[[techniques]]
name = "t"
template = "SELECT 1"
confidence = 0.75
expected_pattern = "SELECT"
"#,
    )
    .unwrap();

    let payloads = db.payloads("meta-cat");
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].severity.as_deref(), Some("high"));
    assert_eq!(payloads[0].cwe.as_deref(), Some("CWE-89"));
    assert!((payloads[0].confidence - 0.75).abs() < f64::EPSILON);
    assert_eq!(payloads[0].expected_pattern.as_deref(), Some("SELECT"));
}

#[test]
fn iter_payloads_streams_category_payloads() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "stream"
sink_category = "stream-cat"

[[techniques]]
name = "t1"
template = "{var}"

[[vars]]
value = "a"
[[vars]]
value = "b"
"#,
    )
    .unwrap();

    let payloads: Vec<_> = db
        .iter_payloads("stream-cat")
        .filter_map(Result::ok)
        .collect();

    assert_eq!(payloads.len(), 2);
    assert_eq!(payloads[0].text, "a");
    assert_eq!(payloads[1].text, "b");
}

#[test]
fn iter_payloads_honors_deduplication_and_limits() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        deduplicate: true,
        max_per_category: 1,
        ..PayloadConfig::default()
    });
    db.load_toml(
        r#"
[grammar]
name = "stream-limit"
sink_category = "stream-limit-cat"

[[techniques]]
name = "a"
template = "same"

[[techniques]]
name = "b"
template = "same"
"#,
    )
    .unwrap();

    let payloads: Vec<_> = db
        .iter_payloads("stream-limit-cat")
        .filter_map(Result::ok)
        .collect();

    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].text, "same");
}

#[test]
fn load_config_and_grammars_loads_relative_grammar_dirs() {
    let root = tempfile::tempdir().unwrap();
    let grammars_dir = root.path().join("grammars");
    std::fs::create_dir(&grammars_dir).unwrap();
    std::fs::write(
        grammars_dir.join("xss.toml"),
        r#"
[grammar]
name = "xss"
sink_category = "xss"

[[techniques]]
name = "basic"
template = "<script>alert(1)</script>"
"#,
    )
    .unwrap();
    let config_path = root.path().join("santh-payloads.toml");
    std::fs::write(
        &config_path,
        r#"
deduplicate = true
grammar_dirs = ["./grammars"]
"#,
    )
    .unwrap();

    let (mut db, errors) = PayloadDb::load_config_and_grammars(&config_path).unwrap();

    assert!(errors.is_empty());
    assert_eq!(db.payloads("xss").len(), 1);
    assert_eq!(db.payloads("xss")[0].text, "<script>alert(1)</script>");
}

#[test]
fn load_config_and_grammars_returns_collected_grammar_errors() {
    let root = tempfile::tempdir().unwrap();
    let grammars_dir = root.path().join("grammars");
    std::fs::create_dir(&grammars_dir).unwrap();
    std::fs::write(
        grammars_dir.join("good.toml"),
        r#"
[grammar]
name = "good"
sink_category = "cat"

[[techniques]]
name = "ok"
template = "payload"
"#,
    )
    .unwrap();
    std::fs::write(grammars_dir.join("bad.toml"), "not valid toml {{{").unwrap();
    let config_path = root.path().join("santh-payloads.toml");
    std::fs::write(&config_path, "grammar_dirs = [\"./grammars\"]").unwrap();

    let (mut db, errors) = PayloadDb::load_config_and_grammars(&config_path).unwrap();

    assert_eq!(errors.len(), 1);
    assert_eq!(db.payloads("cat").len(), 1);
}

#[test]
fn expand_category_warns_when_over_length_payload_dropped() {
    // Residual Law-10 fix for loader.rs:494: a grammar whose FIRST payload is
    // short (so it passes load-time validation, which only checks the first
    // payload) but whose SECOND context expands beyond max_payload_length. The
    // over-length payload is dropped during expand_category; that drop must now
    // be LOUD (tracing::warn), not a silent `filter_map(Result::ok)`.
    let config = attackstr::PayloadConfig::builder()
        .max_payload_length(20)
        .build();
    let mut db = PayloadDb::with_config(config);
    db.load_toml(
        r#"
[grammar]
name = "resid"
sink_category = "resid-cat"

[[contexts]]
name = "short"
prefix = "A"
suffix = ""

[[contexts]]
name = "long"
prefix = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
suffix = ""

[[techniques]]
name = "t1"
template = "{prefix}"

[[encodings]]
name = "raw"
transform = "identity"
"#,
    )
    .expect("load must succeed: the first payload is under the cap");

    let logs = super::capture_logs(|| {
        let payloads = db.payloads("resid-cat");
        // The short payload survives (its pre-marker expansion is under the cap);
        // the 50-byte one is dropped, so nothing over the cap slips through.
        assert!(!payloads.is_empty(), "the short payload must survive");
        assert!(
            payloads.iter().all(|p| p.text.len() <= 20 + 3), // +marker "SLN"
            "no over-length payload should be present, got {:?}",
            payloads.iter().map(|p| p.text.len()).collect::<Vec<_>>()
        );
    });

    assert!(
        logs.contains("dropping payload") && logs.contains("WARN"),
        "the over-length drop must be surfaced via a WARN log; got: {logs:?}"
    );
}
