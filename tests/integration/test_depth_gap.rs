use attackstr::{MarkerPosition, PayloadConfig, PayloadDb};

#[test]
fn test_gap_marker_replacement_not_found() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        marker_position: MarkerPosition::Replace("{NON_EXISTENT}".into()),
        ..Default::default()
    });

    let toml = r#"
[grammar]
name = "gap1"
sink_category = "gap"

[[techniques]]
name = "t1"
template = "payload"
"#;

    // This should ideally pass if the engine silently ignores a missing replacement,
    // or fail if it strictly requires the marker to be placed. The gap is that
    // replacing a non-existent marker shouldn't necessarily crash or misbehave,
    // but the engine's contract expects payloads to carry markers if requested.
    let result = db.load_toml(toml);
    assert!(result.is_ok());

    let marked = db.payloads_with_marker("gap", "SLN");
    // If the marker position is Replace("{NON_EXISTENT}"), and it's not in the template,
    // the marker might not be placed at all. That is a finding!
    assert!(!marked.is_empty());
    // In theory, a strict engine might return an error if it can't place the marker.
    // For now we just test that it doesn't crash.
}

#[test]
fn test_gap_duplicate_techniques_same_template() {
    let mut db = PayloadDb::new();
    let toml = r#"
[grammar]
name = "gap2"
sink_category = "gap2"

[[techniques]]
name = "t1"
template = "payload"

[[techniques]]
name = "t1"
template = "payload"
"#;
    let result = db.load_toml(toml);
    assert!(result.is_ok());

    // The engine dedups by default. Two identical techniques might be reduced to one.
    // Does it?
    let payloads = db.payloads("gap2");
    assert_eq!(
        payloads.len(),
        1,
        "Duplicate techniques with identical templates should be deduplicated"
    );
}

#[test]
fn test_gap_circular_dependency_graceful_failure() {
    let mut db = PayloadDb::new();
    let toml = r#"
[grammar]
name = "gap3"
sink_category = "gap3"

[[a]]
value = "{b}"

[[b]]
value = "{a}"

[[techniques]]
name = "t1"
template = "{a}"
"#;
    let result = db.load_toml(toml);
    // Based on the contract, circular dependencies should fail cleanly, not crash.
    assert!(result.is_err());
}
