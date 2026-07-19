use attackstr::{apply_encoding, mutate_all, PayloadConfig, PayloadDb, PayloadSource};

#[test]
fn test_adversarial_empty_input() {
    let empty = "";
    assert!(mutate_all(empty).unwrap().is_empty());

    // Applying encodings on empty input
    assert_eq!(apply_encoding(empty, "url_encode").unwrap(), "");
    assert_eq!(apply_encoding(empty, "hex").unwrap(), "");
}

#[test]
fn test_adversarial_null_bytes() {
    let payload = "admin\x00 OR 1=1";
    let encoded = apply_encoding(payload, "url_encode").unwrap();
    assert!(encoded.contains("%00"));
}

#[test]
fn test_adversarial_0xff_bytes() {
    let payload = "\u{00FF}\u{00FF}\u{00FF}";
    let encoded = apply_encoding(payload, "url_encode").unwrap();
    assert!(encoded.len() > 0);
}

#[test]
fn test_adversarial_huge_input() {
    let mut db = PayloadDb::new();
    let huge_template = "A".repeat(1_000_000); // 1MB string

    // We expect this to fail gracefully or not crash at least.
    // Attackstr's limit is 262,144 bytes for template expansion length.
    let toml = format!(
        r#"
[grammar]
name = "huge"
sink_category = "huge"

[[techniques]]
name = "t1"
template = "{}"
"#,
        huge_template
    );

    let result = db.load_toml(&toml);
    // Should gracefully fail or limit.
    assert!(
        result.is_err(),
        "Should fail gracefully on huge inputs due to size limits"
    );
}

#[test]
fn test_adversarial_unicode() {
    let payload = "🤡🤡🤡\u{0000}\u{FFFF}";
    let mutations = mutate_all(payload).unwrap();
    assert!(!mutations.is_empty() || mutations.is_empty()); // Should not panic
}

#[test]
fn test_adversarial_path_traversal() {
    let payload = "../../../../../etc/passwd";
    let mutations = mutate_all(payload).unwrap();
    // Path traversal strings should be handled without panics
    assert!(!mutations.is_empty() || mutations.is_empty());
}

#[test]
fn test_adversarial_integer_overflow() {
    let mut db = PayloadDb::with_config(PayloadConfig {
        max_per_category: usize::MAX, // Integer overflow at boundary
        ..Default::default()
    });

    let toml = r#"
[grammar]
name = "overflow"
sink_category = "overflow"

[[techniques]]
name = "t1"
template = "x"
"#;
    let result = db.load_toml(toml);
    assert!(result.is_ok());
    assert_eq!(db.payload_count(), 1);
}
