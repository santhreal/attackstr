use attackstr::{
    apply_encoding, mutate_all, mutate_case, mutate_encoding_mix, mutate_html, mutate_null_bytes,
    EncodingError,
    mutate_sql_comments, mutate_unicode, mutate_whitespace, MarkerPosition, Payload, PayloadConfig,
    PayloadDb, StaticPayloads,
};
use std::sync::{Arc, Mutex};
use std::thread;

// 1. Empty input / zero-length slices

#[test]
fn test_mutate_case_empty() {
    let variants = mutate_case("");
    assert!(variants.is_empty());
}

#[test]
fn test_mutate_whitespace_empty() {
    let variants = mutate_whitespace("");
    assert!(variants.is_empty());
}

#[test]
fn test_mutate_encoding_mix_empty() {
    let variants = mutate_encoding_mix("", &["url", "hex"]).unwrap();
    assert!(variants.is_empty());
}

#[test]
fn test_mutate_encoding_mix_empty_encodings() {
    let variants = mutate_encoding_mix("payload", &[]).unwrap();
    assert!(variants.is_empty());
}

#[test]
fn test_apply_encoding_empty() {
    let encoded = apply_encoding("", "url").unwrap();
    assert_eq!(encoded, "");
}

// 2. Null bytes in input

#[test]
fn test_mutate_null_bytes_with_null_input() {
    let variants = mutate_null_bytes("\0\0\0");
    assert!(!variants.is_empty());
    for v in variants {
        assert!(v.contains('\0') || v.contains("%00"));
    }
}

#[test]
fn test_apply_encoding_null_bytes() {
    let encoded = apply_encoding("a\0b", "hex").unwrap();
    assert_eq!(encoded, "%61%00%62");
}

#[test]
fn test_mutate_html_null_bytes() {
    let variants = mutate_html("<\0script>");
    assert!(!variants.is_empty());
}

// 3. Maximum u32/u64 values for any numeric parameter

#[test]
fn test_config_max_per_category_max_usize() {
    let config = PayloadConfig::builder()
        .max_per_category(usize::MAX)
        .build();
    assert_eq!(config.max_per_category, usize::MAX);
}

#[test]
fn test_grammar_expansion_length_limit() {
    let mut db = PayloadDb::new();
    let toml = format!(
        r#"
[grammar]
name = "huge"
sink_category = "huge"

[[contexts]]
name = "c1"
prefix = "{}"
suffix = ""

[[techniques]]
name = "t1"
template = "{{prefix}}"

[[encodings]]
name = "raw"
transform = "identity"
"#,
        // Exceed MAX_TEMPLATE_LENGTH (256 KB) so expansion is rejected with
        // ExpansionLengthExceeded. A value under the cap is legitimately allowed,
        // so the trigger must be larger than the limit to exercise the guard.
        "A".repeat(300_000)
    );
    let res = db.load_toml(&toml);
    assert!(res.is_err());
}

// 4. 1MB+ input (if the crate processes byte buffers)

#[test]
fn test_mutate_all_1mb_input() {
    let large_input = "A".repeat(1024 * 1024);
    let variants = mutate_all(&large_input).unwrap();
    assert!(!variants.is_empty());
    assert!(variants[0].len() >= 1024 * 1024);
}

#[test]
fn test_apply_encoding_1mb_input() {
    let large_input = "A".repeat(1024 * 1024);
    let encoded = apply_encoding(&large_input, "hex").unwrap();
    assert_eq!(encoded.len(), 1024 * 1024 * 3); // Each 'A' becomes '%41'
}

#[test]
fn test_mutate_html_1mb_input() {
    let large_input = format!("<script>{}</script>", "A".repeat(1024 * 1024));
    let variants = mutate_html(&large_input);
    assert!(!variants.is_empty());
}

// 5. Concurrent access from 8 threads (if the crate has shared state)

#[test]
fn test_payload_db_concurrent_access() {
    let config = PayloadConfig::default();
    let db = Arc::new(Mutex::new(PayloadDb::with_config(config)));
    let mut handles = vec![];

    for i in 0..8 {
        let db_clone = Arc::clone(&db);
        let handle = thread::spawn(move || {
            let toml = format!(
                r#"
[grammar]
name = "t{}"
sink_category = "cat{}"

[[techniques]]
name = "tech"
template = "payload{}"
"#,
                i, i, i
            );
            let mut db_lock = db_clone.lock().unwrap();
            let _ = db_lock.load_toml(&toml);
            let payloads = db_lock.payloads(&format!("cat{}", i));
            assert!(!payloads.is_empty());
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_mutate_concurrent_access() {
    let mut handles = vec![];
    for _ in 0..8 {
        let handle = thread::spawn(|| {
            let variants = mutate_all("<script>alert(1)</script>").unwrap();
            assert!(!variants.is_empty());
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_apply_encoding_concurrent() {
    let mut handles = vec![];
    for _ in 0..8 {
        let handle = thread::spawn(|| {
            let encoded = apply_encoding("test string", "url").unwrap();
            assert_eq!(encoded, "test%20string");
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

// 6. Malformed/truncated input (partial data, missing headers)

#[test]
fn test_toml_missing_headers() {
    let mut db = PayloadDb::new();
    let toml = r#"
name = "missing_grammar_table"
sink_category = "test"
"#;
    let err = db.load_toml(toml).unwrap_err();
    assert!(err.to_string().contains("missing field `grammar`"));
}

#[test]
fn test_toml_malformed() {
    let mut db = PayloadDb::new();
    let toml = r#"
[grammar
name = "unclosed
"#;
    let err = db.load_toml(toml).unwrap_err();
    assert!(err.to_string().contains("grammar parse error"));
}

#[test]
fn test_apply_encoding_unknown_encoding() {
    // An unknown transform must fail closed (no silent identity fallback):
    // apply_encoding returns Err(UnknownTransform) naming the bad transform.
    let err = apply_encoding("test", "nonexistent_encoding").unwrap_err();
    assert!(
        matches!(&err, EncodingError::UnknownTransform { transform } if transform == "nonexistent_encoding"),
        "expected UnknownTransform for an unknown encoding, got {err:?}"
    );
}

#[test]
fn test_mutate_html_malformed() {
    let variants = mutate_html("<script");
    assert!(!variants.is_empty());
}

// 7. Unicode edge cases (BOM, overlong sequences, surrogates)

#[test]
fn test_mutate_unicode_bom() {
    let payload = "\u{FEFF}test";
    let variants = mutate_unicode(payload);
    assert!(!variants.is_empty());
}

#[test]
fn test_mutate_unicode_rtl() {
    let payload = "\u{202E}test";
    let variants = mutate_unicode(payload);
    assert!(!variants.is_empty());
}

#[test]
fn test_apply_encoding_emoji() {
    let payload = "🔥";
    let encoded = apply_encoding(payload, "hex").unwrap();
    // UTF-8 for 🔥 is F0 9F 94 A5
    assert_eq!(encoded, "%f0%9f%94%a5");
}

#[test]
fn test_mutate_case_unicode() {
    let payload = "ß"; // uppercase is SS in some locales, or just ß
    let variants = mutate_case(payload);
    assert!(!variants.is_empty());
}

#[test]
fn test_mutate_unicode_homoglyphs() {
    let payload = "a e o p c x y d < > ' \"";
    let variants = mutate_unicode(payload);
    assert!(!variants.is_empty());
}

// 8. Duplicate entries (same key twice, same pattern twice)

#[test]
fn test_toml_duplicate_keys() {
    let mut db = PayloadDb::new();
    let toml = r#"
[grammar]
name = "dup"
sink_category = "dup"

[[techniques]]
name = "t1"
template = "1"

[[techniques]]
name = "t1"
template = "2"
"#;
    let res = db.load_toml(toml);
    assert!(res.is_ok());
    let payloads = db.payloads("dup");
    assert_eq!(payloads.len(), 2);
}

#[test]
fn test_static_payloads_duplicates() {
    let payload = Payload {
        text: "test".into(),
        category: "cat".into(),
        technique: "t1".into(),
        context: "c1".into(),
        encoding: "raw".into(),
        cwe: None,
        severity: None,
        confidence: 1.0,
        expected_pattern: None,
        target_media_type: None,
    };
    let source = StaticPayloads::new(vec![payload.clone(), payload.clone()]);
    assert_eq!(source.all_payloads().len(), 2);
}

// 9. Off-by-one: first byte, last byte, boundary between chunks

#[test]
fn test_mutate_whitespace_off_by_one() {
    let payload = "a";
    let variants = mutate_whitespace(payload);
    assert!(variants.is_empty());
}

#[test]
fn test_mutate_encoding_mix_one_char() {
    let payload = "a";
    let variants = mutate_encoding_mix(payload, &["url", "hex"]).unwrap();
    assert!(variants.is_empty());
}

#[test]
fn test_mutate_null_bytes_short() {
    let payload = "ab";
    let variants = mutate_null_bytes(payload);
    assert!(!variants.is_empty());
}

#[test]
fn test_mutate_sql_comments_one_word() {
    let payload = "SELECT";
    let variants = mutate_sql_comments(payload);
    assert!(variants.is_empty());
}

// 10. Resource exhaustion: 100K items, deeply nested structures

#[test]
fn test_toml_resource_exhaustion_100k_techniques() {
    let mut toml = r#"
[grammar]
name = "huge"
sink_category = "huge"
"#
    .to_string();
    // Distinct templates so value-dedup (the documented default) does not
    // collapse them; this verifies all 10000 techniques load and expand
    // without resource exhaustion rather than deduping to a single payload.
    for i in 0..10000 {
        toml.push_str(&format!(
            "\n[[techniques]]\nname = \"t{i}\"\ntemplate = \"p{i}\"\n"
        ));
    }
    let mut db = PayloadDb::new();
    let res = db.load_toml(&toml);
    assert!(res.is_ok());
    assert_eq!(db.payloads("huge").len(), 10000);
}

#[test]
fn test_payload_config_exclude_all() {
    let config = PayloadConfig::builder()
        .exclude_categories(vec!["cat1".to_string(), "cat2".to_string()])
        .build();
    let mut db = PayloadDb::with_config(config);
    let toml = r#"
[grammar]
name = "g1"
sink_category = "cat1"

[[techniques]]
name = "t1"
template = "p"
"#;
    db.load_toml(toml).unwrap();
    assert!(db.payloads("cat1").is_empty());
}

#[test]
fn test_marker_position_inline_huge() {
    let config = PayloadConfig::builder()
        .marker_position(MarkerPosition::Inline)
        .build();
    let mut db = PayloadDb::with_config(config);
    let toml = r#"
[grammar]
name = "g1"
sink_category = "cat1"

[[techniques]]
name = "t1"
template = "p"
"#;
    db.load_toml(toml).unwrap();
    let payloads = db.payloads_with_marker("cat1", "MARKER");
    assert!(!payloads.is_empty());
    assert!(payloads[0].text.contains("MARKER"));
}

#[test]
fn test_payload_hash_equality() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    let p1 = Payload {
        text: "A".into(),
        category: "C".into(),
        ..Payload::default()
    };
    let p2 = Payload {
        text: "A".into(),
        category: "C".into(),
        ..Payload::default()
    };
    set.insert(p1);
    assert!(!set.insert(p2)); // Should be false because it's a duplicate
}

#[test]
fn test_mutate_all_empty() {
    let variants = mutate_all("").unwrap();
    assert!(variants.is_empty());
}

#[test]
fn test_grammar_template_unclosed_braces() {
    let mut db = PayloadDb::new();
    let toml = r#"
[grammar]
name = "unclosed"
sink_category = "unclosed"

[[techniques]]
name = "t1"
template = "{prefix"
"#;
    let err = db.load_toml(toml).unwrap_err();
    // An unclosed brace is caught fail-fast by grammar validation with a
    // specific message naming the offending technique, not the generic
    // expansion-error path.
    assert!(
        err.to_string().contains("unclosed"),
        "expected an unclosed-brace validation error, got: {err}"
    );
}

#[test]
fn test_grammar_template_recursion_limit() {
    let mut db = PayloadDb::new();
    let toml = r#"
[grammar]
name = "recursive"
sink_category = "recursive"

[[techniques]]
name = "t1"
template = "{var1}"

[[var1]]
value = "{var1}"
"#;
    let err = db.load_toml(toml).unwrap_err();
    assert!(err.to_string().contains("template expansion error"));
}
