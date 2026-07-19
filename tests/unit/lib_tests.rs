use super::*;

#[test]
fn payload_round_trips_with_serde() {
    let payload = Payload {
        text: "alert(1)".into(),
        category: "xss".into(),
        technique: "basic".into(),
        context: "default".into(),
        encoding: "raw".into(),
        cwe: Some("CWE-79".into()),
        severity: Some("high".into()),
        confidence: 0.9,
        expected_pattern: Some("alert".into()),
        target_media_type: None,
    };

    let encoded = toml::to_string(&payload).unwrap();
    let decoded: Payload = toml::from_str(&encoded).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn payload_config_builder_overrides_defaults() {
    let config = PayloadConfig::builder()
        .max_per_category(100)
        .deduplicate(false)
        .marker_prefix("TAINT")
        .exclude_categories(vec!["xxe".into()])
        .include_categories(vec!["xss".into()])
        .target_runtime(Some(vec!["php".into()]))
        .marker_position(MarkerPosition::Suffix)
        .build();

    assert_eq!(config.max_per_category, 100);
    assert!(!config.deduplicate);
    assert_eq!(config.marker_prefix, "TAINT");
    assert_eq!(config.exclude_categories, vec!["xxe"]);
    assert_eq!(config.include_categories, vec!["xss"]);
    assert_eq!(config.target_runtime, Some(vec!["php".into()]));
    assert_eq!(config.marker_position, MarkerPosition::Suffix);
}

#[test]
fn payload_config_loads_from_toml() {
    let config = PayloadConfig::from_toml(
        r#"
max_per_category = 25
deduplicate = false
marker_position = "suffix"
"#,
        "<test>",
    )
    .unwrap();

    assert_eq!(config.max_per_category, 25);
    assert!(!config.deduplicate);
    assert_eq!(config.marker_position, MarkerPosition::Suffix);
}

#[test]
fn payload_config_loads_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payloads.toml");
    std::fs::write(&path, "marker_prefix = \"TRACE\"\n").unwrap();

    let config = PayloadConfig::load(&path).unwrap();

    assert_eq!(config.marker_prefix, "TRACE");
}

#[cfg(test)]
mod payload_source_tests {
    use super::*;

    fn create_test_payload(text: &str, category: &str) -> Payload {
        Payload {
            text: text.into(),
            category: category.into(),
            technique: "test".into(),
            context: "default".into(),
            encoding: "raw".into(),
            cwe: None,
            severity: None,
            confidence: 1.0,
            expected_pattern: None,
            target_media_type: None,
        }
    }

    #[test]
    fn static_payloads_empty() {
        let source = StaticPayloads::new(vec![]);
        assert_eq!(source.payload_count(), 0);
        assert!(source.categories().is_empty());
    }

    #[test]
    fn static_payloads_single_category() {
        let payloads = vec![
            create_test_payload("payload1", "sqli"),
            create_test_payload("payload2", "sqli"),
        ];
        let source = StaticPayloads::new(payloads);

        assert_eq!(source.payload_count(), 2);
        let cats = source.categories();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0], "sqli");
    }

    #[test]
    fn static_payloads_multiple_categories() {
        let payloads = vec![
            create_test_payload("p1", "sqli"),
            create_test_payload("p2", "xss"),
            create_test_payload("p3", "rce"),
        ];
        let source = StaticPayloads::new(payloads);

        assert_eq!(source.payload_count(), 3);
        let mut cats = source.categories();
        cats.sort_unstable();
        assert_eq!(cats, vec!["rce", "sqli", "xss"]);
    }

    #[test]
    fn static_payloads_add() {
        let mut source = StaticPayloads::new(vec![]);
        source.add(create_test_payload("test", "cat"));

        assert_eq!(source.payload_count(), 1);
    }

    #[test]
    fn static_payloads_from_vec() {
        let payloads = vec![create_test_payload("test", "cat")];
        let source: StaticPayloads = payloads.into();

        assert_eq!(source.payload_count(), 1);
    }

    #[test]
    fn static_payloads_default() {
        let source = StaticPayloads::default();
        assert_eq!(source.payload_count(), 0);
    }

    #[test]
    fn static_payloads_all_payloads() {
        let payloads = vec![
            create_test_payload("p1", "sqli"),
            create_test_payload("p2", "xss"),
        ];
        let source = StaticPayloads::new(payloads);

        assert_eq!(source.all_payloads().len(), 2);
    }

    #[test]
    fn static_payloads_group_interleaved_categories() {
        let payloads = vec![
            create_test_payload("p1", "xss"),
            create_test_payload("p2", "sqli"),
            create_test_payload("p3", "xss"),
        ];
        let mut source = StaticPayloads::new(payloads);

        let xss = source.payloads("xss");
        assert_eq!(xss.len(), 2);
        assert!(xss.iter().all(|payload| payload.category == "xss"));
    }

    #[test]
    fn static_payloads_iter_category_filters() {
        let payloads = vec![
            create_test_payload("p1", "xss"),
            create_test_payload("p2", "sqli"),
            create_test_payload("p3", "xss"),
        ];
        let source = StaticPayloads::new(payloads);

        let texts: Vec<_> = source
            .iter_category("xss")
            .map(|payload| payload.text.as_str())
            .collect();

        assert_eq!(texts, vec!["p1", "p3"]);
    }

    #[test]
    fn static_payloads_iter_returns_all_items() {
        let payloads = vec![
            create_test_payload("p1", "xss"),
            create_test_payload("p2", "sqli"),
        ];
        let source = StaticPayloads::new(payloads);

        let texts: Vec<_> = source.iter().map(|payload| payload.text.as_str()).collect();
        assert_eq!(texts, vec!["p2", "p1"]);
    }

    #[test]
    fn payload_db_implements_payload_source() {
        fn use_trait(source: &mut dyn PayloadSource) -> usize {
            source.payload_count()
        }

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
name = "t1"
template = "hello"
"#,
        )
        .unwrap();

        // Test through the trait interface
        assert_eq!(use_trait(&mut db), 1);

        let cats = db.categories();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0], "test-cat");

        let payloads = db.payloads("test-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "hello");
    }

    #[test]
    fn static_payloads_implements_payload_source() {
        fn use_trait(s: &mut dyn PayloadSource) -> usize {
            s.payload_count()
        }

        let payloads = vec![
            create_test_payload("p1", "cat1"),
            create_test_payload("p2", "cat2"),
        ];
        let mut source = StaticPayloads::new(payloads);

        // Test through the trait interface
        assert_eq!(use_trait(&mut source), 2);
    }

    #[test]
    fn payload_source_trait_object_works() {
        let payloads = vec![create_test_payload("test", "cat")];
        let source: Box<dyn PayloadSource> = Box::new(StaticPayloads::new(payloads));

        assert_eq!(source.payload_count(), 1);
        assert_eq!(source.categories(), vec!["cat"]);
    }
}

#[cfg(test)]
mod encoder_tests {
    use super::{CustomEncoder, Encoder};

    #[test]
    fn custom_encoder_new() {
        let encoder = CustomEncoder::new(|s: &str| s.to_uppercase());
        assert_eq!(encoder.encode("hello"), "HELLO");
    }

    #[test]
    fn custom_encoder_default() {
        let encoder = CustomEncoder::default();
        assert_eq!(encoder.encode("hello"), "hello");
    }

    #[test]
    fn encoder_trait_for_fn() {
        fn upper(s: &str) -> String {
            s.to_uppercase()
        }
        let encoder: &dyn Encoder = &upper;
        assert_eq!(encoder.encode("hello"), "HELLO");
    }

    #[test]
    fn encoder_trait_for_closure() {
        let reverse = |s: &str| s.chars().rev().collect::<String>();
        assert_eq!(reverse.encode("hello"), "olleh");
    }

    #[test]
    fn encoder_trait_for_rot13() {
        let rot13 = |s: &str| {
            s.chars()
                .map(|c| match c {
                    'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                    'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                    _ => c,
                })
                .collect::<String>()
        };
        assert_eq!(rot13.encode("hello"), "uryyb");
    }
}
