use super::*;

#[test]
fn expand_template_basic() {
    let mut lookup = HashMap::new();
    lookup.insert("tautology".to_string(), vec!["1=1".into(), "2>1".into()]);
    lookup.insert("comment".to_string(), vec!["--".into(), "#".into()]);

    let res = expand_template("OR {tautology}{comment}".into(), &lookup).unwrap();
    assert_eq!(res.len(), 4);
    assert!(res.contains(&"OR 1=1--".into()));
    assert!(res.contains(&"OR 2>1#".into()));
}

#[test]
fn expand_template_no_vars() {
    let lookup = HashMap::new();
    let res = expand_template("static content".into(), &lookup).unwrap();
    assert_eq!(res, vec!["static content"]);
}

#[test]
fn expand_template_missing_var() {
    let mut lookup = HashMap::new();
    lookup.insert("a".into(), vec!["X".into()]);

    let res = expand_template("{a}:{missing}".into(), &lookup).unwrap();
    assert_eq!(res, vec!["X:{missing}"]);
}

#[test]
fn expand_template_preserves_marker_placeholder() {
    let lookup = HashMap::new();
    let res = expand_template("<!-- {MARKER} -->".into(), &lookup).unwrap();
    assert_eq!(res, vec!["<!-- {MARKER} -->"]);
}

#[test]
fn expand_template_preserves_unknown_braces() {
    let lookup = HashMap::new();
    let res = expand_template("function() { return 1; }".into(), &lookup).unwrap();
    assert_eq!(res, vec!["function() { return 1; }"]);
}

#[test]
fn expand_template_nested() {
    let mut lookup = HashMap::new();
    lookup.insert("inner".into(), vec!["X".into()]);
    lookup.insert("outer".into(), vec!["{inner}".into()]);

    let res = expand_template("{outer}".into(), &lookup).unwrap();
    assert_eq!(res, vec!["X"]);
}

#[test]
fn expand_template_unclosed_brace_errors() {
    let lookup = HashMap::new();
    let err = expand_template("prefix {broken".into(), &lookup).unwrap_err();
    assert!(matches!(err, TemplateExpansionError::UnclosedBrace { .. }));
}

#[test]
fn expand_template_recursion_limit_errors() {
    let mut lookup = HashMap::new();
    lookup.insert("loop".into(), vec!["{loop}".into()]);

    let err = expand_template("{loop}".into(), &lookup).unwrap_err();
    assert!(matches!(
        err,
        TemplateExpansionError::RecursionLimitExceeded { max_depth: 50 }
    ));
}
#[test]
fn expand_template_deeply_nested_escaped_braces_does_not_overflow_stack() {
    let lookup = HashMap::new();
    // 100,000 escaped braces would overflow thread call-stack if using call-stack recursion
    let template = "{{".repeat(10_000);
    let res = expand_template(template, &lookup).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0], "{".repeat(10_000));
}

#[test]
fn depluralize_cases() {
    assert_eq!(depluralize("tautologies"), "tautology");
    assert_eq!(depluralize("comments"), "comment");
    assert_eq!(depluralize("vars"), "var");
    assert_eq!(depluralize("s"), "s"); // too short
    assert_eq!(depluralize("ssrf_targets"), "ssrf_target");
    // "-sses" plurals drop "es", not just "s" (regression for bypasse bug).
    assert_eq!(depluralize("bypasses"), "bypass");
    assert_eq!(depluralize("classes"), "class");
    assert_eq!(depluralize("passes"), "pass");
    // A single-s stem ending in "es" but not "sses" keeps the plain -s rule.
    assert_eq!(depluralize("houses"), "house");
}

#[test]
fn expand_grammar_cartesian() {
    let mut vars = HashMap::new();
    vars.insert(
        "vars".to_string(),
        vec![
            Variable { value: "A".into() },
            Variable { value: "B".into() },
            Variable { value: "C".into() },
        ],
    );

    let grammar = Grammar {
        meta: GrammarMeta {
            name: "test".into(),
            sink_category: "test".into(),
            description: None,
            tags: vec![],
            severity: None,
            cwe: None,
            target_runtime: None,
        },
        contexts: vec![Context {
            name: "c1".into(),
            prefix: String::new(),
            suffix: String::new(),
            target_media_type: None,
        }],
        techniques: vec![
            Technique {
                name: "t1".into(),
                template: "{var}".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            },
            Technique {
                name: "t2".into(),
                template: "X{var}Y".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            },
        ],
        encodings: vec![
            Encoding {
                name: "raw".into(),
                transform: "identity".into(),
            },
            Encoding {
                name: "url".into(),
                transform: "url_encode".into(),
            },
        ],
        variables: vars,
    };

    let custom = HashMap::new();
    let payloads = expand(&grammar, &custom, 0).unwrap();
    // 3 vars × 2 techniques × 2 encodings = 12
    assert_eq!(payloads.len(), 12);
}

#[test]
fn expand_grammar_defaults() {
    let grammar = Grammar {
        meta: GrammarMeta {
            name: "test".into(),
            sink_category: "test".into(),
            description: None,
            tags: vec![],
            severity: None,
            cwe: None,
            target_runtime: None,
        },
        contexts: vec![], // uses default
        techniques: vec![Technique {
            name: "t1".into(),
            template: "hello".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![], // uses default
        variables: HashMap::new(),
    };

    let custom = HashMap::new();
    let payloads = expand(&grammar, &custom, 0).unwrap();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].text, "hello");
}

#[test]
fn expand_grammar_empty_techniques() {
    let grammar = Grammar {
        meta: GrammarMeta {
            name: "empty".into(),
            sink_category: "empty".into(),
            description: None,
            tags: vec![],
            severity: None,
            cwe: None,
            target_runtime: None,
        },
        contexts: vec![],
        techniques: vec![],
        encodings: vec![],
        variables: HashMap::new(),
    };

    let custom = HashMap::new();
    let payloads = expand(&grammar, &custom, 0).unwrap();
    assert!(payloads.is_empty());
}

#[test]
fn expand_propagates_technique_metadata() {
    let grammar = Grammar {
        meta: GrammarMeta {
            name: "meta".into(),
            sink_category: "meta".into(),
            description: None,
            tags: vec![],
            severity: Some("high".into()),
            cwe: Some("CWE-79".into()),
            target_runtime: None,
        },
        contexts: vec![],
        techniques: vec![Technique {
            name: "t1".into(),
            template: "alert(1)".into(),
            tags: vec![],
            confidence: 0.42,
            expected_pattern: Some("alert".into()),
        }],
        encodings: vec![],
        variables: HashMap::new(),
    };

    let custom = HashMap::new();
    let payloads = expand(&grammar, &custom, 0).unwrap();
    assert_eq!(payloads.len(), 1);
    assert!((payloads[0].confidence - 0.42).abs() < f64::EPSILON);
    assert_eq!(payloads[0].expected_pattern.as_deref(), Some("alert"));
}
