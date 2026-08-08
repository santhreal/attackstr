use super::*;

fn meta(name: &str, cat: &str) -> GrammarMeta {
    GrammarMeta {
        name: name.into(),
        sink_category: cat.into(),
        description: None,
        tags: vec![],
        severity: None,
        cwe: None,
        target_runtime: None,
    }
}

#[test]
fn valid_grammar_no_issues() {
    let mut vars = HashMap::new();
    vars.insert("cmds".into(), vec![Variable { value: "id".into() }]);

    let g = Grammar {
        meta: meta("test", "rce"),
        contexts: vec![Context {
            name: "default".into(),
            prefix: String::new(),
            suffix: String::new(),
            target_media_type: None,
        }],
        techniques: vec![Technique {
            name: "exec".into(),
            template: "{cmd}".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![Encoding {
            name: "raw".into(),
            transform: "identity".into(),
        }],
        variables: vars,
    };

    let issues = validate(&g);
    assert!(issues.is_empty(), "unexpected issues: {issues:?}");
}

#[test]
fn empty_name_is_error() {
    let g = Grammar {
        meta: meta("", "cat"),
        contexts: vec![],
        techniques: vec![],
        encodings: vec![],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues
        .iter()
        .any(|i| i.level == IssueLevel::Error && i.message.contains("name is empty")));
}
#[test]
fn empty_context_technique_encoding_names_are_errors() {
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![Context {
            name: "   ".into(),
            prefix: String::new(),
            suffix: String::new(),
            target_media_type: None,
        }],
        techniques: vec![Technique {
            name: "".into(),
            template: "payload".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![Encoding {
            name: "".into(),
            transform: "identity".into(),
        }],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues.iter().any(|i| i.level == IssueLevel::Error && i.message.contains("context has empty name")));
    assert!(issues.iter().any(|i| i.level == IssueLevel::Error && i.message.contains("technique has empty name")));
    assert!(issues.iter().any(|i| i.level == IssueLevel::Error && i.message.contains("has empty name")));
}

#[test]
fn empty_category_is_error() {
    let g = Grammar {
        meta: meta("test", ""),
        contexts: vec![],
        techniques: vec![],
        encodings: vec![],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues
        .iter()
        .any(|i| i.level == IssueLevel::Error && i.message.contains("sink_category")));
}

#[test]
fn no_techniques_warns() {
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![],
        techniques: vec![],
        encodings: vec![],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues
        .iter()
        .any(|i| i.level == IssueLevel::Warning && i.message.contains("no techniques")));
}

#[test]
fn empty_template_is_error() {
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![],
        techniques: vec![Technique {
            name: "blank".into(),
            template: "   ".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![],
        variables: HashMap::new(),
    };

    let issues = validate(&g);
    assert!(issues
        .iter()
        .any(|i| i.level == IssueLevel::Error && i.message.contains("empty template")));
}

#[test]
fn undefined_variable_warns() {
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![],
        techniques: vec![Technique {
            name: "t".into(),
            template: "{missing_var}".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues
        .iter()
        .any(|i| i.message.contains("undefined variable")));
}

#[test]
fn unclosed_brace_is_error() {
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![],
        techniques: vec![Technique {
            name: "t".into(),
            template: "unclosed {brace".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues
        .iter()
        .any(|i| i.level == IssueLevel::Error && i.message.contains("unclosed")));
}

#[test]
fn unknown_encoding_warns() {
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![],
        techniques: vec![Technique {
            name: "t".into(),
            template: "x".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![Encoding {
            name: "custom".into(),
            transform: "nonexistent_transform".into(),
        }],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues
        .iter()
        .any(|i| i.message.contains("unknown transform")));
}

#[test]
fn bad_confidence_warns() {
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![],
        techniques: vec![Technique {
            name: "t".into(),
            template: "x".into(),
            tags: vec![],
            confidence: 1.5,
            expected_pattern: None,
        }],
        encodings: vec![],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues.iter().any(|i| i.message.contains("confidence")));
}

#[test]
fn prefix_suffix_not_flagged_as_undefined() {
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![Context {
            name: "c".into(),
            prefix: "'".into(),
            suffix: "--".into(),
            target_media_type: None,
        }],
        techniques: vec![Technique {
            name: "t".into(),
            template: "{prefix}OR 1=1{suffix}".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues.is_empty(), "unexpected: {issues:?}");
}
#[test]
fn empty_variable_name_is_error() {
    let mut vars = HashMap::new();
    vars.insert("   ".into(), vec!["value".into()]);
    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![],
        techniques: vec![Technique {
            name: "t".into(),
            template: "x".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![],
        variables: vars,
    };
    let issues = validate(&g);
    assert!(issues.iter().any(|i| i.level == IssueLevel::Error && i.message.contains("variable has empty name")));
}

#[test]
fn whitespace_only_meta_names_are_errors() {
    let g = Grammar {
        meta: meta("  ", "\t"),
        contexts: vec![],
        techniques: vec![],
        encodings: vec![],
        variables: HashMap::new(),
    };
    let issues = validate(&g);
    assert!(issues.iter().any(|i| i.level == IssueLevel::Error && i.message.contains("grammar name is empty")));
    assert!(issues.iter().any(|i| i.level == IssueLevel::Error && i.message.contains("sink_category is empty")));
}

#[test]
fn plural_variable_resolves() {
    let mut vars = HashMap::new();
    vars.insert(
        "tautologies".into(),
        vec![Variable {
            value: "1=1".into(),
        }],
    );

    let g = Grammar {
        meta: meta("test", "cat"),
        contexts: vec![],
        techniques: vec![Technique {
            name: "t".into(),
            template: "{tautology}".into(),
            tags: vec![],
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![],
        variables: vars,
    };
    let issues = validate(&g);
    assert!(issues.is_empty(), "unexpected: {issues:?}");
}
