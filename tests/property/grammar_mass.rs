//! Mass grammar / encoding property tests (S-proptest-02).

use attackstr::{
    apply_encoding, depluralize, expand, expand_template, validate, BuiltinEncoding, Context,
    Encoding, Grammar, GrammarMeta, Technique, Variable,
};
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

fn minimal_grammar(name: &str, category: &str, template: &str) -> Grammar {
    Grammar {
        meta: GrammarMeta {
            name: name.into(),
            sink_category: category.into(),
            description: None,
            tags: Vec::new(),
            severity: None,
            cwe: None,
            target_runtime: None,
        },
        contexts: vec![Context {
            name: "ctx".into(),
            prefix: String::new(),
            suffix: String::new(),
            target_media_type: None,
        }],
        techniques: vec![Technique {
            name: "t".into(),
            template: template.into(),
            tags: Vec::new(),
            confidence: 1.0,
            expected_pattern: None,
        }],
        encodings: vec![Encoding {
            name: "raw".into(),
            transform: "identity".into(),
        }],
        variables: HashMap::new(),
    }
}

macro_rules! grammar_validate_never_panics {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            $(
                #[test]
                fn $name(
                    name in "[a-zA-Z0-9_-]{0,40}",
                    category in "[a-zA-Z0-9_-]{0,40}",
                    template in "\\PC{0,200}",
                ) {
                    let grammar = minimal_grammar(&name, &category, &template);
                    let _ = validate(&grammar);
                }
            )+
        }
    };
}

grammar_validate_never_panics! {
    grammar_validate_nopanic_01,
    grammar_validate_nopanic_02,
    grammar_validate_nopanic_03,
    grammar_validate_nopanic_04,
    grammar_validate_nopanic_05,
    grammar_validate_nopanic_06,
    grammar_validate_nopanic_07,
    grammar_validate_nopanic_08,
    grammar_validate_nopanic_09,
    grammar_validate_nopanic_10,
    grammar_validate_nopanic_11,
    grammar_validate_nopanic_12,
    grammar_validate_nopanic_13,
    grammar_validate_nopanic_14,
    grammar_validate_nopanic_15,
    grammar_validate_nopanic_16,
    grammar_validate_nopanic_17,
    grammar_validate_nopanic_18,
    grammar_validate_nopanic_19,
    grammar_validate_nopanic_20,
    grammar_validate_nopanic_21,
}

macro_rules! expand_template_nopanic {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            $(
                #[test]
                fn $name(template in "\\PC{0,300}") {
                    let lookup = HashMap::new();
                    let _ = expand_template(template, &lookup);
                }
            )+
        }
    };
}

expand_template_nopanic! {
    expand_template_nopanic_16,
    expand_template_nopanic_17,
    expand_template_nopanic_18,
    expand_template_nopanic_19,
    expand_template_nopanic_20,
    expand_template_nopanic_21,
    expand_template_nopanic_22,
    expand_template_nopanic_23,
    expand_template_nopanic_24,
    expand_template_nopanic_25,
}

macro_rules! encoding_identity_roundtrip {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            $(
                #[test]
                fn $name(s in "\\PC{0,128}") {
                    let out = apply_encoding(&s, "identity").unwrap();
                    assert_eq!(out, s);
                }
            )+
        }
    };
}

encoding_identity_roundtrip! {
    encoding_identity_26,
    encoding_identity_27,
    encoding_identity_28,
    encoding_identity_29,
    encoding_identity_30,
    encoding_identity_31,
    encoding_identity_32,
    encoding_identity_33,
    encoding_identity_34,
    encoding_identity_35,
}

macro_rules! grammar_expand_count_bounded {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(24))]

            $(
                #[test]
                fn $name(
                    n_vars in 1usize..4,
                ) {
                    let mut grammar = minimal_grammar("b", "xss", "static");
                    for i in 0..n_vars {
                        grammar.variables.insert(
                            format!("vars{i}"),
                            vec![Variable { value: format!("v{i}") }],
                        );
                    }
                    let custom = HashMap::new();
                    if let Ok(payloads) = expand(&grammar, &custom, 64 * 1024) {
                        assert!(payloads.len() < 10_000);
                    }
                }
            )+
        }
    };
}

grammar_expand_count_bounded! {
    grammar_expand_bounded_36,
    grammar_expand_bounded_37,
    grammar_expand_bounded_38,
    grammar_expand_bounded_39,
    grammar_expand_bounded_40,
}
