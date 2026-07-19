use super::*;

#[test]
fn case_mutations_are_generated() {
    let variants = mutate_case("ScRiPt");
    assert!(variants.contains(&"script".to_string()));
    assert!(variants.contains(&"SCRIPT".to_string()));
    assert!(variants.contains(&"sCrIpT".to_string()));
    assert!(variants.contains(&"ScRiPt".to_string()));
}

#[test]
fn whitespace_mutations_are_generated() {
    let variants = mutate_whitespace("UNION SELECT");
    assert!(variants.contains(&"UNION\tSELECT".to_string()));
    assert!(variants.contains(&"UNION\nSELECT".to_string()));
    assert!(variants.contains(&"UNION/**/SELECT".to_string()));
}

#[test]
fn encoding_mix_mutations_are_generated() {
    let variants = mutate_encoding_mix("alert(1)", &["url_encode", "unicode"]).unwrap();
    assert!(!variants.is_empty());
    assert!(variants.iter().any(|variant| variant.contains('%')));
    assert!(variants.iter().any(|variant| variant.contains("\\u")));
}

#[test]
fn all_mutations_combine_strategies() {
    let variants = mutate_all("UNION SELECT").unwrap();
    assert!(variants.iter().any(|variant| variant.contains("/**/")));
    assert!(variants.iter().any(|variant| variant.contains('%')));
    assert!(variants.iter().any(|variant| variant != "UNION SELECT"));
}

#[test]
fn html_tag_case_mixing_uses_uppercase_first_alternation() {
    // The tag-casing path folds into `alternate_case(tag, 1)` (offset 1 =>
    // even index uppercase, odd lowercase), replacing the former
    // `alternating_ascii_case`. Pin the exact output so the consolidation
    // stays behavior-identical: "script" -> "ScRiPt", "iframe" -> "IfRaMe".
    let variants = mutate_html("<script>alert(1)</script>");
    assert!(
        variants.iter().any(|v| v.contains("<ScRiPt")),
        "expected an uppercase-first alternated <ScRiPt tag variant, got {variants:?}"
    );

    let iframe = mutate_html("<iframe src=x>");
    assert!(
        iframe.iter().any(|v| v.contains("<IfRaMe")),
        "expected <IfRaMe alternation, got {iframe:?}"
    );
}

#[test]
fn null_byte_mutations() {
    let variants = mutate_null_bytes("test");
    assert!(variants.iter().any(|v| v.starts_with("%00")));
    assert!(variants.iter().any(|v| v.ends_with("%00")));
    assert!(variants
        .iter()
        .any(|v| v.contains("%00") && !v.starts_with("%00") && !v.ends_with("%00")));
}

#[test]
fn null_byte_empty_input() {
    assert!(mutate_null_bytes("").is_empty());
}

#[test]
fn null_byte_short_inputs_only_use_prefix_and_suffix_variants() {
    let variants = mutate_null_bytes("x");
    assert_eq!(variants.len(), 4);
    assert!(variants.iter().any(|v| v == "%00x"));
    assert!(variants.iter().any(|v| v == "x%00"));
    assert!(variants.iter().any(|v| v == "x\x00"));
    assert!(variants.iter().any(|v| v == "\x00x"));
}

#[test]
fn sql_comment_mutations() {
    let variants = mutate_sql_comments("UNION SELECT 1");
    assert!(variants.iter().any(|v| v.contains("/**/")));
    assert!(variants.iter().any(|v| v.contains("/*!*/")));
    assert!(variants.iter().any(|v| v.contains("--\n")));
    assert!(variants.iter().any(|v| v.contains("#\n")));
}

#[test]
fn sql_comment_single_word_returns_empty() {
    assert!(mutate_sql_comments("SELECT").is_empty());
}

#[test]
fn html_mutations_tag_case() {
    let variants = mutate_html("<script>alert(1)</script>");
    assert!(variants.iter().any(|v| v.contains("<SCRIPT")));
    assert!(variants.iter().any(|v| v.contains("<ScRiPt")));
    assert!(variants.iter().any(|v| v.contains("<script/")));
}

#[test]
fn html_mutations_quote_variants() {
    let variants = mutate_html("onload=\"alert(1)\"");
    assert!(variants.iter().any(|v| v.contains('\'')));
    assert!(variants.iter().any(|v| v.contains('`')));
}

#[test]
fn html_mutations_no_tags_returns_fewer() {
    let variants = mutate_html("plain text");
    // No tags, no quotes, no equals  -  should produce nothing.
    assert!(variants.is_empty());
}

#[test]
fn unicode_fullwidth_mutation() {
    let variants = mutate_unicode("alert");
    assert!(!variants.is_empty());
    // Fullwidth 'a' is U+FF41.
    assert!(variants.iter().any(|v| v.contains('\u{FF41}')));
}

#[test]
fn unicode_homoglyph_mutation() {
    let variants = mutate_unicode("exec");
    assert!(!variants.is_empty());
    // Cyrillic 'е' (U+0435) replaces 'e'.
    assert!(variants.iter().any(|v| v.contains('\u{0435}')));
}

#[test]
fn unicode_no_substitutable_chars() {
    let variants = mutate_unicode("123");
    // Fullwidth digits exist, so we should get a variant.
    assert!(!variants.is_empty());
}

#[test]
fn unicode_high_codepoint_does_not_overflow() {
    let variants = mutate_unicode("\u{10ffff}");
    assert!(variants.is_empty());
}

#[test]
fn mutate_all_includes_new_strategies() {
    let variants = mutate_all("UNION SELECT 1").unwrap();
    // Should include SQL comments.
    assert!(variants.iter().any(|v| v.contains("/*!*/")));
    // Should include null bytes.
    assert!(variants.iter().any(|v| v.contains("%00")));
}

#[test]
fn mutate_all_deduplicates() {
    let variants = mutate_all("test").unwrap();
    let unique: std::collections::HashSet<&String> = variants.iter().collect();
    assert_eq!(
        variants.len(),
        unique.len(),
        "mutate_all produced duplicates"
    );
}

#[test]
fn case_mutation_preserves_non_alpha() {
    let variants = mutate_case("alert(1)");
    for v in &variants {
        assert!(v.contains("(1)"), "non-alpha chars altered in: {v}");
    }
}

#[test]
fn whitespace_mutation_single_char() {
    // Single char = too short, should return empty.
    assert!(mutate_whitespace("x").is_empty());
}

#[test]
fn encoding_mix_single_encoding() {
    // Need at least 2 encodings to mix.
    assert!(mutate_encoding_mix("test", &["url_encode"])
        .unwrap()
        .is_empty());
}

#[test]
fn encoding_mix_empty_payload() {
    assert!(mutate_encoding_mix("", &["url_encode", "hex"])
        .unwrap()
        .is_empty());
}

#[test]
fn encoding_mix_single_char() {
    assert!(mutate_encoding_mix("x", &["url_encode", "hex"])
        .unwrap()
        .is_empty());
}
