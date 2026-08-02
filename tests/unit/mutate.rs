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

/// Regression for the mutate_html body-corruption bug: the tag-mutation
/// branch used to build variants from `payload.to_lowercase()`, silently
/// rewriting the JS body (`ALERT` -> `alert`), which emits a non-functional
/// payload because JS identifiers are case-sensitive. Only the matched tag
/// span may change; the body must stay byte-for-byte intact.
#[test]
fn html_tag_mutation_preserves_payload_body_case() {
    let variants = mutate_html("<script>ALERT(1)</script>");
    // The tag-span mutations exist...
    assert!(
        variants.iter().any(|v| v == "<ScRiPt>ALERT(1)</script>"),
        "mixed-case tag variant with verbatim body missing: {variants:?}"
    );
    assert!(
        variants.iter().any(|v| v == "<script/>ALERT(1)</script>"),
        "slash-insertion variant with verbatim body missing: {variants:?}"
    );
    assert!(
        variants.iter().any(|v| v == "<script    >ALERT(1)</script>"),
        "space-insertion variant with verbatim body missing: {variants:?}"
    );
}

/// The tag lookup is case-insensitive, so an uppercase `<SCRIPT>` in the
/// original payload is still perturbed, without touching anything else.
#[test]
fn html_tag_mutation_matches_tags_case_insensitively() {
    let variants = mutate_html("<SCRIPT>Alert(1)</SCRIPT>");
    assert!(
        variants.iter().any(|v| v == "<ScRiPt>Alert(1)</SCRIPT>"),
        "case-insensitive tag match missing: {variants:?}"
    );
    // The closing tag and body are never rewritten by the tag branch.
    assert!(
        variants
            .iter()
            .filter(|v| v.starts_with("<ScRiPt>") || v.contains("/>") || v.contains("    >"))
            .all(|v| v.ends_with("</SCRIPT>")),
        "closing tag was corrupted: {variants:?}"
    );
}

/// Every occurrence of the tag is rewritten (the old `str::replace` semantics
/// are preserved), and a payload without the tag yields no tag variants.
#[test]
fn html_tag_mutation_rewrites_all_occurrences() {
    let variants = mutate_html("<script><script>x");
    assert!(
        variants.iter().any(|v| v == "<ScRiPt><ScRiPt>x"),
        "second occurrence was not rewritten: {variants:?}"
    );
}

/// The `case_alternate` encoding and the `mutate_case` mutation share one
/// `alternate_case` owner; they must agree on non-ASCII input so a maintainer
/// editing one cannot drift from the other.
#[test]
fn alternate_case_encoding_and_mutation_agree_on_non_ascii() {
    // 'é' is a non-ASCII alphabetic char: the unified Unicode-aware owner
    // case-mixes it (é -> É at odd indices) instead of passing it verbatim.
    let encoded = apply_encoding("héllo", "case_alternate").unwrap();
    let mutated = mutate_case("héllo");
    assert_eq!(encoded, "hÉlLo");
    assert!(
        mutated.iter().any(|v| v == &encoded),
        "mutate_case must include the encoding-identical variant: {mutated:?}"
    );
}
