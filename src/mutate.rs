//! Payload mutation helpers for lightweight evasive variants.

use std::collections::HashSet;

use crate::encoding::{alternate_case, apply_encoding, EncodingError};

/// Generate case-mutated variants of a payload.
pub fn mutate_case(payload: &str) -> Vec<String> {
    if payload.is_empty() {
        return Vec::new();
    }
    collect_unique([
        payload.to_lowercase(),
        payload.to_uppercase(),
        alternate_case(payload, 0),
        alternate_case(payload, 1),
    ])
}

/// Generate whitespace and comment-split variants of a payload.
pub fn mutate_whitespace(payload: &str) -> Vec<String> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() >= 2 {
        let variants = collect_unique([
            parts.join("\t"),
            parts.join("\n"),
            parts.join("/**/"),
            parts.join("/*comment*/"),
        ]);
        return variants.into_iter().filter(|v| v != payload).collect();
    }

    let chars: Vec<char> = payload.chars().collect();
    if chars.len() < 2 {
        return Vec::new();
    }

    let split = chars.len() / 2;
    let left: String = chars[..split].iter().collect();
    let right: String = chars[split..].iter().collect();

    collect_unique([
        format!("{left}\t{right}"),
        format!("{left}\n{right}"),
        format!("{left}/**/{right}"),
        format!("{left}/*comment*/{right}"),
    ])
}

/// Generate mixed-encoding variants by applying different transforms to payload segments.
///
/// # Errors
/// Returns [`EncodingError::UnknownTransform`] if any encoding name is not recognized.
pub fn mutate_encoding_mix(
    payload: &str,
    encodings: &[&str],
) -> Result<Vec<String>, EncodingError> {
    if encodings.len() < 2 || payload.chars().count() < 2 {
        return Ok(Vec::new());
    }

    let split_at = payload
        .char_indices()
        .nth(payload.chars().count() / 2)
        .map_or(payload.len(), |(idx, _)| idx);
    let (left, right) = payload.split_at(split_at);

    let mut variants = Vec::new();
    for left_encoding in encodings {
        for right_encoding in encodings {
            if left_encoding == right_encoding {
                continue;
            }
            variants.push(format!(
                "{}{}",
                apply_encoding(left, left_encoding)?,
                apply_encoding(right, right_encoding)?
            ));
        }
    }

    Ok(collect_unique(variants))
}

/// Insert null bytes at various positions.
pub fn mutate_null_bytes(payload: &str) -> Vec<String> {
    if payload.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = payload.chars().collect();
    if chars.len() < 3 {
        return collect_unique([
            format!("%00{payload}"),
            format!("{payload}%00"),
            format!("\x00{payload}"),
            format!("{payload}\x00"),
        ]);
    }
    let mid = chars.len() / 2;
    let left: String = chars[..mid].iter().collect();
    let right: String = chars[mid..].iter().collect();

    collect_unique([
        format!("%00{payload}"),
        format!("{payload}%00"),
        format!("{left}%00{right}"),
        format!("\x00{payload}"),
        format!("{payload}\x00"),
        format!("{left}\x00{right}"),
    ])
}

/// Generate SQL-specific comment variants for WAF bypass.
pub fn mutate_sql_comments(payload: &str) -> Vec<String> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() < 2 {
        return Vec::new();
    }
    collect_unique([
        parts.join("/**/"),
        parts.join("/*!*/"),
        parts.join("/*! */"),
        parts.join("/**_**/"),
        parts.join("--\n"),
        parts.join("#\n"),
    ])
}

/// Generate HTML/JS-specific evasion variants.
pub fn mutate_html(payload: &str) -> Vec<String> {
    let mut variants = Vec::new();

    // Tag case variants.
    if payload.contains('<') {
        let lower = payload.to_lowercase();
        let upper = payload.to_uppercase();
        if lower != payload {
            variants.push(lower);
        }
        if upper != payload {
            variants.push(upper);
        }
    }

    // Attribute quote variants.
    if payload.contains('"') {
        variants.push(payload.replace('"', "'"));
        variants.push(payload.replace('"', "`"));
        variants.push(payload.replace('"', ""));
    }

    // Event handler space injection.
    if payload.contains('=') {
        variants.push(payload.replace('=', " = "));
        variants.push(payload.replace('=', "\t=\t"));
        variants.push(payload.replace('=', "\n=\n"));
    }

    // Forward slash insertion in common tags. Only the matched tag span is
    // rewritten: the payload body must stay byte-for-byte intact, because JS
    // identifiers are case-sensitive and lowercasing the whole payload (the
    // old behavior) silently emitted non-functional variants.
    let tags = [
        "script", "img", "svg", "body", "iframe", "object", "embed", "math", "a", "form",
    ];
    for tag in tags {
        let mixed_tag = format!("<{}", alternate_case(tag, 1));
        if let Some(variant) = replace_tag_span(payload, tag, &mixed_tag) {
            variants.push(variant);
        }
        if let Some(variant) = replace_tag_span(payload, tag, &format!("<{tag}/")) {
            variants.push(variant);
        }
        if let Some(variant) = replace_tag_span(payload, tag, &format!("<{tag}    ")) {
            variants.push(variant);
        }
    }

    collect_unique(variants)
}

/// Replace every case-insensitive occurrence of `<{tag}` in `payload` with
/// `replacement`, leaving the rest of the payload byte-for-byte intact.
/// Returns `None` when the tag does not occur.
fn replace_tag_span(payload: &str, tag: &str, replacement: &str) -> Option<String> {
    let span = 1 + tag.len(); // "<" + tag; both ASCII
    let bytes = payload.as_bytes();
    let mut out = String::with_capacity(payload.len());
    let mut last = 0;
    let mut i = 0;
    let mut replaced = false;
    while i + span <= bytes.len() {
        // b'<' is ASCII, so a match index is always a char boundary; the tag
        // comparison via `get` safely rejects spans split by multi-byte chars.
        if bytes[i] == b'<'
            && payload
                .get(i + 1..i + span)
                .is_some_and(|s| s.eq_ignore_ascii_case(tag))
            && (i + span == bytes.len() || !bytes[i + span].is_ascii_alphanumeric())
        {
            out.push_str(&payload[last..i]);
            out.push_str(replacement);
            i += span;
            last = i;
            replaced = true;
        } else {
            i += 1;
        }
    }
    out.push_str(&payload[last..]);
    replaced.then_some(out)
}

/// Generate unicode normalization bypass variants.
pub fn mutate_unicode(payload: &str) -> Vec<String> {
    let mut variants = Vec::new();
    // Fullwidth character substitution (A → Ａ, < → ＜).
    // Valid only for pure ASCII range 0x21 to 0x7E
    let fullwidth: String = payload
        .chars()
        .map(|c| {
            let u = c as u32;
            if (0x21..=0x7E).contains(&u) {
                char::from_u32(u + 0xFEE0).unwrap_or(c)
            } else if u == 0x20 {
                '\u{3000}' // Ideographic space for normal space
            } else {
                c
            }
        })
        .collect();
    if fullwidth != payload {
        variants.push(fullwidth);
    }

    // Homoglyph substitution (expanded set).
    let homoglyph: String = payload
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a' => '\u{0430}',  // cyrillic а
            'e' => '\u{0435}',  // cyrillic е
            'o' => '\u{03BF}',  // greek ο
            'p' => '\u{0440}',  // cyrillic р
            'c' => '\u{0441}',  // cyrillic с
            'x' => '\u{0445}',  // cyrillic х
            'y' => '\u{0443}',  // cyrillic у
            'd' => '\u{217E}',  // small roman numeral d
            '>' => '\u{FE65}',  // small greater-than sign
            '<' => '\u{FE64}',  // small less-than sign
            '\'' => '\u{02B9}', // modifier letter prime
            '"' => '\u{02BA}',  // modifier letter double prime
            _ => c,
        })
        .collect();
    if homoglyph != payload {
        variants.push(homoglyph);
    }

    collect_unique(variants)
}

/// Combine all built-in mutations into a deduplicated set.
///
/// # Errors
/// Returns [`EncodingError::UnknownTransform`] if an encoding name in the mix is not recognized.
pub fn mutate_all(payload: &str) -> Result<Vec<String>, EncodingError> {
    let mut variants = Vec::new();
    variants.extend(mutate_case(payload));
    variants.extend(mutate_whitespace(payload));
    variants.extend(mutate_encoding_mix(
        payload,
        &["url_encode", "html_entities", "unicode"],
    )?);
    variants.extend(mutate_null_bytes(payload));
    variants.extend(mutate_sql_comments(payload));
    variants.extend(mutate_html(payload));
    variants.extend(mutate_unicode(payload));
    Ok(collect_unique(variants))
}

fn collect_unique<I>(variants: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut seen = HashSet::new();
    variants
        .into_iter()
        .filter(|variant| seen.insert(variant.clone()))
        .collect()
}
