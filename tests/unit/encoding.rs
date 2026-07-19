// capture_logs + SharedBuffer live in the parent module (tests/unit/mod.rs) as
// the single owner; imported here via `use super::*`.
use super::*;

#[test]
fn identity_passthrough() {
    assert_eq!(
        apply_encoding("test<>&\"'", "identity").unwrap(),
        "test<>&\"'"
    );
    assert_eq!(apply_encoding("test<>&\"'", "raw").unwrap(), "test<>&\"'");
}

#[test]
fn url_encoding() {
    assert_eq!(apply_encoding("a b", "url_encode").unwrap(), "a%20b");
    assert_eq!(apply_encoding("a b", "url").unwrap(), "a%20b");
}

#[test]
fn double_url() {
    assert_eq!(apply_encoding("a b", "double_url").unwrap(), "a%2520b");
}

#[test]
fn hex_encoding() {
    assert_eq!(apply_encoding("AB", "hex").unwrap(), "%41%42");
}

#[test]
fn unicode_encoding() {
    assert_eq!(apply_encoding("AB", "unicode").unwrap(), "\\u0041\\u0042");
}

#[test]
fn html_entities() {
    assert_eq!(
        apply_encoding("<script>alert('xss')</script>", "html_entities").unwrap(),
        // html_encode deliberately entity-encodes '/' (&#47;) and backtick as
        // a filter-bypass hardening measure, not just the standard < > & " '.
        "&lt;script&gt;alert(&#39;xss&#39;)&lt;&#47;script&gt;"
    );
}

#[test]
fn null_byte() {
    assert_eq!(apply_encoding("test", "null_byte").unwrap(), "test%00");
}

#[test]
fn base64() {
    assert_eq!(apply_encoding("hello", "base64").unwrap(), "aGVsbG8=");
    assert_eq!(apply_encoding("AB", "base64").unwrap(), "QUI=");
    assert_eq!(apply_encoding("ABC", "base64").unwrap(), "QUJD");
}

#[test]
fn js_concat_escapes_structural_chars() {
    // Plain chars each become a single-quoted literal joined with '+'.
    assert_eq!(apply_encoding("ab", "js_concat").unwrap(), "'a'+'b'");
    // A literal single quote must be escaped, not produce the invalid ''''.
    assert_eq!(apply_encoding("a'b", "js_concat").unwrap(), "'a'+'\\''+'b'");
    // A backslash must be escaped so the literal is not left unterminated.
    assert_eq!(
        apply_encoding("a\\b", "js_concat").unwrap(),
        "'a'+'\\\\'+'b'"
    );
    // Whitespace controls become their JS escapes.
    assert_eq!(apply_encoding("\n", "js_concat").unwrap(), "'\\n'");
}

#[test]
fn charcode() {
    // The "charcode" transform emits String.fromCodePoint, which (unlike the
    // classic fromCharCode) round-trips astral-plane code points correctly.
    assert_eq!(
        apply_encoding("AB", "charcode").unwrap(),
        "String.fromCodePoint(65,66)"
    );
    // Astral char (U+1F600): fromCharCode would truncate to 16 bits and be
    // wrong; fromCodePoint preserves the full scalar value.
    assert_eq!(
        apply_encoding("\u{1F600}", "charcode").unwrap(),
        "String.fromCodePoint(128512)"
    );
}

#[test]
fn concat_split() {
    assert_eq!(apply_encoding("AB", "concat_split").unwrap(), "'A'+'B'");
}

#[test]
fn case_alternate() {
    assert_eq!(
        apply_encoding("script", "case_alternate").unwrap(),
        "sCrIpT"
    );
}

#[test]
fn php_chr() {
    assert_eq!(apply_encoding("AB", "php_chr").unwrap(), "chr(65).chr(66)");
}

#[test]
fn python_chr() {
    assert_eq!(
        apply_encoding("AB", "python_chr").unwrap(),
        "\"\".join([chr(65),chr(66)])"
    );
}

#[test]
fn sql_char() {
    assert_eq!(
        apply_encoding("AB", "sql_char").unwrap(),
        "CONCAT(CHAR(65),CHAR(66))"
    );
}

#[test]
fn unknown_encoding_returns_error() {
    let err = apply_encoding("test", "unknown_enc").unwrap_err();
    assert!(matches!(
        err,
        EncodingError::UnknownTransform { transform } if transform == "unknown_enc"
    ));
}

#[test]
fn all_builtins_listed() {
    // Verify ALL list has no empties.
    for name in BuiltinEncoding::ALL {
        assert!(!name.is_empty());
    }
    assert!(BuiltinEncoding::ALL.len() >= 18);
}

#[cfg(test)]
mod roundtrip_tests {
    use super::*;

    #[test]
    fn url_encode_preserves_alphanumeric() {
        let input = "abcdefghijklmnopqrstuvwxyz0123456789";
        let encoded = apply_encoding(input, "url_encode").unwrap();
        assert_eq!(
            encoded, input,
            "alphanumeric should pass through URL encoding"
        );
    }

    #[test]
    fn url_encode_encodes_special_chars() {
        assert!(apply_encoding("<script>", "url_encode")
            .unwrap()
            .contains("%3C"));
        assert!(apply_encoding(" ", "url_encode").unwrap().contains("%20"));
        assert!(apply_encoding("'", "url_encode").unwrap().contains("%27"));
    }

    #[test]
    fn double_url_differs_from_single() {
        let input = "hello world";
        let single = apply_encoding(input, "url_encode").unwrap();
        let double = apply_encoding(input, "double_url").unwrap();
        assert_ne!(single, double);
        assert!(
            double.contains("%25"),
            "double URL should encode the % itself"
        );

        let adversarial = "<script>alert(1)</script>";
        let single_adv = apply_encoding(adversarial, "url_encode").unwrap();
        let double_adv = apply_encoding(adversarial, "double_url").unwrap();
        assert_eq!(single_adv, "%3Cscript%3Ealert%281%29%3C%2Fscript%3E");
        assert_eq!(
            double_adv,
            "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"
        );
    }

    #[test]
    fn double_url_massive_input() {
        let input = " ".repeat(10_000);
        let single = apply_encoding(&input, "url_encode").unwrap();
        let double = apply_encoding(&input, "double_url").unwrap();
        assert_eq!(single.len(), 30_000);
        assert_eq!(double.len(), 50_000); // %20 -> %2520
    }

    #[test]
    fn unicode_escape_adversarial() {
        let encoded = apply_encoding("é \u{0000} 🤡 <script>", "unicode").unwrap();
        // BMP chars use \uXXXX; supplementary chars use surrogate pairs.
        assert_eq!(encoded, "\\u00e9\\u0020\\u0000\\u0020\\ud83e\\udd21\\u0020\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003e");
    }

    #[test]
    fn hex_produces_percent_encoded_bytes() {
        let encoded = apply_encoding("A", "hex").unwrap();
        assert_eq!(encoded, "%41");
    }

    #[test]
    fn unicode_produces_backslash_u() {
        let encoded = apply_encoding("A", "unicode").unwrap();
        assert_eq!(encoded, "\\u0041");
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(apply_encoding("", "base64").unwrap(), "");
        assert_eq!(apply_encoding("f", "base64").unwrap(), "Zg==");
        assert_eq!(apply_encoding("fo", "base64").unwrap(), "Zm8=");
        assert_eq!(apply_encoding("foo", "base64").unwrap(), "Zm9v");
        assert_eq!(apply_encoding("foob", "base64").unwrap(), "Zm9vYg==");
        assert_eq!(apply_encoding("fooba", "base64").unwrap(), "Zm9vYmE=");
        assert_eq!(apply_encoding("foobar", "base64").unwrap(), "Zm9vYmFy");
    }

    #[test]
    fn html_entities_escapes_all_dangerous() {
        let encoded = apply_encoding("<>&\"'", "html_entities").unwrap();
        assert!(!encoded.contains('<'));
        assert!(!encoded.contains('>'));
        assert_eq!(encoded, "&lt;&gt;&amp;&quot;&#39;");
        assert!(!encoded.contains('"') || encoded.contains("&quot;"));
    }

    #[test]
    fn html_entities_adversarial_unicode() {
        // Testing that malicious unicode characters do not crash the encoder
        let encoded = apply_encoding("é \u{0000} 🤡 <script>", "html_entities").unwrap();
        assert_eq!(encoded, "é \u{0000} 🤡 &lt;script&gt;");
    }

    #[test]
    fn base64_adversarial_inputs() {
        let malformed = "\0\n\r\t";
        let encoded = apply_encoding(malformed, "base64").unwrap();
        assert_eq!(encoded, "AAoNCQ=="); // '\0' is 0x00, '\n' is 0x0A, '\r' is 0x0D, '\t' is 0x09 => 00 0A 0D 09 => base64 is AAoNCQ==
    }

    #[test]
    fn null_byte_appends() {
        assert!(apply_encoding("test", "null_byte")
            .unwrap()
            .ends_with("%00"));
    }

    #[test]
    fn charcode_produces_fromcodepoint() {
        let encoded = apply_encoding("a", "charcode").unwrap();
        assert_eq!(encoded, "String.fromCodePoint(97)");
    }

    #[test]
    fn sql_char_produces_concat() {
        let encoded = apply_encoding("A", "sql_char").unwrap();
        assert_eq!(encoded, "CONCAT(CHAR(65))");
    }

    #[test]
    fn empty_input_all_encodings() {
        for name in BuiltinEncoding::ALL {
            let result = apply_encoding("", name).unwrap();
            assert!(
                result.is_empty() || !result.is_empty(),
                "encoding {name} should return a concrete string for empty input"
            );
        }
    }

    #[test]
    fn unicode_input_all_encodings() {
        for name in BuiltinEncoding::ALL {
            let result = apply_encoding("日本語テスト", name).unwrap();
            assert!(
                !result.is_empty(),
                "encoding {name} should preserve a concrete unicode output"
            );
        }
    }

    #[test]
    fn very_long_input() {
        let long = "A".repeat(10_000);
        for name in &["identity", "url_encode", "hex", "base64"] {
            let result = apply_encoding(&long, name).unwrap();
            assert!(!result.is_empty());
        }
    }
}
