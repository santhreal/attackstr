//! Encoding transforms  -  applied to payloads after template expansion.
//!
//! Built-in encodings cover the most common evasion techniques.
//! Custom encodings can be registered via [`PayloadDb::register_encoding`].

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A trait for encoding transforms.
///
/// Implement this trait to create custom encoders that can be used
/// with the attackstr encoding system.
///
/// # Thread Safety
/// This trait does not require `Send` or `Sync`. Thread-safety depends on the
/// concrete implementing type.
///
/// # Example
///
/// ```rust
/// use attackstr::Encoder;
///
/// struct Rot13Encoder;
///
/// impl Encoder for Rot13Encoder {
///     fn encode(&self, input: &str) -> String {
///         input.chars().map(|c| match c {
///             'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
///             'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
///             _ => c,
///         }).collect()
///     }
/// }
///
/// let encoder = Rot13Encoder;
/// assert_eq!(encoder.encode("hello"), "uryyb");
/// ```
pub trait Encoder {
    /// Encode the input string.
    fn encode(&self, input: &str) -> String;
}

impl<F> Encoder for F
where
    F: Fn(&str) -> String,
{
    fn encode(&self, input: &str) -> String {
        self(input)
    }
}

/// Errors returned by encoding operations.
///
/// # Thread Safety
/// `EncodingError` is `Send` and `Sync`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum EncodingError {
    /// The requested encoding transform is not known.
    #[error("unknown encoding transform '{transform}'. Fix: use a known built-in or register a custom encoding.")]
    UnknownTransform {
        /// Name of the unrecognized transform.
        transform: String,
    },
}

/// A custom encoder that wraps a callable.
///
/// This is useful for creating encoders from closures or function pointers
/// without defining a new type. Closures may capture state.
///
/// # Thread Safety
/// `CustomEncoder` is `Send` and `Sync`.
///
/// # Example
///
/// ```rust
/// use attackstr::{CustomEncoder, Encoder};
///
/// let salt = "abc".to_string();
/// let encoder = CustomEncoder::new(move |s: &str| format!("{salt}{s}"));
/// assert_eq!(encoder.encode("hello"), "abchello");
/// ```
#[derive(Clone)]
pub struct CustomEncoder {
    func: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

impl CustomEncoder {
    /// Create a new `CustomEncoder` from a closure or function pointer.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::{CustomEncoder, Encoder};
    ///
    /// let encoder = CustomEncoder::new(|value| value.to_uppercase());
    /// assert_eq!(encoder.encode("xss"), "XSS");
    /// ```
    pub fn new<F>(func: F) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        Self {
            func: Arc::new(func),
        }
    }

    /// Apply the encoding to an input string.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::CustomEncoder;
    ///
    /// let encoder = CustomEncoder::new(|value| format!("<{value}>"));
    /// assert_eq!(encoder.encode("a"), "<a>");
    /// ```
    pub fn encode(&self, input: &str) -> String {
        (self.func)(input)
    }
}

impl std::fmt::Debug for CustomEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomEncoder").finish_non_exhaustive()
    }
}

impl Default for CustomEncoder {
    fn default() -> Self {
        Self::new(std::string::ToString::to_string)
    }
}

impl Encoder for CustomEncoder {
    fn encode(&self, input: &str) -> String {
        self.encode(input)
    }
}

impl std::fmt::Display for CustomEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustomEncoder(..)")
    }
}

/// Apply a built-in encoding transform by name.
///
/// Returns [`EncodingError::UnknownTransform`] if the transform name is not
/// recognized.
///
/// Example:
/// ```rust
/// use attackstr::apply_encoding;
///
/// assert_eq!(apply_encoding("a b", "url").unwrap(), "a%20b");
/// ```
pub fn apply_encoding(s: &str, transform: &str) -> Result<String, EncodingError> {
    // The `BuiltinEncoding` enum is the single owner of the encoding-name set:
    // parsing resolves the name (canonical or alias) and `apply` dispatches.
    let encoding: BuiltinEncoding = transform.parse()?;
    Ok(encoding.apply(s))
}

fn percent_hex_encode(s: &str) -> String {
    s.bytes()
        .fold(String::with_capacity(s.len() * 3), |mut acc, b| {
            use std::fmt::Write;
            // Writing to a String sink is infallible.
            let _ = write!(&mut acc, "%{b:02x}");
            acc
        })
}

fn unicode_escape(s: &str) -> String {
    s.chars()
        .fold(String::with_capacity(s.len() * 6), |mut acc, c| {
            use std::fmt::Write;
            let u = c as u32;
            if u > 0xFFFF {
                // Generate UTF-16 surrogate pair for JS compatibility.
                let code = u - 0x1_0000;
                let high = 0xD800 + (code >> 10);
                let low = 0xDC00 + (code & 0x3FF);
                let _ = write!(&mut acc, "\\u{:04x}\\u{:04x}", high, low);
            } else {
                // Writing to a String sink is infallible.
                let _ = write!(&mut acc, "\\u{:04x}", u);
            }
            acc
        })
}

fn octal_escape(s: &str) -> String {
    s.bytes()
        .fold(String::with_capacity(s.len() * 4), |mut acc, b| {
            use std::fmt::Write;
            // Writing to a String sink is infallible.
            let _ = write!(&mut acc, "\\{b:03o}");
            acc
        })
}

fn js_charcode(s: &str) -> String {
    let codes: Vec<String> = s.chars().map(|c| (c as u32).to_string()).collect();
    format!("String.fromCodePoint({})", codes.join(","))
}

fn js_concat_split(s: &str) -> String {
    // Each char becomes a single-quoted JS string literal joined with '+'.
    // Characters with structural meaning inside a single-quoted literal
    // ('\'' and '\\') and the whitespace controls must be escaped, or the
    // generated JS is syntactically invalid (e.g. a literal ' yielded '''').
    let parts: Vec<String> = s
        .chars()
        .map(|c| match c {
            '\'' => "'\\''".to_string(),
            '\\' => "'\\\\'".to_string(),
            '\n' => "'\\n'".to_string(),
            '\r' => "'\\r'".to_string(),
            '\t' => "'\\t'".to_string(),
            other => format!("'{other}'"),
        })
        .collect();
    parts.join("+")
}

/// Alternating-case transform, Unicode-aware, keyed on char index plus
/// `offset`. The single owner for both the `case_alternate` encoding and the
/// `mutate_case`/tag-casing mutation paths; `offset` 0 lowercases even
/// indices, `offset` 1 uppercases them.
pub(crate) fn alternate_case(s: &str, offset: usize) -> String {
    // Build in one buffer instead of allocating a `String` per char. Keeps the
    // Unicode-aware case mapping (`char::to_lowercase`/`to_uppercase` can yield
    // more than one char, e.g. 'İ'), so the result is byte-identical.
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        if (i + offset) % 2 == 0 {
            out.extend(c.to_lowercase());
        } else {
            out.extend(c.to_uppercase());
        }
    }
    out
}

fn join_chars_with(s: &str, separator: &str) -> String {
    // Build the result in one allocation instead of collecting N single-char
    // `String`s into a `Vec` and re-joining (N+1 allocations).
    let char_count = s.chars().count();
    let mut out = String::with_capacity(s.len() + separator.len() * char_count.saturating_sub(1));
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        out.push(first);
        for c in chars {
            out.push_str(separator);
            out.push(c);
        }
    }
    out
}

fn php_chr_concat(s: &str) -> String {
    let parts: Vec<String> = s.bytes().map(|b| format!("chr({b})")).collect();
    parts.join(".")
}

fn python_chr_join(s: &str) -> String {
    let parts: Vec<String> = s.chars().map(|c| format!("chr({})", c as u32)).collect();
    format!("\"\".join([{}])", parts.join(","))
}

fn sql_char_concat(s: &str) -> String {
    let parts: Vec<String> = s.bytes().map(|b| format!("CHAR({b})")).collect();
    format!("CONCAT({})", parts.join(","))
}

fn rot13_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

fn css_escape(s: &str) -> String {
    s.chars()
        .fold(String::with_capacity(s.len() * 6), |mut acc, c| {
            use std::fmt::Write;
            // Writing to a String sink is infallible.
            let _ = write!(&mut acc, "\\{:02x}", c as u32);
            acc
        })
}

/// All built-in encoding names, for documentation and validation.
///
/// # Thread Safety
/// `BuiltinEncoding` is `Send` and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BuiltinEncoding {
    /// No encoding.
    Identity,
    /// URL percent-encoding.
    UrlEncode,
    /// Double URL encoding.
    DoubleUrl,
    /// Hex percent-encoding.
    Hex,
    /// Unicode \uXXXX escapes.
    Unicode,
    /// HTML entity encoding.
    HtmlEntities,
    /// Append null byte.
    NullByte,
    /// Base64 encoding.
    Base64,
    /// Octal \NNN escapes.
    Octal,
    /// JavaScript `String.fromCodePoint()`.
    JsCharCode,
    /// JavaScript string concatenation.
    JsConcat,
    /// Alternating case.
    CaseAlternate,
    /// Tab-separated characters.
    TabSplit,
    /// Newline-separated characters.
    NewlineSplit,
    /// PHP `chr()` concatenation.
    PhpChr,
    /// Python `chr()` concatenation.
    PythonChr,
    /// SQL `CHAR()` function.
    SqlChar,
    /// CSS unicode escapes.
    CssEscape,
    /// ROT13 encoding.
    Rot13,
}

impl std::fmt::Display for BuiltinEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Identity => "identity",
            Self::UrlEncode => "url_encode",
            Self::DoubleUrl => "double_url",
            Self::Hex => "hex",
            Self::Unicode => "unicode",
            Self::HtmlEntities => "html_entities",
            Self::NullByte => "null_byte",
            Self::Base64 => "base64",
            Self::Octal => "octal",
            Self::JsCharCode => "js_charcode",
            Self::JsConcat => "js_concat",
            Self::CaseAlternate => "case_alternate",
            Self::TabSplit => "tab_split",
            Self::NewlineSplit => "newline_split",
            Self::PhpChr => "php_chr",
            Self::PythonChr => "python_chr",
            Self::SqlChar => "sql_char",
            Self::CssEscape => "css_escape",
            Self::Rot13 => "rot13",
        };
        f.write_str(value)
    }
}

impl std::str::FromStr for BuiltinEncoding {
    type Err = EncodingError;

    /// Resolve an encoding name (canonical or alias) to its variant.
    ///
    /// This is the single owner of the encoding-name set: `apply_encoding`
    /// dispatches through it, and [`BuiltinEncoding::ALL`] is validated
    /// against it by the bidirectional completeness test.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let variant = match name {
            "identity" | "raw" => Self::Identity,
            "url_encode" | "url" => Self::UrlEncode,
            "double_url" => Self::DoubleUrl,
            "hex" => Self::Hex,
            "unicode" => Self::Unicode,
            "html_entities" | "html" => Self::HtmlEntities,
            "null_byte" => Self::NullByte,
            "base64" => Self::Base64,
            "octal" => Self::Octal,
            "charcode" | "js_charcode" => Self::JsCharCode,
            "concat_split" | "js_concat" => Self::JsConcat,
            "case_alternate" => Self::CaseAlternate,
            "tab_split" => Self::TabSplit,
            "newline_split" => Self::NewlineSplit,
            "php_chr" => Self::PhpChr,
            "python_chr" => Self::PythonChr,
            "sql_char" => Self::SqlChar,
            "css_escape" => Self::CssEscape,
            "rot13" => Self::Rot13,
            other => {
                return Err(EncodingError::UnknownTransform {
                    transform: other.to_string(),
                })
            }
        };
        Ok(variant)
    }
}

impl BuiltinEncoding {
    /// Check whether `name` (canonical or alias) is a recognized builtin encoding.
    pub fn is_builtin(name: &str) -> bool {
        name.parse::<Self>().is_ok()
    }

    /// Apply this encoding to `s`.
    fn apply(self, s: &str) -> String {
        match self {
            Self::Identity => s.to_string(),
            Self::UrlEncode => urlencoding::encode(s).into_owned(),
            Self::DoubleUrl => urlencoding::encode(&urlencoding::encode(s)).into_owned(),
            Self::Hex => percent_hex_encode(s),
            Self::Unicode => unicode_escape(s),
            Self::HtmlEntities => html_encode(s),
            Self::NullByte => format!("{s}%00"),
            Self::Base64 => encodex::base64::encode(s.as_bytes()),
            Self::Octal => octal_escape(s),
            Self::JsCharCode => js_charcode(s),
            Self::JsConcat => js_concat_split(s),
            Self::CaseAlternate => alternate_case(s, 0),
            Self::TabSplit => join_chars_with(s, "\t"),
            Self::NewlineSplit => join_chars_with(s, "\n"),
            Self::PhpChr => php_chr_concat(s),
            Self::PythonChr => python_chr_join(s),
            Self::SqlChar => sql_char_concat(s),
            Self::CssEscape => css_escape(s),
            Self::Rot13 => rot13_encode(s),
        }
    }

    /// All builtin encoding names as strings.
    pub const ALL: &'static [&'static str] = &[
        "identity",
        "raw",
        "url_encode",
        "url",
        "double_url",
        "hex",
        "unicode",
        "html_entities",
        "html",
        "null_byte",
        "base64",
        "octal",
        "charcode",
        "js_charcode",
        "concat_split",
        "js_concat",
        "case_alternate",
        "tab_split",
        "newline_split",
        "php_chr",
        "python_chr",
        "sql_char",
        "css_escape",
        "rot13",
    ];
}

fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '`' => out.push_str("&#96;"),
            '/' => out.push_str("&#47;"),
            _ => out.push(c),
        }
    }
    out
}
