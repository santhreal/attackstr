//! TOML-configurable PayloadConfig  -  load settings from file.
//!
//! ```toml
//! # santh-payloads.toml
//! max_per_category = 1000
//! deduplicate = true
//! marker_prefix = "SLN"
//! marker_position = "prefix"   # prefix | suffix | inline | replace:{MARKER}
//! target_runtime = ["php", "node"]
//! exclude_categories = ["xxe"]
//! include_categories = []
//! grammar_dirs = ["./grammars", "/usr/share/santh/grammars"]
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{MarkerPosition, PayloadConfig, PayloadError};

/// TOML-serializable configuration that loads into [`PayloadConfig`].
///
/// # Thread Safety
/// `PayloadConfigFile` is `Send` and `Sync`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
#[serde(default)]
pub struct PayloadConfigFile {
    /// Maximum payloads per category (0 = unlimited).
    pub max_per_category: usize,
    /// Deduplicate identical payloads.
    pub deduplicate: bool,
    /// Marker prefix for taint tracking.
    pub marker_prefix: String,
    /// Marker position: "prefix", "suffix", "inline", or "replace:{PLACEHOLDER}".
    pub marker_position: String,
    /// Restrict to specific runtimes.
    pub target_runtime: Option<Vec<String>>,
    /// Categories to exclude.
    pub exclude_categories: Vec<String>,
    /// Categories to include (empty = all).
    pub include_categories: Vec<String>,
    /// Directories to load grammars from.
    pub grammar_dirs: Vec<String>,
    /// Maximum length of a single payload in bytes (0 = unlimited).
    pub max_payload_length: usize,
}

impl Default for PayloadConfigFile {
    fn default() -> Self {
        Self {
            max_per_category: 0,
            deduplicate: true,
            marker_prefix: "SLN".into(),
            marker_position: "prefix".into(),
            target_runtime: None,
            exclude_categories: Vec::new(),
            include_categories: Vec::new(),
            grammar_dirs: Vec::new(),
            max_payload_length: 100_000,
        }
    }
}

impl PayloadConfigFile {
    /// Load from a TOML file path.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfigFile;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let path = dir.path().join("payloads.toml");
    /// std::fs::write(&path, "max_per_category = 5\n").unwrap();
    ///
    /// let file = PayloadConfigFile::load(&path).unwrap();
    /// assert_eq!(file.max_per_category, 5);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if the TOML is invalid.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, PayloadError> {
        let content = std::fs::read_to_string(path.as_ref())?;
        Self::from_toml(&content, path.as_ref().display().to_string())
    }

    /// Parse from a TOML string.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfigFile;
    ///
    /// let file = PayloadConfigFile::from_toml("deduplicate = false", "<inline>".into()).unwrap();
    /// assert!(!file.deduplicate);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML string is invalid.
    pub fn from_toml(toml_str: &str, source: String) -> Result<Self, PayloadError> {
        toml::from_str(toml_str).map_err(|e| PayloadError::ConfigParse {
            file: source,
            source: Box::new(e),
        })
    }

    /// Convert to a [`PayloadConfig`].
    ///
    /// Example:
    /// ```rust
    /// use attackstr::{MarkerPosition, PayloadConfigFile};
    ///
    /// let config = PayloadConfigFile::from_toml("marker_position = \"suffix\"", "<inline>".into())
    ///     .unwrap()
    ///     .into_config()
    ///     .unwrap();
    /// assert_eq!(config.marker_position, MarkerPosition::Suffix);
    /// ```
    pub fn into_config(self) -> Result<PayloadConfig, PayloadError> {
        Ok(PayloadConfig {
            max_per_category: self.max_per_category,
            deduplicate: self.deduplicate,
            marker_prefix: self.marker_prefix,
            exclude_categories: self.exclude_categories,
            include_categories: self.include_categories,
            target_runtime: self.target_runtime,
            marker_position: parse_marker_position(&self.marker_position)
                .map_err(PayloadError::InvalidConfig)?,
            max_payload_length: self.max_payload_length,
        })
    }

    /// Grammar directories to load.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfigFile;
    ///
    /// let file = PayloadConfigFile::from_toml("grammar_dirs = [\"./grammars\"]", "<inline>".into()).unwrap();
    /// assert_eq!(file.grammar_dirs(), ["./grammars"]);
    /// ```
    pub fn grammar_dirs(&self) -> &[String] {
        &self.grammar_dirs
    }
}

impl std::fmt::Display for PayloadConfigFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PayloadConfigFile(max_per_category={}, grammar_dirs={})",
            self.max_per_category,
            self.grammar_dirs.len()
        )
    }
}

/// Parse a [`MarkerPosition`] from a string.
///
/// # Errors
/// Returns an error string if the input is not a valid marker position.
pub fn parse_marker_position(s: &str) -> Result<MarkerPosition, String> {
    match s {
        "prefix" => Ok(MarkerPosition::Prefix),
        "suffix" => Ok(MarkerPosition::Suffix),
        "inline" => Ok(MarkerPosition::Inline),
        s if s.starts_with("replace:") => {
            let placeholder = &s[8..];
            if placeholder.is_empty() {
                Err("invalid marker_position 'replace:': placeholder cannot be empty.".to_string())
            } else {
                Ok(MarkerPosition::Replace(placeholder.to_string()))
            }
        }
        _ => Err(format!("invalid marker_position '{s}': expected 'prefix', 'suffix', 'inline', or 'replace:PLACEHOLDER'.")),
    }
}
