//! Payload database  -  loads grammars from TOML files, expands payloads, serves them.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::grammar::{self, ExpandedPayload, Grammar, GrammarExpansionIter};
use crate::validate::{validate, GrammarIssue, IssueLevel};
use crate::{MarkerPosition, Payload, PayloadConfig, PayloadConfigFile, PayloadError};

/// The central payload database. Loads grammars, expands payloads, serves them.
///
/// # Thread Safety
/// `PayloadDb` is `Send` and `Sync`.
///
/// # Example
///
/// ```rust
/// use attackstr::{PayloadDb, PayloadConfig};
///
/// let mut db = PayloadDb::with_config(PayloadConfig {
///     deduplicate: true,
///     ..PayloadConfig::default()
/// });
///
/// // Load from directory
/// // db.load_dir("./grammars").unwrap();
///
/// // Or load from a TOML string
/// db.load_toml(r#"
/// [grammar]
/// name = "test"
/// sink_category = "test-injection"
///
/// [[contexts]]
/// name = "default"
/// prefix = ""
/// suffix = ""
///
/// [[techniques]]
/// name = "basic"
/// template = "test payload"
///
/// [[encodings]]
/// name = "raw"
/// transform = "identity"
/// "#).unwrap();
///
/// let payloads = db.payloads("test-injection");
/// assert_eq!(payloads.len(), 1);
/// ```
#[derive(Serialize, Deserialize)]
pub struct PayloadDb {
    /// Configuration.
    config: PayloadConfig,
    /// Loaded grammars by category.
    grammars: HashMap<String, Vec<Grammar>>,
    /// Expanded payloads by category (lazily populated).
    cache: HashMap<String, Vec<Payload>>,
    /// Custom encoding functions.
    #[serde(skip, default)]
    custom_encodings: HashMap<String, Arc<dyn Fn(&str) -> String + Send + Sync>>,
    /// Guards directory loads so concurrent callers fail explicitly.
    #[serde(skip, default = "default_load_state")]
    load_in_progress: Arc<AtomicBool>,
}

impl Clone for PayloadDb {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            grammars: self.grammars.clone(),
            cache: self.cache.clone(),
            custom_encodings: self.custom_encodings.clone(),
            load_in_progress: default_load_state(),
        }
    }
}

impl PartialEq for PayloadDb {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config && self.grammars == other.grammars && self.cache == other.cache
    }
}

impl Eq for PayloadDb {}

impl Hash for PayloadDb {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.config.hash(state);
        hash_string_keyed_map(&self.grammars, state);
        hash_string_keyed_map(&self.cache, state);
    }
}

impl PayloadDb {
    /// Create a new empty database with default config.
    pub fn new() -> Self {
        Self::with_config(PayloadConfig::default())
    }

    /// Create a new database with the given configuration.
    pub fn with_config(config: PayloadConfig) -> Self {
        Self {
            config,
            grammars: HashMap::new(),
            cache: HashMap::new(),
            custom_encodings: HashMap::new(),
            load_in_progress: default_load_state(),
        }
    }

    /// Load a config file and then load every grammar directory declared in it.
    ///
    /// Relative `grammar_dirs` entries are resolved relative to the config file's
    /// parent directory so project-local configs work from any current directory.
    ///
    /// Returns the configured database and any per-grammar load errors collected
    /// while scanning the configured grammar directories.
    ///
    /// # Errors
    /// Returns a `PayloadError` if the initial config file fails to load.
    pub fn load_config_and_grammars<P: AsRef<Path>>(
        config_path: P,
    ) -> Result<(Self, Vec<PayloadError>), PayloadError> {
        let config_path = config_path.as_ref();
        let config_file = PayloadConfigFile::load(config_path)?;
        let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));

        let mut db = Self::with_config(config_file.clone().into_config()?);
        let mut errors = Vec::new();

        for grammar_dir in config_file.grammar_dirs() {
            let resolved_dir = if Path::new(grammar_dir).is_absolute() {
                Path::new(grammar_dir).to_path_buf()
            } else {
                config_dir.join(grammar_dir)
            };

            errors.extend(db.load_dir_lenient(&resolved_dir)?);
        }

        Ok((db, errors))
    }

    /// Register a custom encoding transform.
    ///
    /// Custom encodings take precedence over built-ins with the same name.
    /// Closures capturing state are supported.
    ///
    /// # Example
    /// ```rust
    /// use attackstr::PayloadDb;
    ///
    /// let mut db = PayloadDb::new();
    /// let salt = "abc".to_string();
    /// db.register_encoding("salted", move |s| format!("{salt}{s}"));
    /// ```
    pub fn register_encoding<F>(&mut self, name: &str, func: F)
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        self.custom_encodings.insert(name.to_string(), Arc::new(func));
        self.cache.clear(); // Invalidate cache  -  encodings changed.
    }

    fn runtime_allowed(&self, grammar: &Grammar) -> bool {
        let Some(targets) = &self.config.target_runtime else {
            return true;
        };
        if targets.is_empty() {
            return true;
        }

        let Some(grammar_runtimes) = &grammar.meta.target_runtime else {
            return true;
        };

        grammar_runtimes.iter().any(|runtime| {
            targets
                .iter()
                .any(|target| runtime.eq_ignore_ascii_case(target))
        })
    }

    /// Load all `.toml` grammar files from a directory.
    ///
    /// Non-TOML files are silently skipped. Subdirectories are NOT recursed
    /// (flat layout by design  -  one category per file or split across files).
    ///
    /// # Errors
    /// Returns a `PayloadError` if the path doesn't exist or isn't a directory.
    pub fn load_dir<P: AsRef<Path>>(&mut self, dir: P) -> Result<Vec<PayloadError>, PayloadError> {
        self.load_dir_lenient(dir)
    }

    /// Load all `.toml` grammar files from a directory and collect per-file errors.
    ///
    /// Successfully parsed grammars remain loaded even if other files fail.
    ///
    /// # Errors
    /// Returns a `PayloadError` if the path doesn't exist or isn't a directory.
    pub fn load_dir_lenient<P: AsRef<Path>>(
        &mut self,
        dir: P,
    ) -> Result<Vec<PayloadError>, PayloadError> {
        let _load_guard = self.begin_load_session()?;
        self.load_dir_lenient_inner(dir.as_ref())
    }

    fn load_dir_lenient_inner(&mut self, path: &Path) -> Result<Vec<PayloadError>, PayloadError> {
        if !path.is_dir() {
            return Err(PayloadError::NotADirectory(path.display().to_string()));
        }

        let mut errors = Vec::new();
        let mut entries = Vec::new();
        match std::fs::read_dir(path) {
            Ok(read_dir) => {
                for entry_result in read_dir {
                    match entry_result {
                        Ok(entry) => {
                            if entry.path().extension().and_then(|s| s.to_str()) == Some("toml") {
                                entries.push(entry);
                            }
                        }
                        Err(err) => {
                            errors.push(PayloadError::Io(err));
                        }
                    }
                }
            }
            Err(err) => return Err(PayloadError::Io(err)),
        }

        // Sort for deterministic ordering.
        entries.sort_by_key(std::fs::DirEntry::path);

        let mut loaded = Vec::new();

        for entry in entries {
            if let Some(grammar) = self.load_single_grammar_file(&entry.path(), &mut errors) {
                let category = grammar.meta.sink_category.clone();
                loaded.push((category, grammar));
            }
        }

        for (category, grammar) in loaded {
            self.grammars.entry(category).or_default().push(grammar);
        }

        self.cache.clear(); // Invalidate cache.
        Ok(errors)
    }

    fn load_single_grammar_file(
        &self,
        file_path: &Path,
        errors: &mut Vec<PayloadError>,
    ) -> Option<Grammar> {
        let content = match std::fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(err) => {
                errors.push(PayloadError::Io(err));
                return None;
            }
        };
        let grammar: Grammar = match toml::from_str(&content) {
            Ok(grammar) => grammar,
            Err(source) => {
                errors.push(PayloadError::GrammarParse {
                    file: file_path.display().to_string(),
                    source: Box::new(source),
                });
                return None;
            }
        };
        if let Err(error) = self.validate_grammar(&grammar, &file_path.display().to_string()) {
            errors.push(error);
            return None;
        }
        // Lightweight validation: ensure the grammar can produce at least one payload
        // without materialising the entire expansion.
        let validation_result = grammar::iter_expanded(&grammar, &self.custom_encodings, self.config.max_payload_length)
            .and_then(|mut iter| match iter.next() {
                Some(Err(e)) => Err(e),
                _ => Ok(()),
            });
        if let Err(source) = validation_result {
            errors.push(PayloadError::TemplateExpansion {
                file: file_path.display().to_string(),
                source,
            });
            return None;
        }

        let category = grammar.meta.sink_category.clone();

        // Check include/exclude filters.
        if !self.config.include_categories.is_empty()
            && !self.config.include_categories.contains(&category)
        {
            return None;
        }
        if self.config.exclude_categories.contains(&category) {
            return None;
        }
        if !self.runtime_allowed(&grammar) {
            return None;
        }

        Some(grammar)
    }

    /// Load a grammar from a TOML string.
    ///
    /// # Errors
    /// Returns a `PayloadError` if the TOML is invalid or template variables fail to expand.
    pub fn load_toml(&mut self, toml_str: &str) -> Result<(), PayloadError> {
        self.load_reader(std::io::Cursor::new(toml_str), "<string>")
    }

    /// Load a grammar from any reader containing TOML.
    ///
    /// # Errors
    /// Returns a `PayloadError` if reading, parsing, or template expansion fails.
    pub fn load_reader<R: Read>(
        &mut self,
        mut reader: R,
        source_name: &str,
    ) -> Result<(), PayloadError> {
        let mut toml_str = String::new();
        reader
            .read_to_string(&mut toml_str)
            .map_err(PayloadError::Io)?;
        let grammar: Grammar =
            toml::from_str(&toml_str).map_err(|e| PayloadError::GrammarParse {
                file: source_name.into(),
                source: Box::new(e),
            })?;
        self.validate_grammar(&grammar, source_name)?;
        let validation_result = grammar::iter_expanded(&grammar, &self.custom_encodings, self.config.max_payload_length)
            .and_then(|mut iter| match iter.next() {
                Some(Err(e)) => Err(e),
                _ => Ok(()),
            });
        validation_result.map_err(|source| PayloadError::TemplateExpansion {
            file: source_name.into(),
            source,
        })?;

        let category = grammar.meta.sink_category.clone();

        if !self.config.include_categories.is_empty()
            && !self.config.include_categories.contains(&category)
        {
            return Ok(());
        }
        if self.config.exclude_categories.contains(&category) {
            return Ok(());
        }
        if !self.runtime_allowed(&grammar) {
            return Ok(());
        }

        self.grammars.entry(category).or_default().push(grammar);
        self.cache.clear();
        Ok(())
    }

    fn validate_grammar(&self, grammar: &Grammar, source_name: &str) -> Result<(), PayloadError> {
        let mut issues = validate(grammar);
        // The free `validate()` function only knows the built-in encodings, so it
        // downgrades an unknown transform to a Warning ("might be a custom
        // encoding"). Here in the loader we know the registered custom encodings
        // too, so an encoding that resolves to NEITHER a builtin NOR a registered
        // custom transform is a hard configuration error: at expansion time
        // `apply_encoding_dispatch` returns `Err(UnknownEncoding)`, which the
        // `payloads()` path would otherwise SILENTLY drop (Law 10). Fail closed at
        // the load boundary instead of losing the payload invisibly later.
        for enc in &grammar.encodings {
            let is_builtin = crate::encoding::BuiltinEncoding::is_builtin(&enc.transform);
            let is_custom = self.custom_encodings.contains_key(&enc.transform);
            if !is_builtin && !is_custom {
                issues.push(GrammarIssue {
                    grammar: grammar.meta.name.clone(),
                    level: IssueLevel::Error,
                    message: format!(
                        "encoding '{}' references unknown transform '{}'. Fix: use a built-in encoding or register it with `register_encoding` before loading.",
                        enc.name, enc.transform
                    ),
                });
            }
        }
        let errors: Vec<_> = issues
            .into_iter()
            .filter(|issue| issue.level == IssueLevel::Error)
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(PayloadError::GrammarValidation {
                file: source_name.to_string(),
                issues: errors,
            })
        }
    }

    /// Begins a load session, returning a guard that prevents concurrent loads.
    pub fn begin_load_session(&self) -> Result<LoadSessionGuard, PayloadError> {
        self.load_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PayloadError::ConcurrentLoad)?;
        Ok(LoadSessionGuard {
            flag: Arc::clone(&self.load_in_progress),
        })
    }

    /// Get all expanded payloads for a category.
    ///
    /// Results are cached after first expansion.
    pub fn payloads(&mut self, category: &str) -> &[Payload] {
        if !self.cache.contains_key(category) {
            let payloads = self.expand_category(category);
            self.cache.insert(category.to_string(), payloads);
        }
        self.cache
            .get(category)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Stream payloads for a category without materializing the full category at once.
    pub fn iter_payloads<'a>(
        &'a self,
        category: &'a str,
    ) -> impl Iterator<Item = Result<Payload, crate::grammar::TemplateExpansionError>> + 'a {
        let grammars = match self.grammars.get(category) {
            Some(v) => v.as_slice(),
            None => Default::default(),
        };
        PayloadIter {
            category,
            grammars,
            grammar_index: 0,
            current_iter: None,
            custom_encodings: &self.custom_encodings,
            deduplicate: self.config.deduplicate,
            max_per_category: self.config.max_per_category,
            max_payload_length: self.config.max_payload_length,
            emitted: 0,
            seen_payloads: HashSet::new(),
        }
    }

    /// Get payload strings only (no metadata) for a category.
    pub fn payload_strings(&mut self, category: &str) -> Vec<String> {
        self.payloads(category)
            .iter()
            .map(|p| p.text.clone())
            .collect()
    }

    /// Iterate over loaded category names in sorted order.
    pub fn iter_categories(&self) -> impl Iterator<Item = &str> {
        let mut categories: Vec<_> = self.grammars.keys().map(String::as_str).collect();
        categories.sort_unstable();
        categories.into_iter()
    }

    /// Get all payloads with a taint marker injected.
    ///
    /// Marker placement is controlled by [`crate::PayloadConfig::marker_position`].
    pub fn payloads_with_marker(&mut self, category: &str, marker: &str) -> Vec<Payload> {
        let marker_position = self.config.marker_position.clone();
        self.payloads(category)
            .iter()
            .map(|p| Payload {
                text: Self::apply_marker_position(&marker_position, &p.text, marker),
                category: p.category.clone(),
                technique: p.technique.clone(),
                context: p.context.clone(),
                encoding: p.encoding.clone(),
                cwe: p.cwe.clone(),
                severity: p.severity.clone(),
                confidence: p.confidence,
                expected_pattern: p.expected_pattern.clone(),
                target_media_type: p.target_media_type.clone(),
            })
            .collect()
    }

    /// Get all categories that have been loaded.
    pub fn categories(&self) -> Vec<&str> {
        self.iter_categories().collect()
    }

    /// Total number of grammars loaded.
    pub fn grammar_count(&self) -> usize {
        self.grammars.values().map(std::vec::Vec::len).sum()
    }

    /// Clear all loaded grammars and cached payloads.
    pub fn clear(&mut self) {
        self.grammars.clear();
        self.cache.clear();
    }

    /// Expand all grammars for a category into payloads.
    fn expand_category(&self, category: &str) -> Vec<Payload> {
        self.iter_payloads(category)
            .filter_map(|result| match result {
                Ok(payload) => Some(payload),
                Err(error) => {
                    // Law-10: a per-payload expansion failure (e.g. an
                    // over-length payload exceeding max_payload_length) used to
                    // vanish from the category via `filter_map(Result::ok)` with
                    // no operator-visible signal - an invisible recall loss.
                    // Surface it loudly before dropping so the missing payload is
                    // diagnosable. (Unknown-encoding is already fail-closed at
                    // load; this covers the residual length-exceeded case.)
                    tracing::warn!(
                        category,
                        %error,
                        "attackstr: dropping payload whose expansion failed"
                    );
                    None
                }
            })
            .collect()
    }

    fn apply_marker_position(
        marker_position: &MarkerPosition,
        payload: &str,
        marker: &str,
    ) -> String {
        match marker_position {
            MarkerPosition::Prefix => format!("{marker}{payload}"),
            MarkerPosition::Suffix => format!("{payload}{marker}"),
            MarkerPosition::Inline => format!("{{{marker}}}{payload}"),
            MarkerPosition::Replace(placeholder) => payload.replace(placeholder, marker),
        }
    }
}

impl std::fmt::Display for PayloadDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PayloadDb(categories={}, grammars={}, cached_categories={})",
            self.grammars.len(),
            self.grammar_count(),
            self.cache.len()
        )
    }
}

impl Default for PayloadDb {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::PayloadSource for PayloadDb {
    fn payloads(&mut self, category: &str) -> &[crate::Payload] {
        self.payloads(category)
    }

    fn categories(&self) -> Vec<&str> {
        self.categories()
    }

    fn payload_count(&self) -> usize {
        // Sum each category's payload count. Reuse the cache when a category
        // has already been expanded (the cache is invalidated on every config
        // or grammar change, so a present entry is authoritative); only
        // re-expand categories that were never materialized.
        self.grammars
            .keys()
            .map(|cat| {
                if let Some(cached) = self.cache.get(cat) {
                    cached.len()
                } else {
                    self.iter_payloads(cat)
                        .filter(std::result::Result::is_ok)
                        .count()
                }
            })
            .sum()
    }
}

/// Iterator over expanded payloads for a single category.
///
/// # Thread Safety
/// `PayloadIter` is `Send` and `Sync`.
pub struct PayloadIter<'a> {
    category: &'a str,
    grammars: &'a [Grammar],
    grammar_index: usize,
    current_iter: Option<GrammarExpansionIter<'a>>,
    custom_encodings: &'a HashMap<String, Arc<dyn Fn(&str) -> String + Send + Sync>>,
    deduplicate: bool,
    max_per_category: usize,
    max_payload_length: usize,
    emitted: usize,
    seen_payloads: HashSet<String>,
}

impl Iterator for PayloadIter<'_> {
    type Item = Result<Payload, crate::grammar::TemplateExpansionError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.max_per_category > 0 && self.emitted >= self.max_per_category {
            return None;
        }

        loop {
            if let Some(iter) = self.current_iter.as_mut() {
                if let Some(res) = iter.next() {
                    match res {
                        Ok(expanded_payload) => {
                            let grammar = &self.grammars[self.grammar_index - 1];
                            if self.deduplicate
                                && !self.seen_payloads.insert(expanded_payload.text.clone())
                            {
                                continue;
                            }

                            self.emitted += 1;
                            return Some(Ok(payload_from_expanded(
                                self.category,
                                grammar,
                                expanded_payload,
                            )));
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }

                self.current_iter = None;
            }

            let grammar = self.grammars.get(self.grammar_index)?;
            self.grammar_index += 1;
            match grammar::iter_expanded(grammar, self.custom_encodings, self.max_payload_length) {
                Ok(iter) => self.current_iter = Some(iter),
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

fn hash_string_keyed_map<T, Hs>(map: &HashMap<String, Vec<T>>, state: &mut Hs)
where
    T: Hash,
    Hs: Hasher,
{
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (key, value) in entries {
        key.hash(state);
        value.hash(state);
    }
}

fn default_load_state() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// A guard that protects against concurrent directory loads.
pub struct LoadSessionGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for LoadSessionGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

fn payload_from_expanded(
    category: &str,
    grammar: &Grammar,
    expanded_payload: ExpandedPayload,
) -> Payload {
    Payload {
        text: expanded_payload.text,
        category: category.to_string(),
        technique: expanded_payload.technique,
        context: expanded_payload.context,
        encoding: expanded_payload.encoding,
        cwe: grammar.meta.cwe.clone(),
        severity: grammar.meta.severity.clone(),
        confidence: expanded_payload.confidence,
        expected_pattern: expanded_payload.expected_pattern,
        target_media_type: expanded_payload.target_media_type,
    }
}
