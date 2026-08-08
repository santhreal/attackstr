//! Grammar validation  -  catch errors at load time, not expansion time.

use serde::{Deserialize, Serialize};

use crate::grammar::{Grammar, GrammarMeta};

/// A validation warning or error found in a grammar.
///
/// # Thread Safety
/// `GrammarIssue` is `Send` and `Sync`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GrammarIssue {
    /// The grammar name.
    pub grammar: String,
    /// The issue severity.
    pub level: IssueLevel,
    /// Human-readable description of the issue.
    pub message: String,
}

impl std::fmt::Display for GrammarIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.level, self.message)
    }
}

/// Severity of a grammar validation issue.
///
/// # Thread Safety
/// `IssueLevel` is `Send` and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IssueLevel {
    /// Problem that will cause incorrect behavior.
    Error,
    /// Likely mistake but grammar will still work.
    Warning,
}

impl std::fmt::Display for IssueLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => f.write_str("error"),
            Self::Warning => f.write_str("warning"),
        }
    }
}

/// Validate a grammar and return any issues found.
///
/// Example:
/// ```rust
/// use attackstr::{validate, Grammar, GrammarMeta, Technique};
/// use std::collections::HashMap;
///
/// let grammar = Grammar {
///     meta: GrammarMeta {
///         name: "example".into(),
///         sink_category: "xss".into(),
///         description: None,
///         tags: Vec::new(),
///         severity: None,
///         cwe: None,
///         target_runtime: None,
///     },
///     contexts: Vec::new(),
///     techniques: vec![Technique {
///         name: "basic".into(),
///         template: "<script>alert(1)</script>".into(),
///         tags: Vec::new(),
///         confidence: 1.0,
///         expected_pattern: None,
///     }],
///     encodings: Vec::new(),
///     variables: HashMap::new(),
/// };
///
/// assert!(validate(&grammar).is_empty());
/// ```
pub fn validate(grammar: &Grammar) -> Vec<GrammarIssue> {
    let mut issues = Vec::new();
    let name = &grammar.meta.name;

    validate_meta(&grammar.meta, name, &mut issues);
    validate_contexts(grammar, name, &mut issues);
    validate_techniques(grammar, name, &mut issues);
    validate_encodings(grammar, name, &mut issues);
    validate_variables(grammar, name, &mut issues);
    issues
}

fn validate_meta(meta: &GrammarMeta, name: &str, issues: &mut Vec<GrammarIssue>) {
    if meta.name.trim().is_empty() {
        issues.push(GrammarIssue {
            grammar: name.into(),
            level: IssueLevel::Error,
            message: "grammar name is empty".into(),
        });
    }
    if meta.sink_category.trim().is_empty() {
        issues.push(GrammarIssue {
            grammar: name.into(),
            level: IssueLevel::Error,
            message: "sink_category is empty  -  payloads won't be retrievable".into(),
        });
    }
}

fn validate_techniques(grammar: &Grammar, name: &str, issues: &mut Vec<GrammarIssue>) {
    if grammar.techniques.is_empty() {
        issues.push(GrammarIssue {
            grammar: name.into(),
            level: IssueLevel::Warning,
            message: "no techniques defined  -  grammar produces no payloads".into(),
        });
        return;
    }

    for tech in &grammar.techniques {
        if tech.name.trim().is_empty() {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Error,
                message: "technique has empty name".into(),
            });
        }
        if tech.template.trim().is_empty() {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Error,
                message: format!("technique '{}' has empty template", tech.name),
            });
        }

        // Check for unreferenced variables in template.
        check_template_variables(grammar, tech, name, issues);

        if tech.confidence < 0.0 || tech.confidence > 1.0 {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Warning,
                message: format!(
                    "technique '{}' confidence {} is outside [0.0, 1.0]",
                    tech.name, tech.confidence
                ),
            });
        }
    }
}

fn check_template_variables(
    grammar: &Grammar,
    tech: &crate::grammar::Technique,
    name: &str,
    issues: &mut Vec<GrammarIssue>,
) {
    let mut pos = 0;
    while let Some(start) = tech.template[pos..].find('{') {
        let abs_start = pos + start;
        // Escaped brace: "{{" renders to a literal "{" (grammar.rs:534). It is
        // neither a variable reference nor an unclosed brace, so skip both
        // characters. Without this, a template containing a "{{" escape but no
        // later "}" was wrongly reported as having an unclosed "{".
        if tech.template[abs_start..].starts_with("{{") {
            pos = abs_start + 2;
            continue;
        }
        if let Some(end) = tech.template[abs_start..].find('}') {
            let var_name = &tech.template[abs_start + 1..abs_start + end];
            let looks_like_var = var_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
            if looks_like_var
                && var_name != "prefix"
                && var_name != "suffix"
                && !var_name.is_empty()
            {
                // Check if this variable exists (plural or singular).
                let has_var = grammar.variables.contains_key(var_name)
                    || grammar.variables.contains_key(&format!("{var_name}s"))
                    || grammar
                        .variables
                        .keys()
                        .any(|k| crate::grammar::depluralize(k) == var_name);
                if !has_var {
                    issues.push(GrammarIssue {
                        grammar: name.into(),
                        level: IssueLevel::Warning,
                        message: format!(
                            "technique '{}' references undefined variable '{{{}}}'",
                            tech.name, var_name
                        ),
                    });
                }
            }
            pos = abs_start + end + 1;
        } else {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Error,
                message: format!("technique '{}' has unclosed '{{' in template", tech.name),
            });
            break;
        }
    }
}

fn validate_encodings(grammar: &Grammar, name: &str, issues: &mut Vec<GrammarIssue>) {
    for enc in &grammar.encodings {
        if enc.name.trim().is_empty() {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Error,
                message: format!("encoding transform '{}' has empty name", enc.transform),
            });
        }
        if !crate::encoding::BuiltinEncoding::is_builtin(&enc.transform) {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Warning,
                message: format!(
                    "encoding '{}' uses unknown transform '{}' (not a built-in). If it is not a registered custom encoding, loading fails closed: the payload is rejected, not passed through.",
                    enc.name, enc.transform
                ),
            });
        }
    }
}

fn validate_contexts(grammar: &Grammar, name: &str, issues: &mut Vec<GrammarIssue>) {
    for ctx in &grammar.contexts {
        if ctx.name.trim().is_empty() {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Error,
                message: "context has empty name".into(),
            });
        }
    }
}

fn validate_variables(grammar: &Grammar, name: &str, issues: &mut Vec<GrammarIssue>) {
    for (var_name, values) in &grammar.variables {
        // Skip known non-variable keys.
        if ["grammar", "contexts", "techniques", "encodings"].contains(&var_name.as_str()) {
            continue;
        }
        if var_name.trim().is_empty() {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Error,
                message: "variable has empty name".into(),
            });
        }
        if values.is_empty() {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Warning,
                message: format!("variable '{var_name}' has no values"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar::Technique;
    use std::collections::HashMap;

    fn grammar_with_template(template: &str) -> Grammar {
        Grammar {
            meta: GrammarMeta {
                name: "t".into(),
                sink_category: "xss".into(),
                description: None,
                tags: Vec::new(),
                severity: None,
                cwe: None,
                target_runtime: None,
            },
            contexts: Vec::new(),
            techniques: vec![Technique {
                name: "basic".into(),
                template: template.into(),
                tags: Vec::new(),
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: Vec::new(),
            variables: HashMap::new(),
        }
    }

    fn has_unclosed_error(g: &Grammar) -> bool {
        validate(g)
            .iter()
            .any(|i| i.level == IssueLevel::Error && i.message.contains("unclosed '{'"))
    }

    #[test]
    fn escaped_brace_is_not_unclosed() {
        // Regression for validate.rs:182: a "{{" escape (renders to literal "{"
        // per grammar.rs:534) followed by no "}" must NOT be flagged unclosed.
        assert!(!has_unclosed_error(&grammar_with_template("payload {{ literal text")));
        assert!(!has_unclosed_error(&grammar_with_template("a{{b")));
        // Escaped brace before a real, closed variable reference stays valid.
        assert!(!has_unclosed_error(&grammar_with_template("{{ then {prefix}")));
    }

    #[test]
    fn genuinely_unclosed_brace_still_errors() {
        // The NOTE in the finding: a real unclosed "{prefix" must still be
        // rejected - the escape fix must not mask it.
        assert!(has_unclosed_error(&grammar_with_template("alert{prefix")));
        assert!(has_unclosed_error(&grammar_with_template("x { y no close")));
    }
}
