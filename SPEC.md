# attackstr  -  Technical Spec

## Overview

# attackstr  Grammar-based security payload generation for the Santh ecosystem.  Every security tool needs attack payloads  -  `SQLi`, XSS, command injection, SSTI, SSRF, XXE, and more. This crate provides a single, configurable engine that all Santh tools share. Upgrade payloads once, every tool benefits.  # Architecture  Payloads are defined in TOML grammar files. Each grammar specifies:  - **Contexts**: injection points (string break, numeric, attribute, etc.) - **Techniques**: attack patterns with template variables - **Variables**: substitution values (tautologies, commands, etc.) - **Encodings**: transforms applied to final payloads (URL, hex, unicode, etc.)  The engine computes the Cartesian product: `contexts × techniques × variable_combos × encodings`  # Usage  ```rust use attackstr::{PayloadDb, PayloadConfig};  let mut db = PayloadDb::with_config(PayloadConfig::default()); db.load_toml(r#" [grammar] name = "example" sink_category = "sql-injection"  [[techniques]] name = "basic" template = "' OR 1=1 --" "#).unwrap();  // Get payloads for a category let sqli = db.payloads("sql-injection"); for payload in sqli { println!("{}", payload.text); }  // Get payloads with marker injection for taint tracking let marked = db.payloads_with_marker("xss", "SLN_MARKER_42"); ```  # Custom Encodings  Register custom encoding transforms:  ```rust use attackstr::PayloadDb;  let mut db = PayloadDb::new(); db.register_encoding("rot13", |s| { s.chars().map(|c| match c { 'a'..='m' | 'A'..='M' => (c as u8 + 13) as char, 'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char, _ => c, }).collect() }); ```

## Architecture

The crate is organized into the following public modules:

- `config`
- `validate`

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- `PayloadError`
