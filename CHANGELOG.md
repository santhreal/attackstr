# Changelog

All notable changes to this project are documented in this file. The format follows Keep a Changelog and the crate adheres to Semantic Versioning.

## [0.2.2] - 2026-08-02

### Fixed
- `mutate_html` no longer lowercases the entire payload body in its tag-mutation branch. Only the matched tag span is rewritten (case-insensitive match, replace-all preserved), so payloads with case-sensitive JavaScript keep working.
- Unified the two divergent `alternate_case` implementations into one Unicode-aware helper; the encoding and mutate paths now agree on non-ASCII input.
- Consolidated the triplicated encoding-name set into one `FromStr` dispatch; unknown encoding names fail closed.

## [0.2.1] - 2026-07-30

- Published release: refined metadata, docs, and tests for the crates.io train.
