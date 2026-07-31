# Changelog

## v0.2.1

- Fixed: replaced `expect()` on infallible `write!` calls into `String` sinks in `percent_hex_encode`, `unicode_escape`, `octal_escape`, and `css_escape`, clearing the crate's own `deny(clippy::expect_used)` gate.
- Added regression tests locking the exact output of the `octal` and `css_escape` transforms.
- Verified building and testing against encodex 0.1.13, which restores the `encodex::base64::encode` dependency (SD-021); the path dependency now pins `version = "0.1.13"` so a future publish resolves encodex from crates.io.

## v0.2.0

- Added `#[non_exhaustive]` to extensible public enums such as `MarkerPosition`, `TemplateExpansionError`, `IssueLevel`, `BuiltinEncoding`, and `PayloadError`.
- Added `Display` implementations for developer-facing public types including `PayloadDb`, `Grammar`, `ExpandedPayload`, `Payload`, `PayloadConfig`, and related helper types.
- Added `# Thread Safety` sections across the public API to state whether each type is `Send`, `Sync`, or implementation-defined.
- Added `#[must_use]` to important constructors and value-returning APIs that are easy to ignore by accident.
