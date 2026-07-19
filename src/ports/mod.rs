//! Legacy static exploitation payloads ported from older Santh tools.
//!
//! These rules predate the generic grammar engine and are kept behind the
//! `exploits` feature so consumers opt into them explicitly.

pub mod cmdi;
pub mod sqli;
