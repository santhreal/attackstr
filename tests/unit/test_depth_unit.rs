use attackstr::{
    apply_encoding, expand_template, mutate_all, PayloadConfig, PayloadDb, PayloadSource,
};
use std::collections::HashMap;

#[test]
fn test_mutate_all_normal() {
    let payload = "SELECT * FROM users";
    let mutations = mutate_all(payload).unwrap();
    assert!(
        !mutations.is_empty(),
        "mutate_all should return mutations for a normal payload"
    );
    assert!(mutations.iter().any(|m| m.contains("/*")));
}

#[test]
fn test_apply_encoding_normal() {
    let input = "admin' OR 1=1--";
    let encoded = apply_encoding(input, "url_encode").unwrap();
    assert_eq!(encoded, "admin%27%20OR%201%3D1--");
}

#[test]
fn test_apply_encoding_edge_cases() {
    assert_eq!(apply_encoding("", "url_encode").unwrap(), "");
    let spaces = "   ";
    assert_eq!(apply_encoding(spaces, "url_encode").unwrap(), "%20%20%20");
}

#[test]
fn test_expand_template_normal() {
    let template = "SELECT {col} FROM {table}";
    let mut lookup = HashMap::new();
    lookup.insert(
        "col".to_string(),
        vec!["id".to_string(), "name".to_string()],
    );
    lookup.insert("table".to_string(), vec!["users".to_string()]);

    let expanded = expand_template(template.to_string(), &lookup).unwrap();
    assert_eq!(expanded.len(), 2);
    assert!(expanded.contains(&"SELECT id FROM users".to_string()));
    assert!(expanded.contains(&"SELECT name FROM users".to_string()));
}

#[test]
fn test_expand_template_missing_var() {
    let template = "SELECT {col} FROM {table}";
    let lookup = HashMap::new();

    let expanded = expand_template(template.to_string(), &lookup).unwrap();
    assert_eq!(expanded.len(), 1);
    assert_eq!(expanded[0], "SELECT {col} FROM {table}");
}

#[test]
fn test_expand_template_edge_cases() {
    let template = "{}";
    let lookup = HashMap::new();
    let expanded = expand_template(template.to_string(), &lookup).unwrap();
    assert_eq!(expanded.len(), 1);
    assert_eq!(expanded[0], "{}");
}

#[test]
fn test_payload_db_new_and_config() {
    let db = PayloadDb::new();
    assert_eq!(db.payload_count(), 0);

    let config = PayloadConfig::default();
    let db2 = PayloadDb::with_config(config);
    assert_eq!(db2.payload_count(), 0);
}

#[test]
fn test_payload_db_clear() {
    let mut db = PayloadDb::new();
    db.load_toml(
        r#"
[grammar]
name = "test"
sink_category = "test-cat"

[[techniques]]
name = "t1"
template = "payload"
"#,
    )
    .unwrap();
    assert_eq!(db.payload_count(), 1);
    db.clear();
    assert_eq!(db.payload_count(), 0);
}
