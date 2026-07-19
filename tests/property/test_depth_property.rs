use attackstr::{apply_encoding, expand_template, mutate_all, BuiltinEncoding};
use proptest::prelude::*;
use std::collections::HashMap;

proptest! {
    #[test]
    fn prop_apply_encoding_does_not_panic(s in "\\PC*", encoding_idx in 0..BuiltinEncoding::ALL.len()) {
        let encoding = BuiltinEncoding::ALL[encoding_idx];
        let _ = apply_encoding(&s, encoding);
    }

    #[test]
    fn prop_mutate_all_does_not_panic(s in "\\PC*") {
        let _ = mutate_all(&s);
    }

    #[test]
    fn prop_expand_template_does_not_panic(template in "\\PC*") {
        let lookup = HashMap::new();
        let _ = expand_template(template, &lookup);
    }
}
