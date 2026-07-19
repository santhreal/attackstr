use attackstr::{
    mutate_all, mutate_case, mutate_encoding_mix, mutate_sql_comments, mutate_whitespace,
};

fn main() {
    let payload = "UNION SELECT 1";

    println!("case mutations:");
    for variant in mutate_case(payload) {
        println!("  {variant}");
    }

    println!("whitespace mutations:");
    for variant in mutate_whitespace(payload) {
        println!("  {variant}");
    }

    println!("encoding mix mutations:");
    match mutate_encoding_mix(payload, &["url_encode", "unicode", "html_entities"]) {
        Ok(variants) => {
            for variant in variants {
                println!("  {variant}");
            }
        }
        Err(e) => eprintln!("encoding error: {e}"),
    }

    println!("sql comment mutations:");
    for variant in mutate_sql_comments(payload) {
        println!("  {variant}");
    }

    println!("all mutations:");
    match mutate_all("<script>alert(1)</script>") {
        Ok(variants) => {
            for variant in variants.into_iter().take(10) {
                println!("  {variant}");
            }
        }
        Err(e) => eprintln!("encoding error: {e}"),
    }
}
