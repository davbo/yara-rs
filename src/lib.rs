mod yara;
extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}


#[wasm_bindgen]
pub fn yara_match(rules: &str, payload: &[u8]) -> bool {
    let rule = yara::parser::rule().parse(rules.as_bytes()).unwrap();
    let result = rule.matches(payload);
    if result {
        log(&format!("Match against rule: {}", rule.name));
    }
    result
}

#[wasm_bindgen]
pub fn parse() {
    let input = br#"
rule test
{
    meta:
        description = "This is just an example"
    strings:
        $a = { 66 [0-9] 7? }
    condition:
        $a
}
        "#;
    let result = yara::parser::rule().parse(input);
    log(&format!("Parsed: {:#?}!", result));
    log(&format!(
        "Matches: {:#?}!",
        result.unwrap().matches(b"foo bar baz")
    ));
}
