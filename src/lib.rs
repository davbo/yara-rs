mod yara;
extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

// Import the `window.alert` function from the Web.
#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
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
    alert(&format!("Parsed: {:#?}!", result));
    alert(&format!(
        "Matches: {:#?}!",
        result.unwrap().matches(b"foo bar baz")
    ));
}
