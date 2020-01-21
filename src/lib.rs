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
rule rule_name
{
    meta:
        description = "This is just an example"
}
        "#;
    let result = yara::rule().parse(input);
    alert(&format!("Parsed: {:#?}!", result));
}
