extern crate proc_macro;
use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use yara::parse_rules;

/// a proc macro takes tokens as argument, and generates tokens
#[proc_macro]
pub fn yara(input: TokenStream) -> TokenStream {
    // we expect a string literal here, we let syn extract it
    let s: syn::LitStr = syn::parse(input).unwrap();
    let string = s.value();

    // we can then parse that string. We unwrap here because
    // panicking will display a compilation error
    let rules = parse_rules(&string);
    let name = rules.name;
    let identifier = match name {
        yara::yara::parser::YaraIdentifier::Str(id) => id,
    };

    // we can then generate code using what we parsed. That
    // code will replace the macro call, so
    // `let val = parse!("Hello Alice!");` will be replaced
    // by `let val = Hello { name: "Alice" };`
    let gen = quote! {
        yara::yara::parser::YaraRule {
            name: yara::yara::parser::YaraIdentifier::Str(#identifier.to_string()),
            sections: Vec::new(),
        }
    };
    gen.into()
}
