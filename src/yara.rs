extern crate pom;
use pom::Parser;
use pom::parser::*;

use std::collections::HashMap;

#[derive(Debug, PartialEq, Hash, Eq)]
pub enum YaraIdentifier {
    Str(String)
}

#[derive(Debug, PartialEq)]
pub enum YaraHex {
    Byte(u8),
    Wildcard,
    Jump(usize, usize)
}

#[derive(Debug, PartialEq)]
pub enum YaraStrings {
    Str(String),
    Hex(Vec<YaraHex>)
}

#[derive(Debug)]
pub struct YaraRule {
    name: YaraIdentifier,
    meta: HashMap<YaraIdentifier, String>,
}

fn space() -> Parser<u8, ()> {
	  one_of(b" \t\r\n").repeat(0..).discard()
}

fn string() -> Parser<u8, String> {
    let special_char = sym(b'\\') | sym(b'/') | sym(b'"')
		    | sym(b'b').map(|_|b'\x08') | sym(b'f').map(|_|b'\x0C')
		    | sym(b'n').map(|_|b'\n') | sym(b'r').map(|_|b'\r') | sym(b't').map(|_|b'\t');
	  let escape_sequence = sym(b'\\') * special_char;
	  let string = sym(b'"') * (none_of(b"\\\"") | escape_sequence).repeat(0..) - sym(b'"');
	  string.convert(String::from_utf8)
}

fn identifier() -> Parser<u8, YaraIdentifier> {
    let identifier = space() * one_of(b"abcdefghijklmnopqrstuvwxyz_").repeat(1..) - space();
    identifier.convert(String::from_utf8).map(|id|YaraIdentifier::Str(id))
}

fn meta() -> Parser<u8, HashMap<YaraIdentifier, String>> {
    let member = identifier() - space() - sym(b'=') - space() + string();
    let members = list(member, space());
    let meta = space() * seq(b"meta:") * space() * members - space();
	  meta.map(|members|members.into_iter().collect::<HashMap<_,_>>())
}

pub fn rule() -> Parser<u8, YaraRule> {
    let rule_name = seq(b"rule") * identifier();
    let rule = (space() * rule_name - sym(b'{')) + (meta() - sym(b'}') - space());
    rule.map(|r|YaraRule{name: r.0, meta: r.1})
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_basic_example() {
        let input = br#"
rule rule_name
{
    meta:
        description = "This is just an example"
}
        "#;
        let result = rule().parse(input);
	      assert!(result.is_ok(), format!("Example failed to parse: {:#?}", result));
        println!()
    }
}
