extern crate pom;
use pom::parser::{call, empty, list, none_of, one_of, seq, sym, Parser};
use std::collections::HashMap;
use std::fmt;

const HEX: &'static [u8; 16] = b"0123456789ABCDEF";

#[derive(Debug, PartialEq, Hash, Eq, Clone)]
pub enum YaraIdentifier {
    Str(String),
}

impl fmt::Display for YaraIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YaraIdentifier::Str(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum YaraHex {
    Byte(u8),
    Wildcard,
    Jump(usize, usize),
}

#[derive(Debug, PartialEq)]
pub enum YaraMetaValues {
    Str(String),
    Bool(bool),
    Int(usize),
}

#[derive(Debug, PartialEq)]
pub enum YaraStringsModifier {
    None,
    Nocase,
    Wide,
    ASCII,
    XOR,
    Base64,
    Base64Wide,
    Fullword,
    Private,
}

#[derive(Debug, PartialEq)]
pub enum YaraStrings {
    Str(String, YaraStringsModifier),
    Regex(String, YaraStringsModifier),
    Hex(Vec<YaraHex>, YaraStringsModifier),
}

#[derive(Debug, PartialEq)]
pub enum YaraCondition {
    Identifier(YaraIdentifier),
    Or(Box<YaraCondition>, Box<YaraCondition>),
    And(Box<YaraCondition>, Box<YaraCondition>),
}

#[derive(Debug)]
pub enum YaraSections {
    Meta(HashMap<YaraIdentifier, YaraMetaValues>),
    Strings(HashMap<YaraIdentifier, YaraStrings>),
    Condition(YaraCondition),
}

#[derive(Debug)]
pub struct YaraRule {
    pub name: YaraIdentifier,
    pub sections: Vec<YaraSections>,
}

fn space<'a>() -> Parser<'a, u8, ()> {
    one_of(b" \t\r\n").repeat(0..).discard()
}

fn integer<'a>() -> Parser<'a, u8, usize> {
    one_of(b"0123456789")
        .repeat(1..)
        .convert(String::from_utf8)
        .map(|i| i.parse::<usize>().unwrap())
}

fn opt_integer<'a>() -> Parser<'a, u8, usize> {
    one_of(b"0123456789")
        .repeat(0..)
        .convert(String::from_utf8)
        .map(|i| i.parse::<usize>().unwrap_or(0))
}

fn meta_integer<'a>() -> Parser<'a, u8, YaraMetaValues> {
    integer().map(|i| YaraMetaValues::Int(i))
}

fn string<'a>() -> Parser<'a, u8, String> {
    let special_char = sym(b'\\')
        | sym(b'/')
        | sym(b'"')
        | sym(b'b').map(|_| b'\x08')
        | sym(b'f').map(|_| b'\x0C')
        | sym(b'n').map(|_| b'\n')
        | sym(b'r').map(|_| b'\r')
        | sym(b't').map(|_| b'\t');
    let escape_sequence = sym(b'\\') * special_char;
    let string = sym(b'"') * (none_of(b"\\\"") | escape_sequence).repeat(0..) - sym(b'"');
    string.convert(String::from_utf8)
}

fn meta_string<'a>() -> Parser<'a, u8, YaraMetaValues> {
    string().map(|s| YaraMetaValues::Str(s))
}

fn opt_modifier<'a>() -> Parser<'a, u8, YaraStringsModifier> {
    seq(b"nocase").map(|_| YaraStringsModifier::Nocase)
        | seq(b"wide").map(|_| YaraStringsModifier::Wide)
        | seq(b"ascii").map(|_| YaraStringsModifier::ASCII)
        | seq(b"xor").map(|_| YaraStringsModifier::XOR)
        | seq(b"base64").map(|_| YaraStringsModifier::Base64)
        | seq(b"base64wide").map(|_| YaraStringsModifier::Base64Wide)
        | seq(b"fullword").map(|_| YaraStringsModifier::Fullword)
        | seq(b"private").map(|_| YaraStringsModifier::Private)
        | empty().map(|_| YaraStringsModifier::None)
}

fn st_string<'a>() -> Parser<'a, u8, YaraStrings> {
    let modified_string = string() - space() + opt_modifier();
    modified_string.map(|(s, m)| YaraStrings::Str(s, m))
}

fn st_regex<'a>() -> Parser<'a, u8, YaraStrings> {
    let special_char = sym(b'\\')
        | sym(b'/')
        | sym(b'"')
        | sym(b'n').map(|_| b'\n')
        | sym(b'r').map(|_| b'\r')
        | sym(b't').map(|_| b'\t');
    let escape_sequence = sym(b'\\') * special_char;
    let regexp = sym(b'/') * (none_of(b"\\/") | escape_sequence).repeat(0..) - sym(b'/');
    let regex_str = regexp.convert(String::from_utf8);
    let modified_regexp = regex_str - space() + opt_modifier();
    modified_regexp.map(|(s, m)| YaraStrings::Regex(s, m))
}

fn st_hex<'a>() -> Parser<'a, u8, YaraStrings> {
    let wildcard = sym(b'?').map(|_| YaraHex::Wildcard);
    let jump =
        (sym(b'[') * space()) * opt_integer() - sym(b'-') + opt_integer() - (space() - sym(b']'));
    let jump_res = jump.map(|j| YaraHex::Jump(j.0, j.1));
    let byte = one_of(HEX).map(|b| YaraHex::Byte(b));
    let hex_string = list(byte | jump_res | wildcard, space());
    let pattern = (sym(b'{') - space()) * hex_string - (space() - sym(b'}'));
    let modified_pattern = pattern - space() + opt_modifier();
    modified_pattern.map(|(h, m)| YaraStrings::Hex(h, m))
}

fn boolean<'a>() -> Parser<'a, u8, YaraMetaValues> {
    seq(b"true").map(|_| YaraMetaValues::Bool(true))
        | seq(b"false").map(|_| YaraMetaValues::Bool(false))
}

fn identifier<'a>() -> Parser<'a, u8, YaraIdentifier> {
    let identifier = space()
        * (one_of(b"abcdefghijklmnopqrstuvwxyz_$") | one_of(b"ABCDEFGHUIJKLMNOPQRSTUVWXYZ"))
            .repeat(1..)
        - space();
    identifier
        .convert(String::from_utf8)
        .map(|id| YaraIdentifier::Str(id))
}

fn meta<'a>() -> Parser<'a, u8, YaraSections> {
    let member =
        identifier() - space() - sym(b'=') - space() + (meta_integer() | meta_string() | boolean());
    let members = list(member, space());
    let meta = space() * seq(b"meta:") * space() * members - space();
    meta.map(|members| members.into_iter().collect::<HashMap<_, _>>())
        .map(|s| YaraSections::Meta(s))
}

fn strings<'a>() -> Parser<'a, u8, YaraSections> {
    let member =
        identifier() - space() - sym(b'=') - space() + (st_string() | st_hex() | st_regex());
    let members = list(member, space());
    let strings = space() * seq(b"strings:") * space() * members - space();
    strings
        .map(|members| members.into_iter().collect::<HashMap<_, _>>())
        .map(|s| YaraSections::Strings(s))
}

fn c_identifier<'a>() -> Parser<'a, u8, YaraCondition> {
    identifier().map(|i| YaraCondition::Identifier(i))
}

fn c_and<'a>() -> Parser<'a, u8, YaraCondition> {
    let p_and = (c_identifier() | call(conditions)) - (space() * seq(b"and") * space())
        + (call(conditions) | c_identifier());
    p_and.map(|c| YaraCondition::And(Box::new(c.0), Box::new(c.1)))
}

fn c_or<'a>() -> Parser<'a, u8, YaraCondition> {
    let p_or = (c_identifier() | call(conditions)) - (space() * seq(b"or") * space())
        + (call(conditions) | c_identifier());
    p_or.map(|c| YaraCondition::Or(Box::new(c.0), Box::new(c.1)))
}

fn conditions<'a>() -> Parser<'a, u8, YaraCondition> {
    let open_b = || space() * sym(b'(') * space();
    let close_b = || space() * sym(b')') * space();
    let subcondition = || ((open_b()) * (c_and() | c_or()) - (close_b()));
    let sub_and =
        subcondition() - (space() * seq(b"and") * space()) + (call(conditions) | c_identifier());
    let p_sub_and = sub_and.map(|c| YaraCondition::And(Box::new(c.0), Box::new(c.1)));
    let sub_or =
        subcondition() - (space() * seq(b"or") * space()) + (call(conditions) | c_identifier());
    let p_sub_or = sub_or.map(|c| YaraCondition::Or(Box::new(c.0), Box::new(c.1)));
    (p_sub_and | p_sub_or | subcondition()) | (c_and() | c_or() | c_identifier())
}

fn s_conditions<'a>() -> Parser<'a, u8, YaraSections> {
    let conditions = space() * seq(b"condition:") * conditions();
    conditions.map(|c| YaraSections::Condition(c))
}

pub fn rule<'a>() -> Parser<'a, u8, YaraRule> {
    let sections = meta() | strings() | s_conditions();
    let rule_name = seq(b"rule") * identifier();
    let rule = (space() * rule_name - sym(b'{')) + (sections.repeat(0..) - sym(b'}') - space());
    rule.map(|r| YaraRule {
        name: r.0,
        sections: r.1,
    })
}

#[allow(dead_code)]
pub fn parse_rules<'a>(input: &'a [u8]) -> Result<Vec<YaraRule>, pom::Error> {
    list(rule(), space()).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn parse_basic_example() {
        let input = br#"
rule rule_name
{
    meta:
        description = "This is just an example"
        priority = 5
        enabled = true
    strings:
        $a = "123"
        $b = { AB [0-2] ?D }
        $c = "abcd"
    condition:
        $a or $b or $c
}
        "#;
        let result = rule().parse(input);
        assert!(
            result.is_ok(),
            "Example failed to parse: {:#?}", result
        );
    }
    #[test]
    fn parse_tricky_condition_example() {
        let input = br#"
rule rule_name
{
    meta:
        description = "This is just an example"
        priority = 5
        enabled = true
    strings:
        $a = "123"
        $b = { AB [0-2] ?D }
        $c = "abcd"
        $d = "asdf"
    condition:
        ($a or ($b and $c)) or $d
}
        "#;
        let result = rule().parse(input);
        assert!(
            result.is_ok(),
            "Example failed to parse: {:#?}", result
        );
    }
    #[test]
    fn parse_add_example() {
        let input = br#"
rule add
{
    meta:
        description = "Add example wasm file"
    strings:
        $a = { 00 61 73 6D }
        $b = { 61 64 64 }
    condition:
        ($a and $b)
}
        "#;

        let result = rule().parse(input);
        println!("{:#?}", result);
        assert!(
            result.is_ok(),
            "Example failed to parse: {:#?}", result
        );
    }
    #[test]
    fn parse_apple_rules() {
        let apple_rules = fs::read("tests/rules.yara").expect("unable to open file");
        let result = parse_rules(&apple_rules[..]);
        assert!(
            result.is_ok(),
            "Example failed to parse: {:#?}", result
        );
    }
    #[test]
    fn parse_string_modifiers() {
        let input = br#"
rule rule_name
{
    meta:
        description = "This is just an example"
        priority = 5
        enabled = true
    strings:
        $a = "foobar" nocase
        $b = { AB [0-2] ?D } private
    condition:
        $a or $b or $c
}
        "#;
        let result = rule().parse(input);
        assert!(
            result.is_ok(),
            "Example failed to parse: {:#?}", result
        );
    }
    #[test]
    fn parse_regex() {
        let input = br#"
rule rule_name
{
    meta:
        description = "This is just an example"
        priority = 5
        enabled = true
    strings:
        $a = /foo.ar/ nocase
        $b = /foo\/ar/ nocase
    condition:
        $a
}
        "#;
        let result = rule().parse(input);
        assert!(
            result.is_ok(),
            "Example failed to parse: {:#?}", result
        );
    }
}
