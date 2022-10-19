use crate::yara::parser::{
    YaraCondition, YaraHex, YaraIdentifier, YaraRule, YaraSections, YaraStrings,
};
use hex;
use regex;
use std::collections::HashMap;

fn check_hex(test_hex: &Vec<YaraHex>, payload: &[u8]) -> bool {
    let hex_string = hex::encode(payload);
    let test_hex_string: String = test_hex
        .iter()
        .map(|h| match h {
            YaraHex::Byte(b) => std::str::from_utf8(&[*b]).unwrap().to_ascii_lowercase(),
            YaraHex::Jump(start, end) => format!("[0-9a-f]{{{},{}}}", start, end),
            YaraHex::Wildcard => "[0-9a-f]".to_string(),
        })
        .collect();
    println!("{} - {}", hex_string, test_hex_string);
    let re = regex::Regex::new(&test_hex_string).unwrap();
    re.is_match(&hex_string)
}

impl YaraRule {
    fn strings(&self) -> &HashMap<YaraIdentifier, YaraStrings> {
        for section in &self.sections {
            match section {
                YaraSections::Strings(strings) => return strings,
                _ => continue,
            }
        }
        panic!("oops")
    }

    fn conditions(&self) -> &YaraCondition {
        for section in &self.sections {
            match section {
                YaraSections::Condition(condition) => return condition,
                _ => continue,
            }
        }
        panic!()
    }

    fn check_strings(&self, payload: &[u8]) -> HashMap<YaraIdentifier, bool> {
        self.strings()
            .iter()
            .map(|(id, strs)| match strs {
                YaraStrings::Regex(s, _) => (
                    id.clone(),
                    regex::bytes::Regex::new(s).unwrap().is_match(payload),
                ),
                YaraStrings::Str(s, _) => (
                    id.clone(),
                    regex::bytes::Regex::new(&regex::escape(s))
                        .unwrap()
                        .is_match(payload),
                ),
                YaraStrings::Hex(h, _) => (id.clone(), check_hex(h, payload)),
            })
            .collect()
    }

    fn evaluate(&self, matches: &HashMap<YaraIdentifier, bool>, cond: &YaraCondition) -> bool {
        match cond {
            YaraCondition::Identifier(id) => *matches.get(id).unwrap(),
            YaraCondition::And(l, r) => self.evaluate(matches, &*l) && self.evaluate(matches, &*r),
            YaraCondition::Or(l, r) => self.evaluate(matches, &*l) || self.evaluate(matches, &*r),
        }
    }

    pub fn matches(&self, payload: &[u8]) -> bool {
        let matches = self.check_strings(payload);
        self.evaluate(&matches, self.conditions())
    }
}

#[cfg(test)]
mod tests {
    use crate::yara::parser;
    #[test]
    fn matches_strings() {
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
        $c = "bar"
    condition:
        $a or $b or $c
}
        "#;
        let result = parser::rule().parse(input);
        assert!(result.is_ok(), "Example failed to parse: {:#?}", result);
        assert!(result.unwrap().matches(b"foo bar baz"));
    }

    #[test]
    fn matches_hex() {
        let input = br#"
rule rule_name
{
    meta:
        description = "This is just an example"
        priority = 5
        enabled = true
    strings:
        $a = "123"
        $b = { 66 [0-9] 7? }
        $c = "oops"
    condition:
        $a or $b or $c
}
        "#;
        let result = parser::rule().parse(input);
        assert!(result.is_ok(), r#"Example failed to parse: {:#?}"#, result);
        assert!(result.unwrap().matches(b"foo bar baz"));
    }
}
