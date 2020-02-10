use crate::yara::parser::{YaraIdentifier, YaraRule, YaraSections, YaraStrings, YaraHex};
use std::collections::HashMap;

fn check_hex(test_hex: &Vec<YaraHex>, payload: &[u8]) -> bool {
    true
}

impl YaraRule {
    fn strings(&self) -> &HashMap<YaraIdentifier, YaraStrings> {
        for section in &self.sections {
            match section {
                YaraSections::Strings(strings) => return strings,
                _ => continue
            }
        };
        panic!()
    }

    fn check_strings(&self, payload: &[u8]) -> HashMap<YaraIdentifier, bool> {
        self.strings().iter().map(|(id, strs)| {
            match strs {
                YaraStrings::Str(s) => (id.clone(), payload.windows(s.len()).position(|win| win == s.as_bytes()).is_some()),
                YaraStrings::Hex(h) => (id.clone(), check_hex(h, payload)),
            }
        }).collect()
    }

    pub fn matches(&self, payload: &[u8]) -> bool {
        self.check_strings(payload).iter().any(|(_, val)| *val)
    }
}

#[cfg(test)]
mod tests {
    use crate::yara::parser;
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
        $c = "bar"
    condition:
        $a or $b or $c
}
        "#;
        let result = parser::rule().parse(input);
	      assert!(result.is_ok(), format!("Example failed to parse: {:#?}", result));
        assert!(result.unwrap().matches(b"foo bar baz"));
    }

    #[test]
    fn match_hex_example() {
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
        assert!(
            result.is_ok(),
            format!("Example failed to parse: {:#?}", result)
        );
        assert!(result.unwrap().matches(b"foo AB__CD baz"));
  }
}
