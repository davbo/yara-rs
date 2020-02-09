use crate::yara::parser::{YaraIdentifier, YaraRule, YaraSections, YaraStrings};
use std::collections::HashMap;

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

    fn check_strings(&self, payload: &[u8]) -> bool {
        let strings = self.strings();
        for (_, strs) in strings {
            if match strs {
                YaraStrings::Str(s) => payload.windows(s.len()).position(|win| win == s.as_bytes()).is_some(),
                _ => false
            } { return true }
        }
        false
    }

    pub fn matches(&self, payload: &[u8]) -> bool {
        self.check_strings(payload)
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
}
