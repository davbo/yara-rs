pub mod yara;

pub fn yara_match(rules: &str, payload: &[u8]) -> bool {
    let rule = yara::parser::rule().parse(rules.as_bytes()).unwrap();
    let result = rule.matches(payload);
    result
}

pub fn parse_rules(rules: &str) -> yara::parser::YaraRule {
    yara::parser::rule().parse(rules.as_bytes()).unwrap()
}
