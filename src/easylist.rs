/*
https://github.com/gorhill/uBlock/wiki/Static-filter-syntax
*/

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_until, take_while1},
    character::complete::{char, multispace0, not_line_ending},
    combinator::{map, opt, recognize, rest},
    multi::separated_list1,
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult, Parser,
};

// TODO: Handle PCRE-style regexes
// TODO: Use String::with_capacity
// TODO: Use trie or Aho-Corasick automaton for better filter ordering for substring-based rules
// TODO: Use domain-tree for || rules

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    Block,
    Allow, // corresponds to '@@'
}

/// The type of filter—Network (URL) or Cosmetic (CSS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterCategory {
    Network,  // e.g. "||example.com^$script"
    Cosmetic, // e.g. "example.com###ad-banner"
    CosmeticException, // e.g. "##@#example###rule" (rare)
              // TODO include redirections and Content Security Policy blocks
}

/// Represents the options after the `$` in a network filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkOptions {
    pub resource_types: Vec<String>,  // script, image, xmlhttprequest…
    pub domain_includes: Vec<String>, // domain=foo.com
    pub domain_excludes: Vec<String>, // domain=~bar.example
    pub third_party: Option<bool>, // Some(true) = only third-party, Some(false) = only first-party, None = either
}

/// A fully parsed filter rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    pub rule_type: RuleType,
    pub category: FilterCategory,
    pub raw_filter: String, // The original line (for reference/debug)
    pub pattern: String,    // The portion before any `$`
    pub options: Option<NetworkOptions>,
    pub css_selector: Option<String>, // for cosmetic filters, e.g. "#ad-banner"
    pub domain_specifier: Option<String>, // e.g. "example.com" in `example.com##.ads`
}

fn not_newline(c: char) -> bool {
    c != '\n' && c != '\r'
}

fn parse_comment(input: &str) -> IResult<&str, &str> {
    alt((
        preceded(tag("!"), not_line_ending),
        delimited(char('['), take_until("]"), char(']')),
    ))
    .parse(input)
}

fn parse_exception_prefix(input: &str) -> IResult<&str, RuleType> {
    map(opt(tag("@@")), |opt_tag: Option<&str>| {
        if opt_tag.is_some() {
            RuleType::Allow
        } else {
            RuleType::Block
        }
    })
    .parse(input)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    Domain, // "||"
    Left,   // "|" at start
    Right,  // "|" at end
    None,
}

fn parse_double_pipe(input: &str) -> IResult<&str, Anchor> {
    map(tag("||"), |_| Anchor::Domain).parse(input)
}
fn parse_single_pipe(input: &str) -> IResult<&str, Anchor> {
    map(char('|'), |_| Anchor::Left).parse(input)
}
fn parse_anchor(input: &str) -> IResult<&str, Anchor> {
    alt((
        parse_double_pipe,
        parse_single_pipe,
        map(tag(""), |_| Anchor::None),
    ))
    .parse(input)
}

fn parse_pattern(input: &str) -> IResult<&str, &str> {
    recognize(take_while1(|c: char| c != '$' && not_newline(c))).parse(input)
}

fn parse_single_option(input: &str) -> IResult<&str, &str> {
    recognize(take_while1(|c: char| c != ',' && not_newline(c))).parse(input)
}

fn parse_option_list(input: &str) -> IResult<&str, Vec<&str>> {
    separated_list1(char(','), parse_single_option).parse(input)
}

fn parse_network_filter(input: &str) -> IResult<&str, FilterRule> {
    let (rem, rule_type) = parse_exception_prefix(input)?;
    // Pattern (up to '$' or end)
    let (rem, raw_pattern) = parse_pattern(rem)?;
    // Maybe options after '$'
    let (rem, opts) = opt(preceded(char('$'), parse_option_list)).parse(rem)?;

    let mut pattern = raw_pattern.trim().to_string();

    if pattern.ends_with('|') {
        pattern.pop();
    }

    let options = opts.map(|vec_str| {
        let mut netopt = NetworkOptions {
            resource_types: Vec::new(),
            domain_includes: Vec::new(),
            domain_excludes: Vec::new(),
            third_party: None,
        };
        for opt in vec_str {
            if opt == "third-party" {
                netopt.third_party = Some(true);
            } else if opt == "first-party" {
                netopt.third_party = Some(false);
            } else if let Some(rest) = opt.strip_prefix("domain=") {
                // Domain list can be separated by '|'
                for dom in rest.split('|') {
                    if dom.starts_with('~') {
                        netopt
                            .domain_excludes
                            .push(dom.trim_start_matches('~').to_string());
                    } else {
                        netopt.domain_includes.push(dom.to_string());
                    }
                }
            } else if [
                "script",
                "image",
                "object",
                "xmlhttprequest",
                "subdocument",
                "stylesheet",
                "popup",
                "other",
            ]
            .contains(&opt)
            {
                netopt.resource_types.push(opt.to_string());
            } else {
                // handle other flags like `important`, `redirect=…`, etc.
            }
        }
        netopt
    });

    Ok((
        rem,
        FilterRule {
            rule_type,
            category: FilterCategory::Network,
            raw_filter: input.lines().next().unwrap_or("").to_string(),
            pattern,
            options,
            css_selector: None,
            domain_specifier: None,
        },
    ))
}

fn parse_domain_specifier(input: &str) -> IResult<&str, &str> {
    // Domain specifier ends right before '##' or '#@#'
    take_while1(|c: char| c != '#')(input)
}

fn parse_cosmetic_filter(input: &str) -> IResult<&str, FilterRule> {
    let (rem, rule_type) = parse_exception_prefix(input)?;
    let (rem2, (domain_opt, is_exception)) = alt((
        map(
            terminated(parse_domain_specifier, tag("#@#")),
            |ds: &str| (ds.trim(), true),
        ),
        map(terminated(parse_domain_specifier, tag("##")), |ds: &str| {
            (ds.trim(), false)
        }),
        // If there is no domain and only "#@#"
        map(tag("#@#"), |_| ("", true)),
        // If there is no domain and only "##"
        map(tag("##"), |_| ("", false)),
    ))
    .parse(rem)?;

    // At this point, rem2 starts right *after* "##" or "#@#"
    let (rem3, selector_raw) = not_line_ending(rem2)?;
    let selector = selector_raw.trim();

    // Strip all leading '#' and '.' from the selector
    let selector_trimmed = selector
        .trim_start_matches(|c| c == '#' || c == '.')
        .to_string();

    let category = if is_exception {
        FilterCategory::CosmeticException
    } else {
        FilterCategory::Cosmetic
    };

    let domain_str = domain_opt.trim();
    let domain = if domain_str.is_empty() {
        None
    } else {
        Some(domain_str.to_string())
    };

    Ok((
        rem3,
        FilterRule {
            rule_type,
            category,
            raw_filter: input.lines().next().unwrap_or("").to_string(),
            pattern: String::new(),
            options: None,
            css_selector: Some(selector_trimmed),
            domain_specifier: domain,
        },
    ))
}

fn parse_line(input: &str) -> Option<FilterRule> {
    let line = input.trim();
    if line.is_empty() {
        return None;
    }

    // If it starts with '!' or is of the form "[...]", skip it entirely.
    if line.starts_with('!') || (line.starts_with('[') && line.ends_with(']')) {
        return None;
    }

    // If there's any internal whitespace (spaces/tabs), it's not a valid filter
    if line.chars().any(|c: char| c.is_whitespace()) {
        return None;
    }

    // Try cosmetic first—but only if it consumes the entire line
    if let Ok((rem, rule)) = parse_cosmetic_filter(line) {
        if rem.trim().is_empty() {
            return Some(rule);
        }
    }

    if let Ok((rem, rule)) = parse_network_filter(line) {
        if rem.trim().is_empty() {
            return Some(rule);
        }
    }

    eprintln!("Warning: Could not parse line: {:?}", line);
    None
}

pub fn parse_easylist(contents: &String) -> Vec<FilterRule> {
    contents.lines().filter_map(|l| parse_line(l)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_domain() {
        let line = "||ads.example.com^$script,image";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Block);
        assert_eq!(rule.pattern, "||ads.example.com^".to_string());
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"script".to_string()));
        assert!(opts.resource_types.contains(&"image".to_string()));
    }

    #[test]
    fn test_whitelist_url() {
        let line = "@@|http://goodtracker.net/track.js$third-party";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Allow);
        assert_eq!(rule.pattern, "|http://goodtracker.net/track.js".to_string());
        assert_eq!(rule.options.unwrap().third_party, Some(true));
    }

    #[test]
    fn test_cosmetic_block() {
        let line = "example.com###ad-banner";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(rule.domain_specifier, Some("example.com".to_string()));
        assert_eq!(rule.css_selector, Some("ad-banner".to_string()));
    }

    #[test]
    fn test_cosmetic_exception() {
        let line = "example.com#@#popunder";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::CosmeticException);
        assert_eq!(rule.domain_specifier, Some("example.com".to_string()));
        assert_eq!(rule.css_selector, Some("popunder".to_string()));
    }

    #[test]
    fn test_global_cosmetic_block() {
        let line = "###floating-banner";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(rule.domain_specifier, None);
        assert_eq!(rule.css_selector, Some("floating-banner".to_string()));
    }

    #[test]
    fn test_domain_include_exclude() {
        let line = "||example.org^$domain=foo.com|~bar.com,script";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.pattern, "||example.org^".to_string());
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"script".to_string()));
        assert!(opts.domain_includes.contains(&"foo.com".to_string()));
        assert!(opts.domain_excludes.contains(&"bar.com".to_string()));
    }

    #[test]
    fn test_url_with_trailing_pipe() {
        let line = "|http://mysite.com/ads/banner.png|$image";
        let rule = parse_network_filter(line).unwrap().1;
        // We strip the trailing '|' from pattern, so we expect:
        assert_eq!(
            rule.pattern,
            "|http://mysite.com/ads/banner.png".to_string()
        );
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"image".to_string()));
    }

    #[test]
    fn test_simple_block_no_options() {
        // A basic blocking filter without any `$`-options
        let line = "ads.badsite.com/banner.jpg";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Block);
        assert_eq!(rule.pattern, "ads.badsite.com/banner.jpg".to_string());
        assert!(rule.options.is_none());
    }

    #[test]
    fn test_whitelist_domain_level() {
        // Whitelist at domain-level with no extra options
        let line = "@@||example.com^";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Allow);
        assert_eq!(rule.pattern, "||example.com^".to_string());
        assert!(rule.options.is_none());
    }

    #[test]
    fn test_first_party_option() {
        // Filter specifying first-party
        let line = "||tracking.example.net^$first-party,popup";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Block);
        assert_eq!(rule.pattern, "||tracking.example.net^".to_string());
        let opts = rule.options.unwrap();
        assert_eq!(opts.third_party, Some(false));
        // 'popup' is recognized as a resource type
        assert!(opts.resource_types.contains(&"popup".to_string()));
    }

    #[test]
    fn test_multiple_resource_types_and_caret_anchor() {
        // A filter with ^ anchor and multiple resource types
        let line = "|http://site.org^$script,stylesheet,xmlhttprequest,object";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.pattern, "|http://site.org^".to_string());
        let opts = rule.options.unwrap();
        let expected = vec!["script", "stylesheet", "xmlhttprequest", "object"];
        for typ in expected {
            assert!(opts.resource_types.contains(&typ.to_string()));
        }
    }

    #[test]
    fn test_domain_option_only_includes_multiple() {
        // Domain option with multiple includes, no excludes
        let line = "||example.co.uk^$domain=foo.com|bar.com";
        let rule = parse_network_filter(line).unwrap().1;
        let opts = rule.options.unwrap();
        assert_eq!(opts.domain_includes.len(), 2);
        assert!(opts.domain_includes.contains(&"foo.com".to_string()));
        assert!(opts.domain_includes.contains(&"bar.com".to_string()));
        assert!(opts.domain_excludes.is_empty());
    }

    #[test]
    fn test_empty_domain_list() {
        // Domain= with no actual domains (edge case)
        let line = "||example.test^$domain=";
        let rule = parse_network_filter(line).unwrap().1;
        let opts = rule.options.unwrap();
        // domain_includes should contain a single empty string, as split("") yields [""].
        assert_eq!(opts.domain_includes, vec!["".to_string()]);
        assert!(opts.domain_excludes.is_empty());
    }

    #[test]
    fn test_parse_line_ignores_blank_and_comments() {
        // parse_line should return None for blank lines or comments
        assert!(parse_line("").is_none());
        assert!(parse_line("   ").is_none());
        assert!(parse_line("! This is a comment").is_none());
        assert!(parse_line("[Adblock Plus 2.0]").is_none());
    }

    #[test]
    fn test_parse_easylist_mixed_content() {
        let contents = r#"
            ! This is a comment
            ||a.example.com^$image

            example.com###banner
            @@||b.example.org^$third-party,script
            ###floating-ad
            "#;
        let rules = parse_easylist(&contents.to_string());
        // We expect 4 rules (two network, two cosmetic)
        assert_eq!(rules.len(), 4);

        // 1st: network block
        assert_eq!(rules[0].category, FilterCategory::Network);
        assert_eq!(rules[0].pattern, "||a.example.com^".to_string());

        // 2nd: cosmetic block with domain
        assert_eq!(rules[1].category, FilterCategory::Cosmetic);
        assert_eq!(rules[1].domain_specifier, Some("example.com".to_string()));
        assert_eq!(rules[1].css_selector, Some("banner".to_string()));

        // 3rd: network allow
        assert_eq!(rules[2].rule_type, RuleType::Allow);
        assert_eq!(rules[2].pattern, "||b.example.org^".to_string());
        let opts = rules[2].options.clone().unwrap();
        assert_eq!(opts.third_party, Some(true));
        assert!(opts.resource_types.contains(&"script".to_string()));

        // 4th: global cosmetic block
        assert_eq!(rules[3].category, FilterCategory::Cosmetic);
        assert_eq!(rules[3].domain_specifier, None);
        assert_eq!(rules[3].css_selector, Some("floating-ad".to_string()));
    }

    #[test]
    fn test_cosmetic_selector_with_class_prefix() {
        // Selector starts with a dot; ensure strip_prefix('.') works
        let line = "##.ad-class.large";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(rule.domain_specifier, None);
        // Leading '.' stripped, so we get "ad-class.large"
        assert_eq!(rule.css_selector, Some("ad-class.large".to_string()));
    }

    #[test]
    fn test_cosmetic_selector_with_hash_prefix() {
        // Selector starts with '#'; ensure strip_prefix('#') works
        let line = "example.org####header";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(rule.domain_specifier, Some("example.org".to_string()));
        // It sees selector_raw = "#header", strip_prefix('#') -> "header"
        assert_eq!(rule.css_selector, Some("header".to_string()));
    }

    #[test]
    fn test_cosmetic_exception_without_domain() {
        // Exception cosmetic when no domain is given
        let line = "#@#.popup-element";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::CosmeticException);
        assert_eq!(rule.domain_specifier, None);
        // Leading '.' stripped
        assert_eq!(rule.css_selector, Some("popup-element".to_string()));
    }

    #[test]
    fn test_invalid_line_warning_and_none() {
        // A line that can't be parsed as either network or cosmetic
        // parse_line should return None and produce a warning
        let line = "not a valid filter $$$";
        assert!(parse_line(line).is_none());
    }
}
