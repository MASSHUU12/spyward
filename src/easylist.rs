/*
https://github.com/gorhill/uBlock/wiki/Static-filter-syntax
*/

use nom::{
    branch::alt,
    bytes::{
        complete::{tag, take_until, take_while1},
        escaped, is_not,
    },
    character::complete::{char, not_line_ending},
    combinator::{map, map_res, opt, recognize},
    multi::separated_list1,
    sequence::{delimited, preceded, terminated},
    IResult, Parser,
};
use regex::Regex;

// TODO: Use trie or Aho-Corasick automaton for better filter ordering for substring-based rules

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

/// Either a literal substring (with anchors/caret) or a full PCRE.
#[derive(Debug, Clone)]
pub enum FilterPattern {
    Literal(String),
    Regex(Regex),
}

/// A fully parsed filter rule.
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub rule_type: RuleType,
    pub category: FilterCategory,
    pub raw_filter: String, // The original line (for reference/debug)
    pub pattern: FilterPattern,
    pub options: Option<NetworkOptions>,
    pub css_selector: Option<String>, // for cosmetic filters, e.g. "#ad-banner"
    pub domain_specifier: Option<String>, // e.g. "example.com" in `example.com##.ads`
}

impl FilterRule {
    pub fn is_literal(&self) -> bool {
        matches!(self.pattern, FilterPattern::Literal(_))
    }
    pub fn as_literal(&self) -> Option<&str> {
        if let FilterPattern::Literal(ref s) = self.pattern {
            Some(s)
        } else {
            None
        }
    }
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

fn parse_pattern_or_regex(input: &str) -> IResult<&str, FilterPattern> {
    // Try PCRE regex: / ... /, allowing escaped "/" and "\" inside
    let parse_regex = map_res(
        delimited(
            char('/'),
            recognize(escaped(
                is_not("/\\"),
                '\\',
                nom::character::complete::anychar,
            )),
            char('/'),
        ),
        |raw_re: &str| {
            let processed = raw_re.replace("\\/", "/");
            Regex::new(&processed).map(FilterPattern::Regex)
        },
    );

    // Fallback: literal substring up to '$' or end‐of‐line (no newlines)
    let parse_literal = map(
        recognize(take_while1(|c: char| c != '$' && not_newline(c))),
        |s: &str| {
            let trimmed = s.trim();
            let mut lit = String::with_capacity(trimmed.len());
            lit.push_str(trimmed);
            FilterPattern::Literal(lit)
        },
    );

    alt((parse_regex, parse_literal)).parse(input)
}

fn parse_single_option(input: &str) -> IResult<&str, &str> {
    recognize(take_while1(|c: char| c != ',' && not_newline(c))).parse(input)
}

fn parse_option_list(input: &str) -> IResult<&str, Vec<&str>> {
    separated_list1(char(','), parse_single_option).parse(input)
}

fn parse_network_filter(input: &str) -> IResult<&str, FilterRule> {
    // Save the original line for raw_filter
    let original_line = {
        let line = input.lines().next().unwrap_or("");
        let mut s = String::with_capacity(line.len());
        s.push_str(line);
        s
    };

    let (rem, rule_type) = parse_exception_prefix(input)?;
    let (rem, raw_pattern) = parse_pattern_or_regex(rem)?;
    // Maybe options after '$'
    let (rem, opts) = opt(preceded(char('$'), parse_option_list)).parse(rem)?;

    // If it's a Literal, strip one trailing '|' if present
    let pattern = match raw_pattern {
        FilterPattern::Literal(mut s) => {
            if s.ends_with('|') {
                s.pop();
            }
            FilterPattern::Literal(s)
        }
        FilterPattern::Regex(r) => FilterPattern::Regex(r),
    };

    let options = opts.map(|vec_str| {
        let mut netopt = NetworkOptions {
            resource_types: Vec::with_capacity(vec_str.len()),
            domain_includes: Vec::with_capacity(vec_str.len()),
            domain_excludes: Vec::with_capacity(vec_str.len()),
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
                        let bare = dom.trim_start_matches('~');
                        let mut s = String::with_capacity(bare.len());
                        s.push_str(bare);
                        netopt.domain_excludes.push(s);
                    } else {
                        let mut s = String::with_capacity(dom.len());
                        s.push_str(dom);
                        netopt.domain_includes.push(s);
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
                let mut s = String::with_capacity(opt.len());
                s.push_str(opt);
                netopt.resource_types.push(s)
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
            raw_filter: original_line,
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
    let original_line = {
        let line = input.lines().next().unwrap_or("");
        let mut s = String::with_capacity(line.len());
        s.push_str(line);
        s
    };

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
    let stripped = selector.trim_start_matches(|c| c == '#' || c == '.');
    let mut css_sel = String::with_capacity(stripped.len());
    css_sel.push_str(stripped);

    let category = if is_exception {
        FilterCategory::CosmeticException
    } else {
        FilterCategory::Cosmetic
    };

    let domain_str = domain_opt.trim();
    let domain = if domain_str.is_empty() {
        None
    } else {
        let mut dom_s = String::with_capacity(domain_str.len());
        dom_s.push_str(domain_str);
        Some(dom_s)
    };

    Ok((
        rem3,
        FilterRule {
            rule_type,
            category,
            raw_filter: original_line,
            pattern: FilterPattern::Literal(String::new()), // unused for cosmetic
            options: None,
            css_selector: Some(css_sel),
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
    fn test_block_domain_literal() {
        let line = "||ads.example.com^$script,image";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Block);
        assert_eq!(rule.as_literal().unwrap(), "||ads.example.com^");
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"script".to_string()));
        assert!(opts.resource_types.contains(&"image".to_string()));
    }

    #[test]
    fn test_block_domain_regex() {
        let line = r"/https?:\/\/ads\.example\.com\/.*/$script";
        let rule = parse_network_filter(line).unwrap().1;
        match &rule.pattern {
            FilterPattern::Regex(re) => {
                assert!(re.is_match("https://ads.example.com/banner.js"));
            }
            _ => panic!("Expected a Regex pattern"),
        }
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"script".to_string()));
    }

    #[test]
    fn test_whitelist_url_literal() {
        let line = "@@|http://goodtracker.net/track.js$third-party";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Allow);
        assert_eq!(
            rule.as_literal().unwrap(),
            "|http://goodtracker.net/track.js"
        );
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
        assert_eq!(rule.as_literal().unwrap(), "||example.org^");
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"script".to_string()));
        assert!(opts.domain_includes.contains(&"foo.com".to_string()));
        assert!(opts.domain_excludes.contains(&"bar.com".to_string()));
    }

    #[test]
    fn test_url_with_trailing_pipe() {
        let line = "|http://mysite.com/ads/banner.png|$image";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(
            rule.as_literal().unwrap(),
            "|http://mysite.com/ads/banner.png"
        );
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"image".to_string()));
    }

    #[test]
    fn test_simple_block_no_options() {
        let line = "ads.badsite.com/banner.jpg";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Block);
        assert_eq!(rule.as_literal().unwrap(), "ads.badsite.com/banner.jpg");
        assert!(rule.options.is_none());
    }

    #[test]
    fn test_whitelist_domain_level() {
        let line = "@@||example.com^";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Allow);
        assert_eq!(rule.as_literal().unwrap(), "||example.com^");
        assert!(rule.options.is_none());
    }

    #[test]
    fn test_first_party_option() {
        let line = "||tracking.example.net^$first-party,popup";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Block);
        assert_eq!(rule.as_literal().unwrap(), "||tracking.example.net^");
        let opts = rule.options.unwrap();
        assert_eq!(opts.third_party, Some(false));
        assert!(opts.resource_types.contains(&"popup".to_string()));
    }

    #[test]
    fn test_multiple_resource_types_and_caret_anchor() {
        let line = "|http://site.org^$script,stylesheet,xmlhttprequest,object";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.as_literal().unwrap(), "|http://site.org^");
        let opts = rule.options.unwrap();
        let expected = vec!["script", "stylesheet", "xmlhttprequest", "object"];
        for typ in expected {
            assert!(opts.resource_types.contains(&typ.to_string()));
        }
    }

    #[test]
    fn test_domain_option_only_includes_multiple() {
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
        let line = "||example.test^$domain=";
        let rule = parse_network_filter(line).unwrap().1;
        let opts = rule.options.unwrap();
        // domain_includes should contain a single empty string
        assert_eq!(opts.domain_includes, vec!["".to_string()]);
        assert!(opts.domain_excludes.is_empty());
    }

    #[test]
    fn test_invalid_line_warning_and_none() {
        let line = "not a valid filter $$$";
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn test_parse_line_ignores_blank_and_comments() {
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
        assert_eq!(rules[0].as_literal().unwrap(), "||a.example.com^");

        // 2nd: cosmetic block with domain
        assert_eq!(rules[1].category, FilterCategory::Cosmetic);
        assert_eq!(rules[1].domain_specifier, Some("example.com".to_string()));
        assert_eq!(rules[1].css_selector, Some("banner".to_string()));

        // 3rd: network allow
        assert_eq!(rules[2].rule_type, RuleType::Allow);
        assert_eq!(rules[2].as_literal().unwrap(), "||b.example.org^");
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
        let line = "##.ad-class.large";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(rule.domain_specifier, None);
        assert_eq!(rule.css_selector, Some("ad-class.large".to_string()));
    }

    #[test]
    fn test_cosmetic_selector_with_hash_prefix() {
        let line = "example.org####header";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(rule.domain_specifier, Some("example.org".to_string()));
        assert_eq!(rule.css_selector, Some("header".to_string()));
    }

    #[test]
    fn test_cosmetic_exception_without_domain() {
        let line = "#@#.popup-element";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::CosmeticException);
        assert_eq!(rule.domain_specifier, None);
        assert_eq!(rule.css_selector, Some("popup-element".to_string()));
    }

    #[test]
    fn test_network_filter_unknown_option_is_ignored() {
        let line = "||unknown.example^$foo,bar";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.rule_type, RuleType::Block);
        assert_eq!(rule.as_literal().unwrap(), "||unknown.example^");
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.is_empty());
        assert!(opts.domain_includes.is_empty());
        assert!(opts.domain_excludes.is_empty());
        assert_eq!(opts.third_party, None);
    }

    #[test]
    fn test_network_filter_multiple_domain_excludes_only() {
        let line = "||site.test^$domain=~a.com|~b.com";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.as_literal().unwrap(), "||site.test^");
        let opts = rule.options.unwrap();
        assert!(opts.domain_includes.is_empty());
        assert_eq!(opts.domain_excludes.len(), 2);
        assert!(opts.domain_excludes.contains(&"a.com".to_string()));
        assert!(opts.domain_excludes.contains(&"b.com".to_string()));
        assert_eq!(opts.third_party, None);
    }

    #[test]
    fn test_network_filter_various_resource_types_including_other_and_stylesheet() {
        let line = "|http://foo.bar^$stylesheet,popup,other,redirect=foo";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.as_literal().unwrap(), "|http://foo.bar^");
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"stylesheet".to_string()));
        assert!(opts.resource_types.contains(&"popup".to_string()));
        assert!(opts.resource_types.contains(&"other".to_string()));
        // "redirect" is not recognized -> not inserted
        assert!(opts.domain_includes.is_empty());
        assert!(opts.domain_excludes.is_empty());
        assert_eq!(opts.third_party, None);
    }

    #[test]
    fn test_parse_line_rejects_whitespace_inside_string() {
        assert!(parse_line("ads .example.com").is_none());
        assert!(parse_line("example.com##banner something").is_none());
    }

    #[test]
    fn test_cosmetic_filter_with_no_selector_after_hashes() {
        let line = "example.com##";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(rule.domain_specifier, Some("example.com".to_string()));
        assert_eq!(rule.css_selector, Some("".to_string()));
    }

    #[test]
    fn test_cosmetic_filter_strips_multiple_leading_dots() {
        let line = "##...class";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(rule.domain_specifier, None);
        assert_eq!(rule.css_selector, Some("class".to_string()));
    }

    #[test]
    fn test_cosmetic_filter_domain_with_hyphens() {
        let line = "sub-domain.example123.org##banner-1.2";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::Cosmetic);
        assert_eq!(
            rule.domain_specifier,
            Some("sub-domain.example123.org".to_string())
        );
        assert_eq!(rule.css_selector, Some("banner-1.2".to_string()));
    }

    #[test]
    fn test_network_filter_strip_only_one_trailing_pipe() {
        let line = "||ads||";
        let rule = parse_network_filter(line).unwrap().1;
        // One trailing '|' stripped -> "||ads|"
        assert_eq!(rule.as_literal().unwrap(), "||ads|");
        assert!(rule.options.is_none());
    }

    #[test]
    fn test_parse_easylist_ignores_invalid_lines_and_counts_only_valid() {
        let contents = r#"
                invalid line $$$
                ||good.example^$script
                example.com##.cls
                foo bar baz
                "#;
        let rules = parse_easylist(&contents.to_string());
        // Only two valid filters: one network, one cosmetic
        assert_eq!(rules.len(), 2);

        // Network filter first
        assert_eq!(rules[0].category, FilterCategory::Network);
        assert_eq!(rules[0].as_literal().unwrap(), "||good.example^");

        // Cosmetic filter second
        assert_eq!(rules[1].category, FilterCategory::Cosmetic);
        assert_eq!(rules[1].css_selector, Some("cls".to_string()));
    }

    #[test]
    fn test_network_filter_pattern_with_caret_anchor_preserved() {
        let line = "|http://site.test/path^$image";
        let rule = parse_network_filter(line).unwrap().1;
        assert_eq!(rule.as_literal().unwrap(), "|http://site.test/path^");
        let opts = rule.options.unwrap();
        assert!(opts.resource_types.contains(&"image".to_string()));
    }

    #[test]
    fn test_cosmetic_exception_global_no_domain_and_dot_selector() {
        let line = "#@#.popup";
        let rule = parse_cosmetic_filter(line).unwrap().1;
        assert_eq!(rule.category, FilterCategory::CosmeticException);
        assert_eq!(rule.domain_specifier, None);
        assert_eq!(rule.css_selector, Some("popup".to_string()));
    }

    #[test]
    fn test_network_filter_domain_option_with_empty_value() {
        let line = "||something.test^$domain=";
        let rule = parse_network_filter(line).unwrap().1;
        let opts = rule.options.unwrap();
        assert_eq!(opts.domain_includes, vec!["".to_string()]);
        assert!(opts.domain_excludes.is_empty());
    }
}
