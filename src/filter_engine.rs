use once_cell::sync::Lazy;
use std::fs::File;
use std::io::Read;
use url::Url;

use crate::{
    domain_trie::DomainTrieNode,
    easylist::{parse_easylist, FilterPattern, FilterRule, RuleType},
};

// TODO: Read path from config file
pub static FILTER_ENGINE: Lazy<FilterEngine> = Lazy::new(|| {
    let mut f = File::open("./lists/test_list.txt").expect("Could not open EasyList text file.");
    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .expect("Could not read EasyList file.");

    FilterEngine::new(&contents)
});

pub struct FilterEngine {
    pub rules: Vec<FilterRule>,
    pub domain_trie: DomainTrieNode,
}

pub enum Verdict {
    Accept,
    Drop,
}

impl FilterEngine {
    /// Build a `FilterEngine` given the raw EasyList contents.
    /// This will parse all filters, then insert every `Literal`‐pattern rule
    /// that begins with "||" into the domain_trie.
    /// The index used is the position in the `rules` Vec.
    pub fn new(contents: &str) -> Self {
        let rules = parse_easylist(&contents.to_string());
        let mut domain_trie = DomainTrieNode::default();

        for (idx, rule) in rules.iter().enumerate() {
            if let FilterPattern::Literal(pat) = &rule.pattern {
                if pat.starts_with("||") {
                    let remainder = &pat["||".len()..];
                    let domain_part = if remainder.ends_with('^') {
                        &remainder[..remainder.len() - 1]
                    } else {
                        remainder
                    };
                    let labels: Vec<&str> = domain_part.split('.').rev().collect();
                    domain_trie.insert(&labels, idx);
                }
            }
        }

        FilterEngine { rules, domain_trie }
    }

    /// Given a URL string, return a Vec of references to FilterRules whose
    /// "||" domain literal would match that host. Does not check other anchors
    /// (e.g. path '^'), nor `$options` (resource type, domain=, etc.). This is purely
    /// the domain‐suffix‐matching step.
    pub fn match_domain_only<'a>(&'a self, url_str: &str) -> Vec<&'a FilterRule> {
        let url = match Url::parse(url_str) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };
        let host = match url.host_str() {
            Some(h) => h,
            None => return Vec::new(),
        };
        let labels: Vec<&str> = host.split('.').rev().collect();
        let idxs = self.domain_trie.find_matching_indices(&labels);
        idxs.into_iter().map(|i| &self.rules[i]).collect()
    }

    pub fn decide(&self, url_str: &str, origin_host: Option<&str>) -> Verdict {
        let parsed = match Url::parse(url_str) {
            Ok(u) => u,
            Err(_) => {
                return Verdict::Accept;
            }
        };

        // Figure out if it's third‐party or first‐party: compare `origin_host` vs `parsed.host_str()`.
        // If origin_host is None, just treat it as "first‐party = true" so that `$first-party` rules can match.
        let is_third_party = match origin_host {
            Some(o) => {
                if let Some(req_host) = parsed.host_str() {
                    req_host.to_lowercase() != o.to_lowercase()
                } else {
                    // no host in parsed? treat as "first‐party".
                    false
                }
            }
            None => false,
        };

        for rule in &self.rules {
            if rule.category != crate::easylist::FilterCategory::Network {
                continue;
            }

            // Does this rule's domain‐anchor (if any) match?
            // If rule.pattern is a literal starting with "||", then match against domain‐only:
            let mut prefix_matched = false;
            if let FilterPattern::Literal(lit) = &rule.pattern {
                // Example `lit`: "||ads.example.com^"
                if lit.starts_with("||") {
                    // Let domain_part = `"ads.example.com"` (strip `||` and trailing `^` if present).
                    let remainder = &lit[2..];
                    let domain_part = if remainder.ends_with('^') {
                        &remainder[..remainder.len() - 1]
                    } else {
                        remainder
                    };
                    if let Some(req_host) = parsed.host_str() {
                        // e.g. req_host = "tracker.ads.example.com"
                        // We only match if either `req_host == domain_part` or it ends‐with `.` + domain_part.
                        let rh = req_host.to_lowercase();
                        let dp = domain_part.to_lowercase();
                        if rh == dp || rh.ends_with(&format!(".{}", dp)) {
                            prefix_matched = true;
                        }
                    }
                }
            }

            // If it was a "||...^" rule but prefix_matched == false, skip it immediately.
            if let FilterPattern::Literal(lit) = &rule.pattern {
                if lit.starts_with("||") && !prefix_matched {
                    continue;
                }
            }
            // If it was a "regex" or a literal not starting with "||", we fall through.

            // Match the full pattern (regex or literal):
            let full_pattern_match = match &rule.pattern {
                FilterPattern::Literal(lit) => {
                    // A "literal" can contain anchors:
                    //  - Leading "|"  -> match at beginning-of-string
                    //  - Trailing "|" -> match at end‐of‐string
                    //  - "^"          -> match any "delimiter" (anything not alnum, not in URL‐charset)
                    self.literal_matches(lit, url_str)
                }
                FilterPattern::Regex(re) => re.is_match(url_str),
            };
            if !full_pattern_match {
                continue;
            }

            // Now check options, if any (resource types, domain‐includes/excludes, third‐party):
            if let Some(opts) = &rule.options {
                if !opts.domain_includes.is_empty() {
                    if let Some(origin) = origin_host {
                        let mut found = false;
                        for dom in &opts.domain_includes {
                            if origin.eq_ignore_ascii_case(dom) {
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            // Origin not in "includes" -> rule does not apply
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                if !opts.domain_excludes.is_empty() {
                    if let Some(origin) = origin_host {
                        let mut excluded = false;
                        for dom in &opts.domain_excludes {
                            if origin.eq_ignore_ascii_case(dom) {
                                excluded = true;
                                break;
                            }
                        }
                        if excluded {
                            continue;
                        }
                    }
                }
                if let Some(third_party_opt) = opts.third_party {
                    // If the rule is $third-party but our request is not third‐party, skip.
                    if third_party_opt && !is_third_party {
                        continue;
                    }
                    // If rule is $first-party but our request is third‐party, skip.
                    if !third_party_opt && is_third_party {
                        continue;
                    }
                }
            }

            // If we reach here, the rule "matches" this URL. Now obey allow/block:
            match rule.rule_type {
                RuleType::Allow => {
                    // "@@" means whitelist: accept immediately
                    return Verdict::Accept;
                }
                RuleType::Block => {
                    // First "block" we see -> drop.
                    return Verdict::Drop;
                }
            }
        }

        // If no rule matched at all, accept by default
        Verdict::Accept
    }

    /// Returns true if `lit_pattern` matches `text` according to Adblock‐style literal semantics.
    /// - If lit_pattern starts with "|", that ′|′ means "match beginning of text"
    /// - If lit_pattern ends with "|", that ′|′ means "match end of text"
    /// - Any "^" in the pattern matches a "separator" (any character outside [A-Za-z0-9._-])
    /// - Otherwise it's just a substring check.
    fn literal_matches(&self, lit_pattern: &str, text: &str) -> bool {
        // A very basic implementation:
        // 1. Handle leading "|"
        // 2. Handle trailing "|"
        // 3. Handle "^" (map to regex "[^A-Za-z0-9._-]")
        // 4. Otherwise search as substring.

        // TODO: compile a tiny Regex once per pattern

        // If starts_with('|') -> we only match if text starts exactly at next characters.
        if lit_pattern.starts_with('|') {
            let remainder = &lit_pattern[1..]; // e.g. "http://ads.example.com/banner.js"
                                               // Does the text start with remainder, except we might have trailing '|', '^', etc.
            return self.literal_anchor_match_at_start(remainder, text);
        }

        // If does not start with '|' but has '^', we replace every '^' with "separator regex":
        if lit_pattern.contains('^') {
            // Build a tiny regex: escape all other chars, replace '^' with "(?P<sep>[^A-Za-z0-9._-])"
            let mut regex_src = String::new();
            for ch in lit_pattern.chars() {
                match ch {
                    '^' => {
                        // "separator": anything not in URL‐safe characters
                        regex_src.push_str(r#"[^A-Za-z0-9\.\_\-]"#);
                    }
                    '$' | '(' | ')' | '.' | '+' | '[' | ']' | '?' | '*' | '{' | '}' | '|'
                    | '\\' => {
                        regex_src.push('\\');
                        regex_src.push(ch);
                    }
                    c => {
                        regex_src.push(c);
                    }
                }
            }
            if let Ok(re) = regex::Regex::new(&regex_src) {
                return re.is_match(text);
            } else {
                return false;
            }
        }

        // If ends_with('|') -> match end‐of‐string exactly
        if lit_pattern.ends_with('|') {
            let sub = &lit_pattern[..lit_pattern.len() - 1];
            return text.ends_with(sub);
        }

        // Otherwise, plain substring:
        text.contains(lit_pattern)
    }

    /// If `pat` might end in "|" or contain "^", handle those anchors at the *very start*:
    fn literal_anchor_match_at_start(&self, pat: &str, text: &str) -> bool {
        // If pat ends with '|' -> match exactly "pat[..len-1]" to very start of text
        if pat.ends_with('|') {
            let core = &pat[..pat.len() - 1];
            return text.starts_with(core) && core.len() == text.len() - 0;
            // i.e. exact match of whole text; but that's an odd case—rare.
        }

        // TODO: compile a tiny Regex once per pattern

        // If pat contains "^", we must check that every '^' in pat matches a "separator" at the same index.
        let mut regex_src = String::from("^");
        for ch in pat.chars() {
            match ch {
                '^' => regex_src.push_str(r#"[^A-Za-z0-9\.\_\-]"#),
                '$' | '(' | ')' | '.' | '+' | '[' | ']' | '?' | '*' | '{' | '}' | '|' | '\\' => {
                    regex_src.push('\\');
                    regex_src.push(ch);
                }
                c => regex_src.push(c),
            }
        }
        if let Ok(re) = regex::Regex::new(&regex_src) {
            re.is_match(text)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_trie_single_label() {
        let contents = "||example.com^";
        let engine = FilterEngine::new(contents);
        let matches = engine.match_domain_only("http://example.com/path");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_literal().unwrap(), "||example.com^");
    }

    #[test]
    fn test_domain_trie_subdomain_match() {
        let contents = "||example.com^";
        let engine = FilterEngine::new(contents);
        let matches = engine.match_domain_only("https://ads.example.com/banner");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_literal().unwrap(), "||example.com^");
    }

    #[test]
    fn test_domain_trie_no_match_for_non_suffix() {
        let contents = "||example.com^";
        let engine = FilterEngine::new(contents);
        // This host ends with "example.com.evil.com", not exactly ".example.com"
        let matches = engine.match_domain_only("http://example.com.evil.com/whatever");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_domain_trie_multiple_rules() {
        let contents = "\
            ||example.com^$script\n\
            ||ads.example.com^\n\
            ||test.org^\n\
        ";
        let engine = FilterEngine::new(contents);
        // A host "ads.example.com" should match both "ads.example.com^" (more specific)
        // and "example.com^" (less specific)
        let matches = engine.match_domain_only("http://ads.example.com/foo.js");
        // We expect two matching rules: first the one inserted at index 0 ("example.com"),
        // then the one at index 1 ("ads.example.com"), although our trie collects in insertion order.
        assert_eq!(matches.len(), 2);
        let patterns: Vec<&str> = matches.iter().map(|r| r.as_literal().unwrap()).collect();
        assert!(patterns.contains(&"||example.com^"));
        assert!(patterns.contains(&"||ads.example.com^"));
    }
}
