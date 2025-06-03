use url::Url;

use crate::{
    domain_trie::DomainTrieNode,
    easylist::{parse_easylist, FilterPattern, FilterRule},
};

pub struct FilterEngine {
    pub rules: Vec<FilterRule>,
    pub domain_trie: DomainTrieNode,
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
