use std::collections::HashMap;

/// A node in the domain‐trie. Each edge corresponds to one label (a dot‐separated piece),
/// stored in reverse order ("com -> example -> adserver" for "adserver.example.com").
#[derive(Default)]
pub struct DomainTrieNode {
    /// Children keyed by the next label (in lowercase).
    pub children: HashMap<String, DomainTrieNode>,
    /// A list of rule indices that match exactly at this node.
    pub rule_indices: Vec<usize>,
}

impl DomainTrieNode {
    /// Insert a domain (split into labels in reverse order) associated with `rule_idx`.
    ///
    /// Example:
    ///   domain_labels = ["com", "example", "ads"]
    /// will store `rule_idx` at the node reached by walking children["com"]["example"]["ads"].
    pub fn insert(&mut self, domain_labels: &[&str], rule_idx: usize) {
        if domain_labels.is_empty() {
            self.rule_indices.push(rule_idx);
        } else {
            let label = domain_labels[0].to_lowercase();
            let child = self.children.entry(label).or_default();
            child.insert(&domain_labels[1..], rule_idx);
        }
    }

    /// Given an iterator over host labels in reverse order, walk as far as possible,
    /// collecting all rule indices on the path. Returns a Vec of matching indices.
    ///
    /// Example: host_labels = ["com", "example", "ads", "sub"]
    /// Will check node at "com" (collect its rule_indices), then "example", "ads", "sub" until a missing child.
    pub fn find_matching_indices<'a>(&'a self, host_labels: &[&str]) -> Vec<usize> {
        let mut matches = Vec::new();
        let mut node = self;

        matches.extend(&node.rule_indices);

        for &label_raw in host_labels {
            let label = label_raw.to_lowercase();
            if let Some(child) = node.children.get(&label) {
                // Any rules at this node apply to this suffix
                matches.extend(&child.rule_indices);
                node = child;
            } else {
                break;
            }
        }
        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_find_empty_domain() {
        let mut root = DomainTrieNode::default();
        root.insert(&[], 42);
        let results = root.find_matching_indices(&[]);
        assert_eq!(
            results,
            vec![42],
            "Should match the inserted rule index for an empty domain"
        );
    }

    #[test]
    fn test_insert_single_label() {
        let mut root = DomainTrieNode::default();
        root.insert(&["com"], 1);
        let results = root.find_matching_indices(&["com"]);
        assert_eq!(
            results,
            vec![1],
            "Should match the inserted rule index for single-label domain"
        );
    }

    #[test]
    fn test_insert_multiple_labels() {
        let mut root = DomainTrieNode::default();
        let domain_labels = ["com", "example", "ads"];
        root.insert(&domain_labels, 10);
        assert!(
            root.children.contains_key("com"),
            "Child for 'com' should be present"
        );
        let results = root.find_matching_indices(&["com", "example", "ads"]);
        assert_eq!(
            results,
            vec![10],
            "Should match the inserted rule index for multi-label domain"
        );
    }

    #[test]
    fn test_insert_and_find_partial_match() {
        let mut root = DomainTrieNode::default();
        root.insert(&["com", "example"], 101);
        let results_full = root.find_matching_indices(&["com", "example"]);
        let results_partial = root.find_matching_indices(&["com"]);

        assert_eq!(
            results_full,
            vec![101],
            "Matching two labels should yield the inserted rule index"
        );
        assert_eq!(
            results_partial.len(),
            0,
            "Should not match the rule index when only partially matching (example label missing)"
        );
    }

    #[test]
    fn test_find_multiple_indices_along_path() {
        let mut root = DomainTrieNode::default();
        root.insert(&["com"], 1);
        root.insert(&["com", "example", "ads"], 2);
        root.insert(&["com", "example"], 3);

        let host_labels = ["com", "example", "ads", "sub"];
        let results = root.find_matching_indices(&host_labels);

        // Indices found along the path should include rule 1 at 'com' node,
        // then rule 3 at ["com", "example"], then rule 2 at ["com","example","ads"].
        // The "sub" label doesn't match anything further, so stops there.
        assert!(
            results.contains(&1),
            "Should contain index from shared 'com' node"
        );
        assert!(
            results.contains(&3),
            "Should contain index from shared 'com'->'example' node"
        );
        assert!(
            results.contains(&2),
            "Should contain index from 'com'->'example'->'ads' node"
        );
    }

    #[test]
    fn test_case_insensitivity() {
        let mut root = DomainTrieNode::default();
        root.insert(&["COM", "ExAmPlE"], 999);

        let results_lower = root.find_matching_indices(&["com", "example"]);
        let results_mixed = root.find_matching_indices(&["Com", "ExaMplE"]);
        assert_eq!(results_lower, vec![999], "Lowercase query should match");
        assert_eq!(results_mixed, vec![999], "Mixed case query should match");
    }
}
