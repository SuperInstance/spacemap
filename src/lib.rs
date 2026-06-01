#![deny(unsafe_code)]

//! # forbidden-zones
//!
//! Forbidden output space checking. Define regions of your output space that
//! must remain empty, then check if any actual output intrudes.
//!
//! Like a firewall for your data — define what's **not** allowed and verify
//! nothing crosses the boundary.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Detailed audit report produced by [`SpaceMap::audit`].
#[derive(Debug, Clone)]
pub struct AuditReport<K> {
    /// Total number of occupied regions.
    pub occupied_count: usize,
    /// Total number of forbidden regions.
    pub forbidden_count: usize,
    /// Keys that are both occupied and forbidden (intrusions).
    pub intrusions: Vec<K>,
    /// Number of intrusions found.
    pub intrusion_count: usize,
    /// Percentage of forbidden space that is still clean (0.0–100.0).
    pub negative_space_ratio: f64,
    /// Whether the map is completely clean (no intrusions).
    pub is_clean: bool,
    /// Occupied keys that are not in the forbidden set (potential early-warning layer).
    pub boundaries: HashSet<K>,
}

/// A map that tracks occupied regions and forbidden zones, detecting
/// intrusions where occupied keys overlap with forbidden keys.
///
/// # Type Parameters
///
/// * `K` — The key type identifying a region (must be `Eq + Hash + Clone`).
/// * `V` — The value type stored for each occupied region.
///
/// # Example
///
/// ```
/// use forbidden_zones::SpaceMap;
///
/// let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
/// sm.occupy("zone_a", 42);
/// sm.forbid("zone_b");
/// assert!(sm.is_clean());
///
/// sm.occupy("zone_b", 99);
/// assert!(!sm.is_clean());
/// ```
#[derive(Debug, Clone)]
pub struct SpaceMap<K, V> {
    occupied: HashMap<K, V>,
    forbidden: HashSet<K>,
}

impl<K, V> SpaceMap<K, V>
where
    K: Eq + Hash + Clone,
{
    /// Create a new, empty `SpaceMap`.
    pub fn new() -> Self {
        Self {
            occupied: HashMap::new(),
            forbidden: HashSet::new(),
        }
    }

    /// Mark a region as occupied with an associated value.
    ///
    /// If the key was already occupied, its value is updated.
    pub fn occupy(&mut self, key: K, value: V) {
        self.occupied.insert(key, value);
    }

    /// Mark a region as forbidden. Any subsequent occupation of this key
    /// will be treated as an intrusion.
    pub fn forbid(&mut self, key: K) {
        self.forbidden.insert(key);
    }

    /// Remove a region from the occupied set, returning its value if present.
    pub fn vacate(&mut self, key: &K) -> Option<V> {
        self.occupied.remove(key)
    }

    /// Remove a region from the forbidden set.
    pub fn permit(&mut self, key: &K) -> bool {
        self.forbidden.remove(key)
    }

    /// Returns `true` if the key is currently occupied.
    pub fn is_occupied(&self, key: &K) -> bool {
        self.occupied.contains_key(key)
    }

    /// Returns `true` if the key is currently forbidden.
    pub fn is_forbidden(&self, key: &K) -> bool {
        self.forbidden.contains(key)
    }

    /// Returns a reference to the value stored for an occupied key.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.occupied.get(key)
    }

    /// Find all occupied regions that are also forbidden.
    pub fn check_intrusions(&self) -> Vec<K> {
        self.occupied
            .keys()
            .filter(|k| self.forbidden.contains(k))
            .cloned()
            .collect()
    }

    /// Returns the percentage of forbidden space that is still clean.
    ///
    /// * If no regions are forbidden, returns 100.0.
    /// * Value is in the range 0.0–100.0.
    pub fn negative_space_ratio(&self) -> f64 {
        if self.forbidden.is_empty() {
            return 100.0;
        }
        let forbidden_count = self.forbidden.len();
        let intrusion_count = self
            .occupied
            .keys()
            .filter(|k| self.forbidden.contains(k))
            .count();
        let clean = forbidden_count - intrusion_count;
        (clean as f64 / forbidden_count as f64) * 100.0
    }

    /// Returns `true` if there are no intrusions at all.
    pub fn is_clean(&self) -> bool {
        !self.occupied.keys().any(|k| self.forbidden.contains(k))
    }

    /// Produce a detailed audit report.
    pub fn audit(&self) -> AuditReport<K> {
        let intrusions = self.check_intrusions();
        let intrusion_count = intrusions.len();
        AuditReport {
            occupied_count: self.occupied.len(),
            forbidden_count: self.forbidden.len(),
            is_clean: intrusion_count == 0,
            intrusion_count,
            intrusions,
            negative_space_ratio: self.negative_space_ratio(),
            boundaries: self.boundaries(),
        }
    }

    /// Return the set of occupied regions that are **not** forbidden.
    ///
    /// This is an early-warning layer: these occupied keys are safe for now,
    /// but if their keys were later added to the forbidden set, they would
    /// become intrusions. Use this to monitor how close your occupied space
    /// is to the forbidden boundary.
    ///
    /// Note: this does **not** compute spatial adjacency (since `K` is generic).
    /// It returns all occupied keys that are not intrusions — i.e., the
    /// complement of [`check_intrusions`](Self::check_intrusions) within
    /// the occupied set.
    pub fn boundaries(&self) -> HashSet<K> {
        self.occupied
            .keys()
            .filter(|k| !self.forbidden.contains(k))
            .cloned()
            .collect()
    }

    /// Merge another `SpaceMap` into this one.
    ///
    /// Occupied entries from `other` overwrite existing entries on collision.
    /// Forbidden sets are unioned.
    pub fn merge(&mut self, other: SpaceMap<K, V>) {
        for (k, v) in other.occupied {
            self.occupied.insert(k, v);
        }
        for k in other.forbidden {
            self.forbidden.insert(k);
        }
    }

    /// Returns the number of occupied regions.
    pub fn occupied_len(&self) -> usize {
        self.occupied.len()
    }

    /// Returns the number of forbidden regions.
    pub fn forbidden_len(&self) -> usize {
        self.forbidden.len()
    }

    /// Returns `true` if there are no occupied or forbidden regions.
    pub fn is_empty(&self) -> bool {
        self.occupied.is_empty() && self.forbidden.is_empty()
    }

    /// Clear all occupied and forbidden regions.
    pub fn clear(&mut self) {
        self.occupied.clear();
        self.forbidden.clear();
    }

    /// Returns an iterator over all occupied keys.
    pub fn occupied_keys(&self) -> impl Iterator<Item = &K> {
        self.occupied.keys()
    }

    /// Returns an iterator over all forbidden keys.
    pub fn forbidden_keys(&self) -> impl Iterator<Item = &K> {
        self.forbidden.iter()
    }

    /// Returns `true` if a given key is an intrusion (both occupied and forbidden).
    pub fn is_intrusion(&self, key: &K) -> bool {
        self.occupied.contains_key(key) && self.forbidden.contains(key)
    }
}

impl<K, V> Default for SpaceMap<K, V>
where
    K: Eq + Hash + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction ──────────────────────────────────────────────

    #[test]
    fn new_creates_empty_map() {
        let sm: SpaceMap<&str, i32> = SpaceMap::new();
        assert!(sm.is_empty());
        assert_eq!(sm.occupied_len(), 0);
        assert_eq!(sm.forbidden_len(), 0);
    }

    #[test]
    fn default_trait_works() {
        let sm: SpaceMap<&str, i32> = SpaceMap::default();
        assert!(sm.is_empty());
    }

    // ── Occupy ────────────────────────────────────────────────────

    #[test]
    fn occupy_adds_entry() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        assert_eq!(sm.occupied_len(), 1);
        assert_eq!(sm.get(&"a"), Some(&1));
    }

    #[test]
    fn occupy_updates_existing_key() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.occupy("a", 2);
        assert_eq!(sm.occupied_len(), 1);
        assert_eq!(sm.get(&"a"), Some(&2));
    }

    #[test]
    fn occupy_multiple_keys() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.occupy("b", 2);
        sm.occupy("c", 3);
        assert_eq!(sm.occupied_len(), 3);
    }

    // ── Forbid ────────────────────────────────────────────────────

    #[test]
    fn forbid_adds_forbidden_region() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("x");
        assert_eq!(sm.forbidden_len(), 1);
        assert!(sm.is_forbidden(&"x"));
    }

    #[test]
    fn forbid_is_idempotent() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("x");
        sm.forbid("x");
        assert_eq!(sm.forbidden_len(), 1);
    }

    #[test]
    fn forbid_multiple_keys() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("a");
        sm.forbid("b");
        sm.forbid("c");
        assert_eq!(sm.forbidden_len(), 3);
    }

    // ── Intrusion detection ───────────────────────────────────────

    #[test]
    fn check_intrusions_empty_when_clean() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("b");
        assert!(sm.check_intrusions().is_empty());
    }

    #[test]
    fn check_intrusions_detects_single_intrusion() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("a");
        let intrusions = sm.check_intrusions();
        assert_eq!(intrusions, vec!["a"]);
    }

    #[test]
    fn check_intrusions_detects_multiple() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.occupy("b", 2);
        sm.forbid("a");
        sm.forbid("b");
        let mut intrusions = sm.check_intrusions();
        intrusions.sort();
        assert_eq!(intrusions, vec!["a", "b"]);
    }

    #[test]
    fn check_intrusions_partial_overlap() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.occupy("b", 2);
        sm.occupy("c", 3);
        sm.forbid("b");
        sm.forbid("d");
        let intrusions = sm.check_intrusions();
        assert_eq!(intrusions, vec!["b"]);
    }

    #[test]
    fn is_intrusion_method() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("a");
        assert!(sm.is_intrusion(&"a"));
        assert!(!sm.is_intrusion(&"b"));
    }

    // ── is_clean ──────────────────────────────────────────────────

    #[test]
    fn is_clean_when_no_intrusions() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("b");
        assert!(sm.is_clean());
    }

    #[test]
    fn is_not_clean_when_intrusion() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("a");
        assert!(!sm.is_clean());
    }

    #[test]
    fn is_clean_on_empty_map() {
        let sm: SpaceMap<&str, i32> = SpaceMap::new();
        assert!(sm.is_clean());
    }

    // ── negative_space_ratio ──────────────────────────────────────

    #[test]
    fn negative_space_ratio_100_when_no_forbidden() {
        let sm: SpaceMap<&str, i32> = SpaceMap::new();
        assert_eq!(sm.negative_space_ratio(), 100.0);
    }

    #[test]
    fn negative_space_ratio_all_clean() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("a");
        sm.forbid("b");
        // nothing occupied
        assert_eq!(sm.negative_space_ratio(), 100.0);
    }

    #[test]
    fn negative_space_ratio_half_dirty() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("a");
        sm.forbid("b");
        sm.occupy("a", 1);
        let ratio = sm.negative_space_ratio();
        assert!((ratio - 50.0).abs() < 0.001);
    }

    #[test]
    fn negative_space_ratio_all_dirty() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("a");
        sm.occupy("a", 1);
        assert_eq!(sm.negative_space_ratio(), 0.0);
    }

    // ── Audit ─────────────────────────────────────────────────────

    #[test]
    fn audit_clean_report() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("b");
        let report = sm.audit();
        assert!(report.is_clean);
        assert_eq!(report.intrusion_count, 0);
        assert_eq!(report.occupied_count, 1);
        assert_eq!(report.forbidden_count, 1);
    }

    #[test]
    fn audit_dirty_report() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("a");
        let report = sm.audit();
        assert!(!report.is_clean);
        assert_eq!(report.intrusion_count, 1);
        assert_eq!(report.intrusions, vec!["a"]);
    }

    // ── Boundaries ────────────────────────────────────────────────

    #[test]
    fn boundaries_returns_non_intrusion_occupied() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.occupy("b", 2);
        sm.forbid("b");
        let bounds = sm.boundaries();
        assert!(bounds.contains("a"));
        assert!(!bounds.contains("b"));
    }

    #[test]
    fn boundaries_empty_when_all_intrusions() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("a");
        assert!(sm.boundaries().is_empty());
    }

    // ── Merge ─────────────────────────────────────────────────────

    #[test]
    fn merge_combines_maps() {
        let mut sm1: SpaceMap<&str, i32> = SpaceMap::new();
        sm1.occupy("a", 1);
        sm1.forbid("x");

        let mut sm2: SpaceMap<&str, i32> = SpaceMap::new();
        sm2.occupy("b", 2);
        sm2.forbid("y");

        sm1.merge(sm2);
        assert_eq!(sm1.occupied_len(), 2);
        assert_eq!(sm1.forbidden_len(), 2);
        assert!(sm1.is_clean());
    }

    #[test]
    fn merge_overwrites_on_collision() {
        let mut sm1: SpaceMap<&str, i32> = SpaceMap::new();
        sm1.occupy("a", 1);

        let mut sm2: SpaceMap<&str, i32> = SpaceMap::new();
        sm2.occupy("a", 99);

        sm1.merge(sm2);
        assert_eq!(sm1.get(&"a"), Some(&99));
    }

    #[test]
    fn merge_creates_intrusion() {
        let mut sm1: SpaceMap<&str, i32> = SpaceMap::new();
        sm1.forbid("a");

        let mut sm2: SpaceMap<&str, i32> = SpaceMap::new();
        sm2.occupy("a", 1);

        sm1.merge(sm2);
        assert!(!sm1.is_clean());
    }

    // ── Vacate & Permit ───────────────────────────────────────────

    #[test]
    fn vacate_removes_occupation() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 42);
        let val = sm.vacate(&"a");
        assert_eq!(val, Some(42));
        assert!(!sm.is_occupied(&"a"));
    }

    #[test]
    fn vacate_returns_none_for_missing() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        assert_eq!(sm.vacate(&"a"), None);
    }

    #[test]
    fn permit_removes_forbidden() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("a");
        assert!(sm.permit(&"a"));
        assert!(!sm.is_forbidden(&"a"));
    }

    #[test]
    fn permit_returns_false_for_missing() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        assert!(!sm.permit(&"a"));
    }

    // ── Vacate resolves intrusion ─────────────────────────────────

    #[test]
    fn vacating_intrusion_makes_clean() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("a");
        assert!(!sm.is_clean());
        sm.vacate(&"a");
        assert!(sm.is_clean());
    }

    #[test]
    fn permitting_intrusion_makes_clean() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("a");
        assert!(!sm.is_clean());
        sm.permit(&"a");
        assert!(sm.is_clean());
    }

    // ── Clear ─────────────────────────────────────────────────────

    #[test]
    fn clear_empties_everything() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("b");
        sm.clear();
        assert!(sm.is_empty());
    }

    // ── Integer keys ──────────────────────────────────────────────

    #[test]
    fn works_with_integer_keys() {
        let mut sm: SpaceMap<u32, &str> = SpaceMap::new();
        sm.occupy(1, "one");
        sm.forbid(2);
        assert!(sm.is_clean());
        sm.occupy(2, "two");
        assert!(!sm.is_clean());
        let intrusions = sm.check_intrusions();
        assert_eq!(intrusions, vec![2]);
    }

    // ── Iterators ─────────────────────────────────────────────────

    #[test]
    fn occupied_keys_iterator() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.occupy("b", 2);
        let keys: Vec<&&str> = sm.occupied_keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn forbidden_keys_iterator() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("x");
        sm.forbid("y");
        let keys: Vec<&&str> = sm.forbidden_keys().collect();
        assert_eq!(keys.len(), 2);
    }

    // ── Clone ─────────────────────────────────────────────────────

    #[test]
    fn clone_works() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("b");
        let cloned = sm.clone();
        assert_eq!(cloned.occupied_len(), 1);
        assert_eq!(cloned.forbidden_len(), 1);
    }

    // ── Edge cases ────────────────────────────────────────────────

    #[test]
    fn occupy_then_forbid_same_key_is_intrusion() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        sm.forbid("a");
        assert!(!sm.is_clean());
        assert_eq!(sm.check_intrusions(), vec!["a"]);
    }

    #[test]
    fn forbid_then_occupy_same_key_is_intrusion() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("a");
        sm.occupy("a", 1);
        assert!(!sm.is_clean());
    }

    #[test]
    fn negative_space_ratio_with_only_occupied() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("a", 1);
        // no forbidden → ratio is 100%
        assert_eq!(sm.negative_space_ratio(), 100.0);
    }

    #[test]
    fn audit_report_negative_space_ratio_matches() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.forbid("a");
        sm.forbid("b");
        sm.forbid("c");
        sm.occupy("a", 1);
        let report = sm.audit();
        let expected = (2.0 / 3.0) * 100.0;
        assert!((report.negative_space_ratio - expected).abs() < 0.001);
    }

    #[test]
    fn boundaries_includes_all_non_forbidden_occupied() {
        let mut sm: SpaceMap<&str, i32> = SpaceMap::new();
        sm.occupy("clean1", 1);
        sm.occupy("clean2", 2);
        sm.forbid("bad");
        let bounds = sm.boundaries();
        assert_eq!(bounds.len(), 2);
        assert!(bounds.contains("clean1"));
        assert!(bounds.contains("clean2"));
    }
}
