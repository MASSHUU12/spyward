use dashmap::DashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use crate::protocol::reassembly::buffer::ReassemblyBuffer;

/// Generic reassembly table for protocol B with key K.
pub struct ReassemblyManager<K, B>
where
    K: Eq + Hash + Clone,
    B: ReassemblyBuffer,
{
    pub table: DashMap<K, B>,
    timeout: Duration,
    max_entries: usize,
}

impl<K, B> ReassemblyManager<K, B>
where
    K: Eq + Hash + Clone,
    B: ReassemblyBuffer,
{
    pub fn new(timeout: Duration, max_entries: usize) -> Self {
        ReassemblyManager {
            table: DashMap::new(),
            timeout,
            max_entries,
        }
    }

    /// Evict one oldest entry based on last_seen.
    fn evict_one(&self) {
        let mut oldest_key: Option<K> = None;
        let mut oldest_time = Instant::now();
        for r in self.table.iter() {
            let buf = r.value();
            let last = buf.last_seen();
            if oldest_key.is_none() || last < oldest_time {
                oldest_time = last;
                oldest_key = Some(r.key().clone())
            }
        }
        if let Some(k) = oldest_key {
            self.table.remove(&k);
        }
    }

    /// Insert or get buffer for this key, then push segment. Returns entire assembled data as Vec<u8>.
    pub fn push(&self, key: K, initial_seq: B::Seq, seq: B::Seq, data: &[u8]) -> Vec<u8> {
        if !self.table.contains_key(&key) && self.table.len() >= self.max_entries {
            self.evict_one();
        }
        let mut entry = self
            .table
            .entry(key.clone())
            .or_insert_with(|| B::new(initial_seq));
        let buf = entry.value_mut();
        let slice = buf.push_segment(seq, data);
        slice.to_vec()
    }

    /// Pushes segment and runs user logic on the buffer, returning whatever the closure returns.
    /// The closure receives (&mut B, &[u8]) where &[u8] is the assembled slice after push_segment.
    pub fn push_with<F, R>(&self, key: K, initial_seq: B::Seq, seq: B::Seq, data: &[u8], f: F) -> R
    where
        F: FnOnce(&mut B, &[u8]) -> R,
    {
        if !self.table.contains_key(&key) && self.table.len() >= self.max_entries {
            self.evict_one();
        }
        let assembled_vec = {
            let mut entry = self
                .table
                .entry(key.clone())
                .or_insert_with(|| B::new(initial_seq));
            let buf = entry.value_mut();
            let slice = buf.push_segment(seq, data);
            slice.to_vec()
        };
        let mut entry2 = self.table.get_mut(&key).expect("Buffer must exist");
        f(entry2.value_mut(), &assembled_vec)
    }

    /// Periodically call to evict old entries
    pub fn evict_stale(&self) {
        let now = Instant::now();
        let keys_to_remove: Vec<K> = self
            .table
            .iter()
            .filter_map(|r| {
                let buf = r.value();
                if now.saturating_duration_since(buf.last_seen()) > self.timeout {
                    Some(r.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for k in keys_to_remove {
            self.table.remove(&k);
        }
    }
}
