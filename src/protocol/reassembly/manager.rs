use dashmap::mapref::one::{Ref, RefMut};
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
    table: DashMap<K, B>,
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

    pub fn get_buffer(&self, key: &K) -> Option<Ref<'_, K, B>> {
        self.table.get(key)
    }

    pub fn get_buffer_mut(&self, key: &K) -> Option<RefMut<'_, K, B>> {
        self.table.get_mut(key)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    /// A dummy buffer that implements `ReassemblyBuffer` for testing.
    #[derive(Clone)]
    struct DummyBuffer {
        data: Vec<u8>,
        last_seen: Instant,
    }

    impl ReassemblyBuffer for DummyBuffer {
        type Seq = u32;

        fn new(_initial_seq: Self::Seq) -> Self {
            DummyBuffer {
                data: Vec::new(),
                last_seen: Instant::now(),
            }
        }

        fn push_segment(&mut self, _seq: Self::Seq, segment: &[u8]) -> &[u8] {
            // Append the segment and update last_seen
            self.data.extend_from_slice(segment);
            self.last_seen = Instant::now();
            &self.data
        }

        fn last_seen(&self) -> Instant {
            self.last_seen
        }

        fn find_message_boundary(&self) -> Option<usize> {
            todo!()
        }

        fn advance_past(&mut self, boundary: usize) {
            todo!()
        }

        fn touch(&mut self) {
            todo!()
        }
    }

    #[test]
    fn test_push_single_and_multiple() {
        let mgr = ReassemblyManager::<u8, DummyBuffer>::new(Duration::from_secs(60), 4);
        // Push a single segment
        let out1 = mgr.push(1, 0, 0, b"Hello");
        assert_eq!(&out1[..], b"Hello");

        // Push another segment on same key
        let out2 = mgr.push(1, 0, 1, b" World");
        assert_eq!(&out2[..], b"Hello World");

        // Ensure get_buffer returns a reference with same data
        let buf_ref = mgr.get_buffer(&1).expect("Buffer should exist");
        assert_eq!(buf_ref.value().data, b"Hello World");
    }

    #[test]
    fn test_push_with_closure() {
        let mgr = ReassemblyManager::<u8, DummyBuffer>::new(Duration::from_secs(60), 4);
        // Use push_with to compute length after appending
        let length = mgr.push_with(2, 0, 0, b"AB", |buf, assembled| {
            // buf is the DummyBuffer, assembled is the slice
            assert_eq!(assembled, b"AB");
            // Now push extra data directly
            buf.push_segment(1, b"CD");
            buf.data.len()
        });
        assert_eq!(length, 4);

        // Verify the manager's stored buffer has both segments
        let buf = mgr.get_buffer(&2).unwrap();
        assert_eq!(buf.value().data, b"ABCD");
    }

    #[test]
    fn test_eviction_on_max_entries() {
        let mgr = ReassemblyManager::<u8, DummyBuffer>::new(Duration::from_secs(60), 1);
        // Insert first entry
        mgr.push(10, 0, 0, b"A");
        assert!(mgr.get_buffer(&10).is_some());

        // Insert second => should evict the oldest (key 10)
        mgr.push(20, 0, 0, b"B");
        assert!(mgr.get_buffer(&10).is_none(), "Old entry should be evicted");
        assert!(mgr.get_buffer(&20).is_some());
    }

    #[test]
    fn test_evict_stale() {
        let timeout = Duration::from_millis(50);
        let mgr = ReassemblyManager::<u8, DummyBuffer>::new(timeout, 10);

        // Push two keys
        mgr.push(1, 0, 0, b"one");
        mgr.push(2, 0, 0, b"two");

        // Manually make key=1 stale by altering its last_seen in a push_with
        let old_time = Instant::now() - Duration::from_secs(10);
        mgr.push_with(1, 0, 1, b"X", |buf, _| {
            buf.last_seen = old_time;
        });

        // Wait to exceed the timeout for key=2 as well
        sleep(timeout * 2);

        // Now evict stale: both should be removed
        mgr.evict_stale();
        assert!(mgr.get_buffer(&1).is_none());
        assert!(mgr.get_buffer(&2).is_none());
    }
}
