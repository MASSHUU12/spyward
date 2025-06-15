use std::time::Instant;

/// A generic reassembly buffer for one direction of a flow/fragment-set.
pub trait ReassemblyBuffer {
    /// Sequence or offset type.
    type Seq: Copy + Ord;
    /// Creates a new buffer with initial sequence/offset.
    fn new(initial_seq: Self::Seq) -> Self;
    /// Insert a segment/chunk at given sequence/offset.
    /// Returns any newly‐assembled contiguous data (or a slice/view to the entire assembled so far).
    fn push_segment(&mut self, seq: Self::Seq, data: &[u8]) -> &[u8];
    /// Detect a message boundary or "complete message" within the assembled data.
    /// Returns the index (byte offset) in the assembled buffer where a complete message ends.
    fn find_message_boundary(&self) -> Option<usize>;
    /// Mark that boundary as handled: drop or advance past those bytes so that next calls look for subsequent messages.
    fn advance_past(&mut self, boundary: usize);
    /// Update last-seen timestamp.
    fn touch(&mut self);
    /// Return last-seen timestamp.
    fn last_seen(&self) -> Instant;
}
