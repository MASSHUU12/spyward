use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use crate::protocol::{header::Header, reassembly::buffer::ReassemblyBuffer};

#[repr(C)]
#[derive(Debug)]
/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
pub struct TCPHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl Header for TCPHeader {
    const MIN_HEADER_SIZE: usize = 20;

    // TODO: Return Result instead of panicking
    // TODO: Define enum ParseError { BufferTooSmall, InvalidDataOffset, /* … */ }
    /// Parses a TCP header from the given buffer.
    /// Ensure that `buf` is at least 20 bytes.
    fn parse(buf: &[u8]) -> Self {
        assert!(
            buf.len() >= Self::MIN_HEADER_SIZE,
            "Buffer too small for TCP header"
        );

        let source_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dest_port = u16::from_be_bytes([buf[2], buf[3]]);
        let seq_number = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ack_number = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        let data_offset_raw = buf[12] >> 4;
        let reserved_flags = u16::from_be_bytes([buf[12] & 0x0F, buf[13]]);
        let data_offset = data_offset_raw;
        // Use bitflags for flags
        let flags = (reserved_flags & 0x003F) as u8;

        let window_size = u16::from_be_bytes([buf[14], buf[15]]);
        let checksum = u16::from_be_bytes([buf[16], buf[17]]);
        let urgent_ptr = u16::from_be_bytes([buf[18], buf[19]]);

        // TODO: Parse options

        TCPHeader {
            source_port,
            dest_port,
            seq_number,
            ack_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_ptr,
        }
    }

    fn header_length(&self) -> usize {
        (self.data_offset as usize) * 4
    }
}

/// A simple key identifying one TCP flow in one direction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TCPConnectionKey {
    // TODO: Use std::net::IpAddr
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
}

impl TCPConnectionKey {
    pub fn new(src_ip: String, dst_ip: String, src_port: u16, dst_port: u16) -> Self {
        TCPConnectionKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }
}

// TODO: Cap total memory usage: if too many concurrent connections, evict oldest.
/// A reassembly buffer for one direction of one TCP connection.
pub struct TCPReassemblyBuffer {
    next_seq: u32,
    assembled: Vec<u8>,
    /// Out–of–order segments waiting for their turn.
    pending: BTreeMap<u32, Vec<u8>>,

    /// Timestamp when this buffer was first created (first segment).
    first_seen: Instant,
    /// Timestamp when we saw the last segment.
    last_seen: Instant,

    /// Whether we've already extracted or inspected an HTTP header in this direction.
    pub http_done: bool,
    /// Whether we've already extracted or inspected TLS ClientHello SNI in this direction.
    pub tls_done: bool,
}

impl TCPReassemblyBuffer {
    /// Creates a new reassembly buffer, initializing `next_seq` to `initial_seq`.
    pub fn with_timestamps(initial_seq: u32) -> Self {
        let now = Instant::now();
        TCPReassemblyBuffer {
            next_seq: initial_seq,
            assembled: Vec::new(),
            pending: BTreeMap::new(),
            first_seen: now,
            last_seen: now,
            http_done: false,
            tls_done: false,
        }
    }

    /// Convenience alias for `with_timestamps(...)`.
    pub fn new(initial_seq: u32) -> Self {
        Self::with_timestamps(initial_seq)
    }

    /// Pushes a TCP segment into the buffer.
    ///
    /// This method:
    /// 1. Drops any data that is already before `next_seq`.
    /// 2. Trims leading overlap if `seq < next_seq`.
    /// 3. Stores remaining bytes in `pending`.
    /// 4. Continuously drains any contiguous segments at the front of `pending`, appending
    ///    them to `assembled` and advancing `next_seq`.
    ///
    /// Returns a slice of *all* assembled bytes so far (from the initial sequence number up to
    /// the highest contiguous byte).
    pub fn push_segment(&mut self, seq: u32, data: &[u8]) -> &[u8] {
        self.last_seen = Instant::now();

        // Ignore data we've already consumed
        if seq + data.len() as u32 <= self.next_seq {
            return &self.assembled;
        }

        // Clip off any overlap at the front
        let (seq, data) = if seq < self.next_seq {
            let skip = (self.next_seq - seq) as usize;
            (self.next_seq, &data[skip..])
        } else {
            (seq, data)
        };

        self.pending.entry(seq).or_insert_with(|| data.to_vec());

        // Now drain in‐order entries from the front
        while let Some((&front_seq, buf)) = self.pending.iter().next() {
            if front_seq != self.next_seq {
                break;
            }
            // We have exactly the piece we need next
            let buf = self.pending.remove(&front_seq).unwrap();
            self.next_seq = front_seq + buf.len() as u32;
            self.assembled.extend_from_slice(&buf);
        }

        &self.assembled
    }

    /// Attempts to find the end of an HTTP header (`\r\n\r\n`) in the assembled buffer.
    ///
    /// Returns `Some(header_length)` if a double-CRLF is found, where `header_length`
    /// is the index immediately after `\r\n\r\n` (i.e., the byte-offset where the HTTP
    /// "body" would begin). Returns `None` if the header terminator is not yet present.
    pub fn find_header_end(&self) -> Option<usize> {
        // Search for the byte sequence [0x0D,0x0A, 0x0D,0x0A].
        // We only need to scan in `assembled`, since that is the full contiguous data so far.
        let haystack = &self.assembled;
        if haystack.len() < 4 {
            return None;
        }
        // TODO: Optimize using memchr
        for i in 0..=(haystack.len() - 4) {
            if &haystack[i..i + 4] == b"\r\n\r\n" {
                return Some(i + 4);
            }
        }
        None
    }

    /// Returns how long it has been since we last saw any segment for this buffer.
    pub fn age(&self) -> Duration {
        Instant::now().saturating_duration_since(self.last_seen)
    }
}

impl ReassemblyBuffer for TCPReassemblyBuffer {
    type Seq = u32;

    fn new(initial_seq: Self::Seq) -> Self {
        TCPReassemblyBuffer::with_timestamps(initial_seq)
    }

    fn push_segment(&mut self, seq: Self::Seq, data: &[u8]) -> &[u8] {
        self.push_segment(seq, data)
    }

    /// Here we treat a "message boundary" as end of HTTP header, if not done yet.
    fn find_message_boundary(&self) -> Option<usize> {
        // If HTTP not done, look for header end; else None or could implement body-length-based.
        if !self.http_done {
            self.find_header_end()
        } else {
            None
        }
    }

    fn advance_past(&mut self, boundary: usize) {
        // Drop the first `boundary` bytes from `assembled`.
        if boundary == 0 {
            return;
        }
        if boundary >= self.assembled.len() {
            // Drop all
            self.assembled.clear();
        } else {
            // Remove consumed bytes
            self.assembled.drain(0..boundary);
        }
        // Note: next_seq has already advanced when assembling; assembled now holds the "tail".
    }

    fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    fn last_seen(&self) -> Instant {
        self.last_seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_reassembly_in_order() {
        let mut buf = TCPReassemblyBuffer::new(1000);
        let r1 = buf.push_segment(1000, b"Hello");
        assert_eq!(r1, b"Hello");
        let r2 = buf.push_segment(1005, b", world");
        assert_eq!(r2, b"Hello, world");
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let mut buf = TCPReassemblyBuffer::new(1000);
        // Out-of-order: seq=1005, data=", world"
        let r1 = buf.push_segment(1005, b", world");
        assert_eq!(r1, b""); // nothing contiguous yet
                             // Now the first part: seq=1000, data="Hello"
        let r2 = buf.push_segment(1000, b"Hello");
        assert_eq!(r2, b"Hello, world");
    }

    #[test]
    fn test_overlap_segments() {
        let mut buf = TCPReassemblyBuffer::new(1000);
        // First: seq=1000, data="ABCDEFGHIJ" (10 bytes)
        let r1 = buf.push_segment(1000, b"ABCDEFGHIJ");
        assert_eq!(r1, b"ABCDEFGHIJ");
        // Overlapping segment: seq=1005, data="FGHIJKLMNOP"
        let r2 = buf.push_segment(1005, b"FGHIJKLMNOP");
        assert_eq!(r2, b"ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn test_find_header_end_not_found() {
        let mut buf = TCPReassemblyBuffer::new(0);
        buf.assembled
            .extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\n");
        assert_eq!(buf.find_header_end(), None);
    }

    #[test]
    fn test_find_header_end_found() {
        let mut buf = TCPReassemblyBuffer::new(0);
        buf.assembled
            .extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY");
        assert_eq!(
            buf.find_header_end(),
            Some((b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").len())
        );
    }

    #[test]
    fn test_timestamps_and_age() {
        let mut buf = TCPReassemblyBuffer::new(0);
        // Immediately after creation, age should be very small.
        assert!(buf.age() < Duration::from_millis(10));

        // Simulate waiting by manually stepping the timestamp.
        let before = buf.last_seen;
        std::thread::sleep(Duration::from_millis(5));
        buf.push_segment(0, b"A");
        assert!(buf.last_seen > before);
    }
}
