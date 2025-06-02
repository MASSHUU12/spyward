use std::collections::BTreeMap;

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

impl TCPHeader {
    /// Parses a TCP header from the given buffer.
    /// Ensure that `buf` is at least 20 bytes.
    pub fn parse(buf: &[u8]) -> Self {
        assert!(buf.len() >= 20, "Buffer too small for TCP header");

        let source_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dest_port = u16::from_be_bytes([buf[2], buf[3]]);
        let seq_number = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ack_number = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        let data_offset_raw = buf[12] >> 4;
        let reserved_flags = u16::from_be_bytes([buf[12] & 0x0F, buf[13]]);
        let data_offset = data_offset_raw;
        let flags = (reserved_flags & 0x003F) as u8;

        let window_size = u16::from_be_bytes([buf[14], buf[15]]);
        let checksum = u16::from_be_bytes([buf[16], buf[17]]);
        let urgent_ptr = u16::from_be_bytes([buf[18], buf[19]]);

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

    pub fn header_length(&self) -> usize {
        (self.data_offset as usize) * 4
    }
}

/// A simple key identifying one TCP flow in one direction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TCPConnectionKey {
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

/// A reassembly buffer for one direction of one TCP connection.
pub struct TCPReassemblyBuffer {
    next_seq: u32,
    assembled: Vec<u8>,
    /// Out–of–order segments waiting for their turn.
    pending: BTreeMap<u32, Vec<u8>>,
}

impl TCPReassemblyBuffer {
    pub fn new(initial_seq: u32) -> Self {
        TCPReassemblyBuffer {
            next_seq: initial_seq,
            assembled: Vec::new(),
            pending: BTreeMap::new(),
        }
    }

    /// Pushes a TCP segment into the buffer.
    ///
    /// Returns a slice of *all* assembled bytes (from initial_seq up to
    /// the highest contiguous byte) so far.
    pub fn push_segment(&mut self, seq: u32, data: &[u8]) -> &[u8] {
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
}
