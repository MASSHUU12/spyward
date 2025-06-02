#[repr(C)]
#[derive(Debug)]
/// https://networklessons.com/ip-routing/tcp-header
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
}
