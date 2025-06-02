#[repr(C)]
#[derive(Debug)]
/// https://en.wikipedia.org/wiki/User_Datagram_Protocol
pub struct UDPHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UDPHeader {
    /// Parses a UDP header from the given buffer.
    /// Ensure that `buf` is at least 8 bytes.
    pub fn parse_udp_header(buf: &[u8]) -> Self {
        assert!(buf.len() >= 8, "Buffer too small for UDP header");

        let source_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dest_port = u16::from_be_bytes([buf[2], buf[3]]);
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        let checksum = u16::from_be_bytes([buf[6], buf[7]]);

        UDPHeader {
            source_port,
            dest_port,
            length,
            checksum,
        }
    }
}
