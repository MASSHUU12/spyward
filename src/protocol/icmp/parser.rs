use crate::protocol::header::Header;

#[repr(C)]
#[derive(Debug)]
/// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
pub struct ICMPHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
}

impl Header for ICMPHeader {
    const MIN_HEADER_SIZE: usize = 8;

    /// Parses an ICMP header from the given buffer.
    /// The fields after the first 4 bytes may differ in format based on ICMP message type.
    fn parse(buf: &[u8]) -> Self {
        assert!(
            buf.len() >= Self::MIN_HEADER_SIZE,
            "Buffer too small for ICMP header"
        );

        let icmp_type = buf[0];
        let icmp_code = buf[1];
        let checksum = u16::from_be_bytes([buf[2], buf[3]]);
        let identifier = u16::from_be_bytes([buf[4], buf[5]]);
        let sequence_number = u16::from_be_bytes([buf[6], buf[7]]);

        ICMPHeader {
            icmp_type,
            icmp_code,
            checksum,
            identifier,
            sequence_number,
        }
    }

    fn header_length(&self) -> usize {
        Self::MIN_HEADER_SIZE
    }
}
