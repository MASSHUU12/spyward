use std::any::Any;
use std::fmt;

/// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#[repr(u8)]
pub enum IPProtocol {
    /// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    ICMP = 1,
    /// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    TCP = 6,
    /// https://en.wikipedia.org/wiki/User_Datagram_Protocol
    UDP = 17,
    RDP = 27,
    IPV6 = 41,
    IPV6ROUTE = 43,
    IPV6FRAG = 44,
    TLSP = 56,
    /// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    IPV6ICMP = 58,
    IPV6NONXT = 59,
    IPV6OPTS = 60,
}

pub trait IIPHeader: Any + fmt::Debug {
    /// Return the version (4 or 6).
    fn version(&self) -> u8;

    /// dotted-decimal or canonical IPv6 representation
    fn source_as_string(&self) -> String;
    fn destination_as_string(&self) -> String;

    fn packet_protocol(&self) -> IPProtocol;

    /// Required for downcasting
    fn as_any(&self) -> &dyn Any;
}

/// Parse the first 20 (IPv4) or 40 (IPv6) bytes of `buf` and return
/// a boxed header.
pub fn parse_ip_header(buf: &[u8]) -> Box<dyn IIPHeader> {
    let ver = (buf[0] >> 4) & 0xF;
    if ver == 4 {
        assert!(buf.len() >= 20, "Buffer too small for IPv4 header");
        let mut tmp4 = [0u8; 20];
        tmp4.copy_from_slice(&buf[..20]);
        Box::new(IP4Header::new(tmp4))
    } else if ver == 6 {
        assert!(buf.len() >= 40, "Buffer too small for IPv6 header");
        let mut tmp6 = [0u8; 40];
        tmp6.copy_from_slice(&buf[..40]);
        Box::new(IP6Header::new(tmp6))
    } else {
        panic!("Unsupported IP version: {}", ver);
    }
}

/// Log header fields (version, TTL/hop-limit, lengths, addresses).
pub fn log_ip_header(hdr: &dyn IIPHeader) {
    match hdr.version() {
        4 => {
            let ip4 = hdr
                .as_any()
                .downcast_ref::<IP4Header>()
                .expect("Expected IPv4 header");
            println!("IPv{} header:", ip4.ver);
            println!("\tTTL: {}", ip4.ttl);
            println!("\tTotal Length: {}", ip4.total_length);
        }
        6 => {
            let ip6 = hdr
                .as_any()
                .downcast_ref::<IP6Header>()
                .expect("Expected IPv6 header");
            println!("IPv{} header:", ip6.ver);
            println!("\tHop limit: {}", ip6.hop_limit);
            println!("\tPayload length: {}", ip6.payload_length);
        }
        _ => unreachable!(),
    }

    println!("\tFrom: {}", hdr.source_as_string());
    println!("\tTo:   {}", hdr.destination_as_string());
}

/// IPv4 header
#[derive(Debug)]
pub struct IP4Header {
    pub ver: u8, // Version
    pub ihl: u8, // Internet Header Length
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_address: u32,
    pub destination_address: u32,
}

impl IP4Header {
    pub fn new(buf: [u8; 20]) -> Self {
        let ver = (buf[0] >> 4) & 0xF;
        let ihl = buf[0] & 0x0F;
        let type_of_service = buf[1];
        let total_length = u16::from_be_bytes([buf[2], buf[3]]);
        let identification = u16::from_be_bytes([buf[4], buf[5]]);
        let flags = (buf[6] >> 5) & 0x7;
        let fragment_offset = u16::from_be_bytes([buf[6] & 0x1F, buf[7]]);
        let ttl = buf[8];
        let protocol = buf[9];
        let header_checksum = u16::from_be_bytes([buf[10], buf[11]]);
        let source_address = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let destination_address = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);

        IP4Header {
            ver,
            ihl,
            type_of_service,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_address,
            destination_address,
        }
    }

    fn ip4_to_string(addr: u32) -> String {
        let bytes = addr.to_be_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

impl IIPHeader for IP4Header {
    fn version(&self) -> u8 {
        self.ver
    }

    fn source_as_string(&self) -> String {
        Self::ip4_to_string(self.source_address)
    }

    fn destination_as_string(&self) -> String {
        Self::ip4_to_string(self.destination_address)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn packet_protocol(&self) -> IPProtocol {
        unsafe { std::mem::transmute(self.protocol) }
    }
}

/// IPv6 header
#[derive(Debug)]
pub struct IP6Header {
    pub ver: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
}

impl IP6Header {
    pub fn new(buf: [u8; 40]) -> Self {
        let ver = (buf[0] >> 4) & 0xF;
        let traffic_class = ((buf[0] & 0x0F) << 4) | ((buf[1] >> 4) & 0x0F);
        let flow_label = ((buf[1] as u32 & 0x0F) << 16) | ((buf[2] as u32) << 8) | buf[3] as u32;
        let payload_length = u16::from_be_bytes([buf[4], buf[5]]);
        let next_header = buf[6];
        let hop_limit = buf[7];

        let mut src = [0u8; 16];
        src.copy_from_slice(&buf[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&buf[24..40]);

        IP6Header {
            ver,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source_address: src,
            destination_address: dst,
        }
    }

    fn ip6_to_string(addr: &[u8; 16]) -> String {
        // Convert each pair to hex segments
        let mut parts: Vec<String> = addr
            .chunks(2)
            .map(|chunk| {
                let seg = u16::from_be_bytes([chunk[0], chunk[1]]);
                format!("{:x}", seg)
            })
            .collect();

        // Find longest run of "0"
        let mut best_start = 0;
        let mut best_len = 0;
        let mut cur_start = 0;
        let mut cur_len = 0;

        for (i, p) in parts.iter().enumerate() {
            if p == "0" {
                if cur_len == 0 {
                    cur_start = i;
                }
                cur_len += 1;
                if cur_len > best_len {
                    best_len = cur_len;
                    best_start = cur_start;
                }
            } else {
                cur_len = 0;
            }
        }

        // Compress if run >= 2
        if best_len > 1 {
            let mut compressed = Vec::new();
            compressed.extend_from_slice(&parts[..best_start]);
            compressed.push(String::new());
            compressed.extend_from_slice(&parts[best_start + best_len..]);
            parts = compressed;
        }

        let joined = parts.join(":");
        // Replace any accidental ':::'
        joined.replace(":::", "::")
    }
}

impl IIPHeader for IP6Header {
    fn version(&self) -> u8 {
        self.ver
    }

    fn source_as_string(&self) -> String {
        Self::ip6_to_string(&self.source_address)
    }

    fn destination_as_string(&self) -> String {
        Self::ip6_to_string(&self.destination_address)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn packet_protocol(&self) -> IPProtocol {
        unsafe { std::mem::transmute(self.next_header) }
    }
}
