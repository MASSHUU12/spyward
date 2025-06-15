use crate::{
    filter_engine::Verdict,
    packet::{handler::PacketHandler, PacketMeta},
    protocol::udp::parser::UDPHeader,
};

pub struct UdpPacketHandler;

impl UdpPacketHandler {
    pub fn new() -> Self {
        UdpPacketHandler
    }
}

impl PacketHandler for UdpPacketHandler {
    type Header = UDPHeader;

    // TODO: Handle HTTP/3
    fn inspect(&mut self, meta: &PacketMeta, hdr: &UDPHeader, _payload: &[u8]) -> Verdict {
        println!(
            "UDP {}:{} -> {}:{} {:?}",
            meta.src, meta.src_port, meta.dst, meta.dst_port, hdr
        );
        Verdict::Accept
    }
}
