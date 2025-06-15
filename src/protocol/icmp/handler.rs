use crate::{
    filter_engine::Verdict,
    packet::{handler::PacketHandler, PacketMeta},
    protocol::icmp::parser::ICMPHeader,
};

pub struct IcmpPacketHandler;

impl IcmpPacketHandler {
    pub fn new() -> Self {
        IcmpPacketHandler
    }
}

impl PacketHandler for IcmpPacketHandler {
    type Header = ICMPHeader;

    fn inspect(&mut self, meta: &PacketMeta, hdr: &ICMPHeader, _payload: &[u8]) -> Verdict {
        println!("ICMP from {} -> {}: {:?}", meta.src, meta.dst, hdr);
        Verdict::Accept
    }
}
