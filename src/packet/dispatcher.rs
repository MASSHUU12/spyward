use crate::{
    filter_engine::Verdict,
    packet::{handler::PacketHandler, Packet},
    protocol::{
        icmp::handler::IcmpPacketHandler, tcp::handler::TcpPacketHandler,
        udp::handler::UdpPacketHandler,
    },
};

pub struct PacketDispatcher {
    icmp: IcmpPacketHandler,
    udp: UdpPacketHandler,
    tcp: TcpPacketHandler,
}

impl PacketDispatcher {
    pub fn new() -> Self {
        PacketDispatcher {
            icmp: IcmpPacketHandler::new(),
            udp: UdpPacketHandler::new(),
            tcp: TcpPacketHandler::new(),
        }
    }

    pub fn dispatch(&mut self, pkt: Packet<'_>) -> Verdict {
        match pkt {
            Packet::Icmp(meta, hdr, payload) => self.icmp.inspect(meta, hdr, payload),
            Packet::Udp(meta, hdr, payload) => self.udp.inspect(meta, hdr, payload),
            Packet::Tcp(meta, hdr, payload) => self.tcp.inspect(meta, hdr, payload),
            Packet::Other(_, _) => Verdict::Accept,
        }
    }
}
