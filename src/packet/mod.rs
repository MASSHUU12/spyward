pub mod dispatcher;
pub mod handler;

use crate::{
    ip::IPProtocol,
    protocol::{icmp::parser::ICMPHeader, tcp::parser::TCPHeader, udp::parser::UDPHeader},
};

/// Metadata common to all packets
pub struct PacketMeta {
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IPProtocol,
}

pub enum Packet<'a> {
    Icmp(&'a PacketMeta, &'a ICMPHeader, &'a [u8]),
    Udp(&'a PacketMeta, &'a UDPHeader, &'a [u8]),
    Tcp(&'a PacketMeta, &'a TCPHeader, &'a [u8]),
    Other(&'a PacketMeta, &'a [u8]),
}
