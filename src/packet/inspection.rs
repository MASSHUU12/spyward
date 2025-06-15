use crate::bindings::*;
use crate::filter_engine::Verdict;
use crate::ip;
use crate::ip::IIPHeader;
use crate::ip::IPProtocol;
use crate::nfqueue::NfQueue;
use crate::packet::dispatcher::PacketDispatcher;
use crate::packet::Packet;
use crate::packet::PacketMeta;
use crate::protocol::header::Header;
use crate::protocol::icmp::parser::ICMPHeader;
use crate::protocol::tcp::parser::TCPHeader;
use crate::protocol::udp::parser::UDPHeader;
use libc::NF_ACCEPT;
use libc::NF_DROP;
use once_cell::sync::Lazy;
use std::ffi::c_void;
use std::io::{self, Write};
use std::os::raw::c_int;
use std::ptr;
use std::sync::Mutex;

extern crate libc;

static DISPATCHER: Lazy<Mutex<PacketDispatcher>> =
    Lazy::new(|| Mutex::new(PacketDispatcher::new()));

fn set_verdict(qh: *mut nfq_q_handle, pkt_id: u32, v: Verdict) -> c_int {
    let code = match v {
        Verdict::Accept => NF_ACCEPT,
        Verdict::Drop => NF_DROP,
    } as u32;
    let r = unsafe { nfq_set_verdict(qh, pkt_id, code, 0, ptr::null()) };
    if r < 0 {
        let err = io::Error::last_os_error();
        let _ = writeln!(io::stderr(), "nfq_set_verdict error: {}", err);
    }
    r as c_int
}

// TODO: Collect stats (total, accepted, dropped)
pub unsafe extern "C" fn packet_inspection(
    qh: *mut nfq_q_handle,
    _nfmsg: *mut nfgenmsg,
    nfdata: *mut nfq_data,
    _data: *mut c_void,
) -> c_int {
    let packet_bytes = NfQueue::extract_payload(nfdata);
    let pkt_id = NfQueue::extract_packet_id(nfdata);

    // TODO: Log only when rejected or --verbose
    // TODO: Use --verbose option
    // TODO: Check DNS for source
    // TODO: Allow custom blocklist/allowlist
    // TODO: Implement statistics (accepted/rejected counts)
    // TODO: Add unit tests for packetCallback logic

    let hdr: Box<dyn IIPHeader> = ip::parse_ip_header(&packet_bytes);
    let transport = &packet_bytes[hdr.header_length() as usize..];

    // Common metadata for all protocols.
    let src = hdr.source_as_string();
    let dst = hdr.destination_as_string();
    let proto = hdr.packet_protocol();

    // Build a Packet enum for dispatch.
    let verdict = match proto {
        IPProtocol::ICMP => {
            let icmp = ICMPHeader::parse(transport);
            let payload = &transport[icmp.header_length()..];
            let meta = PacketMeta {
                src: src.clone(),
                dst: dst.clone(),
                src_port: 0,
                dst_port: 0,
                protocol: proto,
            };
            let pkt = Packet::Icmp(&meta, &icmp, payload);
            DISPATCHER.lock().unwrap().dispatch(pkt)
        }
        IPProtocol::UDP => {
            let udp = UDPHeader::parse(transport);
            let payload = &transport[udp.header_length() as usize..];
            let meta = PacketMeta {
                src: src.clone(),
                dst: dst.clone(),
                src_port: udp.source_port,
                dst_port: udp.dest_port,
                protocol: proto,
            };
            let pkt = Packet::Udp(&meta, &udp, payload);
            DISPATCHER.lock().unwrap().dispatch(pkt)
        }
        IPProtocol::TCP => {
            let tcp = TCPHeader::parse(transport);
            let payload = &transport[tcp.header_length() as usize..];
            let meta = PacketMeta {
                src: src.clone(),
                dst: dst.clone(),
                src_port: tcp.source_port,
                dst_port: tcp.dest_port,
                protocol: proto,
            };
            let pkt = Packet::Tcp(&meta, &tcp, payload);
            DISPATCHER.lock().unwrap().dispatch(pkt)
        }
        _ => {
            // Unsupported protocols are accepted by default.
            let meta = PacketMeta {
                src,
                dst,
                src_port: 0,
                dst_port: 0,
                protocol: proto,
            };
            let pkt = Packet::Other(&meta, &transport);
            DISPATCHER.lock().unwrap().dispatch(pkt)
        }
    };

    set_verdict(qh, pkt_id, verdict)
}
