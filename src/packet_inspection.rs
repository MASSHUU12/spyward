use crate::bindings::*;
use crate::ip;
use crate::ip::IPProtocol;
use crate::nfqueue::NfQueue;
use crate::protocol::icmp::ICMPHeader;
use crate::protocol::tcp::TCPHeader;
use crate::protocol::udp::UDPHeader;
use libc::NF_ACCEPT;
use std::ffi::c_void;
use std::io::{self, Write};
use std::os::raw::c_int;
use std::ptr;

extern crate libc;

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
    // TODO: Use EasyList to decide if packed should be accepted or rejected
    // TODO: Allow custom blocklist/allowlist
    // TODO: Implement statistics (accepted/rejected counts)
    // TODO: Add unit tests for packetCallback logic

    let hdr = ip::parse_ip_header(&packet_bytes);
    let buf = &packet_bytes[hdr.header_length() as usize..];
    // ip::log_ip_header(&*hdr);

    // match hdr.as_any() {
    //     IP4Header => {}
    //     IP6Header => {}
    // }

    match hdr.packet_protocol() {
        IPProtocol::TCP => {
            let tcp_hdr = TCPHeader::parse_tcp_header(buf);

            println!("{:?}", tcp_hdr);

            // TODO: Parse HTTP requests
        }
        IPProtocol::ICMP => {
            let icmp_hdr = ICMPHeader::parse_icmp_header(buf);

            println!("{:?}", icmp_hdr);
        }
        IPProtocol::UDP => {
            let udp_hdr = UDPHeader::parse_udp_header(buf);

            // TODO: Parse HTTP/3

            println!("{:?}", udp_hdr);
        }
        IPProtocol::RDP => unimplemented!(),
        IPProtocol::IPV6 => unimplemented!(),
        IPProtocol::IPV6ROUTE => unimplemented!(),
        IPProtocol::IPV6FRAG => unimplemented!(),
        IPProtocol::TLSP => unimplemented!(),
        IPProtocol::IPV6ICMP => unimplemented!(),
        IPProtocol::IPV6NONXT => unimplemented!(),
        IPProtocol::IPV6OPTS => unimplemented!(),
    }

    let v = nfq_set_verdict(qh, pkt_id, NF_ACCEPT as u32, 0, ptr::null());
    if v < 0 {
        let err = io::Error::last_os_error();
        let _ = writeln!(io::stderr(), "nfq_set_verdict error: {}", err);
    }
    v
}
