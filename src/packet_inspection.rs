use crate::bindings::*;
use crate::ip;
use crate::ip::IIPHeader;
use crate::ip::IPProtocol;
use crate::nfqueue::NfQueue;
use crate::protocol::http::HTTPRequest;
use crate::protocol::http::HTTPResponse;
use crate::protocol::icmp::ICMPHeader;
use crate::protocol::tcp::TCPConnectionKey;
use crate::protocol::tcp::TCPHeader;
use crate::protocol::tcp::TCPReassemblyBuffer;
use crate::protocol::udp::UDPHeader;
use dashmap::DashMap;
use libc::NF_ACCEPT;
use once_cell::sync::Lazy;
use std::ffi::c_void;
use std::io::{self, Write};
use std::os::raw::c_int;
use std::ptr;
use tls_parser::nom;
use tls_parser::SNIType;
use tls_parser::{parse_tls_plaintext, TlsExtension, TlsMessage};

extern crate libc;

// TODO: Evict old buffers
static REASSEMBLY_TABLE: Lazy<DashMap<TCPConnectionKey, TCPReassemblyBuffer>> =
    Lazy::new(|| DashMap::new());

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
    // TODO: Use EasyList to decide if packed should be accepted or rejected
    // TODO: Allow custom blocklist/allowlist
    // TODO: Implement statistics (accepted/rejected counts)
    // TODO: Add unit tests for packetCallback logic

    let hdr = ip::parse_ip_header(&packet_bytes);
    let buf = &packet_bytes[hdr.header_length() as usize..];
    // ip::log_ip_header(&*hdr);

    let verdict = match hdr.packet_protocol() {
        // TODO: Handle HTTPS
        IPProtocol::TCP => handle_tcp(qh, pkt_id, &hdr, buf),
        IPProtocol::ICMP => handle_icmp(qh, pkt_id, &hdr, buf),
        IPProtocol::UDP => handle_udp(qh, pkt_id, &hdr, buf),
        other => {
            println!("Unsupported IP protocol: {:?}", other);
            set_verdict(qh, pkt_id, NF_ACCEPT)
        }
    };

    verdict
}

fn set_verdict(qh: *mut nfq_q_handle, pkt_id: u32, v: c_int) -> c_int {
    let r = unsafe { nfq_set_verdict(qh, pkt_id, v as u32, 0, ptr::null()) };
    if r < 0 {
        let err = io::Error::last_os_error();
        let _ = writeln!(io::stderr(), "nfq_set_verdict error: {}", err);
    }
    r as c_int
}

fn handle_icmp(
    qh: *mut nfq_q_handle,
    pkt_id: u32,
    _hdr: &Box<dyn IIPHeader>,
    payload: &[u8],
) -> c_int {
    let icmp_hdr = ICMPHeader::parse(payload);

    println!("{:?}", icmp_hdr);
    set_verdict(qh, pkt_id, NF_ACCEPT)
}

fn handle_udp(
    qh: *mut nfq_q_handle,
    pkt_id: u32,
    _hdr: &Box<dyn IIPHeader>,
    payload: &[u8],
) -> c_int {
    let udp_hdr = UDPHeader::parse(payload);

    // TODO: Parse HTTP/3

    println!("{:?}", udp_hdr);
    set_verdict(qh, pkt_id, NF_ACCEPT)
}

fn handle_tcp(
    qh: *mut nfq_q_handle,
    pkt_id: u32,
    hdr: &Box<dyn IIPHeader>,
    payload: &[u8],
) -> c_int {
    let tcp_hdr = TCPHeader::parse(payload);
    let payload = &payload[tcp_hdr.header_length()..];

    // println!("{:?}", tcp_hdr);

    if payload.is_empty() {
        return set_verdict(qh, pkt_id, NF_ACCEPT);
    }

    let key = TCPConnectionKey::new(
        hdr.source_as_string(),
        hdr.destination_as_string(),
        tcp_hdr.source_port,
        tcp_hdr.dest_port,
    );

    let contiguous: Vec<u8> = {
        let mut entry = REASSEMBLY_TABLE
            .entry(key.clone())
            .or_insert_with(|| TCPReassemblyBuffer::with_timestamps(tcp_hdr.seq_number));

        let seg_slice = entry.push_segment(tcp_hdr.seq_number, payload);
        let seg = seg_slice.to_vec();

        if seg.is_empty() {
            return set_verdict(qh, pkt_id, NF_ACCEPT);
        }
        if (tcp_hdr.dest_port == 443 || tcp_hdr.source_port == 443) && !entry.tls_done {
            if let Some(hostname) = try_extract_sni(&seg) {
                println!("TLS SNI seen for {:?}: {}", key, hostname);
                entry.tls_done = true;
            }
            return set_verdict(qh, pkt_id, NF_ACCEPT);
        }
        seg
    };

    if let Some(mut entry) = REASSEMBLY_TABLE.get_mut(&key) {
        if !entry.http_done {
            if let Some(header_len) = entry.find_header_end() {
                let header_bytes = &contiguous[..header_len];
                if HTTPRequest::is_request(header_bytes) {
                    if let Some(req) = HTTPRequest::parse(header_bytes) {
                        println!(
                            "HTTP-> {} {} from {}:{}",
                            req.method,
                            req.path,
                            hdr.source_as_string(),
                            tcp_hdr.source_port
                        );
                    }
                } else if HTTPResponse::is_response(header_bytes) {
                    if let Some(resp) = HTTPResponse::parse(header_bytes) {
                        println!(
                            "HTTP<- {} {} from {}:{}",
                            resp.status_code,
                            resp.reason_phrase,
                            hdr.destination_as_string(),
                            tcp_hdr.dest_port
                        );
                    }
                }
                entry.http_done = true;
            }
        }
    }

    set_verdict(qh, pkt_id, NF_ACCEPT)
}

fn try_extract_sni(buf: &[u8]) -> Option<String> {
    match parse_tls_plaintext(buf) {
        Ok((_, records)) => {
            for record in records.msg {
                if let TlsMessage::Handshake(hs) = record {
                    if let tls_parser::TlsMessageHandshake::ClientHello(ch) = hs {
                        if let Some(ext_bytes) = ch.ext {
                            if let Ok((_, exts)) = tls_parser::parse_tls_extensions(ext_bytes) {
                                for ext in exts {
                                    if let TlsExtension::SNI(list) = ext {
                                        if let Some(&(sni_type, sni_bytes)) = list.first() {
                                            if sni_type == SNIType::HostName {
                                                if let Ok(hostname_str) =
                                                    std::str::from_utf8(sni_bytes)
                                                {
                                                    return Some(hostname_str.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        Err(nom::Err::Incomplete(_)) => None,
        Err(e) => {
            println!("TLS parse error: {:?}", e);
            None
        }
    }
}
