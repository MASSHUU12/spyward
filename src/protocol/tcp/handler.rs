use dashmap::DashMap;
use once_cell::sync::Lazy;

use crate::{
    filter_engine::{Verdict, FILTER_ENGINE},
    packet::{handler::PacketHandler, PacketMeta},
    protocol::{
        http::{HTTPRequest, HTTPResponse},
        tcp::parser::{TCPConnectionKey, TCPHeader, TCPReassemblyBuffer},
    },
    sni::{decide_sni_using_easylist, try_extract_sni},
};

// TODO: Evict old buffers
static REASSEMBLY_TABLE: Lazy<DashMap<TCPConnectionKey, TCPReassemblyBuffer>> =
    Lazy::new(|| DashMap::new());

pub struct TcpPacketHandler;

impl TcpPacketHandler {
    pub fn new() -> Self {
        TcpPacketHandler
    }
}

impl PacketHandler for TcpPacketHandler {
    type Header = TCPHeader;

    fn inspect(&mut self, meta: &PacketMeta, hdr: &TCPHeader, payload: &[u8]) -> Verdict {
        if payload.is_empty() {
            return Verdict::Accept;
        }

        let key = TCPConnectionKey::new(
            meta.src.clone(),
            meta.dst.clone(),
            hdr.source_port,
            hdr.dest_port,
        );

        let contiguous: Vec<u8> = {
            let mut entry = REASSEMBLY_TABLE
                .entry(key.clone())
                .or_insert_with(|| TCPReassemblyBuffer::with_timestamps(hdr.seq_number));

            let seg_slice = entry.push_segment(hdr.seq_number, payload);
            let seg = seg_slice.to_vec();

            if seg.is_empty() {
                return Verdict::Accept;
            }
            if (hdr.dest_port == 443 || hdr.source_port == 443) && !entry.tls_done {
                if let Some(hostname) = try_extract_sni(&seg) {
                    println!("TLS SNI seen for {:?}: {}", key, hostname);
                    entry.tls_done = true;

                    match decide_sni_using_easylist(&hostname) {
                        Verdict::Drop => return Verdict::Drop,
                        _ => (),
                    }
                }
                return Verdict::Accept;
            }
            seg
        };

        // If we have reassembled bytes, see if there's a full HTTP header
        if let Some(mut entry) = REASSEMBLY_TABLE.get_mut(&key) {
            if !entry.http_done {
                if let Some(header_len) = entry.find_header_end() {
                    let header_bytes = &contiguous[..header_len];

                    if HTTPRequest::is_request(header_bytes) {
                        match HTTPRequest::parse(header_bytes) {
                            Ok(req) => {
                                if let Some(host) = req.header_value("Host") {
                                    let method = &req.method;
                                    let path = &req.path;
                                    let url = format!("http://{}{}", host, path);

                                    println!(
                                        "HTTP-> {} {} from {}:{}",
                                        method, path, meta.src, hdr.source_port
                                    );

                                    match FILTER_ENGINE.decide(&url, Some(host)) {
                                        Verdict::Drop => {
                                            println!("-> Blocking per EasyList: {}", url);
                                            return Verdict::Drop;
                                        }
                                        _ => (),
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    } else if HTTPResponse::is_response(header_bytes) {
                        match HTTPResponse::parse(header_bytes) {
                            Ok(resp) => {
                                println!(
                                    "HTTP<- {} {} from {}:{}",
                                    resp.status_code, resp.reason_phrase, meta.dst, hdr.dest_port
                                );
                            }
                            Err(_) => {}
                        }
                    }
                    entry.http_done = true;
                }
            }
        }

        Verdict::Accept
    }
}
