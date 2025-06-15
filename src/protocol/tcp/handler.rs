use std::time::Duration;

use once_cell::sync::Lazy;

use crate::{
    filter_engine::{Verdict, FILTER_ENGINE},
    packet::{handler::PacketHandler, PacketMeta},
    protocol::{
        http::{HTTPRequest, HTTPResponse, HttpMessage},
        reassembly::{buffer::ReassemblyBuffer, manager::ReassemblyManager},
        tcp::parser::{TCPConnectionKey, TCPHeader, TCPReassemblyBuffer},
    },
    sni::{decide_sni_using_easylist, try_extract_sni},
};

// TODO: Evict old buffers
static TCP_REASSEMBLY_MANAGER: Lazy<ReassemblyManager<TCPConnectionKey, TCPReassemblyBuffer>> =
    Lazy::new(|| {
        // TODO: Get this from config
        // 60s timeout for stale connections
        ReassemblyManager::new(Duration::from_secs(60), 512)
    });

pub struct TcpPacketHandler;

impl TcpPacketHandler {
    pub fn new() -> Self {
        TcpPacketHandler
    }

    // TODO: Use this on timer thread
    pub fn evict_stale(&self) {
        TCP_REASSEMBLY_MANAGER.evict_stale();
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

        let assembled: Vec<u8> =
            TCP_REASSEMBLY_MANAGER.push(key.clone(), hdr.seq_number, hdr.seq_number, payload);
        if assembled.is_empty() {
            return Verdict::Accept;
        }

        // TODO: Factor out TSL SNI handling & HTTP detection for testing

        // TLS SNI handling
        if hdr.dest_port == 443 || hdr.source_port == 443 {
            if let Some(mut entry) = TCP_REASSEMBLY_MANAGER.get_buffer_mut(&key) {
                if !entry.tls_done {
                    if let Some(hostname) = try_extract_sni(&assembled) {
                        println!("TLS SNI seen for {:?}: {}", key, hostname);
                        entry.tls_done = true;
                        match decide_sni_using_easylist(&hostname) {
                            Verdict::Drop => return Verdict::Drop,
                            _ => {}
                        }
                    }
                }
            }
            return Verdict::Accept;
        }

        // HTTP detection on assembled
        if let Some(mut entry) = TCP_REASSEMBLY_MANAGER.get_buffer_mut(&key) {
            if !entry.http_done {
                if let Some(header_len) = entry.find_header_end() {
                    let header_bytes = &assembled[..header_len];
                    if HTTPRequest::is_request(header_bytes) {
                        if let Ok(req) = HTTPRequest::parse(header_bytes) {
                            if let Some(host) = req.header_value("Host") {
                                let method = &req.message.method;
                                let path = &req.message.path;
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
                                    _ => {}
                                }
                            }
                        }
                    } else if HTTPResponse::is_response(header_bytes) {
                        if let Ok(resp) = HTTPResponse::parse(header_bytes) {
                            println!(
                                "HTTP<- {} {} from {}:{}",
                                resp.message.status_code,
                                resp.message.reason_phrase,
                                meta.dst,
                                hdr.dest_port
                            );
                        }
                    }
                    entry.http_done = true;
                    // Advance past header bytes so we don't repeatedly reprocess:
                    entry.advance_past(header_len);
                }
            }
        }

        Verdict::Accept
    }
}
