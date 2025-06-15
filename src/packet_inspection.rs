use crate::bindings::*;
use crate::easylist::FilterPattern;
use crate::easylist::RuleType;
use crate::filter_engine::FilterEngine;
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
use std::fs::File;
use std::io::Read;
use std::io::{self, Write};
use std::os::raw::c_int;
use std::ptr;
use tls_parser::nom;
use tls_parser::SNIType;
use tls_parser::{parse_tls_plaintext, TlsExtension, TlsMessage};
use url::Url;

extern crate libc;

// TODO: Evict old buffers
static REASSEMBLY_TABLE: Lazy<DashMap<TCPConnectionKey, TCPReassemblyBuffer>> =
    Lazy::new(|| DashMap::new());

// TODO: Read path from config file
static FILTER_ENGINE: Lazy<FilterEngine> = Lazy::new(|| {
    let mut f = File::open("./lists/test_list.txt").expect("Could not open EasyList text file.");
    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .expect("Could not read EasyList file.");

    FilterEngine::new(&contents)
});

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

    let hdr = ip::parse_ip_header(&packet_bytes);
    let buf = &packet_bytes[hdr.header_length() as usize..];

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

                if !decide_sni_using_easylist(&hostname) {
                    return set_verdict(qh, pkt_id, libc::NF_DROP);
                }
            }
            return set_verdict(qh, pkt_id, NF_ACCEPT);
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
                                    method,
                                    path,
                                    hdr.source_as_string(),
                                    tcp_hdr.source_port
                                );

                                if !decide_using_easylist(&url, Some(host)) {
                                    println!("-> Blocking per EasyList: {}", url);
                                    return set_verdict(qh, pkt_id, libc::NF_DROP);
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
                                resp.status_code,
                                resp.reason_phrase,
                                hdr.destination_as_string(),
                                tcp_hdr.dest_port
                            );
                        }
                        Err(_) => {}
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

fn decide_using_easylist(url_str: &str, origin_host: Option<&str>) -> bool {
    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => {
            // If we can't parse it: accept.
            return true;
        }
    };

    // Figure out if it's third‐party or first‐party: compare `origin_host` vs `parsed.host_str()`.
    // If origin_host is None, just treat it as "first‐party = true" so that `$first-party` rules can match.
    let is_third_party = match origin_host {
        Some(o) => {
            if let Some(req_host) = parsed.host_str() {
                req_host.to_lowercase() != o.to_lowercase()
            } else {
                // no host in parsed? treat as "first‐party".
                false
            }
        }
        None => false,
    };

    for rule in &FILTER_ENGINE.rules {
        if rule.category != crate::easylist::FilterCategory::Network {
            continue;
        }

        // Does this rule's domain‐anchor (if any) match?
        // If rule.pattern is a literal starting with "||", then match against domain‐only:
        let mut prefix_matched = false;
        if let FilterPattern::Literal(lit) = &rule.pattern {
            // Example `lit`: "||ads.example.com^"
            if lit.starts_with("||") {
                // Let domain_part = `"ads.example.com"` (strip `||` and trailing `^` if present).
                let remainder = &lit[2..];
                let domain_part = if remainder.ends_with('^') {
                    &remainder[..remainder.len() - 1]
                } else {
                    remainder
                };
                if let Some(req_host) = parsed.host_str() {
                    // e.g. req_host = "tracker.ads.example.com"
                    // We only match if either `req_host == domain_part` or it ends‐with `.` + domain_part.
                    let rh = req_host.to_lowercase();
                    let dp = domain_part.to_lowercase();
                    if rh == dp || rh.ends_with(&format!(".{}", dp)) {
                        prefix_matched = true;
                    }
                }
            }
        }

        // If it was a "||...^" rule but prefix_matched == false, skip it immediately.
        if let FilterPattern::Literal(lit) = &rule.pattern {
            if lit.starts_with("||") && !prefix_matched {
                continue;
            }
        }
        // If it was a "regex" or a literal not starting with "||", we fall through.

        // Match the full pattern (regex or literal):
        let full_pattern_match = match &rule.pattern {
            FilterPattern::Literal(lit) => {
                // A "literal" can contain anchors:
                //  - Leading "|"  -> match at beginning-of-string
                //  - Trailing "|" -> match at end‐of‐string
                //  - "^"          -> match any "delimiter" (anything not alnum, not in URL‐charset)
                literal_matches(lit, url_str)
            }
            FilterPattern::Regex(re) => re.is_match(url_str),
        };
        if !full_pattern_match {
            continue;
        }

        // Now check options, if any (resource types, domain‐includes/excludes, third‐party):
        if let Some(opts) = &rule.options {
            if !opts.domain_includes.is_empty() {
                if let Some(origin) = origin_host {
                    let mut found = false;
                    for dom in &opts.domain_includes {
                        if origin.eq_ignore_ascii_case(dom) {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        // Origin not in "includes" -> rule does not apply
                        continue;
                    }
                } else {
                    continue;
                }
            }
            if !opts.domain_excludes.is_empty() {
                if let Some(origin) = origin_host {
                    let mut excluded = false;
                    for dom in &opts.domain_excludes {
                        if origin.eq_ignore_ascii_case(dom) {
                            excluded = true;
                            break;
                        }
                    }
                    if excluded {
                        continue;
                    }
                }
            }
            if let Some(third_party_opt) = opts.third_party {
                // If the rule is $third-party but our request is not third‐party, skip.
                if third_party_opt && !is_third_party {
                    continue;
                }
                // If rule is $first-party but our request is third‐party, skip.
                if !third_party_opt && is_third_party {
                    continue;
                }
            }
        }

        // If we reach here, the rule "matches" this URL. Now obey allow/block:
        match rule.rule_type {
            RuleType::Allow => {
                // "@@" means whitelist: accept immediately
                return true;
            }
            RuleType::Block => {
                // First "block" we see -> drop.
                return false;
            }
        }
    }

    // If no rule matched at all, accept by default
    true
}

/// Returns true if `lit_pattern` matches `text` according to Adblock‐style literal semantics.
/// - If lit_pattern starts with "|", that ′|′ means "match beginning of text"
/// - If lit_pattern ends with "|", that ′|′ means "match end of text"
/// - Any "^" in the pattern matches a "separator" (any character outside [A-Za-z0-9._-])
/// - Otherwise it's just a substring check.
fn literal_matches(lit_pattern: &str, text: &str) -> bool {
    // A very basic implementation:
    // 1. Handle leading "|"
    // 2. Handle trailing "|"
    // 3. Handle "^" (map to regex "[^A-Za-z0-9._-]")
    // 4. Otherwise search as substring.

    // TODO: compile a tiny Regex once per pattern

    // If starts_with('|') -> we only match if text starts exactly at next characters.
    if lit_pattern.starts_with('|') {
        let remainder = &lit_pattern[1..]; // e.g. "http://ads.example.com/banner.js"
                                           // Does the text start with remainder, except we might have trailing '|', '^', etc.
        return literal_anchor_match_at_start(remainder, text);
    }

    // If does not start with '|' but has '^', we replace every '^' with "separator regex":
    if lit_pattern.contains('^') {
        // Build a tiny regex: escape all other chars, replace '^' with "(?P<sep>[^A-Za-z0-9._-])"
        let mut regex_src = String::new();
        for ch in lit_pattern.chars() {
            match ch {
                '^' => {
                    // "separator": anything not in URL‐safe characters
                    regex_src.push_str(r#"[^A-Za-z0-9\.\_\-]"#);
                }
                '$' | '(' | ')' | '.' | '+' | '[' | ']' | '?' | '*' | '{' | '}' | '|' | '\\' => {
                    regex_src.push('\\');
                    regex_src.push(ch);
                }
                c => {
                    regex_src.push(c);
                }
            }
        }
        if let Ok(re) = regex::Regex::new(&regex_src) {
            return re.is_match(text);
        } else {
            return false;
        }
    }

    // If ends_with('|') -> match end‐of‐string exactly
    if lit_pattern.ends_with('|') {
        let sub = &lit_pattern[..lit_pattern.len() - 1];
        return text.ends_with(sub);
    }

    // Otherwise, plain substring:
    text.contains(lit_pattern)
}

/// If `pat` might end in "|" or contain "^", handle those anchors at the *very start*:
fn literal_anchor_match_at_start(pat: &str, text: &str) -> bool {
    // If pat ends with '|' -> match exactly "pat[..len-1]" to very start of text
    if pat.ends_with('|') {
        let core = &pat[..pat.len() - 1];
        return text.starts_with(core) && core.len() == text.len() - 0;
        // i.e. exact match of whole text; but that's an odd case—rare.
    }

    // TODO: compile a tiny Regex once per pattern

    // If pat contains "^", we must check that every '^' in pat matches a "separator" at the same index.
    let mut regex_src = String::from("^");
    for ch in pat.chars() {
        match ch {
            '^' => regex_src.push_str(r#"[^A-Za-z0-9\.\_\-]"#),
            '$' | '(' | ')' | '.' | '+' | '[' | ']' | '?' | '*' | '{' | '}' | '|' | '\\' => {
                regex_src.push('\\');
                regex_src.push(ch);
            }
            c => regex_src.push(c),
        }
    }
    if let Ok(re) = regex::Regex::new(&regex_src) {
        re.is_match(text)
    } else {
        false
    }
}

fn decide_sni_using_easylist(sni_hostname: &str) -> bool {
    // Build a fake URL (no path).
    let fake = format!("https://{}/", sni_hostname);
    decide_using_easylist(&fake, Some(sni_hostname))
}
