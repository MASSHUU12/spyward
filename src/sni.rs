use tls_parser::nom;
use tls_parser::SNIType;
use tls_parser::{parse_tls_plaintext, TlsExtension, TlsMessage};

use crate::filter_engine::Verdict;
use crate::filter_engine::FILTER_ENGINE;

pub fn try_extract_sni(buf: &[u8]) -> Option<String> {
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

pub fn decide_sni_using_easylist(sni_hostname: &str) -> Verdict {
    // Build a fake URL (no path).
    let fake = format!("https://{}/", sni_hostname);
    FILTER_ENGINE.decide(&fake, Some(sni_hostname))
}
