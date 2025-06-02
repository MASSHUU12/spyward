#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use crate::errors::SpyWardError;
use crate::ip;
use crate::ip::IP4Header;
use crate::ip::IP6Header;
use crate::ip::IPProtocol;
use crate::tcp::TCPHeader;
use crate::udp::UDPHeader;
use libc::recv;
use libc::AF_INET;
use libc::NFQNL_COPY_PACKET;
use libc::NF_ACCEPT;
use std::ffi::c_void;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

extern crate libc;

/// Represents an open NFQUEUE “session” with one queue #0.
pub struct NfQueue {
    /// The raw nfq_handle pointer.
    handle: *mut nfq_handle,
    /// The raw nfq_q_handle pointer associated to queue #0.
    q_handle: *mut nfq_q_handle,
    cleaned_up: bool,
}

impl NfQueue {
    /// Open, bind, and create queue 0 with `packet_callback`.
    pub fn open_and_bind() -> Result<Self, SpyWardError> {
        let handle = unsafe { nfq_open() };
        if handle.is_null() {
            return Err(SpyWardError::InitFailed("nfq_open returned null".into()));
        }

        let bind_res = unsafe { nfq_bind_pf(handle, AF_INET as u16) };
        if bind_res < 0 {
            unsafe { nfq_close(handle) };
            return Err(SpyWardError::Nfqueue(bind_res));
        }

        let q_handle =
            unsafe { nfq_create_queue(handle, 0, Some(Self::packet_callback), ptr::null_mut()) };
        if q_handle.is_null() {
            unsafe {
                nfq_unbind_pf(handle, AF_INET as u16);
                nfq_close(handle);
            }
            return Err(SpyWardError::InitFailed(
                "nfq_create_queue returned null".into(),
            ));
        }

        let setmode_res = unsafe { nfq_set_mode(q_handle, NFQNL_COPY_PACKET as u8, 0xffff) };
        if setmode_res < 0 {
            unsafe {
                nfq_destroy_queue(q_handle);
                nfq_unbind_pf(handle, AF_INET as u16);
                nfq_close(handle);
            }
            return Err(SpyWardError::Nfqueue(setmode_res));
        }

        Ok(Self {
            handle,
            q_handle,
            cleaned_up: false,
        })
    }

    /// Unbinds/destroys the queue and closes everything.
    /// After this returns, `NfQueue` no longer owns any valid handles.
    pub fn unbind(&mut self) -> Result<(), SpyWardError> {
        if self.cleaned_up {
            return Ok(());
        }

        if !self.q_handle.is_null() {
            let res = unsafe { nfq_destroy_queue(self.q_handle) };
            if res < 0 {
                // Still try to continue cleanup, but report an error.
                eprintln!("warning: nfq_destroy_queue failed: {}", res);
            }
            self.q_handle = ptr::null_mut();
        }

        // Unbind the protocol family (AF_INET) from the main handle
        if !self.handle.is_null() {
            let res = unsafe { nfq_unbind_pf(self.handle, AF_INET as u16) };
            if res < 0 {
                eprintln!("warning: nfq_unbind_pf failed: {}", res);
            }
        }

        if !self.handle.is_null() {
            unsafe { nfq_close(self.handle) };
            self.handle = ptr::null_mut();
        }

        self.cleaned_up = true;
        Ok(())
    }

    /// Start the blocking packet loop. This will run until the is_shutting_down is flipped.
    pub fn run_until_shutdown(&self, shutdown_flag: Arc<AtomicBool>) -> Result<(), SpyWardError> {
        const BUF_SIZE: usize = 65_536;
        // TODO: Use fixed-size array or slice and reuse it
        let mut buf = vec![0_u8; BUF_SIZE];

        println!("Listening for packets on NFQUEUE #0...");

        let raw_fd = unsafe { nfq_fd(self.handle) };
        if raw_fd < 0 {
            return Err(SpyWardError::Nfqueue(raw_fd));
        }

        let mut fds = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        loop {
            let poll_ret = unsafe { libc::poll(&mut fds as *mut libc::pollfd, 1, 200) };

            if poll_ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    fds.revents = 0;
                } else {
                    return Err(SpyWardError::Io(err));
                }
            } else if poll_ret == 0 {
                // Timeout expired (no events).
            } else {
                // poll_ret > 0 means there is data on raw_fd. Check revents:
                if (fds.revents & libc::POLLIN) != 0 {
                    let len =
                        unsafe { recv(raw_fd, buf.as_mut_ptr() as *mut _, BUF_SIZE, 0 as c_int) };
                    if len < 0 {
                        let recv_err = io::Error::last_os_error();
                        if recv_err.kind() == io::ErrorKind::Interrupted {
                            // The recv itself was interrupted by the signal.
                        } else {
                            // Some other recv error is fatal
                            return Err(SpyWardError::Io(recv_err));
                        }
                    } else if len > 0 {
                        let handle_res = unsafe {
                            nfq_handle_packet(
                                self.handle,
                                buf.as_mut_ptr() as *mut c_char,
                                len as c_int,
                            )
                        };
                        if handle_res < 0 {
                            let hf_err = io::Error::last_os_error();
                            let _ = writeln!(io::stderr(), "nfq_handle_packet failed: {}", hf_err);
                            return Err(SpyWardError::Io(hf_err));
                        }
                    }
                }
                fds.revents = 0;
            }

            if shutdown_flag.load(Ordering::SeqCst) {
                println!("Exiting packet loop.");
                break;
            }
        }

        Ok(())
    }

    unsafe fn extract_packet_id(data: *mut nfq_data) -> u32 {
        let ph = nfq_get_msg_packet_hdr(data);
        if ph.is_null() {
            0
        } else {
            libc::ntohl((*ph).packet_id)
        }
    }

    unsafe fn extract_payload(data: *mut nfq_data) -> Vec<u8> {
        let mut payload_ptr: *mut u8 = ptr::null_mut();
        let len = nfq_get_payload(data, &mut payload_ptr);
        if len <= 0 || payload_ptr.is_null() {
            Vec::new()
        } else {
            let slice = slice::from_raw_parts(payload_ptr, len as usize);
            slice.to_vec()
        }
    }

    unsafe extern "C" fn packet_callback(
        qh: *mut nfq_q_handle,
        _nfmsg: *mut nfgenmsg,
        nfdata: *mut nfq_data,
        _data: *mut c_void,
    ) -> c_int {
        let packet_bytes = Self::extract_payload(nfdata);
        let pkt_id = Self::extract_packet_id(nfdata);

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

        // TODO: Handle HTTP requests
        match hdr.packet_protocol() {
            IPProtocol::TCP => {
                let tcp_hdr = TCPHeader::parse_tcp_header(buf);

                println!("{:?}", tcp_hdr);
            }
            IPProtocol::ICMP => {
                // TODO
                println!("ICMP");
            }
            IPProtocol::UDP => {
                let udp_hdr = UDPHeader::parse_udp_header(buf);

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
}

/// Automatically clean up if `unbind()` was not explicitly called.
impl Drop for NfQueue {
    fn drop(&mut self) {
        if !self.cleaned_up {
            let _ = self.unbind();
        }
    }
}
