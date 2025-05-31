#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use crate::errors::SpyWardError;
use crate::ip;
use libc::recv;
use libc::AF_INET;
use libc::NFQNL_COPY_PACKET;
use libc::NF_ACCEPT;
use std::ffi::c_void;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;

extern crate libc;

/// Represents an open NFQUEUE “session” with one queue #0.
pub struct NfQueue {
    /// The raw nfq_handle pointer.
    handle: *mut nfq_handle,
    /// The raw nfq_q_handle pointer associated to queue #0.
    q_handle: *mut nfq_q_handle,
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
            return Err(SpyWardError::Nfqueue(bind_res));
        }

        let q_handle =
            unsafe { nfq_create_queue(handle, 0, Some(Self::packet_callback), ptr::null_mut()) };
        if q_handle.is_null() {
            return Err(SpyWardError::InitFailed(
                "nfq_create_queue returned null".into(),
            ));
        }

        let setmode_res = unsafe { nfq_set_mode(q_handle, NFQNL_COPY_PACKET as u8, 0xffff) };
        if setmode_res < 0 {
            return Err(SpyWardError::Nfqueue(setmode_res));
        }

        Ok(Self { handle, q_handle })
    }

    /// Start the blocking packet loop. This will run until the process is killed.
    pub fn run(&self) -> Result<(), SpyWardError> {
        const BUF_SIZE: usize = 65_536;
        let mut buf = vec![0_u8; BUF_SIZE];

        println!("Listening for packets on NFQUEUE #0…");

        // TODO: Add signal handling for graceful shutdown (SIGINT/SIGTERM)
        // TODO: Unbind and close on shutdown
        loop {
            let fd = unsafe { nfq_fd(self.handle) };
            if fd < 0 {
                return Err(SpyWardError::Nfqueue(fd));
            }

            let len = unsafe { recv(fd, buf.as_mut_ptr() as *mut c_void, BUF_SIZE, 0 as c_int) };

            if len < 0 {
                // If recv was interrupted or failed, bail out.
                let err = io::Error::last_os_error();
                return Err(SpyWardError::Io(err));
            } else if len == 0 {
                // No data?
                continue;
            } else {
                let handle_res = unsafe {
                    nfq_handle_packet(self.handle, buf.as_mut_ptr() as *mut c_char, len as c_int)
                };
                if handle_res < 0 {
                    let err = io::Error::last_os_error();
                    let _ = writeln!(io::stderr(), "nfq_handle_packet failed: {}", err);
                    return Err(SpyWardError::Io(err));
                }
            }
        }
        // Note: never return Ok(()) because this loop runs indefinitely.
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
        // TODO: Add --verbose option
        // TODO: Check DNS for source
        // TODO: Use EasyList to decide if packed should be accepted or rejected
        // TODO: Allow custom blocklist/allowlist
        // TODO: Implement statistics (accepted/rejected counts)
        // TODO: Add unit tests for packetCallback logic

        let hdr = ip::parse_ip_header(&packet_bytes);
        ip::log_ip_header(&*hdr);

        let v = nfq_set_verdict(qh, pkt_id, NF_ACCEPT as u32, 0, ptr::null());
        if v < 0 {
            let err = io::Error::last_os_error();
            let _ = writeln!(io::stderr(), "nfq_set_verdict error: {}", err);
        }
        v
    }
}
